"""Recovery of failed deliveries, incomplete history, and severity escalations."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from contextlib import ExitStack
import time
import pytest

import function_app as fa
import geo_monitor
import onboarding
import settings
import mail_access
import ip_checker
from tests.fakes import FakeTable

NOW = datetime(2026, 11, 12, 12, tzinfo=timezone.utc)
USER = 'victim@contoso.com'
IP = '8.8.4.4'


def observation(when=NOW, cc='FR'):
    event = {'Id': 'country-1', 'Operation': 'UserLoggedIn', 'UserId': USER,
             'CreationTime': when.isoformat(), 'ClientIP': IP}
    return {'user': USER, 'country': cc, 'outcome': 'success', 'ip': IP,
            'event': event, 'analysis': {'country': cc, 'org': 'ISP'}}


def test_country_alert_retries_after_send_and_outbox_fail():
    country_table, events = FakeTable(), FakeTable()
    with patch('config.HOME_COUNTRIES', {'US'}), patch('config.GEO_LEARNING_DAYS', 0), \
            patch('geo_monitor.table_client', return_value=country_table), \
            patch('journal.table_client', return_value=FakeTable()), \
            patch('responder.respond', return_value='Revoke sessions: done') as respond, \
            patch('function_app.send_country_anomaly_alert', return_value=False) as first:
        fa._handle_country_anomalies(events, [observation()])
        assert first.call_count == 1
        with patch('function_app.send_country_anomaly_alert', return_value=True) as retry:
            # The record is no longer fetched. Only the durable pending alert remains.
            fa._run_login_check(events, FakeTable(), set(), [])
            assert retry.call_count == 1, 'Failed country alert was suppressed before any successful delivery'
            fa._run_login_check(events, FakeTable(), set(), [])
            assert retry.call_count == 1
        assert respond.call_count == 1
        assert country_table.partition('pending') == {}


@pytest.mark.parametrize('kind', ['compromise', 'signin', 'mail_access'])
def test_failed_delivery_retries_after_the_normal_fetch_window(kind):
    clock = [NOW]

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock[0]

    event = {'Id': 'undelivered-1', 'Operation': 'New-InboxRule', 'UserId': USER,
             'CreationTime': NOW.isoformat(), 'ClientIP': IP}
    if kind == 'signin':
        event.update(Operation='UserLoggedIn', RecordType=15)
    elif kind == 'mail_access':
        event.update(Operation='Send', ClientInfoString='Client=OWA')
    finding = {'type': 'inbox_rule', 'severity': 'high', 'user': USER,
               'description': 'malicious rule', 'event': event, 'ip': IP}
    events = FakeTable()
    patches = {
        'function_app._get_table_clients': (events, FakeTable()),
        'function_app.ensure_subscriptions': {},
        'function_app._check_setup_confirmation': None,
        'onboarding.ensure_started': None,
        'function_app.flush_outbox': None,
        'mail_access.record': None,
        'mail_access.remember_signins': None,
        'function_app._run_login_check': None,
        'function_app._run_session_check': None,
        'function_app._run_mail_access_check': None,
        'function_app._maybe_flush_login_digest': None,
        'proxycheck_quota.check': None,
        'journal.table_client': FakeTable(),
        'geo_monitor.table_client': FakeTable(),
        'responder.respond_to_finding': '',
    }
    handler = {'compromise': '_run_compromise_check', 'signin': '_run_login_check',
               'mail_access': '_run_mail_access_check'}[kind]
    patches.pop(f'function_app.{handler}', None)
    content_type = fa.AAD_CONTENT_TYPE if kind == 'signin' else fa.EXCHANGE_CONTENT_TYPE

    def fetch(ct, start, end):
        return ([event] if ct == content_type and start <= NOW <= end else []), True

    with ExitStack() as stack:
        for target, value in patches.items():
            stack.enter_context(patch(target, return_value=value))
        stack.enter_context(patch('function_app.datetime', Clock))
        stack.enter_context(patch('function_app._DETECTORS', (lambda records: [finding] if records else [],)
                                  if kind == 'compromise' else ()))
        stack.enter_context(patch('config.MAIL_ACCESS_CHECK', True))
        stack.enter_context(patch('responder.respond_to_finding', return_value=''))
        stack.enter_context(patch('function_app.check_ips_batch', return_value={
            IP: {'proxy': 'yes', 'type': 'TOR', 'risk': 100, 'isocode': 'FR', 'organisation': 'Tor'}}))
        stack.enter_context(patch('function_app.fetch_content_records', side_effect=fetch))
        sender = 'send_suspicious_login_alert' if kind == 'signin' else 'send_compromise_alert'
        deliver = stack.enter_context(patch(f'function_app.{sender}', return_value=False))
        fa.audit_log_monitor(None)
        assert deliver.call_count == 1
        assert events.checkpoint(content_type) == NOW - timedelta(minutes=8)
        # A new process can recover the failed record from the saved checkpoint.
        clock[0] += timedelta(minutes=12)
        deliver.return_value = True
        fa.audit_log_monitor(None)
        assert deliver.call_count == 2
        assert events.checkpoint(content_type) == clock[0]


@pytest.mark.parametrize('failure', ['partial', 'exception'])
def test_onboarding_retries_incomplete_fetch_window_without_double_counting(failure):
    events = FakeTable()
    begin, end = NOW - timedelta(hours=1), NOW - timedelta(minutes=8)
    state = onboarding.start(events, NOW, end=end)
    state['history'].update(cursor=begin.strftime(onboarding._TS), **{'from': begin.strftime(onboarding._TS)})
    record = {'Id': 'history-rule', 'CreationTime': begin.isoformat(), 'Operation': 'New-InboxRule',
              'UserId': USER, 'Parameters': [{'Name': 'Name', 'Value': 'Invoices'},
                                           {'Name': 'ForwardTo', 'Value': 'drop@evil.example'}]}
    def fetch(content_type, start, stop):
        if content_type == fa.AAD_CONTENT_TYPE:
            return [record], True
        if failure == 'exception':
            raise RuntimeError('listing failed')
        return [], False

    with patch('onboarding.fetch_content_records', side_effect=fetch) as fetch_mock, \
            patch('geo_monitor.table_client', return_value=FakeTable()), \
            patch('journal.table_client', return_value=FakeTable()):
        assert not onboarding._history(events, FakeTable(), fa._DETECTORS, state, NOW, time.monotonic() + 1)
        assert onboarding.load(events)['history']['cursor'] == begin.strftime(onboarding._TS)
        assert state['history']['records'] == state['history']['findings'] == 0
        assert state['history']['errors']
        fetch_mock.side_effect = lambda ct, start, stop: ([record] if ct == fa.AAD_CONTENT_TYPE else [], True)
        assert onboarding._history(events, FakeTable(), fa._DETECTORS, state, NOW, time.monotonic() + 1)
    assert state['history']['cursor'] == end.strftime(onboarding._TS)
    assert state['history']['records'] == state['history']['findings'] == 1


@pytest.mark.parametrize('days', [11, 30])
def test_valid_promotion_setting_can_promote(days):
    assert settings.validate(settings.BY_NAME['GEO_PROMOTE_DAYS'], days) == days
    table = FakeTable()
    with patch('config.HOME_COUNTRIES', {'US'}), patch('config.GEO_LEARNING_DAYS', 0), \
            patch('config.GEO_PROMOTE_DAYS', days):
        for day in range(days):
            when = NOW + timedelta(days=day)
            geo_monitor.evaluate(table, [observation(when)], when)
        rows = geo_monitor.user_countries(table, USER, when)
        assert next(row for row in rows if row['country'] == 'FR')['status'] == 'usual'


@pytest.mark.parametrize('muted', [True, False])
@pytest.mark.parametrize('operation', ['Send', 'Sync', 'Tor'])
def test_medium_mail_read_does_not_hide_a_later_high_alert(muted, operation):
    events = FakeTable()
    read = {'Id': 'read-1', 'Operation': 'MailItemsAccessed', 'UserId': USER, 'MailboxOwnerUPN': USER,
            'ClientIP': IP, 'ClientInfoString': 'Client=OWA', 'CreationTime': NOW.isoformat()}
    later = dict(read, Id='later-1', CreationTime=(NOW + timedelta(minutes=2)).isoformat())
    if operation == 'Send':
        later['Operation'] = 'Send'
    elif operation == 'Sync':
        later['OperationProperties'] = [{'Name': 'MailAccessType', 'Value': 'Sync'}]
    data = {IP: {'proxy': 'yes', 'type': 'VPN', 'risk': 33, 'isocode': 'US', 'organisation': 'VPN'}}
    mute = {'id': 'mute-1', 'type': 'mail_access', 'user': USER, 'until': (NOW + timedelta(days=30)).isoformat()}
    with patch('config.MAIL_ACCESS_CHECK', True), patch('function_app.check_ips_batch', return_value=data), \
            patch('geo_monitor.table_client', return_value=FakeTable()), \
            patch('journal.table_client', return_value=FakeTable()), \
            patch('admin_store._active_mutes', [mute] if muted else []), \
            patch('function_app.send_compromise_alert', return_value=True) as deliver:
        fa._run_mail_access_check(events, FakeTable(), set(), [read], NOW)
        first_count = 0 if muted else 1
        assert deliver.call_count == first_count
        if operation == 'Tor':
            data[IP].update(type='TOR', risk=100)
        standalone = mail_access.check([later], lambda ips: data, ip_checker.analyze_ip, NOW)
        assert standalone[0]['severity'] == 'high'
        fa._run_mail_access_check(events, FakeTable(), set(), [later], NOW + timedelta(minutes=2))
        assert deliver.call_count == first_count + 1
        fa._run_mail_access_check(events, FakeTable(), set(), [later], NOW + timedelta(minutes=4))
        fa._run_mail_access_check(events, FakeTable(), set(), [read], NOW + timedelta(minutes=6))
        assert deliver.call_count == first_count + 1  # neither high nor medium repeats send again


@pytest.mark.parametrize('partition', ['pending', 'user'])
def test_country_storage_failure_does_not_acknowledge_the_login(partition):
    table, events = FakeTable(), FakeTable()
    obs = observation()
    upsert = table.upsert_entity

    def fail(entity):
        if entity['PartitionKey'] == partition:
            raise RuntimeError('country storage unavailable')
        upsert(entity)

    with patch('config.HOME_COUNTRIES', {'US'}), patch('config.GEO_LEARNING_DAYS', 0), \
            patch('geo_monitor.table_client', return_value=table), \
            patch('journal.table_client', return_value=FakeTable()), \
            patch('function_app.check_ips_batch', return_value={
                IP: {'proxy': 'no', 'risk': 0, 'isocode': 'FR'}}), \
            patch('function_app.send_country_anomaly_alert', return_value=True) as send:
        with patch.object(table, 'upsert_entity', side_effect=fail), \
                pytest.raises(RuntimeError, match='country storage unavailable'):
            fa._run_login_check(events, FakeTable(), set(), [obs['event']])
        assert obs['event']['Id'] not in events.partition('events')
        assert not send.called
        # A pending alert written before a failed baseline update also survives.
        fa._run_login_check(events, FakeTable(), set(), [obs['event']])
        assert send.call_count == 1
        assert obs['event']['Id'] in events.partition('events')


def test_country_pending_delete_failure_does_not_send_twice():
    table, events = FakeTable(), FakeTable()
    with patch('config.HOME_COUNTRIES', {'US'}), patch('config.GEO_LEARNING_DAYS', 0), \
            patch('geo_monitor.table_client', return_value=table), \
            patch('journal.table_client', return_value=FakeTable()), \
            patch('function_app.send_country_anomaly_alert', return_value=True) as send:
        with patch.object(table, 'delete_entity', side_effect=RuntimeError('delete failed')), \
                pytest.raises(RuntimeError, match='delete failed'):
            fa._handle_country_anomalies(events, [observation()])
        assert send.call_count == 1
        fa._handle_country_anomalies(events, [])
        assert send.call_count == 1
        assert table.partition('pending') == {}
