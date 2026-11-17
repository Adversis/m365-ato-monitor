# Application Insights Queries

Open Azure Portal > Application Insights > Logs. Paste a query.

Each query matches a log message that the code writes. If you change a message in the code, change the query.

## Suspicious sign-ins, last 24 hours

```kql
traces
| where timestamp > ago(24h)
| where message startswith "Suspicious login:"
| parse message with "Suspicious login: User=" user ", IP=" ip ", Flags=" flags ", Confidence=" confidence ", Result=" result ", Org=" org ", Location=" location
| project timestamp, user, ip, flags, confidence, result, org, location
| order by timestamp desc
```

## Compromise indicators, last 24 hours

```kql
traces
| where timestamp > ago(24h)
| where message startswith "Compromise indicator:"
| parse message with "Compromise indicator: type=" finding_type ", user=" user ", severity=" severity
| project timestamp, finding_type, user, severity
| order by timestamp desc
```

## New-country sign-ins and response actions

```kql
traces
| where timestamp > ago(30d)
| where message startswith "Country anomaly:" or message startswith "Response action"
| project timestamp, severityLevel, message
| order by timestamp desc
```

Automatic actions log `Response action (new country)` or `Response action (<alert type>)`. Actions from the user page log `Response action (manual)` with the admin in `By=`.

## Muted and turned-off alerts

```kql
traces
| where timestamp > ago(30d)
| where message startswith "Compromise indicator (muted)"
    or message startswith "Compromise indicator (alert turned off)"
    or message startswith "Suspicious sign-in muted"
| project timestamp, message
| order by timestamp desc
```

## Management UI changes and the onboarding scan

```kql
traces
| where timestamp > ago(30d)
| where message startswith "Settings changed by" or message startswith "Mute added by"
    or message startswith "Mute ended by" or message startswith "Country approve"
    or message startswith "Country remove" or message startswith "Onboarding"
| project timestamp, message
| order by timestamp desc
```

## Emails sent and failed

```kql
traces
| where timestamp > ago(7d)
| where message startswith "Email sent:" or message startswith "Email not sent:"
| project timestamp, message
| order by timestamp desc
```

## Runs per hour

```kql
traces
| where timestamp > ago(24h)
| where message startswith "audit_log_monitor run completed"
| summarize runs = count() by bin(timestamp, 1h)
| render timechart
```

Expected: about 30 runs per hour. The health alert `alert-<name>-no-runs` uses the same message.

## Events per run

```kql
traces
| where timestamp > ago(24h)
| where message startswith "Login check:"
| parse message with "Login check: " events " events, " ips " IPs checked, " suspicious " suspicious, " skipped " skipped"
| project timestamp, events = toint(events), ips = toint(ips), suspicious = toint(suspicious), skipped = toint(skipped)
| order by timestamp desc
```

A high `skipped` count means proxycheck.io lookups failed.

## Suspicious sign-ins by user, top 10

```kql
traces
| where timestamp > ago(7d)
| where message startswith "Suspicious login:"
| parse message with "Suspicious login: User=" user ", IP=" *
| summarize count() by user
| top 10 by count_
```

## Suspicious sign-ins by country, top 10

```kql
traces
| where timestamp > ago(7d)
| where message startswith "Suspicious login:"
| parse message with * ", Location=" city "," country
| summarize count() by country
| top 10 by count_
```

## Coverage gaps and catch-up

```kql
traces
| where timestamp > ago(30d)
| where message startswith "Coverage gap:" or message startswith "Catch-up:"
| project timestamp, severityLevel, message
| order by timestamp desc
```

A "Coverage gap" row gives an interval that was not fully processed. Search the unified audit log for that interval by hand.

## Errors

Or from a terminal, with your Azure CLI sign-in (read only): `./scripts/errors.ps1` (`-Hours 72`, `-Warnings`, `-Full`, `-Tenant contoso.com`). It counts the errors by message, then lists the newest. It hides "Exception encountered while listening to EventStream": the Functions host logs it when Azure stops an instance (`-All` shows it). `-Kql '<query>'` runs any query on this page.

```kql
traces
| where timestamp > ago(24h)
| where severityLevel >= 3
| project timestamp, message, severityLevel
| order by timestamp desc
```

## Retry queues

```kql
traces
| where timestamp > ago(7d)
| where message startswith "Email queued in outbox" or message startswith "Outbox:"
    or message startswith "Email dropped" or message startswith "Pending IP checks:"
    or message startswith "Sign-in IP check abandoned"
| project timestamp, severityLevel, message
| order by timestamp desc
```

## No audit content

```kql
traces
| where timestamp > ago(7d)
| where message startswith "No audit content for"
| project timestamp, message
| order by timestamp desc
```

## Token failures

```kql
traces
| where timestamp > ago(7d)
| where message contains "Token request for" or message contains "Managed identity"
| project timestamp, message
| order by timestamp desc
```

A token failure means that the managed identity or its federated credential is missing. Run `./install.ps1 -Update`.

## proxycheck.io quota and errors

```kql
traces
| where timestamp > ago(7d)
| where message startswith "proxycheck.io"
| project timestamp, severityLevel, message
| order by timestamp desc
```

## Detector parse errors

```kql
traces
| where timestamp > ago(7d)
| where message contains "that did not parse" or message startswith "Detector "
| project timestamp, message
| order by timestamp desc
```

A row here can mean that Microsoft changed a record format.
