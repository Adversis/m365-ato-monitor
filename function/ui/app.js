"use strict";

// M365 ATO Monitor: management UI.
// Rules: no innerHTML with data (all text goes through textContent), no inline
// script or style (the page has a strict Content-Security-Policy), and every
// request that changes data sends the X-Monitor-Admin header (CSRF protection).

const API = "/api/manage/api";
const VIEWS = ["overview", "alerts", "users", "mutes", "settings", "countries", "history"];
// Deep links from alert emails: "#user:<upn>", "#mute:<type>:<upn>[:<rule>[:<asn>[:<network>]]]".
const VIEW_ALIASES = { user: "users", mute: "mutes" };
const STALE_MINUTES = 10;
const EMAILS_SHOWN = 10;
const ALERTS_SHOWN = 5;
const ALL_MUTE_TYPES = "All types that can be muted";
const STATUS_PILLS = {
  emailed: ["ok", "Emailed"],
  "email failed": ["bad", "Email failed"],
  "alert off": ["warn", "Alert off"],
  muted: ["info", "Muted"],
  onboarding: ["neutral", "Onboarding scan"],
  microsoft: ["neutral", "Microsoft service"],
  "known sign-in": ["neutral", "Known sign-in"],
  "list only": ["info", "Listed, no email"],
};
// The triage state that an admin sets. It changes only the view: later alerts still go out.
const TRIAGE = { "": ["neutral", "Open"], investigating: ["warn", "Investigating"], benign: ["ok", "Benign"], resolved: ["ok", "Resolved"] };
const TRIAGE_FILTERS = [["open", "Open and investigating"], ["", "All"], ["investigating", "Investigating"], ["benign", "Benign"], ["resolved", "Resolved"]];
const PAGE_SIZE = 50;
const USER_ALERTS_PAGE = 25;
const SCAN_STEPS = { history: "Audit history", rules: "Inbox rules", search: "Older history (audit search)", report: "Report" };
const SEARCH_DAYS = [7, 30, 90, 180];
const SEARCH_POLL_MS = 10000;
const GRANT_RESPONSE = "Run ./install.ps1 -ResponsePermissions yes to grant it.";
const CONTENT_TYPES = [
  ["Audit.AzureActiveDirectory", "Sign-in and directory content"],
  ["Audit.Exchange", "Exchange content"],
];
const CHECK_NAMES = {
  azure_ad_token: "Entra ID app token",
  o365_api_aad: "Audit log: sign-ins and directory",
  o365_api_exchange: "Audit log: Exchange",
  graph_api_token: "Microsoft Graph (email)",
  table_storage: "Table Storage",
  proxycheck_io: "proxycheck.io",
};
const ACTIONS = { none: "Email only", revoke: "Revoke sessions", disable: "Block sign-in and revoke sessions" };

let state = null;      // last /state response
let draft = {};        // setting name -> edited value (UI form); null = reset to default
let errors = {};       // setting name -> message from the server

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") el.className = value;
    else if (key === "text") el.textContent = value;
    else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else if (value === true) el.setAttribute(key, "");
    else el.setAttribute(key, String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

// replaceChildren() does not flatten arrays and writes null as text.
function fill(root, ...children) {
  root.replaceChildren(...children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false));
}

// Icons: SVG elements built with createElementNS. Stroke and fill come from CSS (.icon).
const ICONS = {
  ok: [["circle", { cx: 12, cy: 12, r: 9.5 }], ["path", { d: "M8 12.5l2.7 2.7L16.2 9.5" }]],
  warn: [["path", { d: "M10.3 3.9 1.9 18a2 2 0 0 0 1.7 3h16.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" }],
         ["path", { d: "M12 9v4.5" }], ["path", { d: "M12 17.2h.01" }]],
  bad: [["circle", { cx: 12, cy: 12, r: 9.5 }], ["path", { d: "M12 7.5v5.5" }], ["path", { d: "M12 16.5h.01" }]],
  info: [["circle", { cx: 12, cy: 12, r: 9.5 }], ["path", { d: "M12 16.5V11" }], ["path", { d: "M12 7.6h.01" }]],
  lock: [["rect", { x: 5, y: 11, width: 14, height: 10, rx: 2 }], ["path", { d: "M8 11V7.5a4 4 0 0 1 8 0V11" }]],
  search: [["circle", { cx: 11, cy: 11, r: 7 }], ["path", { d: "m20.5 20.5-4.5-4.5" }]],
  arrow: [["path", { d: "M5 12h14" }], ["path", { d: "m13 6 6 6-6 6" }]],
  clock: [["circle", { cx: 12, cy: 12, r: 9.5 }], ["path", { d: "M12 7v5l3.5 2" }]],
  globe: [["circle", { cx: 12, cy: 12, r: 9.5 }], ["path", { d: "M2.5 12h19" }],
          ["path", { d: "M12 2.5c2.6 2.7 3.9 5.9 3.9 9.5s-1.3 6.8-3.9 9.5c-2.6-2.7-3.9-5.9-3.9-9.5s1.3-6.8 3.9-9.5z" }]],
  mail: [["rect", { x: 2.5, y: 4.5, width: 19, height: 15, rx: 2 }], ["path", { d: "m3 6.5 9 6.5 9-6.5" }]],
  refresh: [["path", { d: "M20 11a8 8 0 0 0-14.5-4.5L4 8" }], ["path", { d: "M4 4v4h4" }],
            ["path", { d: "M4 13a8 8 0 0 0 14.5 4.5L20 16" }], ["path", { d: "M20 20v-4h-4" }]],
};

function icon(name, cls) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  svg.setAttribute("class", cls ? `icon ${cls}` : "icon");
  for (const [tag, attrs] of ICONS[name] || []) {
    const el = document.createElementNS(ns, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
    svg.append(el);
  }
  return svg;
}

class SessionError extends Error {}

async function api(path, options = {}) {
  const init = {
    method: options.method || "GET",
    credentials: "same-origin",
    redirect: "manual",
    headers: { "X-Monitor-Admin": "1", "Accept": "application/json" },
  };
  if (options.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }
  const res = await fetch(API + path, init);
  if (res.type === "opaqueredirect" || res.status === 401) throw new SessionError("Your session ended.");
  let data = null;
  let raw = "";
  try { raw = await res.text(); data = raw ? JSON.parse(raw) : null; } catch (e) { data = null; }
  if (!res.ok) {
    // An answer without our JSON error came from the platform (App Service, Functions host): show its text.
    const detail = data ? "" : raw.replace(/<(style|script)[^>]*>[\s\S]*?<\/\1>/gi, " ")
      .replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim().slice(0, 200);
    const err = new Error((data && data.error) ||
      `Request failed (HTTP ${res.status}${detail ? `: ${detail}` : ", no details from the server"}).`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

function utc(iso) {
  if (!iso) return "never";
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toISOString().slice(0, 16).replace("T", " ") + " UTC";
}

function ago(iso) {
  if (!iso) return "";
  const minutes = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (isNaN(minutes)) return "";
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} h ago`;
  return `${Math.round(hours / 24)} days ago`;
}

function minutesSince(iso) {
  return iso ? (Date.now() - new Date(iso).getTime()) / 60000 : Infinity;
}

// "in 3 days" for a time in the future; "2 h ago" for a time in the past.
function relative(iso) {
  if (!iso) return "";
  const minutes = Math.round((new Date(iso).getTime() - Date.now()) / 60000);
  if (isNaN(minutes)) return "";
  if (minutes <= 0) return ago(iso);
  if (minutes < 60) return `in ${minutes} min`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `in ${hours} h`;
  return `in ${Math.round(hours / 24)} days`;
}

function timeCell(iso) {
  return [h("time", { datetime: iso, text: utc(iso) }), iso ? h("span", { class: "sub", text: relative(iso) }) : null];
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

function pill(kind, text) {
  return h("span", { class: `pill pill-${kind}`, text });
}

function severityPill(severity) {
  if (severity === "high") return pill("bad", "High");
  if (severity === "medium") return pill("warn", "Medium");
  return severity ? pill("neutral", severity) : null;
}

function statusPill(status) {
  const [kind, label] = STATUS_PILLS[status] || ["neutral", status || "Unknown"];
  return pill(kind, label);
}

// Alert type -> label: the names in Settings > Alerts, the mute types, and the sign-in alerts.
let labelCache = null;
function typeLabels() {
  if (labelCache) return labelCache;
  const map = new Map();
  const alertsOff = ((state && state.settings && state.settings.items) || []).find((i) => i.name === "ALERTS_OFF");
  for (const [type, label] of (alertsOff ? alertsOff.choices : [])) map.set(type, label);
  for (const [type, label] of (state && state.mute_types) || []) if (!map.has(type)) map.set(type, label);
  map.set("new_country", "New-country sign-in");
  map.set("suspicious_signin", "Suspicious sign-in");
  labelCache = map;
  return map;
}

function typeLabel(type) {
  return typeLabels().get(type) || type || "Unknown";
}

function muteTypeLabel(type, types) {
  if (type === "*") return ALL_MUTE_TYPES;
  const found = (types || (state && state.mute_types) || []).find((t) => t[0] === type);
  return found ? found[1] : typeLabel(type);
}

// Hash parts are URL-encoded. A part that does not decode stays as it is.
function decodePart(text) {
  try { return decodeURIComponent(text); } catch (e) { return text; }
}

function encodePart(text) {
  return encodeURIComponent(text).replace(/%40/g, "@");
}

function userHash(upn) {
  return `#user:${encodePart(upn)}`;
}

function userLink(upn) {
  if (!upn) return "-";
  if (upn === "*") return "All users";
  return upn.includes("@") ? h("a", { href: userHash(upn), class: "upn", text: upn }) : upn;
}

function lockNote(id, ...content) {
  return h("li", { class: "option-note", id }, icon("lock"), h("span", {}, ...content));
}

function sub(text) {
  return text ? h("span", { class: "sub", text }) : null;
}

let regionNames = null;
function countryName(code) {
  try {
    regionNames = regionNames || new Intl.DisplayNames(["en"], { type: "region" });
    const name = regionNames.of(code);
    return name && name !== code ? name : "";
  } catch (e) {
    return "";
  }
}

function motionOk() {
  return !window.matchMedia || !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function setBusy(button, busy) {
  button.disabled = busy;
  button.classList.toggle("busy", busy);
  if (busy) button.setAttribute("aria-busy", "true");
  else button.removeAttribute("aria-busy");
}

function notice(kind, ...content) {
  const iconName = { ok: "ok", warn: "warn", bad: "bad", info: "info" }[kind] || "info";
  return h("div", { class: `notice notice-${kind}` }, icon(iconName), h("div", {}, ...content));
}

function empty(iconName, title, text) {
  return h("div", { class: "empty" }, icon(iconName), h("strong", { text: title }), text ? h("p", { text }) : null);
}

let toastTimer = null;
function toast(text) {
  const el = document.getElementById("toast");
  el.textContent = text;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.textContent = ""; }, 5000);
}

function showBanner(text, bad, reloadButton) {
  const el = document.getElementById("banner");
  if (!text) {
    el.hidden = true;
    el.removeAttribute("role");
    el.replaceChildren();
    return;
  }
  el.setAttribute("role", "alert");
  fill(el, notice(bad ? "bad" : "info", h("p", { text }),
    reloadButton ? h("button", { type: "button", class: "btn", onclick: () => location.reload(), text: "Reload page" }) : null));
  el.hidden = false;
}

function handleError(err) {
  if (err instanceof SessionError) {
    showBanner("Your session ended. Reload the page to sign in again.", true, true);
  } else {
    showBanner(err.message, true, false);
  }
}

function same(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

// A table that becomes stacked rows on a phone. columns: [label, cellClass]; rows: [[cell, ...], ...].
// rowClass: optional (row index) -> class of the <tr>.
function table(columns, rows, rowClass) {
  return h("div", { class: "table-wrap" }, h("table", { class: "list rows" },
    h("thead", {}, h("tr", {}, columns.map(([label, , head]) => head ? h("th", { scope: "col" }, head) : h("th", { scope: "col", text: label })))),
    h("tbody", {}, rows.map((cells, n) => h("tr", { class: rowClass ? rowClass(n) || null : null }, cells.map((cell, i) => {
      const [label, cls] = columns[i];
      return h("td", { class: cls || null, "data-label": label }, h("span", { class: "cell" }, cell));
    }))))));
}

function facts(rows) {
  return h("dl", { class: "facts" }, rows.filter(Boolean).flatMap(([label, ...value]) =>
    [h("dt", { text: label }), h("dd", {}, ...value)]));
}

// Dialog for a confirmation. Resolves true (OK) or false (Cancel, Esc).
function confirmDialog({ title, body, ok, danger }) {
  const dialog = document.getElementById("confirm");
  const head = document.getElementById("confirm-head");
  head.querySelectorAll("svg").forEach((s) => s.remove());
  head.prepend(icon(danger ? "warn" : "info"));
  document.getElementById("confirm-title").textContent = title;
  fill(document.getElementById("confirm-body"), body);
  const okButton = document.getElementById("confirm-ok");
  const cancel = document.getElementById("confirm-cancel");
  okButton.textContent = ok;
  okButton.className = danger ? "btn btn-danger" : "btn btn-primary";
  const previous = document.activeElement;
  return new Promise((resolve) => {
    const done = (result) => {
      okButton.removeEventListener("click", onOk);
      cancel.removeEventListener("click", onCancel);
      dialog.removeEventListener("cancel", onCancel);
      dialog.close();
      if (previous && previous.isConnected && !previous.closest("[hidden]")) previous.focus();
      resolve(result);
    };
    const onOk = () => done(true);
    const onCancel = (e) => { if (e) e.preventDefault(); done(false); };
    okButton.addEventListener("click", onOk);
    cancel.addEventListener("click", onCancel);
    dialog.addEventListener("cancel", onCancel);
    dialog.showModal();
    cancel.focus();
  });
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

// Hash: "#settings", "#settings:allow" (a settings group), or
// "#countries:jane@contoso.com" (link from a new-country alert).
function currentView() {
  const name = location.hash.replace("#", "").split(":")[0];
  const view = VIEW_ALIASES[name] || name;
  return VIEWS.includes(view) ? view : "overview";
}

function hashArgument() {
  const parts = location.hash.replace("#", "").split(":");
  return parts.length > 1 ? decodePart(parts.slice(1).join(":")) : "";
}

// "#mute:inbox_rule:jane%40contoso.com:.." -> ["inbox_rule", "jane@contoso.com", ".."]
function hashParts() {
  return location.hash.replace("#", "").split(":").slice(1).map(decodePart);
}

function showView(name) {
  for (const view of VIEWS) {
    const selected = view === name;
    document.getElementById(`view-${view}`).hidden = !selected;
    const tab = document.getElementById(`tab-${view}`);
    tab.setAttribute("aria-selected", selected ? "true" : "false");
    tab.tabIndex = selected ? 0 : -1;
    if (selected) revealTab(tab);
  }
  updateSavebar();
  updateActiveGroup();
}

// On a phone the tab bar scrolls. Keep the selected tab in view.
function revealTab(tab) {
  const bar = tab.parentElement;
  if (bar.scrollWidth <= bar.clientWidth) return;
  const b = bar.getBoundingClientRect();
  const t = tab.getBoundingClientRect();
  if (t.left < b.left) bar.scrollLeft += t.left - b.left - 16;
  else if (t.right > b.right) bar.scrollLeft += t.right - b.right + 16;
}

// Load the data that the view in the hash needs.
function routeArguments() {
  if (!state) return;
  const view = currentView();
  const arg = hashArgument();
  if (view === "settings" && arg) scrollToGroup(arg, false);
  if (view === "countries" && arg && arg !== countryUser) lookupCountries(arg);
  if (view === "users" && arg && (!userResult || userResult.user !== arg.trim().toLowerCase()) && arg !== userPending) loadUser(arg);
  if (view === "mutes") openMutes(location.hash.startsWith("#mute:") ? hashParts() : null);
  if (view === "alerts" && !alertsLoading) loadAlerts();
}

function initTabs() {
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  for (const tab of tabs) {
    tab.addEventListener("click", () => { location.hash = tab.dataset.view; });
    tab.addEventListener("keydown", (e) => {
      const i = tabs.indexOf(tab);
      let next = null;
      if (e.key === "ArrowRight") next = tabs[(i + 1) % tabs.length];
      if (e.key === "ArrowLeft") next = tabs[(i - 1 + tabs.length) % tabs.length];
      if (e.key === "Home") next = tabs[0];
      if (e.key === "End") next = tabs[tabs.length - 1];
      if (next) { e.preventDefault(); next.focus(); location.hash = next.dataset.view; }
    });
  }
  window.addEventListener("hashchange", () => {
    showView(currentView());
    routeArguments();
  });
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

function fetchState(iso) {
  if (!iso) return "none";
  return minutesSince(iso) > STALE_MINUTES ? "stale" : "ok";
}

function fetchValue(iso) {
  const s = fetchState(iso);
  if (s === "none") return [pill("warn", "None yet"), " ", h("span", { class: "sub", text: "No complete fetch." })];
  return [pill(s === "ok" ? "ok" : "bad", s === "ok" ? "OK" : "Stale"), " ", ago(iso),
          h("span", { class: "sub", text: utc(iso) })];
}

// Items for the status summary: [level, text]. Levels: bad, warn, info.
function healthIssues() {
  const health = state.health || {};
  const fetches = health.last_complete_fetch || {};
  const queues = health.queues || {};
  const roles = health.graph_roles;
  const issues = [];
  for (const [key, label] of CONTENT_TYPES) {
    const s = fetchState(fetches[key]);
    if (s === "stale") issues.push(["bad", `${label}: no complete fetch in the last ${STALE_MINUTES} minutes. Run the dependency checks.`]);
    if (s === "none") issues.push(["warn", `${label}: no complete fetch yet. Run the dependency checks.`]);
  }
  if (health.credential === "none") {
    issues.push(["bad", "The app has no credential (MANAGED_IDENTITY_CLIENT_ID is not set). Run ./install.ps1 -Update."]);
  }
  if (queues.outbox) {
    const why = queues.outbox_error ? ` Graph said: ${queues.outbox_error}.` : "";
    const hint = /\b404\b|MailboxNotEnabled|ErrorInvalidUser|ResourceNotFound/i.test(queues.outbox_error || "")
      ? "The alert mailbox has no Exchange Online mailbox. Give it a license with Exchange Online, or use a shared mailbox " +
        "(free, no license): run ./install.ps1 -AdminEmail <shared mailbox>. To read the alerts, add your address in Settings > Email > Extra recipients."
      : "Usual cause: the alert mailbox is not licensed, or Mail.Send has no consent.";
    issues.push(["warn", `${queues.outbox} alert email(s) wait in the outbox. Graph refused them.${why} Each run tries again for up to 7 days. ${hint}`]);
  }
  const lookups = health.ip_lookups || {};
  const usage = lookupUsage(lookups);
  if (lookups.level === "exhausted") {
    issues.push(["bad", `The proxycheck.io daily quota is used up${usage ? ` (${usage})` : ""}. Sign-in checks wait for up to 26 hours. The stolen session and mail access checks skip records. Account takeover alerts are still sent. Add a key or a larger plan in Settings > Suspicious sign-ins.`]);
  } else if (lookups.level === "low") {
    issues.push(["warn", `The proxycheck.io daily quota is low${usage ? ` (${usage})` : ""}. When it is used up, sign-in checks wait until the next day.`]);
  } else if (lookups.level === "refused") {
    issues.push(["bad", `proxycheck.io refuses IP lookups${lookups.message ? `: ${lookups.message}` : ""}. Check the key in Settings > Suspicious sign-ins.`]);
  }
  if (queues.pending_ip_checks) {
    issues.push(["warn", `${queues.pending_ip_checks} sign-in(s) wait for an IP check. Each run tries again for up to 26 hours. Usual cause: the proxycheck.io daily quota is used up.`]);
  }
  if (roles === null || roles === undefined) {
    issues.push(["warn", "The app could not get a Microsoft Graph token. Alert emails can fail. Run the dependency checks."]);
  } else if (state.app.mail_send_scope !== "mailbox" && !roles.includes("Mail.Send")) {
    issues.push(["warn", "The Graph token does not have Mail.Send. Alert emails can fail. Grant admin consent in the Entra admin center."]);
  }
  if (!state.app.admin_email) issues.push(["warn", "No alert mailbox is set. Set it in Settings > Email."]);
  if (!state.app.storage) issues.push(["warn", "Table Storage is not configured. Settings cannot be saved."]);
  return issues;
}

// -MailSendScope takes the word "mailbox". People read it as a place for the address.
function limitMailSendText() {
  return "Optional: to limit it to the alert mailbox, run ./install.ps1 -MailSendScope mailbox as shown.";
}

function statusSummary() {
  const health = state.health || {};
  const fetches = health.last_complete_fetch || {};
  const issues = healthIssues();
  const level = issues.some((i) => i[0] === "bad") ? "bad" : issues.some((i) => i[0] === "warn") ? "warn" : "ok";
  const title = {
    ok: "Monitoring runs normally",
    warn: "Monitoring runs. Some items need attention.",
    bad: "Monitoring has a problem",
  }[level];

  const isos = CONTENT_TYPES.map(([key]) => fetches[key]);
  const oldest = isos.every(Boolean) ? isos.reduce((a, b) => (new Date(a) < new Date(b) ? a : b)) : null;
  const fetchLevel = isos.some((iso) => fetchState(iso) === "stale") ? "bad" : oldest ? "ok" : "warn";
  // A complete fetch can bring no records (for example: unified audit logging is off).
  const seen = Object.values(health.last_content_seen || {}).filter(Boolean);
  const lastContent = seen.length ? seen.reduce((a, b) => (new Date(a) > new Date(b) ? a : b)) : null;
  const contentHours = lastContent ? (Date.now() - new Date(lastContent)) / 3600000 : null;
  const contentLevel = lastContent === null ? "warn" : contentHours > 24 ? "warn" : "ok";
  const tenantWide = state.app.mail_send_scope !== "mailbox";

  const stat = (label, dotLevel, value, sub) => h("div", { class: "stat" },
    h("dt", { text: label }),
    h("dd", {}, dotLevel ? h("span", { class: `dot dot-${dotLevel}`, "aria-hidden": "true" }) : null,
      h("span", {}, value, sub ? h("span", { class: "sub", text: sub }) : null)));

  return h("section", { class: `card card-flush summary summary-${level}`, "aria-labelledby": "summary-title" },
    h("div", { class: "summary-head" },
      h("div", { class: "summary-icon" }, icon(level, "icon-lg")),
      h("div", { class: "summary-text" },
        h("h2", { class: "summary-title", id: "summary-title", text: title }),
        h("p", { class: "muted", text: oldest
          ? `Last complete fetch ${ago(oldest)}. Page data from ${utc(new Date().toISOString())}.`
          : `Page data from ${utc(new Date().toISOString())}.` })),
      h("div", { class: "actions" },
        h("button", { type: "button", class: "btn btn-quiet", id: "refresh", onclick: refreshOverview }, icon("refresh"),
          h("span", { class: "btn-text", text: "Refresh" })))),
    h("dl", { class: "stats" },
      stat("Last complete fetch", fetchLevel, oldest ? ago(oldest) : "None yet", oldest ? utc(oldest) : null),
      stat("Last audit content", contentLevel, lastContent ? ago(lastContent) : "None yet",
        lastContent ? utc(lastContent) : "The first content can take 12-24 hours"),
      stat("Mail.Send scope", tenantWide ? null : "ok", tenantWide ? "Tenant-wide" : "Alert mailbox only",
        tenantWide ? "Can be limited later" : (state.app.mail_send_group ? `Group ${state.app.mail_send_group}` : "Exchange RBAC for Applications")),
      stat("Alert mailbox", state.app.admin_email ? null : "warn", state.app.admin_email || "Not set", null)),
    issues.length ? h("ul", { class: "issues", "aria-label": "Items to check" }, issues.map(([lvl, text]) =>
      h("li", { class: `issue-${lvl}` }, icon(lvl),
        h("span", {}, h("span", { class: "visually-hidden", text: { bad: "Problem: ", warn: "Warning: ", info: "Note: " }[lvl] }), text))))
      : null);
}

async function refreshOverview(e) {
  const button = e.currentTarget;
  setBusy(button, true);
  const loaded = await reload(false);
  if (button.isConnected) setBusy(button, false);
  const fresh = document.getElementById("refresh");
  if (fresh) fresh.focus();
  if (loaded) toast("Overview updated.");
}

function monitorCard() {
  const health = state.health || {};
  const fetches = health.last_complete_fetch || {};
  const content = health.last_content_seen || {};
  const queues = health.queues || {};
  const anyStale = Object.values(fetches).some((iso) => minutesSince(iso) > STALE_MINUTES);
  const seen = CONTENT_TYPES.map(([key]) => content[key]).filter(Boolean)
    .sort((a, b) => new Date(b) - new Date(a))[0];
  const queueValue = (n, note) => [String(n ?? "unknown"), n ? h("span", { class: "sub", text: note }) : null];
  return h("section", { class: "card", "aria-labelledby": "card-monitor" },
    h("div", { class: "card-head" }, h("h2", { id: "card-monitor", text: "Monitor" }),
      anyStale ? pill("bad", "Check") : pill("ok", "Running")),
    facts([
      ...CONTENT_TYPES.map(([key, label]) => [label, ...fetchValue(fetches[key])]),
      ["Last audit content", seen ? utc(seen) : "never", seen ? h("span", { class: "sub", text: ago(seen) }) : null],
      ["Alert emails waiting", ...queueValue(queues.outbox, `Graph refused them${queues.outbox_error ? ` (${queues.outbox_error})` : ""}. Retried each run.`)],
      ["Sign-ins waiting for an IP check", ...queueValue(queues.pending_ip_checks, "proxycheck.io lookups failed.")],
      ["Sign-ins in the digest queue", String(queues.digest ?? "unknown")],
      ["Mail access records, 7 days", ...mailAccessValue(health.mail_access)],
      ["IP lookups (proxycheck.io)", ...lookupValue(health.ip_lookups)],
      ["Past sign-ins loaded", ...backfillValue(health.network_backfill)],
      ["Version", ...versionValue(health.update)],
    ]));
}

// The one-time load of 30 days of sign-ins into the network history (MFA and inbox rule checks).
function backfillValue(b) {
  const note = (text) => h("span", { class: "sub", text });
  if (!b) return ["not started", note("Starts within 5 minutes. Until it is done, MFA changes send email only after another alert.")];
  if (b.finished_at && !b.skipped) {
    return [`${(b.records || 0).toLocaleString()} sign-in records`, note(b.limit_exceeded
      ? "Microsoft's search limit was reached: the history is not complete, and builds from new sign-ins (14 days)."
      : `From ${utc(b.from)}. Done ${ago(b.finished_at)}.`)];
  }
  if (b.finished_at) return ["stopped", note(`${b.skipped}. The network history builds from new sign-ins (14 days).`)];
  const status = b.status ? `audit search ${b.status}` : "starting";
  return ["running", note(`${status}${b.records ? `, ${b.records.toLocaleString()} records read` : ""}${b.error ? ` (last error: ${b.error})` : ""}. A search takes 4 to 40 minutes, sometimes hours.`)];
}

// "1.0.0" and, when GitHub has a newer release, "Update available" with the release notes.
function versionValue(u) {
  if (!u || !u.version) return ["unknown"];
  if (u.newer) {
    return [u.version, " ", pill("warn", `Update available: ${u.latest}`),
      h("span", { class: "sub" }, u.url ? h("a", { href: u.url, target: "_blank", rel: "noopener noreferrer", text: "Release notes" }) : "Release notes on GitHub",
        ". To update, run ./install.ps1 -Update.")];
  }
  if (!u.enabled) return [u.version, h("span", { class: "sub", text: "Update check off (Settings > Advanced)." })];
  if (u.error) return [u.version, h("span", { class: "sub", text: `Update check: ${u.error}.` })];
  if (u.checked_at) return [u.version, h("span", { class: "sub", text: `Up to date. Checked ${ago(u.checked_at)}.` })];
  return [u.version, h("span", { class: "sub", text: "Not checked yet (once a day)." })];
}

// "850 of 1,000 used today (Free plan)", or "" if the count is not known.
function lookupUsage(q) {
  if (!q || q.used === null || q.used === undefined || !q.limit) return "";
  return `${q.used.toLocaleString()} of ${q.limit.toLocaleString()} used today${q.plan ? ` (${q.plan} plan)` : ""}`;
}

// proxycheck.io quota: the level from its newest answer, and the usage count (with a key).
function lookupValue(q) {
  if (!q) return ["unknown"];
  const pills = { ok: pill("ok", "OK"), low: pill("warn", "Low"), exhausted: pill("bad", "Used up"),
    refused: pill("bad", "Refused"), unknown: pill("info", "No answer today") };
  const usage = lookupUsage(q);
  let note = "";
  if (q.message) note = `proxycheck.io: ${q.message}`;
  else if (!q.key) note = "No key: 100 lookups per day. A free key gives 1,000: Settings > Suspicious sign-ins.";
  else if (!usage && q.usage_error) note = q.usage_error;
  return [pills[q.level] || pills.unknown, usage ? ` ${usage}` : "", note ? h("span", { class: "sub", text: note }) : null];
}

// MailItemsAccessed and Send records: does the tenant log mail reads?
function mailAccessValue(m) {
  if (!m) return ["unknown"];
  const t = m.totals || {};
  if (!t.reads && !t.sends) {
    return ["None", h("span", { class: "sub", text: "Mail reads are not logged. Mail read with a stolen token is not visible." })];
  }
  const n = t.reads + t.sends;
  const pct = (x) => `${Math.floor((100 * x) / n)}%`;
  return [`${t.reads.toLocaleString()} reads, ${t.sends.toLocaleString()} sends`,
    h("span", { class: "sub", text: `${t.sync.toLocaleString()} sync, ${t.bind.toLocaleString()} bind. With client IP ${pct(t.with_ip)}, session ID ${pct(t.with_session)}, app ID ${pct(t.with_app)}.` })];
}

function countriesCard() {
  const geo = (state.health || {}).country_baseline || null;
  let rows;
  if (!geo || !geo.learning_started) {
    rows = [["State", geo && geo.enabled === false ? pill("warn", "Off") : "Starts with the first sign-in"]];
  } else {
    rows = [
      ["State", geo.enabled ? (geo.learning ? pill("info", "Learning") : pill("ok", "Active")) : pill("warn", "Off")],
      geo.learning ? ["Learning ends", utc(geo.learning_ends)] : null,
      ["Countries seen in the tenant", (geo.tenant_countries || []).join(", ") || "none yet"],
      ["Home countries", (geo.home_countries || []).join(", ") || "none"],
      ["Action on a new country", ACTIONS[geo.anomaly_action] || geo.anomaly_action],
    ];
  }
  return h("section", { class: "card", "aria-labelledby": "card-countries" },
    h("div", { class: "card-head" }, h("h2", { id: "card-countries", text: "New sign-in countries" })),
    facts(rows));
}

function addressList(list) {
  return list && list.length ? h("span", { class: "chips" }, list.map((a) => h("span", { class: "chip", text: a }))) : "none";
}

function accessCard() {
  const health = state.health || {};
  const roles = health.graph_roles;
  const app = state.app;
  return h("section", { class: "card", "aria-labelledby": "card-access" },
    h("div", { class: "card-head" }, h("h2", { id: "card-access", text: "Access" })),
    facts([
      ["Alert mailbox", app.admin_email || "not set", sub("Sends every email. Gets every alert and report.")],
      ["Extra alert recipients", addressList(app.alert_recipients)],
      ["Extra report recipients", addressList(app.report_recipients)],
      ["Tenant label", app.tenant_label
        ? [app.tenant_label, sub(`Subjects start with [M365 Alert][${app.tenant_label}].`)] : "none"],
      ["Graph permissions", roles === null || roles === undefined ? "unknown (no token)"
        : roles.length ? h("span", { class: "chips" }, roles.map((r) => h("span", { class: "chip", text: r }))) : "none"],
      ["Mail.Send scope", state.app.mail_send_scope === "mailbox"
        ? [pill("ok", "Alert mailbox only"), h("span", { class: "sub", text: app.mail_send_group
            ? `The app can send only as a member of the Exchange group ${app.mail_send_group}. To use another alert mailbox, add it to this group (Microsoft 365 admin center > Teams & groups), wait up to 2 hours, then change it in Settings > Email.`
            : "Exchange RBAC for Applications." })]
        : ["Tenant-wide (Microsoft Graph)", sub(limitMailSendText())]],
      ["Settings storage", state.app.storage ? "Table Storage" : "not configured (settings cannot be saved)"],
    ]),
    state.settings.groups.some(([g]) => g === "email")
      ? h("p", { class: "card-note" }, h("a", { href: "#settings:email", class: "link-more", id: "access-email-settings" },
          "Change the recipients and the tenant label", icon("arrow"))) : null);
}

// Overview card: the findings journal of the last 7 days.
function tally(summary) {
  const s = summary || {};
  const item = (n, one, many) => h("span", { class: "tally-item" }, h("strong", { text: String(n || 0) }), ` ${n === 1 ? one : many}`);
  const statuses = Object.entries(s.by_status || {});
  return h("div", { class: "tally" },
    item(s.total, "alert", "alerts"), item(s.high, "high", "high"), item(s.users, "user", "users"),
    statuses.length ? h("span", { class: "tally-status" }, statuses.map(([status, n]) =>
      h("span", { class: "tally-pill" }, statusPill(status), ` ${n}`))) : null);
}

function alertFeed(rows) {
  return h("ul", { class: "feed" }, rows.map((r) => h("li", { class: `feed-item${isQuiet(r) ? " is-closed" : ""}` },
    h("div", { class: "feed-main" },
      h("div", { class: "feed-title" }, severityPill(r.severity), h("strong", { text: typeLabel(r.type) })),
      h("div", { class: "feed-user" }, userLink(r.user)),
      r.description ? h("p", { class: "feed-desc", text: r.description }) : null,
      r.action && r.status === "emailed" ? h("p", { class: "feed-desc muted", text: `Response: ${r.action}` }) : null,
      r.triage_by || autoBenign(r) ? h("p", { class: "feed-desc muted", text: triageText(r) }) : null),
    h("div", { class: "feed-meta" }, statusPill(r.status), triageTag(r),
      h("time", { datetime: r.at, title: utc(r.at), text: ago(r.at) }),
      r.repeats ? h("span", { class: "muted small", title: r.last_repeat ? `Last: ${utc(r.last_repeat)}` : "",
        text: `+${r.repeats} more, no email` }) : null))));
}

// The triage state on the Overview: a tag for Investigating, Benign, and Resolved. Open has none.
const CLOSED = ["benign", "resolved"];
// Rows that sent no email because an admin decided so (a mute, an alert type off), because a
// Microsoft service made the change, or because the user registered an MFA method after a sign-in
// from a known network. They are shown greyed out.
const QUIET = ["muted", "alert off", "microsoft", "known sign-in"];
const isQuiet = (r) => QUIET.includes(r.status) || CLOSED.includes(r.triage);
// A muted row that no admin triaged reads as Benign (the server sets it): say why.
const autoBenign = (r) => r.status === "muted" && r.triage === "benign" && !r.triage_by;

function triageTag(r) {
  if (!r.triage || !TRIAGE[r.triage]) return null;
  const [kind, label] = TRIAGE[r.triage];
  return pill(kind, label);
}

function triageText(r) {
  if (autoBenign(r)) return "Benign: a mute applies";
  return `${TRIAGE[r.triage || ""][1]} by ${r.triage_by}, ${ago(r.triage_at)}` + (r.triage_note ? `: ${r.triage_note}` : "");
}

function alertsCard() {
  const findings = state.findings || {};
  const rows = (findings.recent || []).slice(0, ALERTS_SHOWN);
  return h("section", { class: "card", id: "alerts-card", "aria-labelledby": "card-alerts" },
    h("div", { class: "card-head" },
      h("h2", { id: "card-alerts", text: `Alerts, last ${findings.days || 7} days` }),
      h("a", { href: "#alerts", class: "link-more", id: "alerts-show-all" }, "Show all", icon("arrow"))),
    tally(findings.summary),
    rows.length ? alertFeed(rows)
      : empty("ok", "No alerts in the last 7 days", "Each detection shows here, also when no email was sent."));
}

// Overview > Tools: the onboarding scan.
let lastScan = [];

function scanFacts(scan) {
  const hist = scan.history || {};
  const rules = scan.rules || {};
  const n = (v) => String(v || 0);
  const full = scan.kind !== "rules";
  const by = scan.requested_by === "first run" ? "Started by the first monitor run" : `By ${scan.requested_by || "unknown"}`;
  const list = facts([
    ["State", scan.step === "done" ? pill("ok", "Done") : pill("info", `Running: ${SCAN_STEPS[scan.step] || scan.step}`)],
    ["Scan", full ? "Audit history and inbox rules" : "Inbox rules only"],
    ["Started", utc(scan.started_at), sub(`${by}, ${ago(scan.started_at)}.`)],
    ["Finished", scan.finished_at ? utc(scan.finished_at) : "not yet", scan.finished_at ? sub(ago(scan.finished_at)) : null],
    full ? ["Audit history", `${n(hist.records)} records, ${n(hist.signins)} sign-ins`,
      hist.from ? sub(`${utc(hist.from)} to ${utc(hist.to)}`) : null] : null,
    full ? ["Findings", `${n(hist.findings)}, ${n(hist.high)} high`, sub(`${n(hist.flagged_signins)} flagged sign-ins.`)] : null,
    full ? ["Country baseline", `${n(hist.seeded_users)} users added`] : null,
    full && hist.errors && hist.errors.length
      ? ["History errors", h("ul", { class: "plain-list" }, hist.errors.map((e) => h("li", { text: e })))] : null,
    full ? ["Older history", ...searchFacts(scan.search || {})] : null,
    ["Inbox rules", rules.skipped
      ? [pill("warn", "Skipped"), sub(`The scan ${rules.skipped}.`)]
      : [`${n(rules.checked)} of ${n(rules.mailboxes)} mailboxes checked`,
         sub(`${n(rules.no_mailbox)} with no mailbox. ${n(rules.errors)} errors.`)]],
    rules.error_text ? ["Rule errors", rules.error_text] : null,
    ["Flagged rules", n(rules.flagged_count)],
  ]);
  list.classList.add("facts-wide");
  return list;
}

function searchFacts(sr) {
  const n = (v) => String(v || 0);
  if (sr.skipped) return [pill("warn", "Skipped"), sub(`Not searched: ${sr.skipped}.`)];
  if (!sr.status) return ["Not started yet"];
  if (sr.status !== "succeeded") {
    return [pill("info", sr.status === "running" ? "Microsoft is running the search" : "Waiting for Microsoft"),
      sub(sr.error ? `Last error: ${sr.error}` : "This can take some hours.")];
  }
  return [`${n(sr.records)} records, ${n(sr.findings)} findings (${n(sr.high)} high)`,
    sub(`${utc(sr.from)} to ${utc(sr.to)}.${sr.limit_exceeded ? " Microsoft stopped at its record limit." : ""}`)];
}

function scanCard() {
  const scan = state.onboarding;
  const canRules = (state.permissions || {}).rule_scan !== false;
  return h("section", { class: "card", id: "onboarding-scan", "aria-labelledby": "card-scan" },
    h("h3", { class: "card-title", id: "card-scan", text: "Onboarding scan" }),
    h("p", { class: "card-sub", text: "The scan reads the last 7 days of audit content, checks the inbox rules of every mailbox, " +
      "and searches the audit log for older changes (up to 180 days). Then it emails one \"Starting state\" report. " +
      "It runs in the background, in steps of about 75 seconds every 5 minutes." }),
    scan ? scanFacts(scan) : notice("info", h("p", { text: "No scan yet. The scan starts by itself after the first monitor run." })),
    h("div", { class: "actions more" },
      h("button", { class: "btn", type: "button", id: "scan-rules", disabled: !canRules,
        "aria-describedby": canRules ? null : "scan-rules-note", onclick: (e) => startScan(e, "rules"), text: "Scan inbox rules" }),
      h("button", { class: "btn", type: "button", id: "scan-full", onclick: (e) => startScan(e, "full"),
        text: scan ? "Run the full scan again" : "Run the full scan" })),
    canRules ? null : h("ul", { class: "reasons" }, lockNote("scan-rules-note",
      "Scan inbox rules needs the Graph permissions User.ReadBasic.All and MailboxSettings.Read. Run ./install.ps1 -Update to grant them.")),
    h("div", { id: "scan-out", class: "result", "aria-live": "polite" }, lastScan));
}

async function startScan(e, kind) {
  const button = e.currentTarget;
  const rules = kind === "rules";
  const ok = await confirmDialog({
    title: rules ? "Scan inbox rules" : "Run the full scan",
    body: [h("p", { text: rules ? "Check the inbox rules of every mailbox?"
                             : "Read the audit history again and check the inbox rules of every mailbox?" }),
           h("p", { class: "muted small", text: `The scan runs in the background. When it is done, it emails one "Starting state" report to ${state.app.admin_email || "the alert mailbox"}.` })],
    ok: "Start scan", danger: false });
  if (!ok) return;
  setBusy(button, true);
  const out = () => document.getElementById("scan-out");
  try {
    let result;
    try {
      result = await api("/scan", { method: "POST", body: { kind } });
    } catch (err) {
      if (err.status !== 409) throw err;
      const running = (err.data && err.data.onboarding) || {};
      const replace = await confirmDialog({
        title: "Replace the running scan",
        body: [h("p", { text: `A scan is running. It started at ${utc(running.started_at)}. Step: ${SCAN_STEPS[running.step] || running.step || "unknown"}.` }),
               h("p", { text: "Replace it with a new scan? The running scan stops and does not send its report." })],
        ok: "Replace scan", danger: true });
      if (!replace) {
        if (err.data && err.data.onboarding) state.onboarding = err.data.onboarding;
        lastScan = [notice("info", h("p", { text: "The running scan continues." }))];
        renderOverview();
        return;
      }
      result = await api("/scan", { method: "POST", body: { kind, restart: true } });
    }
    state.onboarding = result.onboarding;
    lastScan = [notice("ok", h("p", { text: "The scan started. It runs in the background. The report arrives by email when the scan is done." }))];
    await reload(false);
    toast("Scan started.");
  } catch (err) {
    if (err instanceof SessionError) handleError(err);
    else if (out()) { lastScan = [notice("bad", h("p", { text: err.message }))]; fill(out(), lastScan); }
  } finally {
    if (button.isConnected) setBusy(button, false);
    const fresh = document.getElementById(button.id);
    if (fresh && !fresh.disabled) fresh.focus();
  }
}

let emailsExpanded = false;

function emailsCard() {
  const emails = state.emails || [];
  const shown = emailsExpanded ? emails : emails.slice(0, EMAILS_SHOWN);
  const kind = (s) => (s === "failed" || String(s).startsWith("webhook failed") ? "bad" : s === "queued" ? "warn" : "ok");
  return h("section", { class: "card", "aria-labelledby": "card-emails" },
    h("div", { class: "card-head" }, h("h2", { id: "card-emails", text: "Recent emails" }),
      emails.length ? h("span", { class: "muted small", text: `Last ${emails.length}` }) : null),
    emails.length
      ? [table([["Time", "nowrap"], ["Subject", "primary"], ["Delivery"]], shown.map((e) => [
          utc(e.at), e.subject, pill(kind(e.status), e.status.charAt(0).toUpperCase() + e.status.slice(1))])),
        emails.length > EMAILS_SHOWN ? h("div", { class: "more" }, h("button", { type: "button", class: "btn", id: "emails-toggle",
          onclick: () => { emailsExpanded = !emailsExpanded; renderOverview(); document.getElementById("emails-toggle").focus(); },
          text: emailsExpanded ? "Show fewer" : `Show all ${emails.length} emails` })) : null]
      : empty("mail", "No emails yet", "Alert and information emails show here after the app sends them."));
}

// The overview is rebuilt after a send (to show Recent emails). Keep the
// selection and the last results across that rebuild.
let selectedTypes = null;
let lastSelftest = [];
let lastChecks = [];

function testAlertsCard() {
  const types = state.selftest_types || [];
  if (!selectedTypes) selectedTypes = new Set(types.some((t) => t.type === "inbox_rule") ? ["inbox_rule"] : []);
  const countText = () => `${selectedTypes.size} of ${types.length} selected`;
  const count = h("span", { id: "selftest-count", "aria-live": "polite", text: countText() });
  const boxes = types.map((t) => {
    const box = h("input", { type: "checkbox", name: "selftest-type", value: t.type,
      onchange: (e) => {
        if (e.target.checked) selectedTypes.add(t.type); else selectedTypes.delete(t.type);
        count.textContent = countText();
      } });
    box.checked = selectedTypes.has(t.type);
    return h("label", { class: "check" }, box, h("span", { text: t.label }));
  });
  const selectAll = (on) => {
    selectedTypes = new Set(on ? types.map((t) => t.type) : []);
    document.querySelectorAll('input[name="selftest-type"]').forEach((box) => { box.checked = on; });
    count.textContent = countText();
  };
  return h("section", { class: "card", id: "test-alerts", "aria-labelledby": "card-test" },
    h("h3", { class: "card-title", id: "card-test", text: "Test alerts" }),
    h("p", { class: "card-sub", text: "Sends a synthetic audit record through the real detectors and email code. " +
      "Emails have [SELF-TEST] in the subject. Nothing in the tenant changes. " +
      "To test with real activity, see How-To: Test the alerts." }),
    h("div", { class: "toolbar" }, count,
      h("button", { class: "btn btn-quiet", type: "button", onclick: () => selectAll(true), text: "Select all" }),
      h("button", { class: "btn btn-quiet", type: "button", onclick: () => selectAll(false), text: "Clear" })),
    h("div", { class: "checklist", role: "group", "aria-label": "Alert types to test" }, boxes),
    h("div", { class: "actions more" },
      h("button", { class: "btn btn-primary", type: "button", onclick: (e) => runSelfTest(e, true), text: "Send test emails" }),
      h("button", { class: "btn", type: "button", onclick: (e) => runSelfTest(e, false), text: "Check detectors (no email)" })),
    h("div", { id: "selftest-out", class: "result", "aria-live": "polite" }, lastSelftest));
}

function checksCard() {
  return h("section", { class: "card", id: "dependency-checks", "aria-labelledby": "card-checks" },
    h("h3", { class: "card-title", id: "card-checks", text: "Dependency checks" }),
    h("p", { class: "card-sub", text: "Checks the tokens, both audit subscriptions, Table Storage, and proxycheck.io (one query)." }),
    h("div", { class: "actions" },
      h("button", { class: "btn", type: "button", onclick: runChecks, text: "Run dependency checks" })),
    h("div", { id: "checks-out", class: "result", "aria-live": "polite" }, lastChecks));
}

function renderOverview() {
  const root = document.getElementById("view-overview");
  fill(root,
    h("div", { class: "page-head" },
      h("h1", { text: "Overview" }),
      h("p", { class: "lead", text: "The monitor runs every 2 minutes. Microsoft publishes audit records some minutes to 1–2 hours after an event." })),
    h("div", { class: "stack" },
      statusSummary(),
      alertsCard(),
      h("div", { class: "grid" }, monitorCard(), countriesCard(), accessCard()),
      emailsCard()),
    h("h2", { class: "section-title", text: "Tools" }),
    h("div", { class: "stack" }, testAlertsCard(), checksCard(), scanCard()));
}

async function runChecks(e) {
  const button = e.currentTarget;
  const out = document.getElementById("checks-out");
  setBusy(button, true);
  out.replaceChildren(h("p", { class: "muted", text: "Running checks…" }));
  try {
    const result = await api("/checks", { method: "POST" });
    const kind = (v) => (v.startsWith("ok") ? "ok" : v.startsWith("SKIPPED") ? "warn" : "bad");
    const word = { ok: "OK", warn: "Skipped", bad: "Failed" };
    const healthy = result.status === "healthy";
    lastChecks = [
      healthy ? notice("ok", h("p", { text: "Every dependency check passed." }))
              : notice("bad", h("p", { text: `Some dependency checks failed. Status: ${result.status}.` })),
      h("p", { class: "result-meta", text: `Checked at ${utc(new Date().toISOString())}.` }),
      table([["Check", "primary"], ["Result", "nowrap"], ["Detail", "detail"]],
        Object.entries(result.checks).map(([name, value]) => [
          CHECK_NAMES[name] || name, pill(kind(value), word[kind(value)]),
          value.replace(/^(ok|FAILED:|SKIPPED)\s*/, "").replace(/^\((.*)\)$/, "$1")])),
    ];
    fill(out, lastChecks);
  } catch (err) {
    out.replaceChildren(notice("bad", h("p", { text: err.message })));
    if (err instanceof SessionError) handleError(err);
  } finally {
    setBusy(button, false);
  }
}

async function runSelfTest(e, send) {
  const button = e.currentTarget;
  const out = document.getElementById("selftest-out");
  const types = Array.from(document.querySelectorAll('input[name="selftest-type"]:checked')).map((b) => b.value);
  if (send && types.length === 0) {
    out.replaceChildren(notice("bad", h("p", { text: "Select at least one alert type." })));
    return;
  }
  if (send && types.length > 10) {
    const ok = await confirmDialog({
      title: "Send test emails",
      body: [h("p", { text: `Send ${types.length} test emails to ${state.app.admin_email || "the alert mailbox"}?` }),
             h("p", { class: "muted small", text: "Each email has [SELF-TEST] in the subject." })],
      ok: "Send test emails", danger: false });
    if (!ok) return;
  }
  setBusy(button, true);
  out.replaceChildren(h("p", { class: "muted", text: send ? "Sending test emails…" : "Checking detectors…" }));
  try {
    const result = await api("/selftest", { method: "POST", body: { types: send ? types : ["all"], send } });
    const rows = result.results.map((r) => [
      r.label,
      r.detected === null ? pill("warn", "Email only") : pill(r.detected ? "ok" : "bad", r.detected ? "Detected" : "Missed"),
      r.severity ? r.severity.charAt(0).toUpperCase() + r.severity.slice(1) : "",
      ...(send ? [pill(r.email_sent ? "ok" : "bad", r.email_sent ? "Sent" : "Failed")] : []),
    ]);
    const columns = [["Alert", "primary"], ["Detector", "nowrap"], ["Severity"], ...(send ? [["Email", "nowrap"]] : [])];
    lastSelftest = [
      result.passed
        ? notice("ok", h("p", { text: send ? "Test emails sent. Look for [SELF-TEST] in the alert mailbox." : "Every detector found its test record." }))
        : notice("bad", h("p", { text: "Some tests failed. See the table, Recent emails, and the Errors query." })),
      table(columns, rows)];
    fill(out, lastSelftest);
    if (send) await reload(false);
  } catch (err) {
    out.replaceChildren(notice("bad", h("p", { text: err.message })));
    if (err instanceof SessionError) handleError(err);
  } finally {
    if (button.isConnected) setBusy(button, false);
  }
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

let setters = {};          // setting name -> function that puts a value into the form control
let settingsQuery = "";

function valueOf(item) {
  if (!(item.name in draft)) return item.value;
  return draft[item.name] === null ? item.default : draft[item.name];
}

function describe(item, value) {
  if (item.kind === "bool") return value ? "On" : "Off";
  if (item.kind === "label" || item.kind === "mailbox") return value ? String(value) : "(empty)";
  if (item.kind === "secret") return value ? "(set)" : "(not set)";
  if (item.kind === "type_set") {
    if (!value || !value.length) return "All on";
    return "Off: " + value.map((v) => (item.choices.find((c) => c[0] === v) || [v, v])[1]).join(", ");
  }
  if (item.kind === "role_set") {
    if (!value || !value.length) return "(none)";
    return value.map((v) => (item.choices.find((c) => c[0] === v) || [v, v])[1]).join(", ");
  }
  if (item.kind === "choice") {
    const choice = item.choices.find((c) => c[0] === value);
    return choice ? choice[1] : String(value);
  }
  if (Array.isArray(value)) return value.length ? value.join(", ") : "(empty)";
  return String(value);
}

function parseInput(item, el) {
  if (item.kind === "bool") return el.checked;
  if (item.kind === "int") return el.value.trim() === "" ? "" : Number(el.value);
  if (item.kind === "choice") return el.value;
  if (item.kind === "label" || item.kind === "mailbox") return el.value.trim();
  return el.value.split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean);
}

function isRadio(item) {
  return item.kind === "choice" && item.choices.length <= 5;
}

function setDraft(item, value) {
  if (same(value, item.value)) delete draft[item.name];
  else draft[item.name] = value;
  delete errors[item.name];
  markField(item);
  updateSavebar();
}

function markField(item) {
  const field = document.getElementById(`field-${item.name}`);
  if (!field) return;
  const dirty = item.name in draft;
  field.classList.toggle("dirty", dirty);
  field.classList.remove("invalid");
  const tag = field.querySelector(".tag-dirty");
  if (tag) tag.hidden = !dirty;
  const err = field.querySelector(".field-error");
  if (err) err.remove();
}

function control(item) {
  const id = `input-${item.name}`;
  const describedBy = `help-${item.name}`;
  const value = valueOf(item);

  if (item.kind === "bool") {
    const unavailable = item.unavailable[JSON.stringify(!value)];
    const stateText = h("span", { class: "switch-state", "aria-hidden": "true", text: value ? "On" : "Off" });
    const input = h("input", { type: "checkbox", role: "switch", class: "switch", id, "aria-describedby": describedBy,
      onchange: (e) => { stateText.textContent = e.target.checked ? "On" : "Off"; setDraft(item, e.target.checked); } });
    input.checked = Boolean(value);
    if (unavailable && !value) input.disabled = true;
    setters[item.name] = (v) => { input.checked = Boolean(v); stateText.textContent = v ? "On" : "Off"; };
    return h("div", { class: "switch-row" }, input, stateText,
      unavailable && !value ? h("span", { class: "option-note" }, icon("lock"), unavailable) : null);
  }

  if (isRadio(item)) {
    const radios = [];
    const group = h("div", { class: "options", id, role: "radiogroup", "aria-labelledby": `label-${item.name}`,
      "aria-describedby": describedBy },
      item.choices.map(([v, label]) => {
        const reason = item.unavailable[JSON.stringify(v)];
        const rid = `${id}-${v}`;
        const radio = h("input", { type: "radio", name: `choice-${item.name}`, id: rid, value: v,
          onchange: () => setDraft(item, v) });
        radio.checked = v === value;
        const disabled = Boolean(reason) && v !== value;
        radio.disabled = disabled;
        radios.push(radio);
        return h("div", { class: `option${disabled ? " option-disabled" : ""}` }, radio,
          h("label", { for: rid }, h("span", { text: label }),
            reason ? h("span", { class: "option-note" }, icon("lock"), reason) : null));
      }));
    setters[item.name] = (v) => radios.forEach((r) => { r.checked = r.value === v; });
    return group;
  }

  if (item.kind === "choice") {
    const select = h("select", { id, "aria-describedby": describedBy, onchange: (e) => setDraft(item, e.target.value) },
      item.choices.map(([v, label]) => {
        const reason = item.unavailable[JSON.stringify(v)];
        const option = h("option", { value: v, text: reason ? `${label} (${reason})` : label });
        if (reason && v !== value) option.disabled = true;
        if (v === value) option.selected = true;
        return option;
      }));
    setters[item.name] = (v) => { select.value = v; };
    return select;
  }

  if (item.kind === "type_set") {
    // The stored value lists the types that are OFF. A checked box means "on".
    const off = new Set(value || []);
    const boxes = [];
    const update = () => setDraft(item, boxes.filter((b) => !b.checked).map((b) => b.value));
    const group = h("div", { class: "checklist", id, role: "group", "aria-labelledby": `label-${item.name}`,
      "aria-describedby": describedBy },
      item.choices.map(([t, label]) => {
        const box = h("input", { type: "checkbox", name: item.name, value: t, onchange: update });
        box.checked = !off.has(t);
        boxes.push(box);
        return h("label", { class: "check" }, box, h("span", { text: label }));
      }));
    setters[item.name] = (v) => boxes.forEach((b) => { b.checked = !(v || []).includes(b.value); });
    return group;
  }

  if (item.kind === "role_set") {
    // The stored value lists the selected roles. A checked box means "selected".
    const on = new Set(value || []);
    const boxes = [];
    const update = () => setDraft(item, boxes.filter((b) => b.checked).map((b) => b.value));
    const group = h("div", { class: "checklist", id, role: "group", "aria-labelledby": `label-${item.name}`,
      "aria-describedby": describedBy },
      item.choices.map(([r, label]) => {
        const box = h("input", { type: "checkbox", name: item.name, value: r, onchange: update });
        box.checked = on.has(r);
        boxes.push(box);
        return h("label", { class: "check" }, box, h("span", { text: label }));
      }));
    setters[item.name] = (v) => boxes.forEach((b) => { b.checked = (v || []).includes(b.value); });
    return group;
  }

  if (item.kind === "secret") {
    // Write-only: the server never sends the value. Empty input = no change.
    const input = h("input", { type: "password", id, class: "text-line", autocomplete: "new-password",
      spellcheck: "false", "aria-describedby": describedBy,
      placeholder: item.is_set ? `Set. Enter a new ${item.name === "WEBHOOK_URL" ? "URL" : "key"} to replace it.` : "Not set",
      oninput: (e) => {
        const v = e.target.value.trim();
        if (v) draft[item.name] = v; else delete draft[item.name];
        delete errors[item.name];
        markField(item);
        updateSavebar();
      } });
    const remove = item.is_set ? h("button", { type: "button", class: "btn-link", text: item.name === "WEBHOOK_URL" ? "Remove the URL" : "Remove the key",
      onclick: () => { input.value = ""; draft[item.name] = ""; markField(item); updateSavebar();
        toast(`${item.label}: the key is removed when you save.`); } }) : null;
    setters[item.name] = () => { input.value = ""; };
    return h("div", { class: "secret-control" }, input, remove);
  }

  if (item.kind === "label" || item.kind === "mailbox") {
    // One line of text. For a label, an empty value is a valid choice (no label).
    const input = h("input", { type: item.kind === "mailbox" ? "email" : "text", id, class: "text-line",
      maxlength: item.max || null, autocomplete: "off", spellcheck: "false", "aria-describedby": describedBy,
      oninput: (e) => setDraft(item, parseInput(item, e.target)) });
    input.value = value || "";
    setters[item.name] = (v) => { input.value = v || ""; };
    return input;
  }

  if (item.kind === "int") {
    const input = h("input", { type: "number", id, inputmode: "numeric", min: item.min, max: item.max, step: 1,
      "aria-describedby": describedBy, oninput: (e) => setDraft(item, parseInput(item, e.target)) });
    input.value = value;
    setters[item.name] = (v) => { input.value = v; };
    return input;
  }

  const textarea = h("textarea", { id, rows: Math.min(8, Math.max(3, (value || []).length + 1)),
    spellcheck: "false", autocapitalize: "off", "aria-describedby": describedBy,
    oninput: (e) => setDraft(item, parseInput(item, e.target)) });
  textarea.value = (value || []).join("\n");
  setters[item.name] = (v) => { textarea.value = (v || []).join("\n"); };
  return textarea;
}

function defaultText(item) {
  const value = item.default;
  if (Array.isArray(value) && item.kind !== "type_set" && value.length > 4) {
    return h("details", {}, h("summary", { text: `Default: ${value.length} entries` }),
      h("p", { text: value.join(", ") }));
  }
  if (item.kind === "secret") return h("span", { text: `Default: ${item.default_is_set ? "set at install" : "not set"}` });
  return h("span", { text: `Default: ${describe(item, value)}` });
}

function field(item) {
  const isDirty = item.name in draft;
  const error = errors[item.name];
  const grouped = isRadio(item) || item.kind === "type_set" || item.kind === "role_set";
  const labelAttrs = { class: "field-label", id: `label-${item.name}`, text: item.label };
  return h("div", { class: `field${item.kind === "type_set" || item.kind === "role_set" ? " field-wide" : ""}${isDirty ? " dirty" : ""}${error ? " invalid" : ""}`,
                    id: `field-${item.name}`, "data-name": item.name },
    h("div", { class: "field-info" },
      h("div", { class: "field-head" },
        grouped ? h("span", labelAttrs) : h("label", { ...labelAttrs, for: `input-${item.name}` }),
        item.overridden ? h("span", { class: "tag tag-changed", text: "Changed", title: "This setting is not the default." }) : null,
        h("span", { class: "tag tag-dirty", text: "Not saved", hidden: !isDirty })),
      h("p", { class: "field-help", id: `help-${item.name}`, text: item.help })),
    h("div", { class: "field-control" },
      control(item),
      h("div", { class: "field-meta" },
        defaultText(item),
        item.overridden ? h("button", { type: "button", class: "btn-link",
          onclick: () => resetToDefault(item), text: "Reset to default" }) : null,
        h("code", { text: item.name })),
      error ? h("div", { class: "field-error", role: "alert" }, icon("bad"), h("span", { text: error })) : null));
}

function resetToDefault(item) {
  draft[item.name] = null;   // null = remove the override
  delete errors[item.name];
  if (setters[item.name]) setters[item.name](item.default);
  markField(item);
  updateSavebar();
  toast(`${item.label}: reset to the default. Select Save changes to apply.`);
}

function settingsNav(s) {
  const search = h("input", { type: "search", id: "settings-search", placeholder: "Find a setting",
    "aria-label": "Find a setting", autocomplete: "off", value: settingsQuery,
    oninput: (e) => { settingsQuery = e.target.value; filterSettings(); } });
  return h("nav", { class: "settings-nav", "aria-label": "Settings groups" },
    h("div", { class: "search" }, icon("search"), search),
    h("ul", {}, s.groups.map(([groupId, groupLabel]) => h("li", {},
      h("a", { href: `#settings:${groupId}`, id: `nav-${groupId}`, "data-group": groupId,
        onclick: (e) => {
          e.preventDefault();
          history.replaceState(null, "", `#settings:${groupId}`);
          scrollToGroup(groupId, true);
        } },
        h("span", { text: groupLabel }),
        h("span", { class: "count", "aria-hidden": "true", hidden: true }),
        h("span", { class: "visually-hidden nav-count" }))))),
    h("p", { class: "nav-note", text: "Changes apply from the next run." }));
}

function renderSettings() {
  const root = document.getElementById("view-settings");
  const s = state.settings;
  setters = {};
  const groups = s.groups.map(([groupId, groupLabel]) => {
    const items = s.items.filter((i) => i.group === groupId);
    return h("section", { class: "card card-flush group", id: `group-${groupId}`, "aria-labelledby": `group-title-${groupId}` },
      h("div", { class: "group-head" },
        h("h2", { id: `group-title-${groupId}`, tabindex: "-1", text: groupLabel }),
        h("span", { class: "muted", text: plural(items.length, "setting") })),
      items.map(field),
      groupId === "access" ? accessPanel() : null);
  });
  const updated = s.updated_at
    ? `Last change: ${utc(s.updated_at)} by ${s.updated_by}.`
    : "No changes yet. All settings use the deployment defaults.";
  fill(root,
    h("div", { class: "page-head" },
      h("h1", { text: "Settings" }),
      h("p", { class: "lead" },
        "Changes apply from the next run (within 2 minutes). Each change is recorded in History and emailed to ",
        h("strong", { text: state.app.admin_email || "the alert mailbox" }), "."),
      h("p", { class: "lead small", text: updated })),
    state.app.storage ? null : h("div", { class: "banner" }, notice("bad", h("p", { text: "Table Storage is not configured. Settings cannot be saved." }))),
    h("div", { class: "settings-layout" },
      settingsNav(s),
      h("div", { class: "settings-groups" },
        groups,
        h("div", { id: "settings-no-match", class: "card no-match", hidden: true }),
        h("p", { class: "settings-foot", text: "Graph permissions and Azure resources are set by install.ps1." }))));
  filterSettings();
  updateSavebar();
}

// Who can open the management UI now: the members of each directory role (live, from Graph).
function accessPanel() {
  const box = h("div", { class: "field field-wide access-now", id: "access-now" },
    h("p", { class: "muted", text: "Reading the members of the directory roles…" }));
  api("/access").then((a) => {
    const how = { "app role": "the Monitor.Admin role", "listed user": "the list of users above",
      "directory role": "a directory role above" }[a.you.access] || "your access";
    const rows = a.roles.map((r) => {
      let members;
      if (r.members === null || r.members === undefined) members = h("span", { class: "muted", text: "Not read" });
      else if (!r.members.length) members = h("span", { class: "muted", text: "No user has this role" });
      else members = h("span", { text: r.members.map((m) => m.upn || m.name).join(", ") });
      return [r.name + (r.selected ? " (selected)" : ""), members];
    });
    fill(box,
      h("p", { class: "field-label", text: "Who has these roles now" }),
      h("p", { class: "field-help", text: `You (${a.you.name}) have access through ${how}. Users with the Monitor.Admin ` +
        "role also have access: Entra ID > Enterprise applications > the admin UI app > Users and groups." }),
      a.can_read_roles ? facts(rows) : notice("warn", h("p", { text: "The monitor cannot read directory roles. " +
        "Run ./install.ps1 -Update to grant the Graph permission RoleManagement.Read.Directory." })));
  }).catch((err) => {
    fill(box, notice("warn", h("p", { text: `The role members were not read: ${err.message}` })));
  });
  return box;
}

function filterSettings() {
  const q = settingsQuery.trim().toLowerCase();
  const s = state.settings;
  let shown = 0;
  for (const [groupId, groupLabel] of s.groups) {
    let groupShown = 0;
    for (const item of s.items.filter((i) => i.group === groupId)) {
      const text = `${item.label} ${item.help} ${item.name} ${groupLabel}`.toLowerCase();
      const match = !q || text.includes(q);
      const el = document.getElementById(`field-${item.name}`);
      if (el) el.hidden = !match;
      if (match) groupShown += 1;
    }
    const group = document.getElementById(`group-${groupId}`);
    if (group) group.hidden = groupShown === 0;
    const link = document.getElementById(`nav-${groupId}`);
    if (link) link.parentElement.hidden = groupShown === 0;
    shown += groupShown;
  }
  const none = document.getElementById("settings-no-match");
  if (none) {
    none.hidden = shown > 0;
    if (!shown) fill(none, empty("search", "No settings match", `Nothing matches "${settingsQuery.trim()}". Try another word, or clear the search.`));
  }
  updateActiveGroup();
}

function scrollToGroup(groupId, focus) {
  const group = document.getElementById(`group-${groupId}`);
  if (!group) return;
  if (group.hidden) { settingsQuery = ""; const box = document.getElementById("settings-search"); if (box) box.value = ""; filterSettings(); }
  group.scrollIntoView({ block: "start", behavior: motionOk() ? "smooth" : "auto" });
  if (focus) document.getElementById(`group-title-${groupId}`).focus({ preventScroll: true });
  setActiveGroup(groupId);
}

function setActiveGroup(groupId) {
  document.querySelectorAll(".settings-nav a[data-group]").forEach((a) => {
    if (a.dataset.group === groupId) a.setAttribute("aria-current", "true");
    else a.removeAttribute("aria-current");
  });
}

let spyQueued = false;
function updateActiveGroup() {
  if (currentView() !== "settings" || !state) return;
  const groups = [...document.querySelectorAll("#view-settings .group:not([hidden])")];
  if (!groups.length) return;
  let active = groups[0];
  for (const g of groups) if (g.getBoundingClientRect().top <= 140) active = g;
  const atEnd = window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4;
  if (atEnd && window.scrollY > 0) active = groups[groups.length - 1];
  setActiveGroup(active.id.replace("group-", ""));
}

function updateSavebar() {
  const bar = document.getElementById("savebar");
  const count = Object.keys(draft).length;
  bar.hidden = count === 0 || currentView() !== "settings";
  const text = `${count} unsaved change${count === 1 ? "" : "s"}`;
  const label = document.getElementById("savebar-text");
  if (label.textContent !== text) label.textContent = text;
  if (!state) return;
  for (const [groupId] of state.settings.groups) {
    const link = document.getElementById(`nav-${groupId}`);
    if (!link) continue;
    const n = state.settings.items.filter((i) => i.group === groupId && i.name in draft).length;
    const badge = link.querySelector(".count");
    badge.textContent = String(n);
    badge.hidden = n === 0;
    link.querySelector(".nav-count").textContent = n ? `, ${n} unsaved` : "";
  }
}

function isRisky(name) {
  const item = state.settings.items.find((i) => i.name === name);
  const value = draft[name] === null ? item.default : draft[name];
  return item.risky.includes('"*"') || item.risky.includes(JSON.stringify(value));
}

function confirmRisky(diff) {
  return confirmDialog({
    title: "Confirm changes",
    body: [
      h("p", { text: "These changes can hide attacks:" }),
      h("ul", {}, diff.map((c) => h("li", {}, h("strong", { text: c.label }), ": ",
        h("span", { class: "muted", text: c.old || "(empty)" }), " → ", h("strong", { text: c.new || "(empty)" })))),
      h("p", { class: "muted small", text: "The change is recorded and emailed to the alert mailbox." })],
    ok: "Save anyway", danger: true });
}

async function save() {
  const button = document.getElementById("save");
  setBusy(button, true);
  document.getElementById("toast").textContent = "";
  try {
    const body = { version: state.settings.version, changes: draft };
    // Validate on the server first, so the confirm dialog shows only valid, normalized values.
    const check = await api("/settings", { method: "PUT", body: { ...body, dry_run: true } });
    const risky = check.changes.filter((c) => isRisky(c.name));
    if (risky.length && !(await confirmRisky(risky))) return;
    const result = await api("/settings", { method: "PUT", body });
    const n = result.changes.length;
    draft = {};
    errors = {};
    await reload(false);
    const notes = (result.notes || []).join(" ");
    toast((n ? `Saved ${n} change${n === 1 ? "" : "s"}. They apply from the next run.` : "No changes to save.")
      + (notes ? ` ${notes}` : ""));
  } catch (err) {
    if (err.status === 400 && err.data && err.data.errors) {
      errors = err.data.errors;
      settingsQuery = "";
      renderSettings();
      const first = document.querySelector(".field.invalid");
      if (first) {
        first.scrollIntoView({ block: "center", behavior: motionOk() ? "smooth" : "auto" });
        const input = first.querySelector("input, textarea, select");
        if (input) input.focus({ preventScroll: true });
      }
      toast("Some values are not valid. See the messages in red.");
    } else {
      handleError(err);
    }
  } finally {
    setBusy(button, false);
  }
}

function discard() {
  draft = {};
  errors = {};
  renderSettings();
  updateSavebar();
  toast("Changes discarded.");
}

// ---------------------------------------------------------------------------
// Countries
// ---------------------------------------------------------------------------

let countryUser = "";
let countryResult = null;

// message: an error to show; messageFor: "lookup" or "approve" (the form that caused it).
function renderCountries(result, message, messageFor) {
  countryResult = result;
  const root = document.getElementById("view-countries");
  const userInput = h("input", { type: "email", id: "country-user", autocomplete: "off", spellcheck: "false",
    placeholder: "jane@contoso.com", value: countryUser, required: true });
  const lookup = h("form", { class: "inline-form", onsubmit: (e) => { e.preventDefault(); lookupCountries(userInput.value, e.submitter); } },
    h("div", { class: "grow" }, h("label", { for: "country-user", text: "User" }), userInput),
    h("button", { class: "btn btn-primary", type: "submit", text: "Look up" }));

  let detail;
  if (result) {
    const rows = result.countries;
    const ccInput = h("input", { type: "text", id: "country-code", class: "short", maxlength: 2,
      autocomplete: "off", spellcheck: "false", placeholder: "FR", "aria-describedby": "approve-help" });
    const status = { usual: ["ok", "Usual"], alerted: ["bad", "Alerted"], new: ["info", "New"] };
    detail = h("section", { class: "card", "aria-labelledby": "countries-title" },
      h("div", { class: "card-head" }, h("h2", { id: "countries-title", text: `Countries for ${result.user}` }),
        h("span", { class: "muted small", text: rows.length === 1 ? "1 country" : `${rows.length} countries` })),
      rows.length ? table([["Country", "primary"], ["Status", "nowrap"], ["Days seen", "num"], ["Last seen", "nowrap"], ["Action"]],
        rows.map((r) => {
          const [kind, word] = status[r.status] || ["info", r.status];
          const name = countryName(r.country);
          return [
            [h("strong", { text: r.country }), name ? h("span", { class: "country-name", text: ` ${name}` }) : null],
            [pill(kind, word), r.approved ? h("span", { class: "muted small", text: " approved" }) : null],
            String(r.days_seen),
            r.last_seen || "-",
            h("button", { type: "button", class: "btn-link", "aria-label": `Remove ${r.country} for ${result.user}`,
              onclick: () => changeCountry(result.user, r.country, "remove"), text: "Remove" }),
          ];
        }))
        : empty("globe", "No countries recorded for this user yet", "The app records a country after a sign-in from it."),
      h("div", { class: "subsection" },
        h("h3", { text: "Approve a country" }),
        h("p", { class: "card-sub", id: "approve-help", text: "Use this before travel. The country becomes usual for this user, so it causes no alert." }),
        h("form", { class: "inline-form", onsubmit: (e) => { e.preventDefault(); changeCountry(result.user, ccInput.value, "approve", e.submitter); } },
          h("div", {}, h("label", { for: "country-code", text: "Country code" }), ccInput),
          h("button", { class: "btn", type: "submit", text: "Approve" })),
        message && messageFor === "approve" ? h("div", { class: "more", role: "alert" }, notice("bad", h("p", { text: message }))) : null));
  } else {
    detail = h("section", { class: "card" },
      empty("globe", "Look up a user", "Enter a user principal name. A new-country alert email has a link that opens this page for the user."));
  }
  fill(root,
    h("div", { class: "page-head" },
      h("h1", { text: "Countries" }),
      h("p", { class: "lead", text: "See the usual sign-in countries of a user. Approve a country for travel, or remove one." })),
    h("section", { class: "card", "aria-label": "Look up a user" }, lookup,
      message && messageFor !== "approve" ? h("div", { class: "more", role: "alert" }, notice("bad", h("p", { text: message }))) : null),
    h("div", { class: "stack more" }, detail));
}

async function lookupCountries(upn, button) {
  countryUser = upn.trim();
  if (button) setBusy(button, true);
  try {
    renderCountries(await api(`/countries?user=${encodeURIComponent(countryUser)}`));
  } catch (err) {
    if (err instanceof SessionError) handleError(err);
    else renderCountries(countryResult, err.message, "lookup");
  } finally {
    if (button && button.isConnected) setBusy(button, false);
  }
}

async function changeCountry(upn, country, action, button) {
  if (button) setBusy(button, true);
  try {
    const result = await api("/countries", { method: "POST", body: { user: upn, country, action } });
    renderCountries(result);
    toast(action === "approve" ? `${country.toUpperCase()} approved for ${upn}.` : `${country} removed for ${upn}.`);
    await reload(false);
  } catch (err) {
    if (err instanceof SessionError) handleError(err);
    else renderCountries(countryResult, err.message, action === "approve" ? "approve" : "lookup");
  } finally {
    if (button && button.isConnected) setBusy(button, false);
  }
}

// ---------------------------------------------------------------------------
// Alerts: the findings journal
// ---------------------------------------------------------------------------

let alertsFilter = { days: "7", type: "", status: "", triage: "open", page: 1 };
let alertsData = null;     // last /findings response
let alertsError = "";
let alertsLoading = false;
let alertsSeq = 0;

// The label of a row's action text: what the monitor did, or why it sent no email.
const ACTION_LABELS = { muted: "Mute", "alert off": "No email", microsoft: "No email", "known sign-in": "No email", "list only": "No email" };

// ``selection`` (optional): { ids: Set of alert IDs, changed() }. Adds a checkbox to each row.
function findingsTable(rows, withUser, onTriaged, selection) {
  const pick = selection ? [["Select", "nowrap", selectAllBox(rows, selection)]] : [];
  const columns = [...pick, ["Time", "nowrap"], ...(withUser ? [["User", "user"]] : []), ["Alert", "primary"], ["Severity", "nowrap"],
                   ["Email", "nowrap"], ["Triage", "nowrap"], ["Description"]];
  return table(columns, rows.map((r) => [
    ...(selection ? [selectBox(r, selection)] : []),
    timeCell(r.at),
    ...(withUser ? [userLink(r.user)] : []),
    typeLabel(r.type),
    severityPill(r.severity),
    statusPill(r.status),
    triageCell(r, onTriaged),
    [h("span", { text: r.description || "" }),
     r.ip_context ? h("span", { class: "sub", text: `IP: ${r.ip_context}` }) : null,
     r.asn ? h("span", { class: "sub", text: `Network: ${networkLabel(r)}` }) : null,
     r.client ? h("span", { class: "sub", text: `Client: ${r.client}` }) : null,
     r.action ? h("span", { class: "sub", text: `${ACTION_LABELS[r.status] || "Response"}: ${r.action}` }) : null,
     r.triage_by || autoBenign(r) ? h("span", { class: "sub", text: triageText(r) }) : null,
     alertActions(r, withUser),
     auditRecord(r)],
  ]), (n) => isQuiet(rows[n]) ? "is-quiet" : "");
}

// The audit record of an alert, as the alert email shows it. Loaded when the section opens.
function auditRecord(r) {
  if (!r.id) return null;
  const out = h("div", { class: "record-body", "aria-live": "polite" });
  const box = h("details", { class: "record" }, h("summary", { text: "Audit record" }), out);
  let loaded = false;
  box.addEventListener("toggle", async () => {
    if (!box.open || loaded) return;
    loaded = true;
    fill(out, h("p", { class: "muted small", text: "Loading the audit record…" }));
    try {
      const data = await api(`/record?id=${encodeURIComponent(r.id)}`);
      if (!data.record) {
        fill(out, h("p", { class: "muted small", text: "The audit record is not kept for this alert. Alerts recorded " +
          "before this version have no record. " + (data.record_id
            ? `Record ID ${data.record_id}: search for it in Microsoft Purview > Audit.`
            : "Search Microsoft Purview > Audit for the user and the time of the alert.") }));
        return;
      }
      let text = data.record;
      try { text = JSON.stringify(JSON.parse(data.record), null, 2); } catch (e) { /* cut record: show the text */ }
      fill(out, h("pre", { class: "record-json", tabindex: "0", text }));
    } catch (err) {
      if (err instanceof SessionError) { handleError(err); return; }
      loaded = false;
      fill(out, h("p", { class: "field-error", text: err.message }));
    }
  });
  return box;
}

// Links under an alert: mute similar alerts (medium alerts of a type that a mute can hide; high
// alerts always send email), and the user page, where revoke, block, and the inbox rules are.
function alertActions(r, withUser) {
  const person = r.user && r.user.includes("@");
  const links = [];
  if (person && r.severity !== "high" && muteTypes().some(([t]) => t === r.type)) {
    const href = (asn, network) => {
      const parts = [r.type, r.user, r.type === "inbox_rule" ? r.rule_name || "" : "", asn || "", asn ? network || "" : ""];
      while (parts.length > 2 && !parts[parts.length - 1]) parts.pop();
      return `#mute:${parts.map(encodePart).join(":")}`;
    };
    const link = h("a", { href: href(r.asn, r.network), text: "Mute similar" });
    // An alert recorded before the journal kept the ASN: look up its IP first (cache, else one query).
    if (!r.asn && r.ip) link.addEventListener("click", (e) => muteSimilarLookup(e, r, href));
    links.push(link);
  }
  if (person && withUser) links.push(h("a", { href: userHash(r.user), text: "Respond on the user page" }));
  if (!links.length) return null;
  return h("span", { class: "sub row-actions" }, links.flatMap((a, i) => (i ? [" · ", a] : [a])));
}

function selectBox(r, selection) {
  return h("input", { type: "checkbox", name: "alert-select", value: r.id, checked: selection.ids.has(r.id),
    "aria-label": `Select the ${typeLabel(r.type)} alert of ${utc(r.at)}`,
    onchange: (e) => { if (e.target.checked) selection.ids.add(r.id); else selection.ids.delete(r.id); selection.changed(); } });
}

// Selects or clears every alert on this page (the other pages keep their selection).
function selectAllBox(rows, selection) {
  const box = h("input", { type: "checkbox", "aria-label": "Select all alerts on this page",
    checked: rows.length > 0 && rows.every((r) => selection.ids.has(r.id)),
    onchange: () => {
      for (const r of rows) { if (box.checked) selection.ids.add(r.id); else selection.ids.delete(r.id); }
      const tableEl = box.closest("table");
      if (tableEl) tableEl.querySelectorAll('input[name="alert-select"]').forEach((b) => { b.checked = box.checked; });
      selection.changed();
    } });
  return box;
}

// The triage state of one alert: a select. A change asks for an optional note, then saves.
function triageCell(r, onTriaged) {
  const id = `triage-${r.id.replace(/[^A-Za-z0-9]/g, "")}`;
  const select = h("select", { id, class: "select-sm", "aria-label": `Triage of the ${typeLabel(r.type)} alert for ${r.user || "unknown"}`,
    onchange: () => setTriage(r, select, onTriaged) },
    Object.entries(TRIAGE).map(([v, [, label]]) => h("option", { value: v, text: label, selected: (r.triage || "") === v })));
  return select;
}

async function setTriage(r, select, onTriaged) {
  const next = select.value;
  const note = h("input", { type: "text", id: "triage-note", maxlength: "300", value: r.triage_note || "",
    placeholder: "For example: the supplier's own rule, checked with Jane" });
  const ok = await confirmDialog({
    title: `Set the alert to ${TRIAGE[next][1]}`,
    body: [h("p", { text: "This changes only this list. Later alerts still send email. History records the change." }),
      h("div", { class: "dialog-field" }, h("label", { for: "triage-note", text: "Note (optional)" }), note)],
    ok: "Save" });
  if (!ok) { select.value = r.triage || ""; return; }
  select.disabled = true;
  try {
    const result = await api("/triage", { method: "POST", body: { id: r.id, state: next, note: note.value } });
    Object.assign(r, result.finding);
    // The Overview list has its own copy of the recent alerts.
    for (const f of (state.findings && state.findings.recent) || []) if (f.id === r.id) Object.assign(f, result.finding);
    const card = document.getElementById("alerts-card");
    if (card) card.replaceWith(alertsCard());
    toast(`Alert set to ${TRIAGE[next][1]}.`);
    if (onTriaged) onTriaged(r);
  } catch (err) {
    select.value = r.triage || "";
    if (err instanceof SessionError) handleError(err);
    else toast(`Not saved: ${err.message}`);
  } finally {
    if (select.isConnected) select.disabled = false;
  }
}

// "Showing 51-100 of 340" with Previous and Next buttons. go(page) loads that page.
function pager(page, size, count, go, label) {
  if (count <= size) return null;
  const first = (page - 1) * size + 1;
  const last = Math.min(count, page * size);
  const pages = Math.ceil(count / size);
  return h("nav", { class: "pager", "aria-label": label },
    h("button", { type: "button", class: "btn btn-quiet", disabled: page <= 1, onclick: () => go(page - 1), text: "Previous" }),
    h("span", { class: "muted small", "aria-live": "polite", text: `${first}-${last} of ${count}` }),
    h("button", { type: "button", class: "btn btn-quiet", disabled: page >= pages, onclick: () => go(page + 1), text: "Next" }));
}

function renderAlerts() {
  const root = document.getElementById("view-alerts");
  const select = (id, label, value, options, key) => h("div", {},
    h("label", { for: id, text: label }),
    h("select", { id, onchange: (e) => { alertsFilter[key] = e.target.value; alertsFilter.page = 1; loadAlerts(); } },
      options.map(([v, text]) => { const o = h("option", { value: v, text }); if (v === value) o.selected = true; return o; })));
  const types = new Map(typeLabels());
  for (const t of Object.keys((alertsData && alertsData.summary.by_type) || {})) if (!types.has(t)) types.set(t, t);
  const data = alertsData;
  let body;
  if (alertsError) body = notice("bad", h("p", { text: alertsError }));
  else if (!data) body = h("p", { class: "muted", text: "Loading alerts…" });
  else if (!data.findings.length) body = empty("search", "No alerts match", "No detections in this period with these filters.");
  else {
    const go = (page) => { alertsFilter.page = page; loadAlerts(); };
    // A triage change can move the row out of this filter: load the page again.
    const onTriaged = () => { if (alertsFilter.triage) loadAlerts(); else renderAlerts(); };
    body = [
      data.capped ? h("p", { class: "result-meta", text: "The list has the newest 2000 alerts of the period. Choose a shorter period or a filter to see the others." }) : null,
      findingsTable(data.findings, true, onTriaged),
      pager(data.page, data.size, data.count, go, "Alert pages")];
  }
  const triageCounts = data && !alertsError ? Object.entries(data.summary.by_triage || {}) : [];
  fill(root,
    h("div", { class: "page-head" },
      h("h1", { text: "Alerts" }),
      h("p", { class: "lead", text: "Each detection of the monitor, newest first. The list also shows detections that sent no email because a mute applies (greyed out, Benign) or the onboarding scan found it. Detections of an alert type that is off are only on the user page. Set an alert to Benign or Resolved when you are done with it." })),
    h("section", { class: "card", "aria-label": "Filters" },
      h("div", { class: "filters" },
        select("alerts-days", "Period", alertsFilter.days, [["7", "Last 7 days"], ["30", "Last 30 days"], ["90", "Last 90 days"]], "days"),
        select("alerts-type", "Alert type", alertsFilter.type, [["", "All types"], ...types], "type"),
        select("alerts-triage", "Triage", alertsFilter.triage, TRIAGE_FILTERS, "triage"),
        // "Alert off" rows are only on the user page.
        select("alerts-status", "Email", alertsFilter.status, [["", "All"], ...Object.entries(STATUS_PILLS)
          .filter(([s]) => s !== "alert off").map(([s, [, l]]) => [s, l])], "status")),
      data && !alertsError ? h("div", { class: "more" }, tally(data.summary),
        triageCounts.length ? h("p", { class: "muted small", text: "Triage: " + triageCounts.map(([s, n]) =>
          `${n} ${(TRIAGE[s === "open" ? "" : s] || [, s])[1].toLowerCase()}`).join(", ") }) : null) : null),
    h("section", { class: "card more", id: "alerts-results", "aria-label": "Alerts", "aria-busy": alertsLoading ? "true" : null }, body));
}

async function loadAlerts() {
  const seq = ++alertsSeq;
  alertsLoading = true;
  alertsError = "";
  const params = new URLSearchParams({ days: alertsFilter.days, page: String(alertsFilter.page), size: String(PAGE_SIZE) });
  if (alertsFilter.type) params.set("type", alertsFilter.type);
  if (alertsFilter.status) params.set("status", alertsFilter.status);
  if (alertsFilter.triage) params.set("triage", alertsFilter.triage);
  const busy = document.getElementById("alerts-results");
  if (alertsData && busy) busy.setAttribute("aria-busy", "true");
  else renderAlerts();
  try {
    const data = await api(`/findings?${params}`);
    if (seq !== alertsSeq) return;
    alertsData = data;
  } catch (err) {
    if (seq !== alertsSeq) return;
    if (err instanceof SessionError) handleError(err);
    alertsError = err.message;
  }
  alertsLoading = false;
  const focused = document.activeElement && document.activeElement.id;
  renderAlerts();
  const el = focused && document.getElementById(focused);
  if (el && el.closest("#view-alerts")) el.focus();
}

// ---------------------------------------------------------------------------
// Users: one user's alerts, inbox rules, countries, mutes; manual response
// ---------------------------------------------------------------------------

let userQuery = "";
let userResult = null;     // last /user response
let userError = "";
let userPending = "";      // UPN of the request in progress
let userSeq = 0;
let userNotice = null;     // {user, ok, text}: result of the last account action
let rulesView = { user: "", data: null, error: "", loading: false };
let rulesNotice = null;    // {user, ok, text}: result of the last rule action
let rulesSeq = 0;

const RESPONSE_LABELS = { revoke: "Revoke sessions", block: "Block sign-in", unblock: "Unblock sign-in" };

function openUser(text) {
  const upn = text.trim().toLowerCase();
  userQuery = upn;
  const target = userHash(upn);
  if (location.hash === target) loadUser(upn);
  else location.hash = target;
}

async function loadUser(upn) {
  const seq = ++userSeq;
  upn = upn.trim();
  userPending = upn;
  userQuery = upn;
  userError = "";
  if (!userResult || userResult.user !== upn.toLowerCase()) {
    userResult = null;
    renderUsers();
  }
  try {
    const result = await api(`/user?user=${encodeURIComponent(upn)}`);
    if (seq !== userSeq) return;
    if (userNotice && userNotice.user !== result.user) userNotice = null;
    if (!userResult || userResult.user !== result.user) userAlertsPage = 1;
    if (rulesNotice && rulesNotice.user !== result.user) rulesNotice = null;
    userResult = result;
    userQuery = result.user;
    userPending = "";
    renderUsers();
    if ((result.permissions || {}).rules_read !== false) loadRules(result.user);
    resumeSearch(result);
  } catch (err) {
    if (seq !== userSeq) return;
    userPending = "";
    if (err instanceof SessionError) { handleError(err); return; }
    userResult = null;
    userError = err.message;
    renderUsers();
  }
}

function renderUsers() {
  const root = document.getElementById("view-users");
  const input = h("input", { type: "email", id: "user-lookup", autocomplete: "off", spellcheck: "false",
    placeholder: "jane@contoso.com", value: userQuery, required: true });
  const form = h("form", { class: "inline-form", onsubmit: (e) => { e.preventDefault(); openUser(input.value); } },
    h("div", { class: "grow" }, h("label", { for: "user-lookup", text: "User" }), input),
    h("button", { class: "btn btn-primary", type: "submit", text: "Look up" }));
  let detail;
  if (userResult) detail = userDetail(userResult);
  else if (userPending) detail = h("section", { class: "card" }, h("p", { class: "muted", text: `Loading ${userPending}…` }));
  else detail = userEmpty();
  fill(root,
    h("div", { class: "page-head" },
      h("h1", { text: "Users" }),
      h("p", { class: "lead", text: "See the alerts, inbox rules, audit log, countries, and mutes of one user. Revoke the sessions or block sign-in." })),
    h("section", { class: "card", "aria-label": "Look up a user" }, form,
      userError ? h("div", { class: "more", role: "alert" }, notice("bad", h("p", { text: userError }))) : null),
    h("div", { class: "stack more" }, detail));
  renderSearch();
}

function userEmpty() {
  const counts = new Map();
  for (const r of (state.findings && state.findings.recent) || []) {
    if (!r.user || !r.user.includes("@")) continue;
    const c = counts.get(r.user) || { n: 0, high: 0 };
    c.n += 1;
    c.high += r.severity === "high" ? 1 : 0;
    counts.set(r.user, c);
  }
  const top = [...counts].sort((a, b) => b[1].high - a[1].high || b[1].n - a[1].n).slice(0, 8);
  return h("section", { class: "card" },
    empty("search", "Look up a user", "Enter a user principal name. Each alert email has a link that opens this page for the user."),
    top.length ? h("div", { class: "subsection" },
      h("h3", { text: "Users with alerts, last 7 days" }),
      h("ul", { class: "user-picks" }, top.map(([upn, c]) => h("li", {},
        userLink(upn), h("span", { class: "muted small", text: ` ${plural(c.n, "alert")}${c.high ? `, ${c.high} high` : ""}` }))))) : null);
}

function userDetail(r) {
  return [userHeadCard(r), userAlertsCard(r), userRulesCard(r), userSearchCard(r),
    h("div", { class: "grid" }, userCountriesCard(r), userMutesCard(r))];
}

function userHeadCard(r) {
  const account = r.account || {};
  const perms = r.permissions || {};
  const missing = r.missing || {};
  const known = account.enabled === true || account.enabled === false;
  let accountPill;
  let accountNote = null;
  if (account.enabled === true) accountPill = pill("ok", "Sign-in allowed");
  else if (account.enabled === false) accountPill = pill("bad", "Sign-in blocked");
  else {
    accountPill = pill("neutral", "Account state unknown");
    if (account.error) accountNote = `Microsoft Graph did not return the account state: ${account.error}.`;
    else if (perms.account_state === false) accountNote = "To show the account state, the app needs the Graph permission User.Read.All.";
  }

  const reasonFor = (action) => {
    if (action === "block" && r.is_alert_mailbox) return "The alert mailbox cannot be blocked. The monitor sends every alert from it.";
    if (action === "block" && r.is_you) return "You cannot block your own account.";
    if (perms[action] === false) return `Needs the Graph permission ${(missing[action] || []).join(", ") || "for this action"}.`;
    return "";
  };
  const buttons = [];
  const notes = [];
  let permissionMissing = false;
  const add = (action, cls) => {
    const reason = reasonFor(action);
    const noteId = `user-${action}-note`;
    buttons.push(h("button", { type: "button", class: cls, id: `user-${action}`, disabled: Boolean(reason),
      "aria-describedby": reason ? noteId : null, onclick: (e) => userAction(e, r, action), text: RESPONSE_LABELS[action] }));
    if (reason) notes.push(lockNote(noteId, h("strong", { text: `${RESPONSE_LABELS[action]}: ` }), reason));
    if (reason && perms[action] === false) permissionMissing = true;
  };
  add("revoke", "btn");
  if (account.enabled !== false) add("block", "btn");
  if (account.enabled === false) add("unblock", "btn");
  else if (!known) add("unblock", "btn btn-quiet");
  if (permissionMissing) {
    notes.push(h("li", { class: "option-note" }, icon("info"), h("span", { text:
      "To add the permissions, run ./install.ps1 -ResponsePermissions yes." })));
  }

  const findings = r.findings || [];
  const high = findings.filter((f) => f.severity === "high").length;
  const highDay = findings.filter((f) => f.severity === "high" && minutesSince(f.at) <= 1440).length;
  const result = userNotice && userNotice.user === r.user ? userNotice : null;
  const name = account.display_name || r.user;
  return h("section", { class: "card", "aria-labelledby": "user-title" },
    h("div", { class: "user-head" },
      h("span", { class: "avatar avatar-lg", "aria-hidden": "true", text: name.charAt(0).toUpperCase() }),
      h("div", { class: "user-id" },
        h("h2", { id: "user-title", text: name }),
        account.display_name ? h("p", { class: "user-upn", text: r.user }) : null,
        h("div", { class: "badges" }, accountPill,
          r.is_alert_mailbox ? pill("info", "Alert mailbox") : null,
          r.exempt ? pill("info", "Exempt from automatic response") : null,
          r.is_you ? pill("info", "Your account") : null),
        accountNote ? h("p", { class: "muted small more", text: accountNote }) : null,
        h("p", { class: "muted small more", text: findings.length
          ? `${plural(findings.length, "alert")} in the last 90 days, ${high} high. Newest: ${ago(findings[0].at)}.`
          : "No alerts in the last 90 days." }))),
    highDay ? h("div", { class: "more" }, notice("bad", h("p", { text:
      `${plural(highDay, "high alert")} in the last 24 hours. Read each alert below. If the account is compromised, block sign-in and reset the password.` }))) : null,
    h("div", { class: "subsection" },
      h("h3", { text: "Response" }),
      h("p", { class: "card-sub", text: "These actions change the account in Entra ID. Each action is recorded in History and emailed to the alert mailbox." }),
      h("div", { class: "actions" }, buttons),
      notes.length ? h("ul", { class: "reasons" }, notes) : null,
      h("div", { id: "user-action-out", class: "result", "aria-live": "polite" },
        result ? notice(result.ok ? "ok" : "bad", h("p", { text: result.text })) : null)));
}

function responseBody(r, action) {
  const sessions = "Refresh tokens and browser sessions stop working. The user must sign in again.";
  const tokens = "Access tokens that were issued before can stay valid for up to about 1 hour.";
  const password = "The password does not change. To reset it, use the Microsoft 365 admin center.";
  const recorded = h("p", { class: "muted small", text: "The action is recorded in History and emailed to the alert mailbox." });
  if (action === "revoke") {
    return [h("p", { text: `Revoke all sessions of ${r.user}?` }),
      h("ul", {}, h("li", { text: sessions }), h("li", { text: tokens }), h("li", { text: password })), recorded];
  }
  if (action === "block") {
    return [h("p", { text: `Block sign-in for ${r.user} and revoke all sessions?` }),
      h("ul", {}, h("li", { text: "The user cannot sign in until an admin unblocks the account." }),
        h("li", { text: sessions }), h("li", { text: tokens }), h("li", { text: password })), recorded];
  }
  return [h("p", { text: `Allow ${r.user} to sign in again?` }),
    h("ul", {}, h("li", { text: password }),
      h("li", { text: "If the account was compromised, reset the password and check the MFA methods before you unblock." })), recorded];
}

async function userAction(e, r, action) {
  const button = e.currentTarget;
  const ok = await confirmDialog({ title: RESPONSE_LABELS[action], body: responseBody(r, action),
    ok: RESPONSE_LABELS[action], danger: action !== "unblock" });
  if (!ok) return;
  setBusy(button, true);
  try {
    const result = await api("/respond", { method: "POST", body: { user: r.user, action } });
    userNotice = { user: r.user, ok: true, text: `${RESPONSE_LABELS[action]}: ${result.result}` };
    toast(`${RESPONSE_LABELS[action]}: done.`);
  } catch (err) {
    if (err instanceof SessionError) { handleError(err); setBusy(button, false); return; }
    const text = (err.data && err.data.result) || err.message;
    userNotice = { user: r.user, ok: false, text: `${RESPONSE_LABELS[action]}: ${text}` };
  }
  await loadUser(r.user);
  const out = document.getElementById("user-action-out");
  if (out) out.scrollIntoView({ block: "nearest", behavior: motionOk() ? "smooth" : "auto" });
  const fresh = document.getElementById(button.id) || document.getElementById("user-revoke");
  if (fresh && !fresh.disabled) fresh.focus({ preventScroll: true });
  reload(false);
}

let userAlertsPage = 1;
// Alerts selected on the user page, to set their triage in one step. Cleared for another user.
const userSelection = { user: "", ids: new Set() };

function userAlertsCard(r) {
  const rows = r.findings || [];
  if (userSelection.user !== r.user) { userSelection.user = r.user; userSelection.ids.clear(); }
  const bar = bulkTriageBar(rows, () => renderUsers());
  const pages = Math.max(1, Math.ceil(rows.length / USER_ALERTS_PAGE));
  if (userAlertsPage > pages) userAlertsPage = pages;
  const shown = rows.slice((userAlertsPage - 1) * USER_ALERTS_PAGE, userAlertsPage * USER_ALERTS_PAGE);
  const go = (page) => { userAlertsPage = page; renderUsers(); document.getElementById("user-alerts-title").focus(); };
  return h("section", { class: "card", "aria-labelledby": "user-alerts-title" },
    h("div", { class: "card-head" }, h("h2", { id: "user-alerts-title", tabindex: "-1", text: "Alerts" }),
      h("span", { class: "muted small", text: "Last 90 days" })),
    rows.length ? [bar.el, findingsTable(shown, false, () => renderUsers(), bar.selection),
                   pager(userAlertsPage, USER_ALERTS_PAGE, rows.length, go, "Alert pages of this user")]
      : empty("ok", "No alerts for this user", "Each detection for this user shows here, also when no email was sent."));
}

// The bar above the user's alerts: how many are selected, a triage state, and Set triage.
function bulkTriageBar(rows, onDone) {
  const count = h("span", { "aria-live": "polite" });
  const choice = h("select", { id: "bulk-triage", class: "select-sm", "aria-label": "Triage for the selected alerts" },
    Object.entries(TRIAGE).map(([v, [, label]]) => h("option", { value: v, text: label, selected: v === "benign" })));
  const apply = h("button", { type: "button", class: "btn", text: "Set triage" });
  const clear = h("button", { type: "button", class: "btn btn-quiet", text: "Clear selection" });
  const selection = {
    ids: userSelection.ids,
    changed() {
      const n = this.ids.size;
      count.textContent = n ? `${n} selected` : "Select alerts to set their triage together.";
      apply.disabled = !n;
      clear.hidden = !n;
    },
  };
  apply.addEventListener("click", () => bulkTriage(rows, selection, choice.value, apply, onDone));
  clear.addEventListener("click", () => { selection.ids.clear(); onDone(); });
  selection.changed();
  return { selection, el: h("div", { class: "toolbar", role: "group", "aria-label": "Selected alerts" }, count, choice, apply, clear) };
}

async function bulkTriage(rows, selection, next, button, onDone) {
  const ids = [...selection.ids];
  const note = h("input", { type: "text", id: "bulk-triage-note", maxlength: "300",
    placeholder: "For example: the user's own rules, checked with them" });
  const ok = await confirmDialog({
    title: `Set ${ids.length} alert${ids.length === 1 ? "" : "s"} to ${TRIAGE[next][1]}`,
    body: [h("p", { text: "This changes only this list. Later alerts still send email. History records the change." }),
      h("div", { class: "dialog-field" }, h("label", { for: "bulk-triage-note", text: "Note (optional)" }), note)],
    ok: "Save" });
  if (!ok) return;
  setBusy(button, true);
  let saved = 0;
  let gone = 0;
  let failed = "";
  try {
    // The server takes up to 100 alerts in one request. It stops at a storage error and says
    // how many it did not save; those stay selected so that Set triage can try them again.
    for (let i = 0; i < ids.length && !failed; i += 100) {
      const result = await api("/triage", { method: "POST", body: { ids: ids.slice(i, i + 100), state: next, note: note.value } });
      for (const f of result.findings || []) {
        const row = rows.find((r) => r.id === f.id);
        if (row) Object.assign(row, f);
        selection.ids.delete(f.id);
        saved += 1;
      }
      gone += result.not_found || 0;
      for (const id of result.not_found_ids || []) selection.ids.delete(id);   // gone: no retry
      if (result.not_saved) failed = "a storage error. Try again";
    }
  } catch (err) {
    if (err instanceof SessionError) { handleError(err); return; }
    failed = err.message;
  }
  setBusy(button, false);
  const left = selection.ids.size;
  if (failed) toast(`${saved} of ${ids.length} saved. ${left} not saved (${failed}); they stay selected.`);
  else toast(`${saved} alert${saved === 1 ? "" : "s"} set to ${TRIAGE[next][1]}.` +
             (gone ? ` ${gone} no longer exist.` : ""));
  if (!failed) selection.ids.clear();
  onDone();
}

// Audit search (Microsoft Graph): the audit records of one user, up to 180 days.

let searchView = { user: "", days: 30, id: "", status: "", data: null, error: "", started: null, by: "" };
let searchTimer = null;

function userSearchCard(r) {
  const allowed = (r.permissions || {}).audit_search !== false;
  const select = h("select", { id: "search-days", disabled: !allowed },
    SEARCH_DAYS.map((d) => h("option", { value: String(d), text: `Last ${d} days`, selected: d === searchView.days })));
  return h("section", { class: "card", "aria-labelledby": "user-search-title" },
    h("div", { class: "card-head" }, h("h2", { id: "user-search-title", text: "Audit log" })),
    h("p", { class: "card-sub", text: "Search the audit log in Microsoft Purview for everything this user did: sign-ins, mail access, " +
      "rules, and admin changes. Microsoft runs the search in the background. It typically takes 5 to 40 minutes. " +
      "You can leave this page: the last search for the user shows here when you come back. Each search is in History." }),
    allowed
      ? h("form", { class: "inline-form", onsubmit: (e) => { e.preventDefault(); startUserSearch(e, r.user, Number(select.value)); } },
          h("div", {}, h("label", { for: "search-days", text: "Period" }), select),
          h("button", { class: "btn", type: "submit", id: "search-start", text: "Search" }))
      : notice("info", h("p", { text: "The audit search needs the Graph permission AuditLogsQuery.Read.All. Run ./install.ps1 -Update to grant it." })),
    h("div", { id: "user-search", class: "more", "aria-live": "polite" }));
}

async function startUserSearch(e, upn, days) {
  const button = e.submitter || document.getElementById("search-start");
  clearTimeout(searchTimer);
  searchView = { user: upn, days, id: "", status: "starting", data: null, error: "", started: Date.now(), by: state.user || "" };
  renderSearch();
  setBusy(button, true);
  try {
    const res = await api("/usersearch", { method: "POST", body: { user: upn, days } });
    searchView = { ...searchView, id: res.id, status: res.status };
    pollUserSearch();
  } catch (err) {
    if (err instanceof SessionError) { handleError(err); return; }
    searchView = { ...searchView, status: "", error: err.message };
  } finally {
    setBusy(button, false);
  }
  renderSearch();
}

async function pollUserSearch() {
  const { id, user } = searchView;
  if (!id) return;
  try {
    const res = await api(`/usersearch?id=${encodeURIComponent(id)}&user=${encodeURIComponent(user)}`);
    if (searchView.id !== id) return;
    searchView = { ...searchView, status: res.status, data: res.status === "succeeded" ? res : null, error: "" };
  } catch (err) {
    if (searchView.id !== id) return;
    if (err instanceof SessionError) { handleError(err); return; }
    searchView = { ...searchView, error: err.message };
  }
  renderSearch();
  if (["notStarted", "running"].includes(searchView.status) && currentView() === "users") {
    searchTimer = setTimeout(pollUserSearch, SEARCH_POLL_MS);
  }
}

// The last search for this user (kept by the server): show it, and wait for it if it runs.
function resumeSearch(r) {
  const last = r.search;
  if (!last || !last.id || (searchView.user === r.user && searchView.id === last.id)) return;
  clearTimeout(searchTimer);
  searchView = { user: r.user, days: last.days, id: last.id, status: "checking", data: null, error: "",
    started: Date.parse(last.at) || null, by: last.by || "" };
  pollUserSearch();
}

function renderSearch() {
  const root = document.getElementById("user-search");
  const r = userResult;
  if (!root || !r || searchView.user !== r.user) { if (root) fill(root); return; }
  const v = searchView;
  let body;
  if (v.error) body = notice("bad", h("p", { text: v.error }));
  else if (v.status === "failed" || v.status === "cancelled") body = notice("bad", h("p", { text: `Microsoft reported the search as ${v.status}. Start it again.` }));
  else if (!v.data) {
    const since = v.started ? ` It started ${ago(new Date(v.started).toISOString())}${v.by ? ` (${v.by})` : ""}.` : "";
    body = h("p", { class: "muted", text: `Microsoft is running the search of the last ${v.days} days.${since} ` +
      "This page checks every 10 seconds. You can leave it." });
  } else if (!v.data.rows.length) {
    body = empty("ok", "No records", `No audit records for this user in the last ${v.days} days.`);
  } else {
    const d = v.data;
    const top = Object.entries(d.by_operation).sort((a, b) => b[1] - a[1]).slice(0, 8);
    body = [
      h("p", { class: "result-meta", text: (v.started ? `Search started ${utc(new Date(v.started).toISOString())}${v.by ? ` by ${v.by}` : ""}. ` : "") +
        `${d.rows.length.toLocaleString()} records in the last ${v.days} days` +
        (d.truncated ? " (the newest records only: the search found more)." : ".") +
        (d.mail_records ? ` ${d.mail_records.toLocaleString()} are mail reads or sends (MailItemsAccessed, Send).` : "") }),
      h("div", { class: "chips", "aria-label": "Records by operation" },
        top.map(([op, n]) => h("span", { class: "chip", text: `${op}: ${n}` }))),
      ipLookupMeta(d.ip_info || {}),
      table([["Time"], ["Operation"], ["Workload"], ["IP address", "mono"], ["Network"], ["Location"], ["Client"], ["Object"]],
        d.rows.map((row) => [timeCell(row.at), row.operation, row.workload, row.ip || "—",
          ...ipCells(d.ip_info, row.ip), row.client || "—", row.object || "—"])),
    ];
  }
  fill(root, body);
}

// proxycheck.io details of the IPs in the audit search. Cached answers cost no query; the server
// looks up a few new IPs per load, and none when the daily quota is low.
const IP_NOTES = { private: "Private network", allowed: "Allowed IP", failed: "Lookup failed" };

function ipCells(info, ip) {
  if (!ip) return ["—", "—"];
  const d = info && info.ips ? info.ips[ip] : null;
  if (!d) return [h("span", { class: "muted", text: "Not looked up" }), "—"];
  if (d.note) return [h("span", { class: "muted", text: IP_NOTES[d.note] || d.note }), "—"];
  const risk = [`Risk ${d.risk}`, d.type].filter(Boolean).join(" · ");
  return [
    [[d.org, d.asn].filter(Boolean).join(" · ") || "—",
      h("span", { class: "sub" }, d.suspicious ? [pill("warn", "Flagged"), " "] : null, risk)],
    [d.city, d.country].filter(Boolean).join(", ") || "—",
  ];
}

function ipCount(n) {
  return `${n} IP ${n === 1 ? "address" : "addresses"}`;
}

function ipLookupMeta(info) {
  const parts = [];
  if (info.error) parts.push("The IP details are not available now.");
  if (info.quota) {
    parts.push(`${ipCount(info.pending)} not looked up: the proxycheck.io quota is ` +
      `${info.quota === "low" ? "low" : "used up"}. The monitor keeps the rest of the quota for its checks.`);
  } else if (info.pending) {
    parts.push(`${ipCount(info.pending)} not looked up yet. Each load looks up ${info.batch || 20} new ` +
      "IP addresses, to save the proxycheck.io quota.");
  }
  if (info.failed) parts.push(`The lookup failed for ${ipCount(info.failed)}. It is tried again some minutes later.`);
  if (!parts.length) return null;
  const more = info.pending && !info.quota
    ? h("button", { type: "button", class: "btn btn-quiet btn-sm", id: "search-more-ips", onclick: lookUpMoreIps,
      text: `Look up ${Math.min(info.pending, info.batch || 20)} more` })
    : null;
  return h("p", { class: "result-meta" }, parts.join(" "), more ? [" ", more] : null);
}

async function lookUpMoreIps(e) {
  setBusy(e.currentTarget, true);
  await pollUserSearch();
}

// Inbox rules

async function loadRules(upn) {
  const seq = ++rulesSeq;
  rulesView = { user: upn, data: rulesView.user === upn ? rulesView.data : null, error: "", loading: true };
  renderRules();
  try {
    const data = await api(`/rules?user=${encodeURIComponent(upn)}`);
    if (seq !== rulesSeq) return;
    rulesView = { user: upn, data, error: "", loading: false };
  } catch (err) {
    if (seq !== rulesSeq) return;
    if (err instanceof SessionError) handleError(err);
    rulesView = { user: upn, data: null, error: err.message, loading: false };
  }
  renderRules();
}

function userRulesCard(r) {
  const perms = r.permissions || {};
  const canRead = perms.rules_read !== false;
  return h("section", { class: "card", "aria-labelledby": "user-rules-title" },
    h("div", { class: "card-head" }, h("h2", { id: "user-rules-title", text: "Inbox rules" }),
      canRead ? h("button", { type: "button", class: "btn btn-quiet", id: "rules-reload", onclick: () => loadRules(r.user) },
        icon("refresh"), h("span", { text: "Reload" })) : null),
    canRead
      ? h("div", { id: "user-rules", "aria-live": "polite" })
      : notice("info", h("p", { text: "Reading inbox rules needs the Graph permission MailboxSettings.Read. Run ./install.ps1 -Update to grant it." })));
}

function renderRules() {
  const root = document.getElementById("user-rules");
  const r = userResult;
  if (!root || !r || rulesView.user !== r.user) return;
  const canWrite = (r.permissions || {}).rules_write !== false;
  const data = rulesView.data;
  const result = rulesNotice && rulesNotice.user === r.user ? rulesNotice : null;
  let body;
  if (rulesView.error) body = notice("bad", h("p", { text: rulesView.error }));
  else if (!data) body = h("p", { class: "muted", text: "Reading the inbox rules from Microsoft Graph…" });
  else if (data.note) body = empty("mail", "No inbox rules to show", data.note);
  else if (!data.rules.length) body = empty("ok", "No inbox rules", "This mailbox has no inbox rules.");
  else {
    body = h("ul", { class: "rules" }, data.rules.map((rule) => {
      const high = rule.severity === "high";
      const label = rule.name || "(no name)";
      // A name with no letters or digits ("..") is hard to see: show it in quotes.
      const plain = /[\p{L}\p{N}]/u.test(label);
      return h("li", { class: `rule${rule.severity ? ` rule-${rule.severity}` : ""}` },
        h("div", { class: "rule-head" },
          h("span", { class: plain ? "rule-name" : "rule-name mono", text: plain ? label : `"${label}"` }),
          rule.enabled ? pill("ok", "On") : pill("neutral", "Off"),
          rule.severity ? pill(high ? "bad" : "warn", high ? "High risk" : "Medium risk") : null,
          h("button", { type: "button", class: "btn btn-sm", disabled: !canWrite,
            "aria-describedby": canWrite ? null : "rules-write-note",
            "aria-label": `${rule.enabled ? "Turn off" : "Turn on"} the rule ${label}`,
            onclick: (e) => ruleAction(e, r.user, rule), text: rule.enabled ? "Turn off" : "Turn on" })),
        rule.reasons && rule.reasons.length
          ? h("ul", { class: "rule-reasons" }, rule.reasons.map((x) => h("li", { text: x }))) : null,
        h("dl", { class: "facts rule-facts" },
          h("dt", { text: "Conditions" }), h("dd", { text: rule.conditions || "all mail" }),
          h("dt", { text: "Actions" }), h("dd", { text: rule.actions || "none" })));
    }));
  }
  fill(root,
    canWrite ? null : h("ul", { class: "reasons rules-note" }, lockNote("rules-write-note",
      "Turn off and Turn on need the Graph permission MailboxSettings.ReadWrite. " + GRANT_RESPONSE)),
    result ? notice(result.ok ? "ok" : "bad", h("p", { text: result.text })) : null,
    body);
}

async function ruleAction(e, upn, rule) {
  const button = e.currentTarget;
  const turnOn = !rule.enabled;
  const name = rule.name || "(no name)";
  const ok = await confirmDialog({
    title: turnOn ? "Turn on inbox rule" : "Turn off inbox rule",
    body: [
      h("p", { text: `${turnOn ? "Turn on" : "Turn off"} the rule "${name}" in the mailbox of ${upn}?` }),
      turnOn
        ? h("p", { text: rule.severity === "high" ? "The monitor rates this rule as high risk. Turn it on only if the user made it and needs it." : "The rule runs on new mail again." })
        : h("p", { text: "The rule stays in the mailbox, but it does not run. Mail that the rule forwarded or moved before does not come back." }),
      h("p", { class: "muted small", text: "The action is recorded in History and emailed to the alert mailbox." })],
    ok: turnOn ? "Turn on rule" : "Turn off rule", danger: turnOn && rule.severity === "high" });
  if (!ok) return;
  setBusy(button, true);
  try {
    const result = await api("/respond", { method: "POST",
      body: { user: upn, action: turnOn ? "rule_on" : "rule_off", rule_id: rule.id, rule_name: rule.name } });
    rulesNotice = { user: upn, ok: true, text: result.result };
    toast(turnOn ? "Rule turned on." : "Rule turned off.");
  } catch (err) {
    if (err instanceof SessionError) { handleError(err); setBusy(button, false); return; }
    rulesNotice = { user: upn, ok: false, text: (err.data && err.data.result) || err.message };
  }
  await loadRules(upn);
  const reloadButton = document.getElementById("rules-reload");
  if (reloadButton) reloadButton.focus();
  reload(false);
}

function userCountriesCard(r) {
  const rows = r.countries || [];
  const status = { usual: ["ok", "Usual"], alerted: ["bad", "Alerted"], new: ["info", "New"] };
  return h("section", { class: "card", "aria-labelledby": "user-countries-title" },
    h("div", { class: "card-head" }, h("h2", { id: "user-countries-title", text: "Countries" }),
      h("a", { href: `#countries:${encodePart(r.user)}`, class: "link-more" }, "Approve or remove", icon("arrow"))),
    rows.length ? table([["Country", "primary"], ["Status", "nowrap"], ["Days seen", "num"], ["Last seen", "nowrap"]],
      rows.map((c) => {
        const [kind, word] = status[c.status] || ["info", c.status];
        const name = countryName(c.country);
        return [[h("strong", { text: c.country }), name ? h("span", { class: "country-name", text: ` ${name}` }) : null],
          [pill(kind, word), c.approved ? h("span", { class: "muted small", text: " approved" }) : null],
          String(c.days_seen), c.last_seen || "-"];
      }))
      : empty("globe", "No countries recorded", "The app records a country after a sign-in from it."));
}

function userMutesCard(r) {
  const rows = r.mutes || [];
  return h("section", { class: "card", "aria-labelledby": "user-mutes-title" },
    h("div", { class: "card-head" }, h("h2", { id: "user-mutes-title", text: "Mutes" }),
      h("a", { href: "#mutes", class: "link-more" }, "All mutes", icon("arrow"))),
    rows.length ? table([["Alert type", "primary"], ["Applies to"], ["Until", "nowrap"], ["Reason"]], rows.map((m) => [
      muteTypeLabel(m.type), [m.user === "*" ? "All users" : "This user", m.rule_name ? h("span", { class: "sub", text: `Rule: ${m.rule_name}` }) : null],
      timeCell(m.until), m.reason]))
      : h("p", { class: "muted small", text: "No active mutes apply to this user. Medium alerts for this user send email." }),
    h("div", { class: "actions more" },
      h("a", { class: "btn", id: "user-mute", href: `#mute:*:${encodePart(r.user)}`, text: "Mute alerts for this user" })));
}

// ---------------------------------------------------------------------------
// Mutes
// ---------------------------------------------------------------------------

// "Mute similar" on an alert without an ASN: find the network of its IP, then open the form.
async function muteSimilarLookup(e, r, href) {
  e.preventDefault();
  if (r.asn) { location.hash = href(r.asn, r.network); return; }   // looked up on an earlier click
  const link = e.currentTarget;
  if (link.getAttribute("aria-busy") === "true") return;
  link.setAttribute("aria-busy", "true");
  let info = { asn: "", network: "", note: "failed" };
  try {
    info = await api(`/ipnetwork?ip=${encodeURIComponent(r.ip)}`);
  } catch (err) {
    if (err instanceof SessionError) { handleError(err); return; }
  } finally {
    link.removeAttribute("aria-busy");
  }
  if (!info.asn) {
    muteHint = {
      private: "The alert IP is private or allowed: the mute applies to all networks.",
      quota: "The network of the alert IP is not known: the proxycheck.io quota is low. Enter an ASN, or leave it empty for all networks.",
    }[info.note] || `The network of ${r.ip} was not found. Enter an ASN, or leave it empty for all networks.`;
  }
  r.asn = info.asn || "";
  r.network = info.network || "";
  location.hash = href(r.asn, r.network);
}

let muteData = null;       // last /mutes response
let mutePromise = null;    // request in progress
let muteError = "";
let muteForm = { type: "*", user: "", rule_name: "", asn: "", network: "", days: "7", reason: "" };
let muteErrors = {};
let muteNotice = null;     // {ok, text, kind}
let muteHint = "";         // shown when the next deep link opens the form

function describeMute(m) {
  return [muteTypeLabel(m.type), m.user === "*" ? "all users" : m.user, m.rule_name ? `rule "${m.rule_name}"` : null,
    m.asn ? `network ${networkLabel(m)}` : null].filter(Boolean).join(", ");
}

function networkLabel(m) {
  return m.asn ? (m.network ? `${m.network} (${m.asn})` : m.asn) : "";
}

function muteTypes() {
  return (muteData && muteData.types) || state.mute_types || [];
}

function maxMuteDays() {
  return (muteData && muteData.max_days) || 3650;
}

function loadMutes() {
  if (mutePromise) return mutePromise;
  mutePromise = (async () => {
    try {
      muteData = await api("/mutes");
      muteError = "";
    } catch (err) {
      if (err instanceof SessionError) handleError(err);
      muteError = err.message;
    }
    mutePromise = null;
    renderMutes();
  })();
  return mutePromise;
}

// Deep link "#mute:<type>:<upn>[:<rule>[:<asn>[:<network>]]]" from a medium alert email: fill the form,
// then move to it when the list is loaded (so that the page does not move after).
function openMutes(parts) {
  if (parts) setMuteForm(parts);
  if (muteData) {
    if (parts) { renderMutes(); focusMuteForm(); } else loadMutes();
    return;
  }
  if (parts) renderMutes();
  loadMutes().then(() => { if (parts && currentView() === "mutes") focusMuteForm(); });
}

function setMuteForm([type, user, rule, asn, network]) {
  muteErrors = {};
  muteNotice = muteHint ? { ok: false, kind: "warn", text: muteHint } : null;
  muteHint = "";
  const known = !type || type === "*" || muteTypes().some((t) => t[0] === type);
  muteForm = { type: known ? type || "*" : "*", user: user || "", rule_name: type === "inbox_rule" ? rule || "" : "",
               asn: asn || "", network: asn ? network || "" : "", days: "7", reason: "" };
  if (!known) {
    muteErrors.type = typeLabels().has(type)
      ? `${typeLabel(type)}: this alert type cannot be muted. It is always high.`
      : `Unknown alert type: ${type}.`;
  }
}

function focusMuteForm() {
  const form = document.getElementById("mute-form");
  if (!form) return;
  form.closest("section").scrollIntoView({ block: "start", behavior: "auto" });
  document.getElementById(muteErrors.type ? "mute-type" : muteForm.user ? "mute-reason" : "mute-user").focus({ preventScroll: true });
}

const MUTE_FIELDS = { type: "mute-type", user: "mute-user", rule_name: "mute-rule", asn: "mute-asn", days: "mute-days",
  reason: "mute-reason" };

function formField(id, label, control, help, error, wide) {
  return h("div", { class: `form-field${wide ? " form-wide" : ""}${error ? " invalid" : ""}`, id: `${id}-field` },
    h("label", { for: id, text: label }), control,
    help ? h("p", { class: "field-help", id: `${id}-help`, text: help }) : null,
    error ? h("div", { class: "field-error", id: `${id}-error`, role: "alert" }, icon("bad"), h("span", { text: error })) : null);
}

function muteFormCard() {
  const keyOf = (id) => Object.keys(MUTE_FIELDS).find((k) => MUTE_FIELDS[k] === id);
  const describedBy = (id) => [`${id}-help`, muteErrors[keyOf(id)] ? `${id}-error` : null].filter(Boolean).join(" ");
  const set = (key) => (e) => {
    muteForm[key] = e.target.value;
    if (!muteErrors[key]) return;
    delete muteErrors[key];
    const field = document.getElementById(`${MUTE_FIELDS[key]}-field`);
    field.classList.remove("invalid");
    const err = field.querySelector(".field-error");
    if (err) err.remove();
    e.target.removeAttribute("aria-invalid");
    e.target.setAttribute("aria-describedby", `${MUTE_FIELDS[key]}-help`);
  };
  const typeSelect = h("select", { id: "mute-type", "aria-describedby": describedBy("mute-type"),
    "aria-invalid": muteErrors.type ? "true" : null,
    onchange: (e) => {
      set("type")(e);
      if (muteForm.type !== "inbox_rule") muteForm.rule_name = "";
      document.getElementById("mute-rule-field").hidden = muteForm.type !== "inbox_rule";
    } },
    [["*", ALL_MUTE_TYPES], ...muteTypes()].map(([v, label]) => {
      const o = h("option", { value: v, text: label });
      if (v === muteForm.type) o.selected = true;
      return o;
    }));
  const input = (id, key, attrs) => {
    const el = h("input", { id, "aria-describedby": describedBy(id), "aria-invalid": muteErrors[key] ? "true" : null,
      autocomplete: "off", spellcheck: "false", oninput: set(key), ...attrs });
    el.value = muteForm[key];
    return el;
  };
  const ruleField = formField("mute-rule", "Rule name", input("mute-rule", "rule_name", { type: "text", maxlength: 255 }),
    "Optional. The exact name of the inbox rule. Empty: all inbox rule alerts.", muteErrors.rule_name);
  ruleField.hidden = muteForm.type !== "inbox_rule";
  return h("section", { class: "card", "aria-labelledby": "mute-form-title" },
    h("h2", { id: "mute-form-title", text: "Add a mute" }),
    h("p", { class: "card-sub", text: "Select one alert type, one user, or both. Optional: one network (ASN)." }),
    h("form", { id: "mute-form", class: "form-grid", onsubmit: addMute },
      formField("mute-type", "Alert type", typeSelect, "Only types that can be medium. High alerts always send email.", muteErrors.type),
      formField("mute-user", "User", input("mute-user", "user", { type: "text", inputmode: "email", placeholder: "jane@contoso.com or *" }),
        "A user principal name, or * for all users.", muteErrors.user),
      ruleField,
      formField("mute-asn", "Network (ASN)", input("mute-asn", "asn", { type: "text", maxlength: 16, placeholder: "AS63023",
        oninput: (e) => {
          set("asn")(e);
          muteForm.network = "";
          const help = document.getElementById("mute-asn-help");
          if (help) help.textContent = "Optional. Mutes only alerts from IPs in this network. Empty: all networks.";
        } }),
        muteForm.asn && muteForm.network ? `Optional. ${muteForm.network}. Empty: all networks.`
          : "Optional. Mutes only alerts from IPs in this network. Empty: all networks.", muteErrors.asn),
      formField("mute-days", "Days", input("mute-days", "days", { type: "number", inputmode: "numeric", min: 1, max: maxMuteDays(), step: 1, required: true }),
        `1 to ${maxMuteDays()} days.`, muteErrors.days),
      formField("mute-reason", "Reason", input("mute-reason", "reason", { type: "text", minlength: 3, maxlength: 200, required: true,
        placeholder: "Why is this alert expected?" }), "Required. 3 to 200 characters. Shows in History and in the email.", muteErrors.reason, true),
      h("div", { class: "actions form-wide" }, h("button", { type: "submit", class: "btn btn-primary", id: "mute-add", text: "Add mute" }))));
}

function muteRows(rows, active) {
  const types = muteTypes();
  const columns = [["Alert type", "primary"], ["User", "user"], ["Rule"], ["Network"], [active ? "Until" : "Ended", "nowrap"], ["Reason"], ["Added", "nowrap"]];
  if (active) columns.push(["Action"]);
  return table(columns, rows.map((m) => {
    const cells = [
      muteTypeLabel(m.type, types),
      userLink(m.user),
      m.rule_name || "-",
      networkLabel(m) || "-",
      active ? timeCell(m.until)
        : m.ended_at ? [h("span", { text: `Ended by ${m.ended_by || "unknown"}` }), h("span", { class: "sub", text: utc(m.ended_at) })]
          : [h("span", { text: "Expired" }), h("span", { class: "sub", text: utc(m.until) })],
      m.reason,
      [h("span", { text: m.created_by || "unknown" }), h("span", { class: "sub", text: utc(m.created_at) })],
    ];
    if (active) {
      cells.push(h("button", { type: "button", class: "btn-link", "data-mute": m.id,
        "aria-label": `End mute: ${muteTypeLabel(m.type, types)}, ${m.user === "*" ? "all users" : m.user}`,
        onclick: (e) => endMute(e, m), text: "End now" }));
    }
    return cells;
  }));
}

function renderMutes() {
  const root = document.getElementById("view-mutes");
  if (!state) return;
  const rows = (muteData && muteData.mutes) || [];
  const active = rows.filter((m) => m.active);
  const ended = rows.filter((m) => !m.active);
  let list;
  if (muteError) list = notice("bad", h("p", { text: muteError }));
  else if (!muteData) list = h("p", { class: "muted", text: "Loading mutes…" });
  else list = active.length ? muteRows(active, true)
    : empty("ok", "No active mutes", "Every alert that is on sends email.");
  fill(root,
    h("div", { class: "page-head" },
      h("h1", { text: "Mutes" }),
      h("p", { class: "lead", text: `A mute stops email for medium alerts of one alert type, one user, one inbox rule, or one network, for 1 to ${maxMuteDays()} days. High alerts always send email.` }),
      h("p", { class: "lead", text: "Muted alerts are still recorded. You see them on the user page and in Alerts. Each change is recorded in History and emailed to the alert mailbox." })),
    h("div", { class: "stack" },
      h("div", { id: "mute-out", "aria-live": "polite" },
        muteNotice ? notice(muteNotice.kind || (muteNotice.ok ? "ok" : "bad"), h("p", { text: muteNotice.text })) : null),
      h("section", { class: "card", "aria-labelledby": "mutes-active-title" },
        h("div", { class: "card-head" }, h("h2", { id: "mutes-active-title", tabindex: "-1", text: "Active mutes" }),
          active.length ? h("span", { class: "muted small", text: plural(active.length, "mute") }) : null),
        list),
      muteFormCard(),
      ended.length ? h("section", { class: "card", "aria-labelledby": "mutes-ended-title" },
        h("div", { class: "card-head" }, h("h2", { id: "mutes-ended-title", text: "Ended or expired" }),
          h("span", { class: "muted small", text: plural(ended.length, "mute") })),
        muteRows(ended, false)) : null));
}

async function addMute(e) {
  e.preventDefault();
  const button = e.submitter || document.getElementById("mute-add");
  const days = muteForm.days === "" ? null : Number(muteForm.days);
  const body = { action: "add", type: muteForm.type, user: muteForm.user.trim() || "*",
    rule_name: muteForm.type === "inbox_rule" ? muteForm.rule_name.trim() : "", asn: muteForm.asn.trim(),
    network: muteForm.asn.trim() ? muteForm.network : "", days, reason: muteForm.reason.trim() };
  const local = {};
  if (!muteForm.user.trim()) local.user = "Enter a user principal name, or * for all users.";
  else if (body.user !== "*" && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(body.user)) {
    local.user = "Enter a user principal name, for example jane@contoso.com, or * for all users.";
  } else if (body.type === "*" && body.user === "*") {
    local.user = "Select one alert type or one user. To stop an alert type, use Settings > Alerts.";
  }
  if (Object.keys(local).length) { showMuteErrors(local); return; }
  const untilDate = Number.isInteger(days) ? utc(new Date(Date.now() + days * 86400000).toISOString()) : "";
  const ok = await confirmDialog({
    title: "Add mute",
    body: [h("p", { text: "Stop email for medium alerts that match:" }),
      h("ul", {},
        h("li", { text: `Alert type: ${muteTypeLabel(body.type)}` }),
        h("li", { text: `User: ${body.user === "*" ? "all users" : body.user}` }),
        body.rule_name ? h("li", { text: `Rule: ${body.rule_name}` }) : null,
        body.asn ? h("li", { text: `Network: ${networkLabel(body)}` }) : null,
        h("li", { text: `For: ${plural(days || 0, "day")}${untilDate ? ` (until about ${untilDate})` : ""}` })),
      h("p", { class: "muted small", text: "High alerts still send email. Muted alerts are still recorded. The change is recorded in History and emailed to the alert mailbox." })],
    ok: "Add mute", danger: true });
  if (!ok) return;
  setBusy(button, true);
  try {
    muteData = await api("/mutes", { method: "POST", body });
    muteErrors = {};
    muteForm = { type: "*", user: "", rule_name: "", asn: "", network: "", days: "7", reason: "" };
    const added = muteData.added;
    muteNotice = { ok: true, text: `Mute added: ${describeMute(added || body)}.${added ? ` It ends ${utc(added.until)}.` : ""}` };
    if (location.hash.startsWith("#mute:")) history.replaceState(null, "", "#mutes");
    renderMutes();
    focusMuteResult();
    toast("Mute added.");
    reload(false);
  } catch (err) {
    if (err instanceof SessionError) { handleError(err); return; }
    const fieldErrors = (err.status === 400 && err.data && err.data.errors) || {};
    if (Object.keys(fieldErrors).length) showMuteErrors(fieldErrors);
    else { muteNotice = { ok: false, text: err.message }; renderMutes(); focusMuteResult(); }
  } finally {
    if (button && button.isConnected) setBusy(button, false);
  }
}

function showMuteErrors(fieldErrors) {
  muteErrors = fieldErrors;
  muteNotice = null;
  renderMutes();
  const first = Object.keys(MUTE_FIELDS).find((k) => muteErrors[k]);
  const el = first && document.getElementById(MUTE_FIELDS[first]);
  if (el) {
    el.scrollIntoView({ block: "center", behavior: motionOk() ? "smooth" : "auto" });
    el.focus({ preventScroll: true });
  }
  toast("Some values are not valid. See the messages in red.");
}

function focusMuteResult() {
  const title = document.getElementById("mutes-active-title");
  const out = document.getElementById("mute-out");
  if (out) out.scrollIntoView({ block: "nearest", behavior: motionOk() ? "smooth" : "auto" });
  if (title) title.focus({ preventScroll: true });
}

async function endMute(e, m) {
  const button = e.currentTarget;
  const ok = await confirmDialog({
    title: "End mute",
    body: [h("p", { text: "End this mute now?" }),
      h("ul", {},
        h("li", { text: `Alert type: ${muteTypeLabel(m.type)}` }),
        h("li", { text: `User: ${m.user === "*" ? "all users" : m.user}` }),
        m.rule_name ? h("li", { text: `Rule: ${m.rule_name}` }) : null,
        h("li", { text: `Reason: ${m.reason}` })),
      h("p", { class: "muted small", text: "Medium alerts of this kind send email again from the next run. The change is recorded in History and emailed to the alert mailbox." })],
    ok: "End mute", danger: false });
  if (!ok) return;
  setBusy(button, true);
  try {
    muteData = await api("/mutes", { method: "POST", body: { action: "end", id: m.id } });
    muteNotice = { ok: true, text: `Mute ended: ${describeMute(m)}. Medium alerts of this kind send email again from the next run.` };
    toast("Mute ended.");
    reload(false);
  } catch (err) {
    if (err instanceof SessionError) { handleError(err); return; }
    muteNotice = { ok: false, text: err.message };
    if (err.status === 404) {
      try { muteData = await api("/mutes"); } catch (e2) { /* keep the old list */ }
    }
  } finally {
    if (button.isConnected) setBusy(button, false);
  }
  renderMutes();
  focusMuteResult();
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

let historyMore = { page: 1, more: null, loading: false };

async function loadMoreHistory(button) {
  historyMore.loading = true;
  setBusy(button, true);
  try {
    const data = await api(`/history?page=${historyMore.page + 1}&size=30`);
    historyMore.page += 1;
    historyMore.more = data.more;
    state.history = (state.history || []).concat(data.history);
  } catch (err) {
    if (err instanceof SessionError) { handleError(err); return; }
    toast(`Not loaded: ${err.message}`);
  } finally {
    historyMore.loading = false;
  }
  renderHistory();
}

function renderHistory() {
  const root = document.getElementById("view-history");
  const items = state.history || [];
  // state.history holds the newest 30. More can exist until a page says there are no more.
  const more = historyMore.more === null ? items.length >= 30 : historyMore.more;
  fill(root,
    h("div", { class: "page-head" },
      h("h1", { text: "History" }),
      h("p", { class: "lead", text: "Changes made in this UI, newest first (90 days)." })),
    h("section", { class: "card card-flush", "aria-label": "Changes" }, items.length
      ? h("ol", { class: "history" }, items.map((entry) =>
        h("li", { class: "history-item" },
          h("div", { class: "history-when" },
            h("strong", { text: entry.by }),
            h("span", { class: "muted", text: utc(entry.at) }),
            entry.at ? h("span", { class: "muted small", text: ` · ${ago(entry.at)}` }) : null),
          h("ul", { class: "changes" }, entry.changes.map((c) => h("li", {},
            h("div", { class: "change-label", text: c.label }),
            h("div", { class: "change-values" },
              c.old ? [h("span", { class: "old", text: c.old }), h("span", { class: "arrow" }, icon("arrow"),
                h("span", { class: "visually-hidden", text: " changed to " }))] : null,
              h("span", { text: c.new }))))))))
      : empty("clock", "No changes yet", "Changes made in Settings and Countries show here.")),
    more ? h("p", { class: "more" }, h("button", { type: "button", class: "btn", id: "history-more",
      onclick: (e) => loadMoreHistory(e.currentTarget), text: "Show older changes" })) : null);
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

async function reload(full = true) {
  try {
    state = await api("/state");
  } catch (err) {
    document.getElementById("loading").hidden = true;
    handleError(err);
    return false;
  }
  document.getElementById("loading").hidden = true;
  const me = state.me || {};
  document.getElementById("user").textContent = me.name || state.user;
  document.getElementById("avatar").textContent = (me.name || state.user || "?").charAt(0).toUpperCase();
  document.getElementById("profile-name").textContent = me.name || state.user || "unknown";
  // Without a display name in the token, the name is the email: show it one time.
  const sameName = !me.name || me.name.toLowerCase() === (me.upn || "").toLowerCase();
  const nameRow = document.getElementById("profile-name");
  nameRow.hidden = sameName;
  nameRow.previousElementSibling.hidden = sameName;
  document.getElementById("profile-email").textContent = me.upn || "unknown";
  document.getElementById("profile-access").textContent = me.access || "unknown";
  document.getElementById("site").textContent = state.app.site;
  showBanner("", false);
  labelCache = null;
  renderOverview();
  if (full || !Object.keys(draft).length) renderSettings();
  renderHistory();
  if (full) {
    renderCountries(null);
    renderUsers();
    renderMutes();
    renderAlerts();
  }
  showView(currentView());
  if (full) routeArguments();
  return true;
}

// The account menu: name, email (from the sign-in token), and why this account has access.
function initProfileMenu() {
  const button = document.getElementById("profile-button");
  const menu = document.getElementById("profile-menu");
  const show = (open) => {
    menu.hidden = !open;
    button.setAttribute("aria-expanded", open ? "true" : "false");
  };
  button.addEventListener("click", () => {
    show(menu.hidden);
    // Focus the title, not "Sign out": a second Enter must not sign the user out.
    if (!menu.hidden) document.getElementById("profile-title").focus();
  });
  menu.addEventListener("focusout", (e) => {
    if (!menu.hidden && !menu.contains(e.relatedTarget) && e.relatedTarget !== button) show(false);
  });
  document.addEventListener("click", (e) => {
    if (!menu.hidden && !menu.contains(e.target) && !button.contains(e.target)) show(false);
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !menu.hidden) { show(false); button.focus(); }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initProfileMenu();
  document.getElementById("save").addEventListener("click", save);
  document.getElementById("discard").addEventListener("click", discard);
  window.addEventListener("beforeunload", (e) => {
    if (Object.keys(draft).length) { e.preventDefault(); e.returnValue = ""; }
  });
  window.addEventListener("scroll", () => {
    if (spyQueued) return;
    spyQueued = true;
    requestAnimationFrame(() => { spyQueued = false; updateActiveGroup(); });
  }, { passive: true });
  reload(true);
});
