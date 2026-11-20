// SecureChat admin page. All data comes from the server's admin API.
// Text from the server is inserted with textContent only (usernames, event details
// and announcements could contain HTML - it must never be executed).
"use strict";

const $ = (id) => document.getElementById(id);
const AVATAR_COLORS = ["#6536D6", "#3579EE", "#7A3FE0", "#2F6FD6", "#8B5CF6"];
const POLL_MS = 3000;

let data = null;
let pollTimer = null;
let settingsLoaded = false;

// ------------------------------------------------------------------ helpers

async function api(path, body) {
  const opts = { credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    opts.method = "POST";
    opts.headers["Content-Type"] = "application/json";
    opts.headers["X-SecureChat-Admin"] = "1";   // CSRF protection
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (res.status === 401) { showLogin(); throw new Error("Session expired"); }
  return res.json();
}

function el(tag, className, text) {
  const n = document.createElement(tag);
  if (className) n.className = className;
  if (text !== undefined && text !== null) n.textContent = text;
  return n;
}

function td(text, className) { return el("td", className, text); }

function when(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString([], { dateStyle: "short", timeStyle: "short" });
}

function timeOnly(ts) {
  return new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function duration(sec) {
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60);
  return h ? `${h}h ${m}m` : `${m}m ${Math.floor(sec % 60)}s`;
}

function avatarColor(name) {
  let s = 0;
  for (const ch of name) s += ch.codePointAt(0);
  return AVATAR_COLORS[s % AVATAR_COLORS.length];
}

function toast(text, error = false) {
  const t = $("toast");
  t.textContent = text;
  t.className = "toast" + (error ? " error" : "");
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, 3500);
}

function confirmAction(title, text) {
  return new Promise((resolve) => {
    $("confirm-title").textContent = title;
    $("confirm-text").textContent = text;
    $("overlay").hidden = false;
    $("confirm-dlg").hidden = false;
    const done = (v) => {
      $("overlay").hidden = true;
      $("confirm-dlg").hidden = true;
      resolve(v);
    };
    $("confirm-yes").onclick = () => done(true);
    $("confirm-no").onclick = () => done(false);
    $("overlay").onclick = () => done(false);
  });
}

// ------------------------------------------------------------------ login

function showLogin() {
  clearInterval(pollTimer);
  $("dash-view").hidden = true;
  $("login-view").hidden = false;
  $("admin-pass").value = "";
  $("admin-user").focus();
}

async function login(ev) {
  ev.preventDefault();
  $("login-btn").disabled = true;
  $("login-status").textContent = "";
  try {
    const res = await api("/api/login", { username: $("admin-user").value.trim(), password: $("admin-pass").value });
    if (res.ok) {
      $("admin-pass").value = "";
      startDashboard(res.admin);
    } else {
      $("login-status").textContent = res.error;
    }
  } catch {
    $("login-status").textContent = "Cannot reach the server.";
  } finally {
    $("login-btn").disabled = false;
  }
}

async function logout() {
  await api("/api/logout", {}).catch(() => {});
  showLogin();
}

// ------------------------------------------------------------------ dashboard

function startDashboard(admin) {
  $("login-view").hidden = true;
  $("dash-view").hidden = false;
  $("admin-name").textContent = admin;
  settingsLoaded = false;
  refresh();
  clearInterval(pollTimer);
  pollTimer = setInterval(refresh, POLL_MS);
}

async function refresh() {
  try {
    data = await api("/api/dashboard");
  } catch {
    return;
  }
  renderStats();
  renderUsers();
  renderEvents();
  renderManage();
}

function renderStats() {
  const s = data.stats;
  const cards = [
    ["Registered users", s.registered, ""],
    ["Online now", s.online, "good"],
    ["Messages relayed (encrypted)", s.relayed, ""],
    ["Files relayed (encrypted)", s.files, ""],
    ["Banned accounts", s.banned, s.banned ? "warn" : ""],
    ["Locked right now", s.locked, s.locked ? "warn" : ""],
    ["Blocked packets", s.blocked, s.blocked ? "warn" : ""],
    ["Friendships", s.friendships, ""],
  ];
  const box = $("stats");
  box.replaceChildren(...cards.map(([label, value, cls]) => {
    const d = el("div", "stat " + cls);
    d.append(el("b", "", String(value)), el("span", "", label));
    return d;
  }));
  $("srv-address").textContent = data.server.address;
  $("srv-fp").textContent = data.server.fingerprint;
  $("srv-uptime").textContent = duration(s.uptime);
  $("srv-reg").textContent = data.settings.registration_open ? "Open" : "Closed";
  const demo = [];
  if (data.server.allow_plain) demo.push("Plain (unencrypted) mode ALLOWED");
  if (data.server.attack) demo.push(`acting as HACKED server: ${data.server.attack}`);
  $("srv-demo").textContent = demo.length ? demo.join(" • ") : "Off";
  $("srv-demo").className = demo.length ? "danger-txt" : "";

  const online = data.users.filter((u) => u.online);
  const list = $("online-list");
  list.replaceChildren(...(online.length
    ? online.map((u) => el("li", "", `${u.username}  (${u.ip})`))
    : [el("li", "empty", "Nobody is online.")]));

  const body = $("overview-events");
  body.replaceChildren(...eventRows(data.events.slice(0, 8), false));
}

function statusTags(u) {
  const tags = [];
  if (u.banned) tags.push(el("span", "tag banned", "Banned"));
  if (u.locked_until) tags.push(el("span", "tag locked", "Locked"));
  tags.push(el("span", "tag " + (u.online ? "online" : "offline"), u.online ? "Online" : "Offline"));
  if (u.online && u.plain) tags.push(el("span", "tag banned", "Plain mode"));
  return tags;
}

function actionButton(label, onClick, danger = false) {
  const b = el("button", "act" + (danger ? " danger" : ""), label);
  b.type = "button";
  b.onclick = onClick;
  return b;
}

async function adminAction(path, username, confirmTitle, confirmText) {
  if (confirmTitle && !(await confirmAction(confirmTitle, confirmText))) return;
  const res = await api(path, { username });
  toast(res.ok ? res.message : res.error, !res.ok);
  refresh();
}

function renderUsers() {
  const q = $("user-search").value.trim().toLowerCase();
  const users = data.users.filter((u) => u.username.toLowerCase().includes(q));
  const body = $("users-body");
  if (!users.length) {
    const tr = el("tr", "empty-row");
    const cell = td(data.users.length ? "No matches." : "No users registered yet.");
    cell.colSpan = 7;
    tr.append(cell);
    body.replaceChildren(tr);
    return;
  }
  body.replaceChildren(...users.map((u) => {
    const tr = el("tr");
    const userCell = el("td");
    const wrap = el("div", "user-cell");
    const av = el("span", "mini-avatar", u.username[0].toUpperCase());
    av.style.background = avatarColor(u.username);
    wrap.append(av, document.createTextNode(u.username));
    userCell.append(wrap);

    const status = el("td");
    status.append(...statusTags(u));

    const actions = el("td");
    const box = el("div", "actions");
    if (u.online) box.append(actionButton("Kick", () => adminAction("/api/kick", u.username,
      "Kick user?", `${u.username} will be disconnected right away. They can log in again.`)));
    if (u.locked_until) box.append(actionButton("Unlock", () => adminAction("/api/unlock", u.username)));
    if (u.banned) box.append(actionButton("Unban", () => adminAction("/api/unban", u.username)));
    else box.append(actionButton("Ban", () => adminAction("/api/ban", u.username,
      "Ban user?", `${u.username} will be disconnected and cannot log in until unbanned.`), true));
    box.append(actionButton("Delete", () => adminAction("/api/delete", u.username,
      "Delete user permanently?", `${u.username}'s account and friendships will be deleted. This cannot be undone. ` +
      "Their messages are not stored on the server, so there is nothing else to delete."), true));
    actions.append(box);

    tr.append(userCell, status, td(when(u.created)), td(when(u.last_login)), td(String(u.friends)),
      td(u.fingerprint, "fp-cell"), actions);
    return tr;
  }));
}

const BAD = new Set(["failed_login", "account_locked", "banned_login", "spoofed_packet", "admin_login_failed",
  "password_change_failed", "plain_mode_connection"]);
const GOOD = new Set(["login", "registered", "password_changed"]);

function eventRows(events, full = true) {
  if (!events.length) {
    const tr = el("tr", "empty-row");
    const c = td("No events yet.");
    c.colSpan = full ? 5 : 4;
    tr.append(c);
    return [tr];
  }
  return events.map((e) => {
    const tr = el("tr");
    const kind = el("td");
    kind.append(el("span", "ev " + (BAD.has(e.kind) ? "bad" : GOOD.has(e.kind) ? "good" : ""), e.kind.replaceAll("_", " ")));
    const cells = [td(full ? when(e.ts) : timeOnly(e.ts)), kind, td(e.username || "—")];
    if (full) cells.push(td(e.ip || "—"));
    cells.push(td(e.details || ""));
    tr.append(...cells);
    return tr;
  });
}

function renderEvents() {
  $("events-body").replaceChildren(...eventRows(data.events));
  const audit = $("audit-body");
  if (!data.audit.length) {
    const tr = el("tr", "empty-row");
    const c = td("No admin actions yet.");
    c.colSpan = 5;
    tr.append(c);
    audit.replaceChildren(tr);
    return;
  }
  audit.replaceChildren(...data.audit.map((a) => {
    const tr = el("tr");
    const action = el("td");
    action.append(el("span", "ev warn", a.action.replaceAll("_", " ")));
    tr.append(td(when(a.ts)), td(a.admin), action, td(a.target || "—"), td(a.details || ""));
    return tr;
  }));
}

function renderManage() {
  const list = $("announce-list");
  list.replaceChildren(...(data.announcements.length
    ? data.announcements.map((a) => {
        const li = el("li");
        li.append(el("time", "", when(a.ts)), document.createTextNode(a.text));
        return li;
      })
    : [el("li", "muted", "No announcements yet.")]));
  if (!settingsLoaded) {   // don't overwrite the form while the admin is editing it
    $("set-reg").checked = data.settings.registration_open;
    $("set-fails").value = data.settings.max_failed_logins;
    $("set-lock").value = data.settings.lockout_seconds;
    settingsLoaded = true;
  }
}

async function announce(ev) {
  ev.preventDefault();
  const text = $("announce-text").value.trim();
  if (!text) return;
  const res = await api("/api/announce", { text });
  toast(res.ok ? res.message : res.error, !res.ok);
  if (res.ok) $("announce-text").value = "";
  refresh();
}

async function saveSettings(ev) {
  ev.preventDefault();
  const res = await api("/api/settings", {
    registration_open: $("set-reg").checked,
    max_failed_logins: Number($("set-fails").value),
    lockout_seconds: Number($("set-lock").value),
  });
  toast(res.ok ? res.message : res.error, !res.ok);
  settingsLoaded = false;
  refresh();
}

function switchTab(name) {
  for (const t of document.querySelectorAll(".tab")) t.classList.toggle("active", t.dataset.tab === name);
  for (const p of document.querySelectorAll(".tab-panel")) p.hidden = p.dataset.panel !== name;
}

// ------------------------------------------------------------------ wiring

document.addEventListener("DOMContentLoaded", async () => {
  $("login-form").addEventListener("submit", login);
  $("logout-btn").onclick = logout;
  $("announce-form").addEventListener("submit", announce);
  $("settings-form").addEventListener("submit", saveSettings);
  $("user-search").oninput = () => data && renderUsers();
  for (const t of document.querySelectorAll(".tab")) t.onclick = () => switchTab(t.dataset.tab);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("confirm-no").click(); });

  try {
    const me = await api("/api/me");
    if (me.admin) startDashboard(me.admin);
    else showLogin();
  } catch {
    showLogin();
  }
});
