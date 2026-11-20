// SecureChat web UI (user page).
// This page does NO cryptography: it talks to the local Python client, which
// encrypts, signs, verifies and decrypts. Network text is ALWAYS inserted with
// textContent (never innerHTML), so a malicious message cannot inject HTML/JS.
"use strict";

const TOKEN = document.querySelector('meta[name="securechat-token"]').content;
const $ = (id) => document.getElementById(id);
const AVATAR_COLORS = ["#6536D6", "#3579EE", "#7A3FE0", "#2F6FD6", "#8B5CF6"];

const state = {
  mode: "login",          // or "register"
  view: "chat",           // or "profile"
  me: null,
  myFp: "",
  serverFp: "",
  serverAddress: "",
  plain: false,           // DEMO: Plain (unencrypted) mode
  profile: {},
  contacts: [],           // friends: {name, online, fingerprint, trusted, changed, verified}
  incoming: [],
  outgoing: [],
  announcements: [],
  history: {},            // friend -> [{kind, text, ts}]
  unread: {},
  selected: null,
  log: [],
  lastEventId: -1,
  events: null,
  pendingLogin: null,     // remembered for retry after trusting a new server key
};

// ------------------------------------------------------------------ helpers

async function api(path, body) {
  const opts = { headers: { "X-SecureChat-Token": TOKEN } };
  if (body !== undefined) {
    opts.method = "POST";
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function clock(ts) {
  return new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function when(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function avatarColor(name) {
  let sum = 0;
  for (const ch of name) sum += ch.codePointAt(0);
  return AVATAR_COLORS[sum % AVATAR_COLORS.length];
}

function now() { return Date.now() / 1000; }

// ------------------------------------------------------------------ auth screen

function setMode(mode) {
  state.mode = mode;
  const reg = mode === "register";
  $("auth-title").textContent = reg ? "Create account" : "Welcome back";
  $("auth-subtitle").textContent = reg ? "Your keys are generated on this device" : "Sign in to your secure account";
  $("confirm-group").hidden = !reg;
  $("policy-hint").hidden = !reg;
  $("auth-submit").textContent = reg ? "Create Account" : "Sign In";
  $("auth-switch").textContent = reg ? "Already have an account? Sign in" : "Don't have an account? Create account";
  $("password").autocomplete = reg ? "new-password" : "current-password";
  // keep username + connection, never carry a password across screens
  $("password").value = "";
  $("confirm").value = "";
  setStatus("");
  ($("username").value ? $("password") : $("username")).focus();
}

function setStatus(text, info = false) {
  $("auth-status").textContent = text;
  $("auth-status").classList.toggle("info", info);
}

function setBusy(busy) {
  $("auth-submit").disabled = busy;
  $("auth-switch").disabled = busy;
  if (busy) $("auth-submit").textContent = "Please wait…";
  else $("auth-submit").textContent = state.mode === "register" ? "Create Account" : "Sign In";
}

async function submitAuth(ev) {
  ev.preventDefault();
  const req = {
    username: $("username").value.trim(),
    password: $("password").value,
    host: $("server-host").value.trim(),
    port: Number($("server-port").value.trim()),
    register: state.mode === "register",
    plain: document.querySelector('input[name="mode"]:checked').value === "plain",
  };
  if (!req.username || !req.password) return setStatus("Enter your username and password.");
  if (!Number.isInteger(req.port) || req.port < 1 || req.port > 65535)
    return setStatus("Port must be a number between 1 and 65535.");
  if (req.register && req.password !== $("confirm").value) return setStatus("Passwords do not match.");
  await doLogin(req);
}

async function doLogin(req) {
  setBusy(true);
  setStatus(req.register ? "Generating your RSA key pair and connecting…" : "Connecting securely…", true);
  try {
    const res = await api("/api/login", req);
    if (res.ok) {
      $("password").value = "";
      $("confirm").value = "";
      await loadState();
      return;
    }
    if (res.server_key_changed) {
      state.pendingLogin = req;
      showServerKeyDialog(res.server_key_changed);
      setStatus("Connection stopped: the server key changed.");
    } else {
      setStatus(res.error || "Login failed.");
    }
  } catch (err) {
    setStatus("Lost contact with the local SecureChat client. Is client.py still running?");
  } finally {
    setBusy(false);
  }
}

function showServerKeyDialog(info) {
  $("sk-address").textContent = info.address;
  $("sk-old").textContent = info.old;
  $("sk-new").textContent = info.new;
  openDialog("dlg-serverkey");
  $("sk-trust").onclick = async () => {
    const req = state.pendingLogin;
    closeDialogs();
    await api("/api/trust_server", { host: req.host, port: req.port, fingerprint: info.new });
    await doLogin(req);
  };
}

// ------------------------------------------------------------------ state + live events

async function loadState() {
  const s = await api("/api/state");
  if (!$("server-host").value) $("server-host").value = s.default_host;
  if (!$("server-port").value) $("server-port").value = s.default_port;
  state.log = s.log;
  if (s.logged_in) {
    Object.assign(state, {
      me: s.username, myFp: s.my_fingerprint, serverFp: s.server_fingerprint,
      serverAddress: s.server_address, plain: s.plain, profile: s.profile, contacts: s.contacts,
      incoming: s.incoming, outgoing: s.outgoing, history: s.history, announcements: s.announcements,
    });
    showChat();
    if (state.announcements.length) showBanner(state.announcements[state.announcements.length - 1]);
  } else {
    showAuth();
  }
  connectEvents(s.next_event);
}

function connectEvents(since) {
  if (state.events) state.events.close();
  state.lastEventId = since - 1;
  const src = new EventSource(`/api/events?since=${since}&token=${encodeURIComponent(TOKEN)}`);
  src.onmessage = (e) => {
    const id = Number(e.lastEventId);
    if (id <= state.lastEventId) return;   // already handled (after an auto-reconnect)
    state.lastEventId = id;
    handleEvent(JSON.parse(e.data));
  };
  state.events = src;
}

function handleEvent({ kind, data }) {
  switch (kind) {
    case "log":
      state.log.push(data);
      appendLog(data);
      break;
    case "friends": {
      const before = new Map(state.contacts.map((c) => [c.name, c]));
      for (const c of data.contacts) {
        const old = before.get(c.name);
        if (old && old.online !== c.online && c.name === state.selected)
          addItem(c.name, { kind: "info", text: `${c.name} is now ${c.online ? "online" : "offline"}.`, ts: now() });
      }
      const newRequests = data.incoming.filter((n) => !state.incoming.includes(n));
      Object.assign(state, { contacts: data.contacts, incoming: data.incoming, outgoing: data.outgoing });
      if (state.selected && !data.contacts.some((c) => c.name === state.selected)) state.selected = null;
      if (newRequests.length) setAddStatus(`New friend request from ${newRequests.join(", ")}`);
      renderContacts();
      renderRequests();
      renderHeader();
      if (!(state.history[state.selected] || []).length) renderMessages();   // refresh empty-state text
      if (state.view === "profile") renderFriendsTable();
      break;
    }
    case "item": {
      const contact = data.contact || state.selected;
      if (contact) addItem(contact, data);
      break;
    }
    case "announcement":
      state.announcements.push(data);
      showBanner(data);
      if (state.view === "profile") renderAnnouncements();
      break;
    case "disconnected":
      if (state.me) {
        alert(data || "Disconnected from server");
        resetChat();
        showAuth();
      }
      break;
  }
}

// ------------------------------------------------------------------ chat screen

function showAuth() {
  $("chat-view").hidden = true;
  $("auth-view").hidden = false;
  document.title = "SecureChat";
  setBusy(false);
}

function showChat() {
  $("auth-view").hidden = true;
  $("chat-view").hidden = false;
  $("me-name").textContent = state.me;
  document.title = `SecureChat — ${state.me}${state.plain ? " (PLAIN DEMO)" : ""}`;
  $("plain-banner").hidden = !state.plain;
  $("mode-badge").textContent = state.plain ? "PLAIN MODE — NOT ENCRYPTED" : "SECURE MODE ON";
  $("mode-badge").classList.toggle("plain", state.plain);
  setView("chat");
  renderContacts();
  renderRequests();
  renderHeader();
  renderMessages();
}

function setView(view) {
  state.view = view;
  $("conversation").hidden = view !== "chat";
  $("profile").hidden = view !== "profile";
  $("rail-chat").classList.toggle("active", view === "chat");
  $("rail-profile").classList.toggle("active", view === "profile");
  if (view === "profile") renderProfile();
}

function resetChat() {
  Object.assign(state, { me: null, contacts: [], incoming: [], outgoing: [], history: {}, unread: {},
    selected: null, announcements: [], profile: {} });
  $("announce-banner").hidden = true;
  closeDialogs();
}

function contact(name) {
  return state.contacts.find((c) => c.name === name);
}

function contactStatus(c) {
  if (c.changed) return ["KEY CHANGED — verify!", "danger"];
  if (!c.online) return ["Offline", "offline"];
  if (c.verified) return ["Online • Verified ✓", ""];
  return ["Online • not verified", ""];
}

function renderContacts() {
  const list = $("contact-list");
  list.replaceChildren();
  const q = $("search").value.trim().toLowerCase();
  if (!state.contacts.length) {
    list.append(el("li", "empty-contacts",
      "No friends yet. Type a username above and press Add. When they accept, you can chat."));
    return;
  }
  const shown = state.contacts.filter((c) => c.name.toLowerCase().includes(q));
  if (!shown.length) {
    list.append(el("li", "empty-contacts", "No matches."));
    return;
  }
  for (const c of shown) {
    const li = el("li", "contact" + (c.name === state.selected ? " selected" : "") + (c.online ? "" : " offline"));
    li.tabIndex = 0;
    const av = el("div", "avatar", c.name[0].toUpperCase());
    av.style.background = avatarColor(c.name);
    const text = el("div", "contact-text");
    const [status, cls] = contactStatus(c);
    text.append(el("div", "contact-name", c.name), el("div", "contact-status " + cls, status));
    li.append(av, text);
    if (state.unread[c.name]) li.append(el("span", "unread", String(state.unread[c.name])));
    li.onclick = () => selectContact(c.name);
    li.onkeydown = (e) => { if (e.key === "Enter") selectContact(c.name); };
    list.append(li);
  }
}

function renderRequests() {
  const box = $("requests");
  const list = $("request-list");
  list.replaceChildren();
  box.hidden = !state.incoming.length && !state.outgoing.length;
  for (const name of state.incoming) {
    const li = el("li");
    const accept = el("button", "mini ok", "Accept");
    const decline = el("button", "mini", "Decline");
    accept.onclick = () => respondFriend(name, true);
    decline.onclick = () => respondFriend(name, false);
    li.append(el("span", "req-name", name), accept, decline);
    list.append(li);
  }
  for (const name of state.outgoing) {
    const li = el("li");
    li.append(el("span", "req-name", name), el("span", "pending", "request sent"));
    list.append(li);
  }
}

function setAddStatus(text, error = false) {
  $("add-friend-status").textContent = text;
  $("add-friend-status").classList.toggle("error", error);
}

async function addFriend(ev) {
  ev.preventDefault();
  const name = $("add-friend-name").value.trim();
  if (!name) return;
  const res = await api("/api/friend_add", { name });
  setAddStatus(res.ok ? res.message : res.error, !res.ok);
  if (res.ok) $("add-friend-name").value = "";
}

async function respondFriend(name, accept) {
  const res = await api("/api/friend_respond", { name, accept });
  setAddStatus(res.ok ? (accept ? `You are now friends with ${name}` : `Declined ${name}`) : res.error, !res.ok);
}

async function removeFriend(name) {
  if (!confirm(`Remove ${name} from your friends?\n\nYou will not be able to message each other until you add each other again.`)) return;
  const res = await api("/api/friend_remove", { name });
  if (!res.ok) return alert(res.error);
  delete state.history[name];
  if (state.selected === name) state.selected = null;
}

function selectContact(name) {
  state.selected = name;
  delete state.unread[name];
  setView("chat");
  renderContacts();
  renderHeader();
  renderMessages();
  $("msg-input").focus();
}

function renderHeader() {
  const c = state.selected ? contact(state.selected) : null;
  const sub = $("peer-sub");
  $("peer-name").textContent = state.selected || "No conversation";
  sub.className = "peer-sub";
  if (!c) {
    sub.textContent = "Select a friend to start";
    sub.classList.add("muted");
  } else if (c.changed) {
    sub.textContent = "Key changed — messages blocked until you verify";
    sub.classList.add("danger");
  } else if (!c.online) {
    sub.textContent = "Offline — messages can only be sent to online friends";
    sub.classList.add("muted");
  } else if (state.plain) {
    sub.textContent = "PLAIN DEMO — not encrypted, not signed";
    sub.classList.add("danger");
  } else {
    sub.textContent = "End-to-end encrypted (AES-256-GCM + RSA-2048)";
  }
  const canSend = Boolean(c && c.trusted && c.online);
  $("send-btn").disabled = !canSend;
  $("msg-input").disabled = !canSend;
  $("file-btn").disabled = !canSend;
}

function addItem(name, item) {
  (state.history[name] = state.history[name] || []).push(item);
  if (name === state.selected && state.view === "chat") {
    renderMessages();
  } else if (["in", "alert", "file_in"].includes(item.kind)) {
    state.unread[name] = (state.unread[name] || 0) + 1;
    renderContacts();
  }
}

function bubble(item) {
  if (item.kind === "alert") {
    const b = el("div", "bubble alert", "WARNING: " + item.text);
    b.append(el("span", "meta", `${clock(item.ts)} • Security event`));
    return b;
  }
  if (item.kind === "info") return el("div", "info-line", item.text);
  if (item.kind === "sending") return el("div", "sending", item.text);
  const incoming = item.kind === "in" || item.kind === "file_in";
  const isFile = item.kind === "file_in" || item.kind === "file_out";
  const safe = item.encrypted !== false;
  const b = el("div", "bubble " + (incoming ? "in" : "out") + (safe ? "" : " plain-msg"), isFile ? undefined : item.text);
  if (isFile) b.append(fileCard(item, incoming));
  let meta;
  if (!safe) meta = incoming ? "NOT encrypted • NOT verified (could be changed)" : "Sent in PLAIN text • NOT encrypted";
  else if (isFile) meta = incoming ? "File decrypted • Signature verified" : "File encrypted & signed";
  else meta = incoming ? "Signature verified" : "Encrypted & signed";
  b.append(el("span", "meta" + (safe ? "" : " unsafe"), `${clock(item.ts)} • ${meta}`));
  return b;
}

function formatSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function fileCard(item, incoming) {
  const card = el("div", "file-card");
  const ext = (item.text.includes(".") ? item.text.split(".").pop() : "file").slice(0, 4);
  const info = el("div");
  info.append(el("div", "file-name", item.text), el("div", "file-size", formatSize(item.size || 0)));
  card.append(el("div", "file-icon", ext), info);
  if (incoming && item.file_id) {
    const a = el("a", "file-dl", "Download");
    a.href = `/api/file?id=${encodeURIComponent(item.file_id)}&token=${encodeURIComponent(TOKEN)}`;
    a.setAttribute("download", item.text);
    card.append(a);
  }
  return card;
}

const MAX_FILE = 10 * 1024 * 1024;

function readAsBase64(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).split(",")[1] || "");
    r.onerror = () => reject(r.error);
    r.readAsDataURL(file);
  });
}

async function sendFile() {
  const input = $("file-input");
  const file = input.files[0];
  input.value = "";
  const to = state.selected;
  if (!file || !to) return;
  if (file.size > MAX_FILE) {
    return addItem(to, { kind: "alert", text: `${file.name} is too large (max 10 MiB).`, ts: now() });
  }
  if (file.size === 0) return addItem(to, { kind: "alert", text: "The file is empty.", ts: now() });
  const box = $("messages");
  const note = el("div", "sending", `${state.plain ? "Sending" : "Encrypting and sending"} ${file.name}…`);
  box.append(note);
  box.scrollTop = box.scrollHeight;
  $("file-btn").disabled = true;
  try {
    const data = await readAsBase64(file);
    const res = await api("/api/send_file", { to, name: file.name, data });
    if (!res.ok) addItem(to, { kind: "alert", text: res.error, ts: now() });
  } catch {
    addItem(to, { kind: "alert", text: "Could not send the file.", ts: now() });
  } finally {
    note.remove();
    renderHeader();
  }
}

function renderMessages() {
  const box = $("messages");
  box.replaceChildren();
  const items = state.selected ? state.history[state.selected] || [] : [];
  if (!items.length) {
    let title, sub;
    if (!state.contacts.length) [title, sub] = ["No friends yet", "Add a friend by username in the left panel."];
    else if (!state.selected) [title, sub] = ["Select a friend", "Choose someone from the list to start an encrypted chat."];
    else [title, sub] = ["No messages yet", "Messages are end-to-end encrypted and kept in memory only."];
    const empty = el("div", "empty-state");
    const circle = el("div", "circle");
    const img = el("img");
    img.src = "/static/shield-soft.svg";
    img.alt = "";
    circle.append(img);
    empty.append(circle, el("h3", "", title), el("p", "", sub));
    box.append(empty);
    return;
  }
  for (const it of items) box.append(bubble(it));
  box.scrollTop = box.scrollHeight;
}

async function sendMessage(ev) {
  ev.preventDefault();
  const input = $("msg-input");
  const text = input.value.trim();
  if (!text || !state.selected) return;
  input.value = "";
  try {
    const res = await api("/api/send", { to: state.selected, text });
    if (!res.ok) {
      input.value = text;   // give the text back so it is not lost
      addItem(state.selected, { kind: "alert", text: res.error, ts: now() });
    }
  } catch {
    input.value = text;
    addItem(state.selected, { kind: "alert", text: "Local client not reachable.", ts: now() });
  }
}

async function logout() {
  await api("/api/logout", {});
  resetChat();
  showAuth();
  setMode("login");
}

function showBanner(a) {
  $("announce-text").textContent = a.text;
  $("announce-banner").hidden = false;
}

// ------------------------------------------------------------------ profile (user page)

function renderProfile() {
  $("pf-name").textContent = state.me;
  $("pf-avatar").textContent = state.me[0].toUpperCase();
  $("pf-avatar").style.background = avatarColor(state.me);
  $("pf-created").textContent = when(state.profile.created);
  $("pf-last").textContent = state.profile.last_login ? when(state.profile.last_login) : "First login";
  $("pf-session").textContent = when(state.profile.logged_in_at);
  $("pf-server").textContent = state.serverAddress;
  $("pf-myfp").textContent = state.myFp;
  $("pf-serverfp").textContent = state.serverFp;
  renderFriendsTable();
  renderAnnouncements();
  loadSecurityEvents();
}

function renderFriendsTable() {
  const body = $("pf-friends");
  body.replaceChildren();
  if (!state.contacts.length) {
    const tr = el("tr", "empty");
    const td = el("td", "", "No friends yet.");
    td.colSpan = 5;
    tr.append(td);
    body.append(tr);
    return;
  }
  for (const c of state.contacts) {
    const tr = el("tr");
    const verify = el("td");
    if (c.changed) verify.append(el("span", "danger-txt", "Key changed!"));
    else if (c.verified) verify.append(el("span", "ok-text", "Verified ✓"));
    else verify.append(el("span", "warn-text", "Not verified"));
    const actions = el("td");
    const check = el("button", "mini", c.changed ? "Review" : "Verify");
    check.onclick = () => { state.selected = c.name; showVerify(); };
    const remove = el("button", "mini danger", "Remove");
    remove.onclick = () => removeFriend(c.name);
    actions.append(check, document.createTextNode(" "), remove);
    tr.append(el("td", "", c.name), el("td", "", c.online ? "Online" : "Offline"),
      el("td", "fp", c.fingerprint), verify, actions);
    body.append(tr);
  }
}

function renderAnnouncements() {
  const list = $("pf-announcements");
  list.replaceChildren();
  if (!state.announcements.length) return list.append(el("li", "empty", "No announcements."));
  for (const a of [...state.announcements].reverse()) {
    const li = el("li");
    li.append(el("time", "", when(a.ts)), document.createTextNode(a.text));
    list.append(li);
  }
}

const BAD_EVENTS = new Set(["failed_login", "account_locked", "banned_login", "spoofed_packet", "password_change_failed"]);
const GOOD_EVENTS = new Set(["login", "registered", "password_changed"]);

async function loadSecurityEvents() {
  const list = $("pf-events");
  try {
    const res = await api("/api/my_security", {});
    list.replaceChildren();
    if (!res.ok) return list.append(el("li", "empty", res.error));
    if (!res.events.length) return list.append(el("li", "empty", "No events."));
    for (const e of res.events) {
      const li = el("li");
      const cls = BAD_EVENTS.has(e.kind) ? "bad" : GOOD_EVENTS.has(e.kind) ? "good" : "";
      li.append(el("time", "", when(e.ts)), el("span", cls, e.kind.replaceAll("_", " ")));
      if (e.ip) li.append(document.createTextNode(` from ${e.ip}`));
      if (e.details) li.append(document.createTextNode(` — ${e.details}`));
      list.append(li);
    }
  } catch {
    list.replaceChildren(el("li", "empty", "Could not load events."));
  }
}

async function changePassword(ev) {
  ev.preventDefault();
  const status = $("pw-status");
  const oldPw = $("pw-old").value, newPw = $("pw-new").value;
  status.className = "status";
  if (!oldPw || !newPw) return (status.textContent = "Fill in all fields.");
  if (newPw !== $("pw-confirm").value) return (status.textContent = "New passwords do not match.");
  $("pw-btn").disabled = true;
  status.textContent = "Changing password…";
  try {
    const res = await api("/api/change_password", { old: oldPw, new: newPw });
    if (res.ok) {
      status.textContent = "Password changed. Your private key is now encrypted with the new password.";
      status.className = "status ok";
      for (const id of ["pw-old", "pw-new", "pw-confirm"]) $(id).value = "";
      loadSecurityEvents();
    } else {
      status.textContent = res.error;
    }
  } finally {
    $("pw-btn").disabled = false;
  }
}

// ------------------------------------------------------------------ dialogs

function openDialog(id) {
  closeDialogs();
  $("overlay").hidden = false;
  $(id).hidden = false;
}

function closeDialogs() {
  $("overlay").hidden = true;
  for (const d of document.querySelectorAll(".dialog")) d.hidden = true;
}

function showVerify() {
  const c = state.selected && contact(state.selected);
  if (!c) return alert("Select a friend first.");
  $("verify-peer-label").textContent = `${c.name}'s public key fingerprint`;
  $("verify-peer-fp").textContent = c.fingerprint;
  $("verify-peer-fp").className = "fp-box" + (c.changed ? " danger" : "");
  $("verify-my-fp").textContent = state.myFp;
  const note = $("verify-note");
  if (c.changed) {
    note.textContent = "WARNING: this key is different from the one you saw before. It may be an impostor " +
      "(man-in-the-middle). Call or meet the person and compare before trusting.";
    note.className = "dlg-note warn";
  } else {
    note.textContent = "Compare these fingerprints with your friend in person or through another trusted " +
      "channel (a phone call). If they match, nobody is in the middle.";
    note.className = "dlg-note";
  }
  $("verify-trust").hidden = !c.changed;
  $("verify-match").hidden = c.changed || c.verified;
  $("verify-trust").onclick = async () => {
    if (!confirm(`Trust the NEW key for ${c.name}?\n\nOnly do this if you confirmed the fingerprint with them.`)) return;
    await api("/api/trust_contact", { name: c.name });
    closeDialogs();
  };
  $("verify-match").onclick = async () => {
    await api("/api/verify_contact", { name: c.name });
    closeDialogs();
  };
  openDialog("dlg-verify");
}

function showMyKey() {
  $("mykey-label").textContent = `Your public key fingerprint (${state.me})`;
  $("mykey-fp").textContent = state.myFp;
  $("server-fp").textContent = state.serverFp;
  openDialog("dlg-mykey");
}

function appendLog(entry) {
  const li = el("li", entry.level);
  li.append(el("time", "", entry.t), document.createTextNode(entry.text));
  const list = $("log-list");
  list.append(li);
  list.scrollTop = list.scrollHeight;
}

function showLog() {
  $("log-list").replaceChildren();
  state.log.forEach(appendLog);
  openDialog("dlg-log");
}

// ------------------------------------------------------------------ wiring

document.addEventListener("DOMContentLoaded", () => {
  $("auth-form").addEventListener("submit", submitAuth);
  $("auth-switch").onclick = () => setMode(state.mode === "login" ? "register" : "login");
  $("show-pw").onchange = (e) => {
    const type = e.target.checked ? "text" : "password";
    $("password").type = type;
    $("confirm").type = type;
  };
  $("composer").addEventListener("submit", sendMessage);
  $("file-btn").onclick = () => $("file-input").click();
  $("file-input").onchange = sendFile;
  for (const r of document.querySelectorAll('input[name="mode"]')) {
    r.onchange = () => {
      const plain = document.querySelector('input[name="mode"]:checked').value === "plain";
      $("mode-note").textContent = plain
        ? "DEMO ONLY: password and messages travel unencrypted and unsigned. Use test accounts. The server must run with --allow-plain."
        : "End-to-end encrypted, server key pinned.";
      $("mode-note").classList.toggle("plain-warn", plain);
    };
  }
  $("add-friend-form").addEventListener("submit", addFriend);
  $("pw-form").addEventListener("submit", changePassword);
  $("sec-refresh").onclick = loadSecurityEvents;
  $("search").oninput = renderContacts;
  $("btn-logout").onclick = logout;
  $("btn-mykey").onclick = showMyKey;
  $("rail-keys").onclick = showMyKey;
  $("btn-log").onclick = showLog;
  $("rail-log").onclick = showLog;
  $("rail-chat").onclick = () => { setView("chat"); renderMessages(); };
  $("rail-profile").onclick = () => setView("profile");
  $("btn-verify").onclick = showVerify;
  $("announce-close").onclick = () => { $("announce-banner").hidden = true; };
  $("overlay").onclick = closeDialogs;
  for (const b of document.querySelectorAll("[data-close]")) b.onclick = closeDialogs;
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDialogs(); });

  loadState().catch(() => setStatus("Cannot reach the local SecureChat client. Start it with: python client.py"));
  setMode("login");
});
