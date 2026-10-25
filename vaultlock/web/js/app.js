/* VaultLock UI - vanilla ES2020, no build step, no third-party code. */
(() => {
"use strict";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const TOKEN = $('meta[name="vl-token"]').content;
const NATIVE = $('meta[name="vl-native"]').content === "true";
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const icon = (n, c) => window.vlIcon(n, c);
const hydrate = (root = document) => $$("[data-icon]", root).forEach((e) => { e.innerHTML = icon(e.dataset.icon); });

/* ---------------------------------------------------------------- helpers */
function fmtSize(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n.toFixed(0) : n.toFixed(n < 10 ? 2 : 1)) + " " + u[i];
}
const fmtSpeed = (b) => (b > 0 ? fmtSize(b) + "/s" : "--");
function fmtEta(s) {
  if (s == null) return "--";
  s = Math.round(s);
  if (s < 60) return s + " s";
  if (s < 3600) return Math.floor(s / 60) + " min " + (s % 60) + " s";
  return Math.floor(s / 3600) + " h " + Math.floor((s % 3600) / 60) + " min";
}
function extIcon(name, kind) {
  if (kind === "dir") return "folder";
  const e = (name.split(".").pop() || "").toLowerCase();
  if (e === "vault") return "shield-lock";
  if (["png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "avif", "heic"].includes(e)) return "image";
  if (["mp4", "mkv", "mov", "avi", "webm", "m4v"].includes(e)) return "film";
  if (["mp3", "wav", "flac", "ogg", "m4a", "aac"].includes(e)) return "music";
  if (["zip", "7z", "rar", "tar", "gz", "bz2", "xz"].includes(e)) return "archive";
  if (["py", "js", "ts", "json", "html", "css", "c", "cpp", "rs", "go", "java", "sh", "yml", "yaml", "toml"].includes(e)) return "code";
  if (["txt", "md", "pdf", "doc", "docx", "rtf", "csv", "log"].includes(e)) return "file-text";
  return "file";
}

async function api(method, path, body) {
  const opt = { method, headers: { "X-VL-Token": TOKEN } };
  if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  let res;
  try { res = await fetch(path, opt); } catch { throw { code: "offline", message: "Lost connection to the VaultLock engine." }; }
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON */ }
  if (!res.ok) throw data && data.error ? data.error : { code: "http", message: "Request failed (" + res.status + ")." };
  return data;
}

/* ------------------------------------------------------------------ state */
const state = {
  mode: "lock",
  lists: { lock: [], unlock: [], shred: [] },
  settings: {},
  info: {},
  keyfile: "",
  out: "",
  passes: 3,
  job: null,
  busy: false,
  nextId: 1,
};
const list = () => state.lists[state.mode];

/* ------------------------------------------------------------ sound/haptic */
let actx = null;
function beep(freqs, dur = 0.12, type = "sine", vol = 0.06) {
  if (!state.settings.sounds) return;
  try {
    actx = actx || new (window.AudioContext || window.webkitAudioContext)();
    let t = actx.currentTime;
    freqs.forEach((f) => {
      const o = actx.createOscillator(), g = actx.createGain();
      o.type = type; o.frequency.value = f;
      g.gain.setValueAtTime(0.0001, t); g.gain.exponentialRampToValueAtTime(vol, t + 0.015); g.gain.exponentialRampToValueAtTime(0.0001, t + dur);
      o.connect(g).connect(actx.destination); o.start(t); o.stop(t + dur + 0.02);
      t += dur * 0.8;
    });
  } catch { /* audio unavailable */ }
}
const sfx = {
  ok: () => beep([523.25, 659.25, 783.99], 0.14),
  bad: () => beep([196, 147], 0.2, "sawtooth", 0.04),
  tick: () => beep([880], 0.04, "sine", 0.025),
};
function haptic(pattern) {
  if (state.settings.haptics && navigator.vibrate) { try { navigator.vibrate(pattern); } catch { /* ignore */ } }
}

/* ------------------------------------------------------------------ toasts */
function toast(msg, kind = "ok", ms = 4200, extra) {
  const t = document.createElement("div");
  t.className = "toast " + kind;
  t.innerHTML = icon(kind === "ok" ? "check" : kind === "bad" ? "alert" : "info") + "<div>" + esc(msg) + "</div>";
  if (extra) t.append(extra);
  $("#toasts").append(t);
  setTimeout(() => t.remove(), ms);
}

/* ------------------------------------------------------------------- modal */
function modal({ title, body, wide, buttons = [], note }) {
  const back = document.createElement("div");
  back.className = "modal-back";
  const m = document.createElement("div");
  m.className = "modal glass" + (wide ? " wide" : "");
  m.setAttribute("role", "dialog"); m.setAttribute("aria-modal", "true"); m.setAttribute("aria-label", title);
  m.innerHTML = '<header><h2>' + esc(title) + '</h2><button class="icon-btn sm" data-x aria-label="Close">' + icon("x") + '</button></header><div class="body"></div><footer></footer>';
  const bodyEl = $(".body", m);
  if (typeof body === "string") bodyEl.innerHTML = body; else if (body) bodyEl.append(body);
  const foot = $("footer", m);
  if (note) foot.insertAdjacentHTML("beforeend", '<span class="grow">' + esc(note) + "</span>");
  const api_ = { el: m, body: bodyEl, close() { back.remove(); document.removeEventListener("keydown", onKey); api_.onClose && api_.onClose(); }, buttons: {} };
  buttons.forEach((b) => {
    const el = document.createElement("button");
    el.className = b.primary ? "btn-primary" + (b.danger ? " btn-danger" : "") : "ghost";
    el.textContent = b.label;
    el.onclick = () => b.onClick ? b.onClick(api_) : api_.close();
    foot.append(el); api_.buttons[b.id || b.label] = el;
  });
  $("[data-x]", m).onclick = () => api_.close();
  const onKey = (e) => { if (e.key === "Escape" && back.parentNode && $("#modalRoot").lastElementChild === back) api_.close(); };
  document.addEventListener("keydown", onKey);
  back.addEventListener("mousedown", (e) => { if (e.target === back) api_.close(); });
  back.append(m); $("#modalRoot").append(back);
  const first = $("input, button.btn-primary", m); if (first) setTimeout(() => first.focus(), 30);
  return api_;
}
function confirmBox({ title, text, ok = "Continue", danger = false }) {
  return new Promise((res) => {
    let done = false;
    const m = modal({
      title, body: '<p style="margin:0;line-height:1.6">' + text + "</p>",
      buttons: [
        { label: "Cancel", onClick: (mm) => { done = true; mm.close(); res(false); } },
        { label: ok, primary: true, danger, onClick: (mm) => { done = true; mm.close(); res(true); } },
      ],
    });
    m.onClose = () => { if (!done) res(false); };
  });
}

/* ------------------------------------------------------------ file browser */
/* mode: items (files+folders) | files | folder | file */
function browse({ title, mode = "items", multiple = true, exts = null, start = "" }) {
  return new Promise(async (resolve) => {
    const sel = new Map();
    let cur = null, hidden = !!state.settings.show_hidden_files, resolved = false;
    const wrap = document.createElement("div");
    wrap.innerHTML = '<div class="fb"><div class="side"></div><div><div class="crumbs"></div><div class="list" tabindex="0"></div><div class="newdir" hidden><input type="text" placeholder="New folder name"><button class="ghost sm">Create</button></div></div></div>';
    const side = $(".side", wrap), crumbs = $(".crumbs", wrap), listEl = $(".list", wrap), newdir = $(".newdir", wrap);
    const buttons = [{ label: "Cancel", onClick: (m) => m.close() }];
    if (mode === "folder") buttons.splice(0, 0, { label: "New folder", onClick: () => { newdir.hidden = !newdir.hidden; $("input", newdir).focus(); } });
    buttons.push({ id: "ok", label: "Select", primary: true, onClick: (m) => { resolved = true; resolve(mode === "folder" && !sel.size ? [cur.path] : [...sel.keys()]); m.close(); } });
    const m = modal({ title, body: wrap, wide: true, buttons, note: "" });
    m.onClose = () => { if (!resolved) resolve(null); };
    const okBtn = m.buttons.ok;
    const refreshOk = () => {
      const n = sel.size;
      okBtn.disabled = mode === "folder" ? false : n === 0;
      okBtn.textContent = mode === "folder" ? (n ? "Select folder" : "Use this folder") : n > 1 ? "Select " + n + " items" : "Select";
    };
    const selectable = (e) => (mode === "items") || (mode === "folder" && e.kind === "dir") || ((mode === "files" || mode === "file") && e.kind === "file" && (!exts || exts.some((x) => e.name.toLowerCase().endsWith(x))));
    async function go(path) {
      try {
        const data = await api("GET", "/api/fs/list?path=" + encodeURIComponent(path || "") + (hidden ? "&hidden=1" : ""));
        cur = data; sel.clear(); render();
      } catch (e) { toast(e.message, "bad"); }
    }
    function render() {
      crumbs.innerHTML = "";
      cur.breadcrumbs.slice(-6).forEach((c, i, a) => {
        const b = document.createElement("button"); b.textContent = c.name; b.onclick = () => go(c.path); crumbs.append(b);
        if (i < a.length - 1) crumbs.insertAdjacentHTML("beforeend", icon("chevron-right"));
      });
      listEl.innerHTML = "";
      if (cur.parent) {
        const up = document.createElement("div"); up.className = "row"; up.innerHTML = icon("arrow-up") + '<span class="nm">Parent folder</span><small></small>'; up.onclick = () => go(cur.parent); listEl.append(up);
      }
      cur.entries.forEach((e) => {
        const ok = selectable(e), nav = e.kind === "dir";
        const row = document.createElement("div");
        row.className = "row" + (!ok && !nav ? " disabled" : "");
        row.innerHTML = icon(extIcon(e.name, e.kind)) + '<span class="nm">' + esc(e.name) + "</span><small>" + (nav ? icon("chevron-right") : fmtSize(e.size)) + "</small>";
        row.onclick = (ev) => {
          if (nav && (!ok || ev.target.closest("small"))) return go(e.path);
          if (!ok) return;
          if (!multiple || mode === "file" || mode === "folder") sel.clear();
          if (sel.has(e.path) && multiple) sel.delete(e.path); else sel.set(e.path, e);
          markSel(); refreshOk();
        };
        row.ondblclick = () => { if (nav) go(e.path); else if (ok && !multiple) { sel.clear(); sel.set(e.path, e); okBtn.click(); } };
        row.dataset.path = e.path;
        listEl.append(row);
      });
      markSel(); refreshOk();
      if (!cur.entries.length) listEl.insertAdjacentHTML("beforeend", '<p class="hint" style="padding:14px">This folder is empty.</p>');
    }
    function markSel() { $$(".row[data-path]", listEl).forEach((r) => r.classList.toggle("sel", sel.has(r.dataset.path))); }
    $("button", newdir).onclick = async () => {
      try { const r = await api("POST", "/api/fs/mkdir", { parent: cur.path, name: $("input", newdir).value }); newdir.hidden = true; $("input", newdir).value = ""; go(cur.path); } catch (e) { toast(e.message, "bad"); }
    };
    try {
      const roots = (await api("GET", "/api/fs/roots")).roots;
      roots.forEach((r) => { const b = document.createElement("button"); b.innerHTML = icon(r.icon) + "<span>" + esc(r.name) + "</span>"; b.onclick = () => go(r.path); side.append(b); });
      go(start || (roots.find((r) => r.name === "Downloads") || roots[0]).path);
    } catch (e) { toast(e.message, "bad"); }
  });
}

async function nativeOrBrowse(opts) {
  if (NATIVE) {
    try { const r = await api("POST", "/api/native/pick", { mode: opts.mode === "folder" ? "folder" : "files" }); return r.paths.length ? r.paths : null; }
    catch { /* fall through to the in-app browser */ }
  }
  return browse(opts);
}

/* ------------------------------------------------------------- list / cards */
function addItem(it) {
  it.id = state.nextId++; it.status = "ready"; it.progress = 0; it.notes = [];
  list().push(it); render();
}
async function addPaths(paths) {
  if (!paths || !paths.length) return;
  const { items } = await api("POST", "/api/stat", { paths });
  const skipped = paths.length - items.length;
  items.forEach((s) => {
    if (list().some((x) => x.path === s.path)) return;
    addItem({ path: s.path, name: s.name, kind: s.kind, size: s.size, count: s.count, vault: s.vault });
  });
  if (skipped) toast(skipped + " item(s) couldn't be read.", "warn");
  if (state.mode === "unlock") inspectVaults();
}
function upload(file, item) {
  return new Promise((resolve) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/upload");
    xhr.setRequestHeader("X-VL-Token", TOKEN);
    xhr.setRequestHeader("X-File-Name", encodeURIComponent(file.name));
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) { item.progress = (e.loaded / e.total) * 100; item.status = "uploading"; renderCard(item); } };
    xhr.onload = () => {
      try {
        const r = JSON.parse(xhr.responseText);
        if (xhr.status !== 200) throw r.error || {};
        item.staged = r.staged; item.status = "ready"; item.progress = 0; item.vault = r.vault;
      } catch (e) { item.status = "failed"; item.error = (e && e.message) || "Upload failed."; }
      renderCard(item); resolve();
    };
    xhr.onerror = () => { item.status = "failed"; item.error = "Upload failed."; renderCard(item); resolve(); };
    xhr.send(file);
  });
}
async function addBrowserFiles(files) {
  for (const f of files) {
    if (f.pywebviewFullPath) { await addPaths([f.pywebviewFullPath]); continue; }
    const it = { name: f.name, size: f.size, kind: "file", vault: f.name.toLowerCase().endsWith(".vault"), status: "uploading" };
    addItem(it); await upload(f, it);
  }
  if (state.mode === "unlock") inspectVaults();
}

async function inspectVaults() {
  const todo = list().filter((i) => i.vault && !i.info && (i.path || i.staged));
  if (!todo.length) return;
  try {
    const r = await api("POST", "/api/inspect", { files: todo.map((i) => (i.staged ? { staged: i.staged } : { path: i.path })) });
    r.vaults.forEach((v, idx) => { todo[idx].info = v; });
    if (r.vaults.some((v) => v.ok && v.uses_keyfile)) { $("#useKey").checked = true; syncKeyBox(); }
    render();
  } catch { /* non-fatal */ }
}

function cardHTML(it) {
  const badges = [];
  if (it.kind === "dir") badges.push('<span class="badge">' + icon("folder") + (it.count != null ? it.count + " files" : "folder") + "</span>");
  if (state.mode === "unlock" || it.vault) {
    if (it.info && it.info.ok) {
      badges.push('<span class="badge ok">' + icon("shield-lock") + esc(it.info.cipher) + "</span>");
      badges.push('<span class="badge">' + esc(it.info.kdf_description.split(" (")[0]) + "</span>");
      if (it.info.uses_keyfile) badges.push('<span class="badge run">' + icon("key") + "needs keyfile</span>");
    } else if (it.info && !it.info.ok) badges.push('<span class="badge bad">' + icon("alert") + "not a vault</span>");
  }
  if (it.status === "uploading") badges.push('<span class="badge run">uploading ' + Math.round(it.progress) + "%</span>");
  if (it.status === "running") badges.push('<span class="badge run">' + esc(it.phase || "working") + "</span>");
  if (it.status === "done") badges.push('<span class="badge ok">' + icon("check") + (it.shredded ? "locked and shredded" : state.mode === "lock" ? "locked" : state.mode === "unlock" ? "unlocked" : "shredded") + "</span>");
  if (it.status === "failed") badges.push('<span class="badge bad">' + icon("alert") + "failed</span>");
  if (it.status === "cancelled") badges.push('<span class="badge">cancelled</span>');
  const acts = [];
  if (state.mode === "unlock" && it.vault && it.status !== "running") acts.push('<button class="icon-btn sm" data-a="preview" title="Preview without saving">' + icon("eye") + "</button>");
  if (it.status === "done" && it.output) acts.push('<button class="icon-btn sm" data-a="reveal" title="Show in folder">' + icon("reveal") + "</button>");
  if (!state.busy) acts.push('<button class="icon-btn sm" data-a="remove" title="Remove">' + icon("x") + "</button>");
  const notes = (it.notes || []).map((n) => '<div class="note">' + esc(n) + "</div>").join("") + (it.error ? '<div class="note err">' + esc(it.error) + "</div>" : "") + (it.out_name ? '<div class="note">Saved as <b>' + esc(it.out_name) + "</b></div>" : "");
  return '<div class="ficon">' + icon(extIcon(it.name, it.kind)) + '</div><div class="meta"><div class="name" title="' + esc(it.path || it.name) + '">' + esc(it.name) + '</div><div class="sub"><span>' + (it.kind === "dir" ? fmtSize(it.size) : fmtSize(it.size)) + "</span>" + badges.join("") + '</div></div><div class="acts">' + acts.join("") + "</div>" + notes + '<i class="bar" style="width:' + (it.progress || 0) + '%"></i>';
}
function renderCard(it) {
  const el = $('[data-id="' + it.id + '"]');
  if (!el) return render();
  el.className = "card" + (it.vault ? " is-vault" : "") + (it.status === "done" ? " done" : "") + (it.status === "failed" ? " failed" : "");
  el.innerHTML = cardHTML(it);
}
function render() {
  const ul = $("#files"); ul.innerHTML = "";
  list().forEach((it) => {
    const li = document.createElement("li");
    li.dataset.id = it.id;
    li.className = "card" + (it.vault ? " is-vault" : "") + (it.status === "done" ? " done" : "") + (it.status === "failed" ? " failed" : "");
    li.innerHTML = cardHTML(it);
    ul.append(li);
  });
  $("#empty").hidden = list().length > 0;
  $("#clearList").hidden = list().length < 2 || state.busy;
  updateGo();
}
$("#files").addEventListener("click", async (e) => {
  const b = e.target.closest("[data-a]"); if (!b) return;
  const it = list().find((x) => x.id === +b.closest("li").dataset.id); if (!it) return;
  if (b.dataset.a === "remove") {
    if (it.staged) api("DELETE", "/api/upload/" + it.staged).catch(() => {});
    state.lists[state.mode] = list().filter((x) => x !== it); render();
  } else if (b.dataset.a === "reveal") api("POST", "/api/reveal", { path: it.output }).catch((er) => toast(er.message, "bad"));
  else if (b.dataset.a === "preview") openPreview(it);
});
$("#clearList").onclick = () => { list().forEach((i) => i.staged && api("DELETE", "/api/upload/" + i.staged).catch(() => {})); state.lists[state.mode] = []; render(); resetDial(); };

/* -------------------------------------------------------------------- dial */
const dial = $("#dial"), arc = $("#arc");
(function buildTicks() {
  const g = $("#ticks"); const ns = "http://www.w3.org/2000/svg";
  for (let i = 0; i < 72; i++) {
    const major = i % 6 === 0, a = (i / 72) * Math.PI * 2, r1 = major ? 140 : 142, r2 = 152;
    const l = document.createElementNS(ns, "line");
    l.setAttribute("x1", 160 + Math.cos(a) * r1); l.setAttribute("y1", 160 + Math.sin(a) * r1);
    l.setAttribute("x2", 160 + Math.cos(a) * r2); l.setAttribute("y2", 160 + Math.sin(a) * r2);
    l.setAttribute("class", "tick" + (major ? " major" : "")); l.dataset.i = i; g.append(l);
  }
})();
const MODE_TEXT = {
  lock: { icon: "lock", title: "Drop files to lock", sub: "or click to browse", go: "Lock", goIcon: "lock" },
  unlock: { icon: "unlock", title: "Drop vaults to unlock", sub: "or click to browse", go: "Unlock", goIcon: "unlock" },
  shred: { icon: "flame", title: "Drop files to shred", sub: "destroyed beyond recovery", go: "Shred permanently", goIcon: "flame" },
};
function setDial({ ic, title, sub, cls = "", pct = 0 }) {
  dial.classList.remove("done", "fail", "busy"); if (cls) dial.classList.add(...cls.split(" "));
  $("#dialIcon").innerHTML = icon(ic); $("#dialTitle").textContent = title; $("#dialSub").textContent = sub;
  arc.style.strokeDashoffset = 100 - pct;
  const lit = Math.round((pct / 100) * 72);
  $$(".tick", $("#ticks")).forEach((t) => t.classList.toggle("lit", +t.dataset.i < lit));
}
function resetDial() { const t = MODE_TEXT[state.mode]; setDial({ ic: t.icon, title: t.title, sub: t.sub }); }
let lastTickPct = 0;
function dialProgress(snap) {
  const o = snap.overall, p = o.percent;
  setDial({ ic: MODE_TEXT[state.mode].icon, title: Math.floor(p) + "%", sub: (snap.current && snap.current.phase) || snap.phase, cls: "busy", pct: p });
  if (Math.floor(p / 10) !== Math.floor(lastTickPct / 10)) sfx.tick();
  lastTickPct = p;
}
dial.addEventListener("click", () => { if (!state.busy) pickItems(); });
dial.addEventListener("keydown", (e) => { if ((e.key === "Enter" || e.key === " ") && !state.busy) { e.preventDefault(); pickItems(); } });

/* ----------------------------------------------------------------- picking */
async function pickItems(folder = false) {
  const unlock = state.mode === "unlock";
  const res = await nativeOrBrowse({
    title: folder ? "Choose a folder" : unlock ? "Choose vaults to unlock" : state.mode === "shred" ? "Choose what to shred" : "Choose files or folders to lock",
    mode: folder ? "folder" : unlock ? "files" : "items", exts: unlock ? [".vault"] : null, multiple: !folder || true,
  });
  if (res) addPaths(res).catch((e) => toast(e.message, "bad"));
}
$("#addFiles").onclick = () => pickItems(false);
$("#addFolder").onclick = () => pickItems(true);

/* drag and drop */
let dragDepth = 0;
const hasFiles = (e) => e.dataTransfer && [...e.dataTransfer.types].includes("Files");
window.addEventListener("dragenter", (e) => { if (!hasFiles(e)) return; e.preventDefault(); dragDepth++; $("#veil").hidden = false; dial.classList.add("over"); });
window.addEventListener("dragover", (e) => { if (hasFiles(e)) e.preventDefault(); });
window.addEventListener("dragleave", () => { if (--dragDepth <= 0) { dragDepth = 0; $("#veil").hidden = true; dial.classList.remove("over"); } });
window.addEventListener("drop", async (e) => {
  if (!hasFiles(e)) return;
  e.preventDefault(); dragDepth = 0; $("#veil").hidden = true; dial.classList.remove("over");
  if (state.busy) return toast("Wait for the current job to finish.", "warn");
  const files = [], entries = [...e.dataTransfer.items].map((i) => (i.webkitGetAsEntry ? i.webkitGetAsEntry() : null));
  let folders = 0;
  [...e.dataTransfer.files].forEach((f, i) => { if (entries[i] && entries[i].isDirectory && !f.pywebviewFullPath) folders++; else files.push(f); });
  if (folders) toast("Browsers can't hand over whole folders. Use Add folder instead.", "warn", 6000);
  if (files.length && files.every((f) => f.name.toLowerCase().endsWith(".vault")) && state.mode === "lock") setMode("unlock");
  await addBrowserFiles(files);
});

/* ------------------------------------------------------------------- modes */
function setMode(mode) {
  if (state.busy) return;
  state.mode = mode; document.body.dataset.mode = mode;
  $$(".modes button").forEach((b) => { b.classList.toggle("on", b.dataset.mode === mode); b.setAttribute("aria-selected", b.dataset.mode === mode); });
  const nav = $(".modes"); nav.dataset.mode = mode;
  const on = $(".modes button.on"), s = $(".slider", nav);
  s.style.width = on.offsetWidth + "px"; s.style.transform = "translateX(" + (on.offsetLeft - 4) + "px)";
  $("#credPanel h2").textContent = mode === "lock" ? "Lock with" : "Unlock with";
  $("#pw").placeholder = mode === "lock" ? "Choose a strong password" : "Enter the vault password";
  const t = MODE_TEXT[mode]; $("#goText").textContent = t.go; $("#go").firstElementChild.innerHTML = icon(t.goIcon); $("#go").classList.toggle("shred", mode === "shred");
  $("#addFolder").hidden = mode === "unlock";
  $("#genPw").hidden = mode !== "lock";
  updateOutName(); resetDial(); render(); updateStrength();
  if (mode === "unlock") inspectVaults();
}
$$(".modes button").forEach((b) => (b.onclick = () => setMode(b.dataset.mode)));
window.addEventListener("resize", () => setMode(state.mode));

/* -------------------------------------------------------------- credentials */
const pw = $("#pw"), pw2 = $("#pw2");
$("#togglePw").onclick = () => { const show = pw.type === "password"; pw.type = pw2.type = show ? "text" : "password"; $("#togglePw").innerHTML = icon(show ? "eye-off" : "eye"); };
let strTimer = null, strSeq = 0;
function updateStrength() {
  clearTimeout(strTimer);
  if (state.mode !== "lock") return;
  const v = pw.value, seq = ++strSeq;
  if (!v) { $("#meter").dataset.s = ""; $("#strLabel").textContent = "Type a password"; $("#strCrack").textContent = ""; $("#strHint").textContent = ""; return; }
  strTimer = setTimeout(async () => {
    try {
      const r = await api("POST", "/api/strength", { password: v });
      if (seq !== strSeq) return;
      $("#meter").dataset.s = r.score; $("#strLabel").textContent = r.label + " (" + Math.round(r.entropy_bits) + " bits)";
      $("#strCrack").textContent = "Cracked in " + r.crack_time;
      $("#strHint").textContent = r.warning || r.suggestions[0] || "";
    } catch { /* ignore */ }
  }, 120);
}
pw.addEventListener("input", () => { updateStrength(); checkMatch(); updateGo(); });
pw2.addEventListener("input", () => { checkMatch(); updateGo(); });
function checkMatch() { pw2.classList.toggle("mismatch", !!pw2.value && pw.value !== pw2.value); }
pw.addEventListener("keydown", (e) => { if (e.key === "Enter" && state.mode === "unlock") go(); });
pw2.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });

$("#genPw").onclick = async () => {
  try {
    const r = await api("POST", "/api/generate", { kind: "passphrase", words: 6 });
    pw.value = pw2.value = r.value; pw.type = pw2.type = "text"; $("#togglePw").innerHTML = icon("eye-off");
    updateStrength(); checkMatch(); updateGo();
    const b = document.createElement("button"); b.className = "ghost sm"; b.style.marginLeft = "auto"; b.innerHTML = icon("copy") + "Copy";
    b.onclick = () => navigator.clipboard.writeText(r.value).then(() => { b.textContent = "Copied"; setTimeout(() => navigator.clipboard.writeText(" ").catch(() => {}), 30000); }).catch(() => toast("Copy failed. Select the text instead.", "warn"));
    toast("New passphrase created. Save it somewhere safe now: it can't be recovered.", "warn", 9000, b);
  } catch (e) { toast(e.message, "bad"); }
};

function syncKeyBox() { $("#keyBox").hidden = !$("#useKey").checked; updateGo(); }
$("#useKey").onchange = syncKeyBox;
function setKeyfile(p) { state.keyfile = p || ""; $("#keyName").textContent = p ? p.split(/[\\/]/).pop() : "No keyfile chosen"; updateGo(); }
$("#pickKey").onclick = async () => {
  const r = await nativeOrBrowse({ title: "Choose your keyfile", mode: "file", multiple: false });
  if (r && r[0]) setKeyfile(r[0]);
};
$("#makeKey").onclick = async () => {
  const body = document.createElement("div");
  body.innerHTML = '<label class="field"><span>File name</span><input type="text" id="kfName" value="vaultlock.key"></label><div class="outrow"><div class="outname" id="kfDir">Choose a folder</div><button class="ghost sm" id="kfPick">Choose folder</button></div><p class="hint warn">Store a copy somewhere offline (a USB stick, a safe). Without this file, vaults locked with it can never be opened.</p>';
  let dir = "";
  const m = modal({ title: "Create a keyfile", body, buttons: [
    { label: "Cancel" },
    { id: "mk", label: "Create keyfile", primary: true, onClick: async (mm) => {
      if (!dir) return toast("Choose a folder first.", "warn");
      const sep = dir.includes("\\") ? "\\" : "/";
      try {
        const r = await api("POST", "/api/keyfile/generate", { path: dir.replace(/[\\/]$/, "") + sep + $("#kfName", body).value });
        setKeyfile(r.path); $("#useKey").checked = true; syncKeyBox(); mm.close();
        toast("Keyfile created (fingerprint " + r.fingerprint + "). Back it up.", "ok", 8000);
      } catch (e) { toast(e.message, "bad"); }
    } },
  ] });
  $("#kfPick", body).onclick = async () => { const r = await nativeOrBrowse({ title: "Where should the keyfile be saved?", mode: "folder", multiple: false }); if (r && r[0]) { dir = r[0]; $("#kfDir", body).textContent = dir; } };
};

/* ------------------------------------------------------------------ options */
$("#oShred").onchange = () => { $("#shredNote").hidden = !$("#oShred").checked; if ($("#oShred").checked) $("#oVerify").checked = true; };
$$("#passSeg button").forEach((b) => (b.onclick = () => { state.passes = +b.dataset.p; $$("#passSeg button").forEach((x) => x.classList.toggle("on", x === b)); }));
function updateOutName() {
  $("#outName").textContent = state.out || "Next to the original";
  $("#outName").title = state.out;
}
$("#pickOut").onclick = async () => {
  const r = await nativeOrBrowse({ title: "Choose where results are saved", mode: "folder", multiple: false });
  if (r && r[0]) { state.out = r[0]; updateOutName(); }
};
function renderChips() {
  const s = state.settings, prof = (state.info.profiles || {})[s.profile] || s.profile;
  const chips = [prof, s.cipher === "aes-256-gcm" ? "AES-256-GCM" : "ChaCha20-Poly1305"];
  if (s.compress) chips.push("compressed");
  if (s.obfuscate_names) chips.push("random file names");
  $("#chips").innerHTML = chips.map((c) => '<button class="chip" data-s>' + esc(c) + "</button>").join("");
  $$("#chips .chip").forEach((c) => (c.onclick = openSettings));
}

/* ----------------------------------------------------------------- run job */
function updateGo() {
  const n = list().length;
  const ready = list().every((i) => i.status !== "uploading");
  let ok = n > 0 && ready && !state.busy;
  if (state.mode === "lock") ok = ok && pw.value.length > 0 && pw.value === pw2.value && (!$("#useKey").checked || !!state.keyfile);
  if (state.mode === "unlock") ok = ok && pw.value.length > 0 && (!$("#useKey").checked || !!state.keyfile);
  $("#go").disabled = !ok;
}
function showError(msg) { const e = $("#formError"); e.textContent = msg || ""; e.hidden = !msg; }
const srcOf = (i) => (i.staged ? { staged: i.staged } : { path: i.path });

async function go(allowWeak = false) {
  if (state.busy || $("#go").disabled) return;
  showError("");
  const L = list(), mode = state.mode;
  const options = { output_dir: state.out || undefined, shred_passes: state.passes };
  let path = "/api/" + (mode === "lock" ? "encrypt" : mode === "unlock" ? "decrypt" : "shred");
  const body = { files: L.map(srcOf), options };
  if (mode !== "shred") {
    body.password = pw.value; body.keyfile = $("#useKey").checked ? state.keyfile : null;
  }
  if (mode === "lock") {
    Object.assign(options, { bundle: $("#oBundle").checked && L.length > 1, verify: $("#oVerify").checked, shred: $("#oShred").checked });
    if (options.bundle) options.bundle_name = "Bundle";
    if (allowWeak) body.allow_weak = true;
    if (options.shred && !(await confirmBox({ title: "Shred the originals?", text: "After your vault is written and fully re-checked, the original " + (L.length > 1 ? "files and folders" : "file or folder") + " will be overwritten " + state.passes + " time(s) and deleted. This cannot be undone.", ok: "Lock and shred", danger: true }))) return;
  }
  if (mode === "unlock") options.remove_vault_after = $("#oRemove").checked, options.overwrite = false;
  if (mode === "shred") {
    if (!(await confirmBox({ title: "Destroy " + L.length + " item(s) forever?", text: "Everything selected will be overwritten " + state.passes + " time(s) and deleted. There is no recycle bin and no undo. On SSDs and cloud-synced folders, overwriting may not reach every copy.", ok: "Shred permanently", danger: true }))) return;
    body.confirm = true;
  }
  try {
    const r = await api("POST", path, body);
    startWatching(r.job, mode);
  } catch (e) {
    if (e.code === "weak_password") {
      if (await confirmBox({ title: "This password is weak", text: "It could be guessed quickly. Use it anyway?", ok: "Use anyway" })) return go(true);
      pw.focus(); return;
    }
    if (e.code === "missing_credentials") { $("#useKey").checked = true; syncKeyBox(); }
    showError(e.message); sfx.bad(); haptic([60]); shake();
  }
}
$("#go").onclick = () => go();
const shake = () => { dial.classList.remove("shake"); void dial.offsetWidth; dial.classList.add("shake"); };

function setBusy(b) {
  state.busy = b; document.body.classList.toggle("busy", b);
  $("#live").hidden = !b; $("#adders").style.opacity = b ? 0.4 : 1; $("#adders").style.pointerEvents = b ? "none" : "";
  $$(".modes button").forEach((x) => (x.disabled = b));
  $("#go").disabled = b || $("#go").disabled; if (!b) updateGo();
}
async function startWatching(jobId, mode) {
  state.job = jobId; setBusy(true); lastTickPct = 0;
  list().forEach((i) => { i.status = "running"; i.progress = 0; i.error = null; i.notes = []; });
  render(); setDial({ ic: MODE_TEXT[mode].icon, title: "0%", sub: "starting", cls: "busy" });
  let snap;
  while (true) {
    try { snap = await api("GET", "/api/jobs/" + jobId); } catch (e) { toast(e.message, "bad"); break; }
    applySnapshot(snap);
    if (["done", "failed", "cancelled"].includes(snap.status)) break;
    await new Promise((r) => setTimeout(r, 140));
  }
  setBusy(false); state.job = null;
  if (snap) finish(snap, mode);
}
function applySnapshot(snap) {
  dialProgress(snap);
  $("#liveSpeed").textContent = fmtSpeed(snap.overall.speed_bps); $("#liveEta").textContent = fmtEta(snap.overall.eta_s); $("#livePhase").textContent = (snap.current && snap.current.phase) || snap.phase;
  const L = list(), shared = snap.items.length === 1 && L.length > 1;
  L.forEach((it, idx) => {
    const s = shared ? snap.items[0] : snap.items[idx]; if (!s) return;
    it.progress = s.percent; it.phase = s.phase; it.status = s.status === "pending" ? "running" : s.status;
    const el = $('[data-id="' + it.id + '"] .bar'); if (el) el.style.width = s.percent + "%";
    const badge = $('[data-id="' + it.id + '"] .badge.run'); if (badge) badge.textContent = s.phase;
  });
}
function finish(snap, mode) {
  const L = list(), shared = snap.items.length === 1 && L.length > 1;
  L.forEach((it, idx) => {
    const s = shared ? snap.items[0] : snap.items[idx]; if (!s) return;
    it.status = s.status; it.progress = s.status === "done" ? 100 : it.progress; it.notes = s.notes; it.output = s.output; it.shredded = s.shredded;
    it.out_name = s.result_name; it.error = s.error ? s.error.message : null; it.phase = s.phase;
    if (s.error && s.error.code === "missing_credentials") { $("#useKey").checked = true; syncKeyBox(); }
  });
  render();
  const sm = snap.summary, ok = sm.ok, bad = sm.failed;
  if (snap.status === "cancelled") { setDial({ ic: "x", title: "Cancelled", sub: "nothing was changed", pct: 0 }); toast("Cancelled. No partial files were kept.", "warn"); sfx.bad(); }
  else if (ok && !bad) {
    setDial({ ic: "check", title: "Done", sub: ok + (ok === 1 ? " item" : " items") + " " + (mode === "lock" ? "locked" : mode === "unlock" ? "unlocked" : "shredded") + " in " + snap.elapsed.toFixed(1) + " s", cls: "done", pct: 100 });
    sfx.ok(); haptic([25, 50, 25]); toast(mode === "lock" ? "Locked safely." : mode === "unlock" ? "Unlocked." : "Shredded.", "ok");
  } else if (ok && bad) {
    setDial({ ic: "alert", title: ok + " done, " + bad + " failed", sub: "see the list below", cls: "fail", pct: 100 }); sfx.bad(); haptic([60, 40, 60]);
  } else {
    const first = snap.items.find((i) => i.error);
    setDial({ ic: "alert", title: "Couldn't finish", sub: first ? first.error.message : "see the list below", cls: "fail" }); sfx.bad(); haptic([80]); shake();
    if (first) showError(first.error.message);
  }
  if (mode === "lock") { pw2.value = ""; checkMatch(); updateGo(); }
  setTimeout(() => { if (!state.busy && (dial.classList.contains("done"))) resetDial(); }, 9000);
}
$("#btnCancel").onclick = () => { if (state.job) api("POST", "/api/jobs/" + state.job + "/cancel").catch(() => {}); $("#btnCancel").disabled = true; setTimeout(() => ($("#btnCancel").disabled = false), 2000); };

/* ------------------------------------------------------------ secure viewer */
async function openPreview(it, entry) {
  if (!pw.value) { pw.focus(); return showError("Enter the password first; the preview is decrypted in memory only."); }
  showError("");
  const body = { files: [srcOf(it)], password: pw.value, keyfile: $("#useKey").checked ? state.keyfile : null };
  try {
    if (!entry) {
      const l = await api("POST", "/api/vault/list", body);
      if (l.meta.kind !== "file") return openTree(it, l);
    }
    const r = await api("POST", "/api/vault/preview", Object.assign({ entry: entry || undefined }, body));
    showViewer(r);
  } catch (e) {
    if (e.code === "missing_credentials") { $("#useKey").checked = true; syncKeyBox(); }
    toast(e.message, "bad", 6000); sfx.bad();
  }
}
function openTree(it, l) {
  const box = document.createElement("div");
  box.innerHTML = '<div class="banner">' + icon("shield-lock") + "Contents read in memory. Nothing was extracted.</div>";
  const tree = document.createElement("div"); tree.className = "tree";
  l.entries.forEach((e) => {
    const b = document.createElement("button");
    b.innerHTML = icon(extIcon(e.name, e.dir ? "dir" : "file")) + "<span>" + esc(e.name) + "</span><small>" + (e.dir ? "" : fmtSize(e.size)) + "</small>";
    if (e.dir) b.disabled = true; else b.onclick = () => openPreview(it, e.name);
    tree.append(b);
  });
  box.append(tree);
  modal({ title: (l.meta.name || "Vault") + " (" + l.entries.length + " entries)", body: box, wide: true, buttons: [{ label: "Close" }] });
}
async function showViewer(r) {
  const body = document.createElement("div");
  body.innerHTML = '<div class="banner">' + icon("shield-lock") + "Decrypted in memory only. Nothing is written to disk, and it disappears when you close this window.</div><div class='viewer'></div>";
  const v = $(".viewer", body); let blobUrl = null;
  try {
    const res = await fetch("/api/preview/" + r.id, { headers: { "X-VL-Token": TOKEN } });
    if (!res.ok) throw new Error("Preview expired.");
    const buf = await res.arrayBuffer();
    if (r.category === "text") { const pre = document.createElement("pre"); pre.textContent = new TextDecoder("utf-8", { fatal: false }).decode(buf).slice(0, 2_000_000); v.append(pre); }
    else {
      blobUrl = URL.createObjectURL(new Blob([buf], { type: r.mime.split(";")[0] }));
      let el;
      if (r.category === "image") { el = new Image(); el.alt = r.name; }
      else if (r.category === "pdf") el = document.createElement("iframe");
      else { el = document.createElement(r.category); el.controls = true; }
      el.src = blobUrl; v.append(el);
    }
  } catch (e) { v.textContent = e.message || "Could not display this file."; }
  const m = modal({ title: r.name + "  (" + fmtSize(r.size) + ")", body, wide: true, buttons: [{ label: "Close" }] });
  m.onClose = () => { if (blobUrl) URL.revokeObjectURL(blobUrl); v.innerHTML = ""; api("DELETE", "/api/preview/" + r.id).catch(() => {}); };
}

/* ---------------------------------------------------------------- settings */
async function openSettings() {
  const s = state.settings, info = state.info;
  const body = document.createElement("div");
  const sw = (k, label) => '<label class="switch"><input type="checkbox" data-k="' + k + '"' + (s[k] ? " checked" : "") + "><i></i><span>" + label + "</span></label>";
  const sel = (k, label, opts) => '<label class="field"><span>' + label + '</span><select data-k="' + k + '">' + opts.map(([v, t]) => '<option value="' + v + '"' + (String(s[k]) === String(v) ? " selected" : "") + ">" + t + "</option>").join("") + "</select></label>";
  body.innerHTML = '<div class="swatches">' + ["cyan", "violet", "emerald", "amber", "rose"].map((a) => '<button class="swatch' + (s.accent === a ? " on" : "") + '" data-accent="' + a + '" aria-label="' + a + '" style="--c:' + { cyan: "#5ee7ff", violet: "#b49bff", emerald: "#4be3a3", amber: "#ffc857", rose: "#ff7a9c" }[a] + '"></button>').join("") + "</div>" +
    '<div class="set-grid">' +
    sel("profile", "Security profile", Object.entries(info.profiles || {}).map(([k, v]) => [k, k[0].toUpperCase() + k.slice(1) + ": " + v])) +
    sel("cipher", "Cipher", [["aes-256-gcm", "AES-256-GCM"], ["chacha20-poly1305", "ChaCha20-Poly1305"]]) +
    sel("chunk_kib", "Chunk size", [[64, "64 KiB"], [256, "256 KiB"], [1024, "1 MiB (default)"], [4096, "4 MiB"]]) +
    sel("shred_passes", "Default shred passes", [[1, "1 pass"], [3, "3 passes (DoD style)"], [7, "7 passes"]]) +
    sel("auto_clear_minutes", "Clear passwords when idle", [[0, "Never"], [1, "1 minute"], [5, "5 minutes"], [15, "15 minutes"], [30, "30 minutes"]]) +
    sel("preview_max_mb", "Preview size limit", [[16, "16 MB"], [96, "96 MB"], [256, "256 MB"], [1024, "1 GB"]]) +
    sw("compress", "Compress before encrypting") + sw("obfuscate_names", "Use random vault file names") +
    sw("sounds", "Sound effects") + sw("haptics", "Haptic feedback") + sw("privacy_blur", "Blur file names when the window loses focus") + sw("reduce_motion", "Reduce motion") +
    "</div>" +
    '<dl class="kv" style="margin-top:14px"><dt>Version</dt><dd>' + esc(info.version) + "</dd><dt>Argon2id</dt><dd>" + (info.argon2 ? "available" : "not available, using PBKDF2") + "</dd><dt>Key wiping</dt><dd>" + (info.can_wipe ? "full (including derived keys)" : "limited on this Python build") + "</dd></dl>";
  const m = modal({ title: "Settings", body, wide: true, buttons: [{ label: "Done", primary: true }] });
  body.addEventListener("change", async (e) => {
    const k = e.target.dataset.k; if (!k) return;
    let v = e.target.type === "checkbox" ? e.target.checked : e.target.value;
    if (e.target.tagName === "SELECT" && /^\d+$/.test(v)) v = +v;
    try { state.settings = await api("POST", "/api/settings", { [k]: v }); applySettings(); } catch (er) { toast(er.message, "bad"); }
  });
  body.addEventListener("click", async (e) => {
    const a = e.target.closest("[data-accent]"); if (!a) return;
    try { state.settings = await api("POST", "/api/settings", { accent: a.dataset.accent }); applySettings(); $$(".swatch", body).forEach((x) => x.classList.toggle("on", x === a)); } catch (er) { toast(er.message, "bad"); }
  });
}
$("#btnSettings").onclick = openSettings;
function applySettings() {
  const s = state.settings;
  document.documentElement.dataset.accent = s.accent;
  document.body.classList.toggle("reduce-motion", !!s.reduce_motion);
  state.passes = s.shred_passes || 3; $$("#passSeg button").forEach((b) => b.classList.toggle("on", +b.dataset.p === state.passes));
  renderChips(); armIdleTimer();
}
window.addEventListener("blur", () => { if (state.settings.privacy_blur) document.body.classList.add("privacy"); });
window.addEventListener("focus", () => document.body.classList.remove("privacy"));

/* ----------------------------------------------------- clearing and idling */
async function clearSecrets(silent) {
  pw.value = pw2.value = ""; checkMatch(); updateStrength();
  $$("#modalRoot .modal-back").forEach((b) => b.remove());
  for (const m of Object.keys(state.lists)) { state.lists[m].filter((i) => i.staged).forEach((i) => (i.staged = null)); }
  try { await api("POST", "/api/clear"); } catch { /* ignore */ }
  updateGo(); if (!silent) toast("Passwords, previews and uploads cleared.", "ok");
}
$("#btnClear").onclick = () => clearSecrets(false);
let idleTimer = null;
function armIdleTimer() {
  clearTimeout(idleTimer);
  const mins = state.settings.auto_clear_minutes;
  if (mins > 0) idleTimer = setTimeout(() => { if (!state.busy && (pw.value || $("#modalRoot").children.length)) { clearSecrets(true); toast("Cleared after " + mins + " minute(s) idle.", "warn"); } armIdleTimer(); }, mins * 60000);
}
["pointerdown", "keydown", "pointermove"].forEach((ev) => window.addEventListener(ev, () => { if (state.settings.auto_clear_minutes) armIdleTimer(); }, { passive: true }));
window.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === "l") { e.preventDefault(); clearSecrets(false); } });

/* ---------------------------------------------------------------- bootstrap */
(async function init() {
  hydrate(); history.replaceState(null, "", location.pathname);
  try {
    state.info = await api("GET", "/api/info"); state.settings = state.info.settings;
  } catch (e) { toast(e.message, "bad", 10000); }
  applySettings(); setMode("lock");
  if (!state.info.can_wipe) console.info("VaultLock: in-place key wiping is limited on this interpreter.");
})();
})();
