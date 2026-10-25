// File picker.  Desktop app -> native dialogs.  Browser tab -> an in-app explorer backed by /api/fs/*
// (the server runs on this very computer, so it can show real paths).
import { api, DESKTOP } from "./api.js";
import { $, h, icon, fmtSize, fileIcon } from "./dom.js";
import { confirmDlg, toast } from "./dialogs.js";

let nativeOk = false;
export function setNative(v) { nativeOk = !!v; }

const NATIVE_KIND = { files: "files", vaults: "vaults", folder: "folder", keyfile: "keyfile", output: "output", save_keyfile: "save_keyfile" };
const CONFIG = {
  files:        { title: "Choose files", select: "files", multiple: true, ok: "Add" },
  vaults:       { title: "Choose vaults to unlock", select: "files", multiple: true, ok: "Add", filter: ".vault" },
  folder:       { title: "Choose a folder", select: "folder", multiple: true, ok: "Add folder" },
  keyfile:      { title: "Choose your keyfile", select: "files", multiple: false, ok: "Use keyfile", filter: ".key" },
  output:       { title: "Choose where to save", select: "folder", multiple: false, ok: "Save here" },
  save_keyfile: { title: "Create a keyfile", select: "save", multiple: false, ok: "Create keyfile", defaultName: "vaultlock.key" },
};

/** Returns an array of absolute paths, or [] if the user cancelled. */
export async function choose(kind, { start = "", showHidden = false } = {}) {
  if (DESKTOP && nativeOk) {
    try { return (await api("/api/native/pick", { method: "POST", body: { kind: NATIVE_KIND[kind], default_name: CONFIG[kind].defaultName ?? "" } })).paths; }
    catch (e) { if (e.code !== "unsupported") toast("bad", e.message); }
  }
  return pickInApp(CONFIG[kind], { start, showHidden });
}

function pickInApp(cfg, { start, showHidden }) {
  const dlg = $("#dlg-pick");
  const list = $("#pick-list"), crumbs = $("#pick-crumbs"), count = $("#pick-count");
  const okBtn = $("#pick-ok"), nameWrap = $("#pick-name-wrap"), nameInput = $("#pick-name");
  const sel = new Set();
  let cwd = "", sep = "/", entries = [], nav = 0;

  $("#pick-title").textContent = cfg.title;
  okBtn.textContent = cfg.ok;
  nameWrap.hidden = cfg.select !== "save";
  if (cfg.select === "save") nameInput.value = cfg.defaultName ?? "";

  const refreshFooter = () => {
    if (cfg.select === "folder") { count.textContent = sel.size ? `${sel.size} selected` : "Current folder will be used"; okBtn.disabled = false; }
    else if (cfg.select === "save") { count.textContent = ""; okBtn.disabled = !nameInput.value.trim(); }
    else { count.textContent = sel.size ? `${sel.size} selected` : ""; okBtn.disabled = sel.size === 0; }
  };

  function render() {
    list.replaceChildren();
    if (!entries.length) list.append(h("li", { class: "dim", style: { cursor: "default" } }, h("span"), h("span", { class: "n", text: "This folder is empty" }), h("span")));
    for (const e of entries) {
      const dir = e.kind === "dir";
      const dim = cfg.select === "save" ? !dir : cfg.select === "folder" ? !dir : (cfg.filter && !dir && !e.name.toLowerCase().endsWith(cfg.filter));
      const li = h("li", { class: (dir ? "dir " : "") + (dim ? "dim" : ""), role: "option", tabindex: "0", "aria-selected": sel.has(e.path) ? "true" : "false", title: e.path },
        icon(fileIcon(e.name, dir)), h("span", { class: "n", text: e.name }), h("span", { class: "s", text: dir ? "" : fmtSize(e.size) }));
      const activate = (ev) => {
        if (dir && (cfg.select !== "folder" || ev.detail >= 2 || ev.key === "Enter")) return go(e.path);
        if (dir && cfg.select === "folder") { toggle(e.path, li); return; }
        if (cfg.select === "save" || cfg.select === "folder") return;
        toggle(e.path, li);
      };
      li.addEventListener("click", activate);
      li.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); activate(ev); } });
      list.append(li);
    }
    refreshFooter();
  }
  function toggle(path, li) {
    if (sel.has(path)) sel.delete(path);
    else { if (!cfg.multiple) { sel.clear(); for (const x of list.children) x.setAttribute("aria-selected", "false"); } sel.add(path); }
    li.setAttribute("aria-selected", sel.has(path) ? "true" : "false");
    refreshFooter();
  }
  async function go(path) {
    const my = ++nav;   // the most recent navigation always wins, however slow earlier ones are
    try {
      const d = await api(`/api/fs/list?path=${encodeURIComponent(path ?? "")}`);
      if (my !== nav) return;
      cwd = d.path; entries = d.entries; sep = cwd.includes("\\") ? "\\" : "/"; sel.clear(); $("#pick-path").value = cwd;
      crumbs.replaceChildren(...d.breadcrumbs.flatMap((c, i) => [i ? icon("chevron-right") : null, h("button", { type: "button", text: c.name, onclick: () => go(c.path) })]));
      render(); list.scrollTop = 0;
    } catch (e) { toast("bad", e.message); }
  }
  async function loadRoots() {
    const { roots } = await api("/api/fs/roots");
    $("#pick-roots").replaceChildren(...roots.map((r) => h("button", { type: "button", onclick: () => go(r.path) }, icon(r.icon), h("span", { text: r.name }))));
    return roots;
  }

  return new Promise(async (resolve) => {
    let out = [];
    const finish = () => dlg.close();
    const onOk = () => {
      if (cfg.select === "folder") out = sel.size ? [...sel] : [cwd];
      else if (cfg.select === "save") out = [cwd.replace(/[\\/]$/, "") + sep + nameInput.value.trim()];
      else out = [...sel];
      finish();
    };
    const onNew = async () => {
      const name = await confirmDlg({ title: "New folder", text: "Create a folder in " + cwd, input: { label: "Folder name", value: "" }, yes: "Create" });
      if (!name) return;
      try { const r = await api("/api/fs/mkdir", { method: "POST", body: { parent: cwd, name } }); await go(cwd); toast("ok", "Folder created."); }
      catch (e) { toast("bad", e.message); }
    };
    const onName = () => refreshFooter();
    const onPath = (e) => { if (e.key === "Enter") { e.preventDefault(); go($("#pick-path").value.trim()); } };
    $("#pick-path").addEventListener("keydown", onPath);
    okBtn.addEventListener("click", onOk); $("#pick-newdir").addEventListener("click", onNew); nameInput.addEventListener("input", onName);
    dlg.addEventListener("close", () => {
      okBtn.removeEventListener("click", onOk); $("#pick-newdir").removeEventListener("click", onNew); nameInput.removeEventListener("input", onName);
      $("#pick-path").removeEventListener("keydown", onPath);
      resolve(out);
    }, { once: true });
    dlg.showModal();
    try { const roots = await loadRoots(); if (!nav) await go(start || roots[0]?.path); } catch (e) { toast("bad", e.message); }
    list.focus();
  });
}
