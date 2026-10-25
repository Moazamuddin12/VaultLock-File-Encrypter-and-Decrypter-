// Secure viewer: decrypts into server RAM, streams to a blob URL here, wipes everything on close.
import { api } from "./api.js";
import { $, h, icon, fmtSize } from "./dom.js";
import { toast } from "./dialogs.js";

let creds = null, url = null, seq = 0;
const dlg = () => $("#dlg-view");

function clearStage() {
  if (url) { URL.revokeObjectURL(url); url = null; }
  $("#view-stage").replaceChildren();
}
const placeholder = (ic, title, text, spin = false) =>
  h("div", { class: "ph" }, icon(ic, spin ? "spin" : ""), h("b", { text: title }), text ? h("span", { text }) : null);

export function closeViewer() {
  seq++;
  clearStage();
  $("#view-tree").replaceChildren();
  creds = null;
  if (dlg().open) dlg().close();
}

export async function openViewer(path, name, credentials) {
  creds = credentials; const my = ++seq;
  $("#view-title").textContent = name;
  $("#view-sub").textContent = "Decrypted in memory only. Nothing is written to disk.";
  const tree = $("#view-tree"); tree.hidden = true; tree.replaceChildren();
  clearStage(); $("#view-stage").append(placeholder("refresh-cw", "Unlocking…", "Deriving the key and checking every block.", true));
  dlg().dataset.sticky = "1";
  if (!dlg().open) dlg().showModal();
  dlg().addEventListener("close", () => { if (creds) closeViewer(); }, { once: true });

  try {
    const list = await api("/api/vault/list", { method: "POST", body: { path, ...creds } });
    if (my !== seq) return;
    const files = list.entries.filter((e) => !e.dir);
    if (list.meta.kind === "file") return await show(path, "", list.meta.name, my);
    tree.hidden = false;
    for (const e of list.entries) {
      const dir = e.dir;
      const li = h("li", { class: dir ? "dir" : "", "aria-selected": "false", title: e.name }, icon(dir ? "folder" : "file"), h("span", { text: e.name.split("/").slice(1).join("/") || e.name }));
      if (!dir) li.addEventListener("click", () => { for (const x of tree.children) x.setAttribute("aria-selected", "false"); li.setAttribute("aria-selected", "true"); show(path, e.name, e.name.split("/").pop(), ++seq); });
      tree.append(li);
    }
    clearStage();
    $("#view-stage").append(placeholder("scan-eye", `${files.length.toLocaleString()} files inside`, "Pick one on the left to preview it."));
  } catch (e) {
    if (my !== seq) return;
    clearStage(); $("#view-stage").append(placeholder("circle-alert", "Couldn't open this vault", e.message));
  }
}

async function show(path, entry, name, my) {
  const stage = $("#view-stage"); clearStage();
  stage.append(placeholder("refresh-cw", "Decrypting…", name, true));
  try {
    const res = await api("/api/preview", { method: "POST", body: { path, entry, ...creds }, raw: true });
    if (my !== seq) return;
    $("#view-title").textContent = name;
    if ((res.headers.get("content-type") || "").includes("application/json")) {
      const d = await res.json(); if (my !== seq) return;
      clearStage();
      stage.append(h("pre", { text: d.text + (d.truncated ? "\n\n… preview truncated at 2 MB …" : "") }));
      $("#view-sub").textContent = `${fmtSize(d.size)} · text · decrypted in memory`;
      return;
    }
    const cat = res.headers.get("x-preview-category");
    const blob = await res.blob(); if (my !== seq) return;
    clearStage(); url = URL.createObjectURL(blob);
    const el = { image: () => h("img", { src: url, alt: name }), video: () => h("video", { src: url, controls: true, autoplay: false }),
                 audio: () => h("audio", { src: url, controls: true }), pdf: () => h("iframe", { src: url, title: name }) }[cat]?.();
    stage.append(el ?? placeholder("file", "No preview", "Unlock the file to open it in another app."));
    $("#view-sub").textContent = `${fmtSize(blob.size)} · ${cat} · decrypted in memory`;
  } catch (e) {
    if (my !== seq) return;
    clearStage(); stage.append(placeholder("circle-alert", "Can't preview this file", e.message));
    if (e.code === "bad_credentials") toast("bad", e.message);
  }
}
