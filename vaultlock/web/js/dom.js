// DOM + formatting helpers.  Untrusted text (file names, errors) only ever goes through textContent.
import { ICONS } from "./icons.js";

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const SVG_NS = "http://www.w3.org/2000/svg";

export function icon(name, cls = "") {
  const s = document.createElementNS(SVG_NS, "svg");
  s.setAttribute("class", ("ic " + cls).trim());
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("aria-hidden", "true");
  s.innerHTML = ICONS[name] ?? "";
  return s;
}

/** Replace every <i data-i="name"> placeholder under ``root`` with the inline SVG. */
export function hydrate(root = document) {
  for (const el of $$("i[data-i]", root)) {
    const svg = icon(el.dataset.i, el.className);
    if (el.id) svg.id = el.id;   // keep ids so code can find the swapped icon later
    el.replaceWith(svg);
  }
}

/** Tiny hyperscript: h("div", {class:"x", onclick:fn, "aria-label":"y"}, "text", child, ...) */
export function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

export function fmtSize(n) {
  if (!Number.isFinite(n)) return "";
  if (n < 1000) return `${n} B`;
  const u = ["KB", "MB", "GB", "TB"]; let i = -1;
  do { n /= 1000; i++; } while (n >= 1000 && i < u.length - 1);
  return `${n >= 100 ? n.toFixed(0) : n >= 10 ? n.toFixed(1) : n.toFixed(2)} ${u[i]}`;
}
export const fmtSpeed = (bps) => `${fmtSize(bps)}/s`;
export function fmtEta(s) {
  if (s == null) return "";
  if (s < 1) return "almost done";
  if (s < 60) return `${Math.ceil(s)} s left`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${Math.ceil(s % 60)} s left`;
  return `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min left`;
}
export const plural = (n, one, many = one + "s") => `${n.toLocaleString()} ${n === 1 ? one : many}`;
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

const EXT_ICON = {
  image: "png jpg jpeg gif webp bmp svg avif heic tiff raw", video: "mp4 mkv mov avi webm m4v wmv",
  audio: "mp3 wav flac aac ogg m4a opus", archive: "zip rar 7z tar gz bz2 xz tgz",
  code: "py js ts jsx tsx html css json xml yml yaml toml rs go java c cpp h cs sh sql php rb kt swift",
  sheet: "xls xlsx csv tsv ods", text: "txt md rtf doc docx odt pdf pages log tex",
};
export function fileIcon(name, isDir = false) {
  if (isDir) return "folder";
  if (name.toLowerCase().endsWith(".vault")) return "file-lock";
  const ext = name.split(".").pop().toLowerCase();
  for (const [k, list] of Object.entries(EXT_ICON)) if (list.split(" ").includes(ext)) {
    return { image: "file-image", video: "file-video", audio: "file-audio", archive: "file-archive", code: "file-code", sheet: "file-spreadsheet", text: "file-text" }[k];
  }
  return "file";
}
