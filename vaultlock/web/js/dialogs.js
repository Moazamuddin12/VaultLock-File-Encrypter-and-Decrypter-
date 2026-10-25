// Toasts and modal helpers.
import { $, $$, h, icon } from "./dom.js";

export function toast(kind, text, ms = 4500) {
  const name = { ok: "circle-check", bad: "circle-alert", warn: "triangle-alert", info: "info" }[kind] ?? "info";
  const el = h("div", { class: `toast ${kind}` }, icon(name), h("span", { text }));
  const box = $("#toasts");
  box.append(el);
  while (box.children.length > 4) box.firstChild.remove();
  setTimeout(() => { el.classList.add("out"); setTimeout(() => el.remove(), 320); }, ms);
}

export function wireDialogs() {
  for (const dlg of $$("dialog")) {
    dlg.addEventListener("click", (e) => { if (e.target === dlg && dlg.dataset.sticky !== "1") dlg.close(); });
    for (const b of $$("[data-close]", dlg)) b.addEventListener("click", () => dlg.close());
  }
}

/** Promise-based confirmation.  {typeToConfirm:"SHRED"} forces the user to type a word. */
export function confirmDlg({ title, text, yes = "Continue", danger = false, typeToConfirm = null, input = null }) {
  const dlg = $("#dlg-confirm");
  $("#cf-title").textContent = title;
  $("#cf-text").textContent = text;
  const yesBtn = $("#cf-yes"), field = $("#cf-type"), box = $("#cf-input");
  yesBtn.textContent = yes;
  yesBtn.className = "btn " + (danger ? "danger" : "primary");
  field.hidden = !(typeToConfirm || input);
  box.value = input?.value ?? "";
  $("#cf-type-label").textContent = typeToConfirm ? `Type ${typeToConfirm} to confirm` : (input?.label ?? "");
  const ready = () => { yesBtn.disabled = !!typeToConfirm && box.value.trim() !== typeToConfirm; };
  ready();
  return new Promise((resolve) => {
    let result = null;
    const done = (v) => { result = v; dlg.close(); };
    const onYes = () => done(input ? box.value.trim() : true);
    const onNo = () => done(input ? null : false);
    const onKey = (e) => { if (e.key === "Enter" && !yesBtn.disabled) { e.preventDefault(); onYes(); } };
    yesBtn.addEventListener("click", onYes); $("#cf-no").addEventListener("click", onNo);
    box.addEventListener("input", ready); box.addEventListener("keydown", onKey);
    dlg.addEventListener("close", () => {
      yesBtn.removeEventListener("click", onYes); $("#cf-no").removeEventListener("click", onNo);
      box.removeEventListener("input", ready); box.removeEventListener("keydown", onKey);
      resolve(result ?? (input ? null : false));
    }, { once: true });
    dlg.showModal();
    (field.hidden ? $("#cf-no") : box).focus();
  });
}
