// Settings drawer: built from a declarative schema, persisted through /api/settings.
import { api } from "./api.js";
import { $, h, debounce } from "./dom.js";
import { toast } from "./dialogs.js";
import { choose } from "./picker.js";
import { Feedback, cue } from "./sound.js";

const ACCENTS = { cyan: ["#53e0d0", "#5aa8ff"], violet: ["#b49bff", "#ff8ad8"], emerald: ["#4ade9a", "#a3e635"], amber: ["#ffb454", "#ff7a59"], rose: ["#ff7a9c", "#c58bff"] };
export const state = { values: {}, onChange: () => {}, profiles: {} };

export function applySettings(s) {
  state.values = s;
  document.documentElement.dataset.accent = s.accent;
  document.documentElement.dataset.reduce = s.reduce_motion ? "1" : "0";
  Feedback.sounds = s.sounds; Feedback.haptics = s.haptics;
  state.onChange(s);
}

const save = debounce(async (patch) => {
  try { applySettings((await api("/api/settings", { method: "POST", body: patch })).settings); }
  catch (e) { toast("bad", e.message); }
}, 150);
const set = (k, v) => { state.values = { ...state.values, [k]: v }; applySettings(state.values); save({ [k]: v }); };

const toggle = (key, label, hint) => {
  const input = h("input", { type: "checkbox", id: `s-${key}` });
  input.checked = !!state.values[key];
  input.addEventListener("change", () => { set(key, input.checked); if (key === "sounds" && input.checked) cue("success"); if (key === "haptics" && input.checked) cue("add"); });
  return h("div", { class: "switch-row" }, h("div", {}, h("label", { class: "plain", for: `s-${key}`, text: label }), hint ? h("p", { class: "hint", text: hint }) : null), h("label", { class: "switch" }, input, h("span")));
};
const select = (key, label, options, numeric = false, hint = "") => {
  const sel = h("select", { id: `s-${key}` }, options.map(([v, t]) => h("option", { value: v, text: t })));
  sel.value = String(state.values[key]);
  sel.addEventListener("change", () => set(key, numeric ? Number(sel.value) : sel.value));
  return h("div", { class: "field" }, h("label", { for: `s-${key}`, text: label }), sel, hint ? h("p", { class: "hint", text: hint }) : null);
};
const number = (key, label, hint, min, max) => {
  const inp = h("input", { type: "number", id: `s-${key}`, min, max, value: state.values[key] });
  inp.addEventListener("change", () => { const v = Math.max(min, Math.min(max, parseInt(inp.value || "0", 10))); inp.value = v; set(key, v); });
  return h("div", { class: "field" }, h("label", { for: `s-${key}`, text: label }), inp, h("p", { class: "hint", text: hint }));
};

export function buildSettings() {
  const v = state.values, body = $("#set-body");
  const sw = h("div", { class: "swatches", role: "group", "aria-label": "Accent colour" }, Object.entries(ACCENTS).map(([name, [c1, c2]]) => {
    const b = h("button", { type: "button", "aria-label": name, "aria-pressed": String(v.accent === name), style: { "--c1": c1, "--c2": c2 } });
    b.addEventListener("click", () => { set("accent", name); for (const x of sw.children) x.setAttribute("aria-pressed", String(x === b)); });
    return b;
  }));
  const outLabel = h("span", { class: "hint", text: v.default_output_dir || "Next to the original (uploads go to ~/VaultLock)" });
  const outBtn = h("button", { type: "button", class: "btn small", text: "Choose folder", onclick: async () => { const [p] = await choose("output"); if (p) { set("default_output_dir", p); outLabel.textContent = p; } } });
  const outClr = h("button", { type: "button", class: "btn small ghost", text: "Reset", onclick: () => { set("default_output_dir", ""); outLabel.textContent = "Next to the original (uploads go to ~/VaultLock)"; } });

  body.replaceChildren(
    h("section", { class: "set-group" }, h("h3", { text: "Appearance" }), h("div", { class: "field" }, h("label", { text: "Accent colour" }), sw), toggle("reduce_motion", "Reduce motion", "Calms the dial and background animation.")),
    h("section", { class: "set-group" }, h("h3", { text: "Feedback" }), toggle("sounds", "Sounds", "Short tones when a job finishes or fails."), toggle("haptics", "Vibration", "On devices that support it.")),
    h("section", { class: "set-group" }, h("h3", { text: "Privacy" }),
      toggle("privacy_blur", "Hide the window when it loses focus", "Covers file names and closes the secure viewer."),
      number("auto_clear_minutes", "Clear passwords after idle (minutes)", "0 turns this off.", 0, 120)),
    h("section", { class: "set-group" }, h("h3", { text: "Defaults for new vaults" }),
      select("profile", "Security level", Object.entries(state.profiles).map(([k, d]) => [k, `${k[0].toUpperCase() + k.slice(1)} - ${d}`])),
      select("cipher", "Cipher", [["aes-256-gcm", "AES-256-GCM"], ["chacha20-poly1305", "ChaCha20-Poly1305"]]),
      select("chunk_kib", "Block size", [[64, "64 KB"], [256, "256 KB"], [1024, "1 MB (recommended)"], [4096, "4 MB"]], true, "Large files are processed block by block, so memory use stays flat."),
      toggle("compress", "Compress before locking"), toggle("obfuscate_names", "Hide file names"),
      select("shred_passes", "Shredder passes", [[1, "1 - zeros"], [3, "3 - DoD 5220.22-M"], [7, "7 - extended"]], true)),
    h("section", { class: "set-group" }, h("h3", { text: "Files" }),
      h("div", { class: "field" }, h("label", { text: "Default output folder" }), outLabel, h("div", { class: "row" }, outBtn, outClr)),
      number("preview_max_mb", "Secure viewer size limit (MB)", "Larger files must be unlocked to open.", 1, 1024),
      toggle("show_hidden_files", "Show hidden files in the file browser")),
  );
}
