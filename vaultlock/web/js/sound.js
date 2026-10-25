// Tiny synthesized UI sounds (WebAudio - no audio files) and haptics.  Both are optional.
let ctx = null;
export const Feedback = { sounds: true, haptics: true };

function ac() {
  if (!ctx) { const C = window.AudioContext || window.webkitAudioContext; if (C) ctx = new C(); }
  if (ctx?.state === "suspended") ctx.resume();
  return ctx;
}
function tone(freq, t0, dur, { type = "sine", gain = 0.07, slide = 0 } = {}) {
  const c = ac(); if (!c) return;
  const o = c.createOscillator(), g = c.createGain();
  o.type = type; o.frequency.setValueAtTime(freq, c.currentTime + t0);
  if (slide) o.frequency.exponentialRampToValueAtTime(freq * slide, c.currentTime + t0 + dur);
  g.gain.setValueAtTime(0.0001, c.currentTime + t0);
  g.gain.exponentialRampToValueAtTime(gain, c.currentTime + t0 + 0.012);
  g.gain.exponentialRampToValueAtTime(0.0001, c.currentTime + t0 + dur);
  o.connect(g).connect(c.destination); o.start(c.currentTime + t0); o.stop(c.currentTime + t0 + dur + 0.02);
}
const SOUNDS = {
  add:     () => tone(740, 0, 0.07, { type: "triangle", gain: 0.04 }),
  success: () => { [523.25, 659.25, 783.99, 1046.5].forEach((f, i) => tone(f, i * 0.075, 0.28, { type: "sine", gain: 0.06 })); tone(130.8, 0, 0.18, { type: "triangle", gain: 0.05, slide: 0.7 }); },
  error:   () => { tone(196, 0, 0.16, { type: "square", gain: 0.035, slide: 0.8 }); tone(147, 0.17, 0.26, { type: "square", gain: 0.035, slide: 0.7 }); },
  shred:   () => { for (let i = 0; i < 6; i++) tone(900 - i * 110, i * 0.045, 0.06, { type: "sawtooth", gain: 0.03 }); },
};
const HAPTICS = { add: [8], success: [18, 40, 28], error: [60, 50, 60, 50, 90], shred: [30, 30, 30, 30, 80] };

export function cue(name) {
  try { if (Feedback.sounds) SOUNDS[name]?.(); } catch { /* audio is best effort */ }
  try { if (Feedback.haptics && navigator.vibrate) navigator.vibrate(HAPTICS[name] ?? 10); } catch { /* ignore */ }
}
