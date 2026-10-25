"""Password strength estimation and generation.

A compact, dependency-free cousin of Dropbox's *zxcvbn*: rather than the naive
"length x log2(alphabet)" formula (which rates ``Password1!`` as strong), the
password is segmented into the **cheapest-to-guess combination of patterns** -
common passwords, dictionary words and names (with capitalisation / leetspeak
variants), keyboard walks, character sequences, repeats and years - using
dynamic programming.  Whatever is left over is charged at brute-force cost.

The resulting figure is an *estimate of guessing entropy in bits*, not a
proof.  The ranked word lists in ``data/`` were derived from the MIT-licensed
zxcvbn project (see ``data/LICENSE-zxcvbn-wordlists.txt``).
"""

from __future__ import annotations

import math
import re
import secrets
import string
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

_DATA = Path(__file__).with_name("data")
_MAX_ANALYSE = 128          # characters analysed pattern-wise; the rest is brute-forced
_MIN_WORD = 4
_GUESSES_PER_SEC = 1_000_000  # assumed well-funded attacker vs. Argon2id (very pessimistic)

LABELS = ["Very weak", "Weak", "Fair", "Strong", "Excellent"]
_KEY_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "!@#$%^&*()"]
_LEET = {
    "@": "a", "4": "a", "8": "b", "(": "c", "3": "e", "6": "g", "9": "g", "!": "i", "|": "l",
    "0": "o", "$": "s", "5": "s", "7": "t", "+": "t", "2": "z", "1": "il",
}


@lru_cache(maxsize=1)
def _dictionaries() -> dict[str, dict[str, int]]:
    def load(name: str) -> dict[str, int]:
        try:
            lines = (_DATA / name).read_text(encoding="utf-8").split()
        except OSError:  # wordlists missing -> degrade gracefully
            return {}
        return {w: i + 1 for i, w in enumerate(lines)}

    return {"password": load("passwords.txt"), "word": load("words.txt"), "name": load("names.txt")}


@dataclass
class Match:
    start: int
    end: int  # exclusive
    kind: str
    bits: float


@dataclass
class Strength:
    score: int
    label: str
    entropy_bits: float
    length: int
    crack_time: str
    warning: str
    suggestions: list[str] = field(default_factory=list)
    segments: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "label": self.label,
            "entropy_bits": round(self.entropy_bits, 1),
            "length": self.length,
            "crack_time": self.crack_time,
            "warning": self.warning,
            "suggestions": self.suggestions,
            "segments": self.segments,
        }


# ---------------------------------------------------------------------------
# cost helpers
# ---------------------------------------------------------------------------

def _cardinality(pw: str) -> int:
    c = 0
    if any(ch.islower() and ch.isascii() for ch in pw):
        c += 26
    if any(ch.isupper() and ch.isascii() for ch in pw):
        c += 26
    if any(ch.isdigit() and ch.isascii() for ch in pw):
        c += 10
    if any(ch in string.punctuation or ch == " " for ch in pw):
        c += 33
    if any(not ch.isascii() for ch in pw):
        c += 100
    return max(c, 10)


def _case_bits(sub: str) -> float:
    letters = [c for c in sub if c.isalpha()]
    if not letters or sub.islower():
        return 0.0
    if sub.isupper() or (sub[0].isupper() and sub[1:].islower()):
        return 1.0
    upper = sum(c.isupper() for c in letters)
    lower = len(letters) - upper
    ways = sum(math.comb(len(letters), k) for k in range(1, min(upper, lower) + 1))
    return math.log2(max(ways, 2))


def _deleet_variants(low: str) -> list[tuple[str, int]]:
    """``(candidate, number_of_substituted_chars)`` for a lower-cased substring."""
    if not any(ch in _LEET for ch in low):
        return []
    outs = [""]
    subs = 0
    for ch in low:
        if ch in _LEET:
            subs += 1
            outs = [o + r for o in outs for r in _LEET[ch]]
            if len(outs) > 8:
                outs = outs[:8]
        else:
            outs = [o + ch for o in outs]
    return [(o, subs) for o in outs]


def _lookup(low: str, dicts) -> tuple[float, str] | None:
    best: tuple[float, str] | None = None
    for kind in ("password", "word", "name"):
        rank = dicts[kind].get(low)
        if rank is not None:
            bits = math.log2(rank + 1)
            if best is None or bits < best[0]:
                best = (bits, kind)
    return best


def _dictionary_cost(sub: str, dicts) -> tuple[float, str] | None:
    low = sub.lower()
    hit = _lookup(low, dicts)
    extra = _case_bits(sub)
    if hit is not None:
        return hit[0] + extra, hit[1]
    best: tuple[float, str] | None = None
    for cand, subs in _deleet_variants(low):
        h = _lookup(cand, dicts)
        if h is not None:
            bits = h[0] + extra + min(subs, 4) + 1
            if best is None or bits < best[0]:
                best = (bits, h[1] + "+leet")
    return best


# ---------------------------------------------------------------------------
# pattern matchers
# ---------------------------------------------------------------------------

def _dictionary_matches(pw: str, dicts) -> list[Match]:
    out: list[Match] = []
    n = len(pw)
    for i in range(n):
        for j in range(i + _MIN_WORD, min(n, i + 32) + 1):
            hit = _dictionary_cost(pw[i:j], dicts)
            if hit:
                out.append(Match(i, j, hit[1], hit[0]))
    # whole-string hits in the password list may be shorter than _MIN_WORD ("abc", "iloveu")
    if n < _MIN_WORD:
        hit = _dictionary_cost(pw, dicts)
        if hit:
            out.append(Match(0, n, hit[1], hit[0]))
    return out


def _sequence_matches(pw: str) -> list[Match]:
    out: list[Match] = []
    n = len(pw)
    i = 0
    while i < n - 2:
        d = ord(pw[i + 1]) - ord(pw[i])
        if d in (1, -1) and (pw[i].isalnum() and pw[i + 1].isalnum()):
            j = i + 1
            while j + 1 < n and ord(pw[j + 1]) - ord(pw[j]) == d and pw[j + 1].isalnum():
                j += 1
            length = j - i + 1
            if length >= 3:
                start_space = 10 if pw[i].isdigit() else 26
                out.append(Match(i, j + 1, "sequence", math.log2(start_space) + math.log2(length) + 1))
                i = j
        i += 1
    return out


def _keyboard_matches(pw: str) -> list[Match]:
    out: list[Match] = []
    low = pw.lower()
    n = len(low)
    for row in _KEY_ROWS:
        for d in (1, -1):
            i = 0
            while i < n - 3:
                pos = row.find(low[i])
                if pos < 0:
                    i += 1
                    continue
                j = i
                while j + 1 < n and 0 <= pos + d < len(row) and row[pos + d] == low[j + 1]:
                    pos += d
                    j += 1
                if j - i + 1 >= 4:
                    out.append(Match(i, j + 1, "keyboard", math.log2(10 * len(_KEY_ROWS)) + math.log2(j - i + 1) + 1))
                    i = j
                i += 1
    return out


def _repeat_matches(pw: str, bf_bits: float) -> list[Match]:
    out: list[Match] = []
    n = len(pw)
    for i in range(n):
        for u in range(1, (n - i) // 2 + 1):
            unit = pw[i : i + u]
            k = 1
            while pw.startswith(unit, i + k * u):
                k += 1
            if k >= 2 and (u * k >= 4 or (u == 1 and k >= 3)):
                out.append(Match(i, i + u * k, "repeat", u * bf_bits + math.log2(k) + 1))
    return out


_YEAR = re.compile(r"(?:19|20)\d\d")
_DATE = re.compile(r"\d{1,2}[/\-. ]\d{1,2}[/\-. ]\d{2,4}")


def _date_matches(pw: str) -> list[Match]:
    out = [Match(m.start(), m.end(), "year", math.log2(130)) for m in _YEAR.finditer(pw)]
    out += [Match(m.start(), m.end(), "date", 15.0) for m in _DATE.finditer(pw)]
    return out


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def _humanise(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = [("second", 60), ("minute", 60), ("hour", 24), ("day", 30), ("month", 12), ("year", 100)]
    value = seconds
    for name, size in units:
        if value < size:
            v = int(value)
            return f"{v} {name}{'' if v == 1 else 's'}"
        value /= size
    centuries = value
    if centuries > 1e9:
        return "longer than the age of the universe"
    if centuries > 1e6:
        return f"{centuries:.1e} centuries".replace("e+0", "e").replace("e+", "e")
    return f"{int(centuries):,} centuries"


def evaluate(password: str) -> Strength:
    """Estimate the guessing entropy of ``password`` (never logs or stores it)."""
    pw = password or ""
    n_total = len(pw)
    if not pw:
        return Strength(0, LABELS[0], 0.0, 0, "instantly", "", ["Enter a password."], [])

    head, tail = pw[:_MAX_ANALYSE], pw[_MAX_ANALYSE:]
    dicts = _dictionaries()
    card = _cardinality(pw)
    bf = math.log2(card)

    matches = (
        _dictionary_matches(head, dicts)
        + _sequence_matches(head)
        + _keyboard_matches(head)
        + _repeat_matches(head, bf)
        + _date_matches(head)
    )
    n = len(head)
    by_end: dict[int, list[Match]] = {}
    for m in matches:
        by_end.setdefault(m.end, []).append(m)

    best = [math.inf] * (n + 1)
    back: list[tuple[int, Match | None]] = [(0, None)] * (n + 1)
    best[0] = 0.0
    for j in range(1, n + 1):
        best[j] = best[j - 1] + bf
        back[j] = (j - 1, None)
        for m in by_end.get(j, ()):
            c = best[m.start] + m.bits
            if c < best[j]:
                best[j], back[j] = c, (m.start, m)

    entropy = best[n] + len(tail) * bf

    # walk back to recover the chosen segmentation (for the UI + feedback)
    chosen: list[Match] = []
    j = n
    while j > 0:
        prev, m = back[j]
        if m is not None:
            chosen.append(m)
        j = prev
    chosen.reverse()

    kinds = {m.kind.split("+")[0] for m in chosen}
    leet = any("+leet" in m.kind for m in chosen)
    covered = sum(m.end - m.start for m in chosen)

    whole = chosen[0] if len(chosen) == 1 and chosen[0].start == 0 and chosen[0].end == n and not tail else None
    is_common = whole is not None and whole.kind.startswith("password")

    # -- score ---------------------------------------------------------------
    if entropy < 28:
        score = 0
    elif entropy < 40:
        score = 1
    elif entropy < 60:
        score = 2
    elif entropy < 80:
        score = 3
    else:
        score = 4
    if is_common:
        score = 0
    if n_total < 8:
        score = min(score, 1)
    if n_total < 6:
        score = 0

    # -- feedback ------------------------------------------------------------
    warning = ""
    suggestions: list[str] = []
    if is_common:
        warning = "This is among the most commonly used passwords."
    elif "password" in kinds and covered >= n * 0.6:
        warning = "This is very similar to a commonly used password."
    elif ({"word", "name"} & kinds) and covered >= n * 0.6 and n_total < 16:
        warning = "A single common word or name is easy to guess."
    elif "keyboard" in kinds:
        warning = "Keyboard patterns like 'qwerty' are among the first things attackers try."
    elif "sequence" in kinds:
        warning = "Sequences like 'abcd' or '1234' are easy to guess."
    elif "repeat" in kinds and covered >= n * 0.5:
        warning = "Repeated characters or patterns are easy to guess."

    if n_total < 12:
        suggestions.append("Use at least 12 characters - a passphrase of 5+ unrelated words is strong and easy to remember.")
    if "year" in kinds or "date" in kinds:
        suggestions.append("Avoid years and dates; they are very guessable.")
    if leet:
        suggestions.append("Predictable substitutions like '@' for 'a' or '0' for 'o' add almost nothing.")
    if "word" in kinds or "name" in kinds or "password" in kinds:
        suggestions.append("Combine several unrelated words rather than one common word.")
    if score <= 2 and len(suggestions) < 3:
        suggestions.append("Longer beats more complex: add words or characters instead of swapping symbols in.")

    if score >= 3:  # don't nag about strong passwords
        warning = ""
        suggestions = []
    # entropy can exceed 1000 bits for very long inputs; avoid float overflow
    crack = _humanise(2 ** max(entropy - 1, 0) / _GUESSES_PER_SEC) if entropy < 200 else "longer than the age of the universe"
    segments = [{"start": m.start, "end": m.end, "kind": m.kind.split("+")[0]} for m in chosen]
    return Strength(score, LABELS[score], entropy, n_total, crack, warning, suggestions[:3], segments)


# ---------------------------------------------------------------------------
# generators (CSPRNG-backed)
# ---------------------------------------------------------------------------

def generate_password(length: int = 24, *, symbols: bool = True) -> str:
    """Uniformly random password containing at least one of each selected class."""
    length = max(12, min(int(length), 128))
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        classes.append("!@#$%^&*()-_=+[]{};:,.?/~")
    alphabet = "".join(classes)
    while True:
        pw = [secrets.choice(alphabet) for _ in range(length)]
        if all(any(c in cls for c in pw) for cls in classes):
            return "".join(pw)


@lru_cache(maxsize=1)
def _passphrase_words() -> list[str]:
    words = list(_dictionaries()["word"].items())
    pool = [w for w, rank in words if w.isalpha() and w.isascii() and 4 <= len(w) <= 8 and rank <= 12000]
    return pool or ["correct", "horse", "battery", "staple", "orbit", "velvet", "harbor", "quartz"]


def generate_passphrase(words: int = 6, separator: str = "-") -> str:
    """Diceware-style passphrase: ~12-13 bits of entropy per word from a ranked English list."""
    words = max(4, min(int(words), 16))
    pool = _passphrase_words()
    return separator.join(secrets.choice(pool) for _ in range(words))
