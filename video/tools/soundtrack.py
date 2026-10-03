"""Synthesize the soundtrack: an original chiptune loop, sound effects on the animation's cues, and the narration.

    uv run --no-project --with numpy python tools/soundtrack.py --lang es   # -> assets/mix-es.wav

Everything is generated here (square / triangle / noise voices), so there are no samples or licenses to track.
Cue times mirror world.js and index.html (scene starts in narration.json).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import wave
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
SR = 44100
LENGTH = 60.0
rng = np.random.default_rng(7)  # deterministic noise


def t_axis(d: float) -> np.ndarray:
    return np.arange(int(d * SR)) / SR


def square(f, d, duty=0.5):
    ph = np.cumsum(np.broadcast_to(f, t_axis(d).shape) / SR) % 1.0
    return np.where(ph < duty, 1.0, -1.0)


def triangle(f, d):
    ph = np.cumsum(np.broadcast_to(f, t_axis(d).shape) / SR) % 1.0
    return 4 * np.abs(ph - 0.5) - 1


def noise(d):
    return rng.uniform(-1, 1, int(d * SR))


def env(d, a=0.005, r=0.08, sustain=1.0):
    n = int(d * SR)
    e = np.full(n, sustain)
    na, nr = min(n, int(a * SR)), min(n, int(r * SR))
    if na:
        e[:na] = np.linspace(0, sustain, na)
    if nr:
        e[-nr:] *= np.linspace(1, 0, nr)
    return e


def lowpass(x, k=0.08):
    y = np.empty_like(x)
    acc = 0.0
    for i, v in enumerate(x):  # one-pole filter, fine for short sounds
        acc += k * (v - acc)
        y[i] = acc
    return y


NOTE = {n: i for i, n in enumerate(["C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B"])}


def hz(name: str) -> float:
    pitch, octave = name[:-1], int(name[-1])
    return 440.0 * 2 ** ((NOTE[pitch] + 12 * (octave + 1) - 69) / 12)


class Track:
    def __init__(self) -> None:
        self.buf = np.zeros(int(LENGTH * SR) + SR)

    def add(self, at: float, x: np.ndarray, gain: float = 1.0) -> None:
        i = int(at * SR)
        n = min(len(x), len(self.buf) - i)
        if n > 0 and i >= 0:
            self.buf[i : i + n] += x[:n] * gain


# ---------------------------------------------------------------------- music
BPM = 100
BEAT = 60 / BPM
PROGRESSION = [("A2", ["A3", "C4", "E4"]), ("F2", ["F3", "A3", "C4"]), ("C3", ["C4", "E4", "G4"]), ("G2", ["G3", "B3", "D4"])]
MELODY = [  # one bar per chord, eighth notes; "-" holds, "." rests
    ["E5", "-", "C5", "E5", "A5", "-", "G5", "E5"],
    ["F5", "-", "A5", "-", "C6", "A5", "F5", "-"],
    ["E5", "G5", "C6", "-", "B5", "G5", "E5", "D5"],
    ["D5", "-", "B4", "D5", "G5", "-", ".", "."],
]


def music() -> Track:
    tr = Track()
    bar = 4 * BEAT
    n_bars = int(LENGTH / bar) + 1
    for b in range(n_bars):
        start = b * bar
        root, chord = PROGRESSION[b % 4]
        for beat in range(4):  # bass: root on the beat, octave on the off-beat
            for half, oct_up in ((0, 1.0), (0.5, 2.0)):
                f = hz(root) * oct_up
                tr.add(start + (beat + half) * BEAT, triangle(f, BEAT * 0.45) * env(BEAT * 0.45, r=0.05), 0.32)
        for step in range(16):  # arpeggio on a thin pulse
            f = hz(chord[step % 3]) * 2
            tr.add(start + step * BEAT / 4, square(f, BEAT / 4 * 0.8, 0.125) * env(BEAT / 4 * 0.8, r=0.03), 0.045)
        if b % 8 >= 2:  # melody enters after two bars, rests every eight
            notes = MELODY[b % 4]
            for i, n in enumerate(notes):
                if n in "-.":
                    continue
                length = 1
                while i + length < 8 and notes[i + length] == "-":
                    length += 1
                d = length * BEAT / 2 * 0.92
                tr.add(start + i * BEAT / 2, square(hz(n), d, 0.25) * env(d, a=0.01, r=0.06), 0.07)
        for beat in range(4):  # drums: kick on 1 and 3, snare on 2 and 4, hats on eighths
            t0 = start + beat * BEAT
            if beat % 2 == 0:
                d = 0.12
                f = np.linspace(150, 45, int(d * SR))
                tr.add(t0, np.sin(2 * np.pi * np.cumsum(f) / SR) * env(d, r=0.1), 0.55)
            else:
                tr.add(t0, noise(0.1) * env(0.1, r=0.09), 0.16)
            for half in (0, 0.5):
                tr.add(t0 + half * BEAT, noise(0.025) * env(0.025, r=0.02), 0.05)
    return tr


# ---------------------------------------------------------------------- effects
def blip():
    return square(1900, 0.018, 0.5) * env(0.018, r=0.01) * 0.22


def typing(tr, at, d):
    k = 0
    while k * 0.045 < d:
        tr.add(at + k * 0.045, square(1700 + (k % 3) * 220, 0.016) * env(0.016, r=0.01), 0.12)
        k += 1


def whoosh(d, up=True):
    x = noise(d)
    k = np.linspace(0.02, 0.25, len(x)) if up else np.linspace(0.25, 0.02, len(x))
    y = np.empty_like(x)
    acc = 0.0
    for i, v in enumerate(x):
        acc += k[i] * (v - acc)
        y[i] = acc
    return y * np.sin(np.linspace(0, np.pi, len(x))) * 1.6


def fall_whistle(d=0.45):
    f = np.linspace(1500, 300, int(d * SR))
    return square(f, d, 0.5) * env(d, r=0.02) * 0.35


def splash():
    d = 0.9
    body = lowpass(noise(d), 0.12) * np.exp(-np.linspace(0, 5, int(d * SR))) * 2.2
    thud_d = 0.25
    f = np.linspace(120, 35, int(thud_d * SR))
    thud = np.sin(2 * np.pi * np.cumsum(f) / SR) * env(thud_d, r=0.2)
    out = body.copy()
    out[: len(thud)] += thud * 1.2
    return out


def clank():
    out = np.zeros(int(0.7 * SR))
    for i, f in enumerate((2400, 3100, 2700)):
        d = 0.18
        hit = (square(f, d, 0.3) * 0.5 + square(f * 1.5, d, 0.3) * 0.3) * np.exp(-np.linspace(0, 9, int(d * SR)))
        s = int(i * 0.12 * SR)
        out[s : s + len(hit)] += hit
    return out * 0.6


def stamp():
    d = 0.3
    f = np.linspace(90, 40, int(d * SR))
    return (np.sin(2 * np.pi * np.cumsum(f) / SR) * env(d, r=0.25) + lowpass(noise(d), 0.3) * env(d, r=0.2) * 0.6) * 1.1


def arpeggio(notes, step=0.07, duty=0.25, gain=0.5):
    out = np.zeros(int((len(notes) * step + 0.3) * SR))
    for i, n in enumerate(notes):
        d = step * 2.2
        tone = square(hz(n), d, duty) * env(d, r=0.08)
        s = int(i * step * SR)
        out[s : s + len(tone)] += tone
    return out * gain


def shimmer(d=1.3):
    f = np.linspace(300, 900, int(d * SR)) * (1 + 0.02 * np.sin(np.linspace(0, 60, int(d * SR))))
    return (triangle(f, d) * 0.6 + square(f * 1.5, d, 0.1) * 0.15) * np.sin(np.linspace(0, np.pi, int(d * SR))) * 0.5


def flap():
    return lowpass(noise(0.07), 0.2) * env(0.07, r=0.05) * 0.9


def chime():
    return arpeggio(["E5", "C5"], step=0.18, duty=0.5, gain=0.35)


def ring_burst(d=0.9):
    t = t_axis(d)
    f = np.where((t * 22).astype(int) % 2 == 0, 1320.0, 1660.0)  # the "purupuru" trill
    return square(f, d, 0.5) * env(d, r=0.05) * 0.28


def click():
    return square(2200, 0.02) * env(0.02, r=0.015) * 0.4


def buzz():
    return square(110, 0.35, 0.5) * env(0.35, r=0.1) * 0.35


def effects(scenes: dict[str, float]) -> Track:
    s2, s3, s4, s5, s6, s7, s8 = (scenes[k] for k in ("s2", "s3", "s4", "s5", "s6", "s7", "s8"))
    tr = Track()
    for cut in (s2, s3, s4, s5, s6, s7, s8):  # pixel dissolve between scenes
        tr.add(cut - 0.35, whoosh(0.7), 0.45)
    tr.add(0.3, arpeggio(["A4", "C5", "E5", "A5"], step=0.09), 0.9)  # title

    for at, d in ((0.9, 0.6), (1.6, 0.9), (2.7, 0.5), (3.3, 0.5), (3.8, 0.6)):
        typing(tr, s2 + at, d)
    tr.add(s2 + 4.0, whoosh(1.6), 0.5)
    tr.add(s2 + 5.8, arpeggio(["E4", "D#4", "D4", "C#4"], step=0.14, duty=0.5), 0.9)  # stolen

    for at, d in ((0.9, 0.45), (1.4, 0.7), (2.2, 0.4), (2.7, 0.4), (3.2, 0.6)):
        typing(tr, s3 + at, d)
    tr.add(s3 + 4.3, whoosh(0.9), 0.4)
    tr.add(s3 + 5.2, fall_whistle(), 1.0)
    tr.add(s3 + 5.65, splash(), 0.9)
    tr.add(s3 + 5.75, clank(), 0.9)
    tr.add(s3 + 5.7, whoosh(0.4, up=False), 0.3)
    tr.add(s3 + 7.25, stamp(), 1.0)

    tr.add(s4 + 3.0, shimmer(), 0.9)
    tr.add(s4 + 6.0, fall_whistle(), 1.0)
    tr.add(s4 + 6.45, splash(), 0.9)
    tr.add(s4 + 6.55, clank(), 0.9)
    tr.add(s4 + 6.95, stamp(), 1.0)

    for at, d in ((0.9, 0.5), (1.5, 0.8), (2.5, 0.5), (3.1, 0.6)):
        typing(tr, s5 + at, d)
    k = 0
    while k * 0.14 < 1.4:
        tr.add(s5 + 3.6 + k * 0.14, flap(), 0.7)
        k += 1
    tr.add(s5 + 5.0, chime(), 1.0)
    tr.add(s5 + 7.4, click(), 1.0)

    for at in (0.6, 1.9, 3.2, 4.5):  # Den Den Mushi rings until the decision
        tr.add(s6 + at, ring_burst(0.9 if at < 4.5 else 0.6), 1.0)
    tr.add(s6 + 1.2, arpeggio(["G5", "C6"], step=0.06, duty=0.5, gain=0.3), 1.0)  # notification pop
    tr.add(s6 + 5.0, click(), 1.0)
    tr.add(s6 + 5.4, arpeggio(["C5", "E5", "G5", "C6"], step=0.07), 0.8)

    typing(tr, s7 + 0.3, 0.4)
    tr.add(s7 + 0.8, buzz(), 1.0)
    typing(tr, s7 + 1.9, 0.4)
    tr.add(s7 + 2.6, arpeggio(["C5", "E5", "G5", "C6", "E6"], step=0.06), 0.9)

    tr.add(s8 + 0.3, arpeggio(["A3", "E4", "A4", "C5", "E5", "A5"], step=0.05, duty=0.5), 1.0)
    return tr


# ---------------------------------------------------------------------- narration and mix
def read_audio(path: Path) -> np.ndarray:
    raw = subprocess.run(["ffmpeg", "-v", "error", "-i", str(path), "-f", "s16le", "-ac", "1", "-ar", str(SR), "-"], capture_output=True, check=True).stdout
    return np.frombuffer(raw, dtype=np.int16).astype(np.float64) / 32768


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--lang", choices=["es", "en"], required=True)
    lang = p.parse_args().lang
    spec = json.loads((ROOT / "narration.json").read_text(encoding="utf-8"))
    scenes = {s["id"]: float(s["start"]) for s in spec["scenes"]}

    voice = Track()
    for s in spec["scenes"]:
        voice.add(s["start"] + 0.35, read_audio(ROOT / "assets" / "narration" / f"{lang}-{s['id']}.mp3"), 1.0)

    # duck the music under the voice (smoothed envelope of the narration)
    level = np.convolve(np.abs(voice.buf), np.ones(4410) / 4410, mode="same")
    duck = np.convolve((level > 0.01).astype(float), np.ones(8820) / 8820, mode="same")
    m = music().buf * (0.55 - 0.35 * np.clip(duck, 0, 1))
    m[: int(1.0 * SR)] *= np.linspace(0, 1, int(1.0 * SR))  # fade in
    fade = int(1.5 * SR)
    end = int(LENGTH * SR)
    m[end - fade : end] *= np.linspace(1, 0, fade)
    m[end:] = 0

    mix = m + effects(scenes).buf * 0.55 + voice.buf * 1.0
    mix = mix[:end]
    mix /= max(1e-9, np.max(np.abs(mix))) / 0.89  # peak at about -1 dBFS
    pcm = (np.clip(mix, -1, 1) * 32767).astype(np.int16)
    stereo = np.repeat(pcm[:, None], 2, axis=1)
    out = ROOT / "assets" / f"mix-{lang}.wav"
    with wave.open(str(out), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes(stereo.tobytes())
    print(f"wrote {out} ({len(pcm) / SR:.1f}s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
