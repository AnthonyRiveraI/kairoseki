"""Generate one narration clip per scene and language with Edge TTS, and check each fits its scene.

    uv run --with edge-tts python tools/narrate.py            # both languages
    uv run --with edge-tts python tools/narrate.py --lang es

Writes assets/narration/<lang>-<scene>.mp3 and prints each clip's length against the scene's budget.
Swap the voice in narration.json (or this function) to use another TTS engine.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
from pathlib import Path

import edge_tts

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "narration"
LEAD_IN = 0.35  # the line starts this long after its scene does


def duration(path: Path) -> float:
    out = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(path)],
        capture_output=True, text=True, check=True,
    )
    return float(out.stdout.strip())


async def main(langs: list[str], rate: str) -> int:
    spec = json.loads((ROOT / "narration.json").read_text(encoding="utf-8"))
    OUT.mkdir(parents=True, exist_ok=True)
    too_long = 0
    for lang in langs:
        for scene in spec["scenes"]:
            path = OUT / f"{lang}-{scene['id']}.mp3"
            await edge_tts.Communicate(scene[lang], spec["voices"][lang], rate=rate).save(str(path))
            length = duration(path)
            budget = scene["duration"] - LEAD_IN - 0.3
            ok = length <= budget
            too_long += not ok
            print(f"{lang} {scene['id']}: {length:4.1f}s / {budget:4.1f}s {'ok' if ok else 'TOO LONG'}")
    return 1 if too_long else 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--lang", action="append", choices=["es", "en"])
    p.add_argument("--rate", default="+6%")
    a = p.parse_args()
    raise SystemExit(asyncio.run(main(a.lang or ["es", "en"], a.rate)))
