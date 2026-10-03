# Kairoseki launch video

A 60-second pixel-art video, in English and Spanish, built with [HyperFrames](https://hyperframes.heygen.com):
HTML + a GSAP timeline, rendered frame by frame in headless Chrome.

- `world.js` paints the pixel world at 480x270 real pixels (shown 4x): the seastone, ships and crews, the bottle,
  the messenger gull, the snail phone, sea, sky and moon. Every frame is a pure function of the time, so any frame
  can be rendered on its own.
- `index.html` holds the scenes, the copy in both languages (`lang` variable) and the timeline.
- `narration.json` is the voiceover script per scene; `tools/narrate.py` turns it into speech with Edge TTS.
- `tools/soundtrack.py` synthesizes an original chiptune loop and the sound effects on the animation's cues, then
  mixes them with the narration (music ducks under the voice). No samples, nothing to license.

## Build

Needs Node.js 22+, FFmpeg and [uv](https://docs.astral.sh/uv/).

```bash
uv run --no-project --with edge-tts python tools/narrate.py          # voice, both languages
uv run --no-project --with numpy python tools/soundtrack.py --lang es
uv run --no-project --with numpy python tools/soundtrack.py --lang en
for l in es en; do
  npx hyperframes render --output renders/silent-$l.mp4 --quality high --variables "{\"lang\":\"$l\"}"
  ffmpeg -i renders/silent-$l.mp4 -i assets/mix-$l.wav -map 0:v -map 1:a -c:v copy \
    -af loudnorm=I=-14:TP=-1:LRA=11 -c:a aac -b:a 192k -shortest renders/kairoseki-$l.mp4
done
```

The rendered videos are attached to the GitHub releases.
