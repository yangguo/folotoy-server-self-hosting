# Experimental multilingual Edge TTS wrapper

This optional overlay demonstrates language-based Edge TTS voice selection
without changing the precompiled FoloToy server modules. It is based on the
`Dockerfile.folotoy` and `main.py.smart` files in this directory.

The default Compose deployment is unchanged. To build and use this image from
the repository root:

```sh
docker compose -f docker-compose.yml -f docker-compose.smart.yml \
  up -d --build folotoy
```

Reconnect or restart the toy after recreating the server container. To return to
the official image, run the original Compose file alone:

```sh
docker compose -f docker-compose.yml up -d folotoy
```

The wrapper keeps these configured voices for common outputs:

| Detected output | Voice |
| --- | --- |
| Japanese | `ja-JP-NanamiNeural` |
| Korean | `ko-KR-SunHiNeural` |
| Cantonese markers | `zh-HK-HiuMaanNeural` |
| Predominantly English | `en-US-AriaNeural` |
| Mandarin from a Cantonese role | `zh-CN-XiaoxiaoNeural` |
| Northeast or Shaanxi Chinese role | configured dialect voice |

This is an opt-in prototype. Detection uses the generated text, so short,
mixed, transliterated, or ambiguous responses can be classified incorrectly.
Streaming or sentence-level synthesis may select different voices for different
segments. It also depends on the image entry point continuing to import
`edge_tts` before the TTS engine is used, and on the selected Edge voices still
being available. It does not provide a stable core extension API and should be
retested after changing the FoloToy image tag or Python dependency versions.

The wrapper has not been run against a live FoloToy container in this repository;
test the build, logs, recognition, generated language, and playback on the
target deployment before relying on it.
