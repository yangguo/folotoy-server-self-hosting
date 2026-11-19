# Builds the single-module xiaozhi-server from a pinned commit.
# MIT: https://github.com/xinnan-tech/xiaozhi-esp32-server
# Tag v0.9.8, commit 8f2dda09cf18f1c1ece0f906eee4cc2fabb7fb58.
# Does not use a floating :latest tag.
FROM python:3.10-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates ffmpeg git libopus0 \
    && rm -rf /var/lib/apt/lists/*

ARG XIAOZHI_SERVER_COMMIT=8f2dda09cf18f1c1ece0f906eee4cc2fabb7fb58
RUN git clone --depth 1 --branch v0.9.8 https://github.com/xinnan-tech/xiaozhi-esp32-server.git /tmp/src \
    && test "$(git -C /tmp/src rev-parse HEAD)" = "${XIAOZHI_SERVER_COMMIT}" \
    && mkdir -p /opt/xiaozhi-esp32-server \
    && cp -a /tmp/src/main/xiaozhi-server/. /opt/xiaozhi-esp32-server/ \
    && rm -rf /tmp/src

COPY requirements-runtime.txt /tmp/requirements-runtime.txt
RUN pip install --no-cache-dir -r /tmp/requirements-runtime.txt

# Upstream SileroVAD loads models/snakers4_silero-vad/src/silero_vad/data/silero_vad.onnx.
RUN python -c "import pathlib, shutil, silero_vad; src=pathlib.Path(silero_vad.__file__).parent; hits=list(src.rglob('silero_vad.onnx')); assert hits, src; dest=pathlib.Path('/opt/xiaozhi-esp32-server/models/snakers4_silero-vad/src/silero_vad/data'); dest.mkdir(parents=True, exist_ok=True); shutil.copy(hits[0], dest/'silero_vad.onnx')"

WORKDIR /opt/xiaozhi-esp32-server
COPY config/server.config.example.yaml /opt/passport/config/server.config.example.yaml
COPY scripts/write_config.py /opt/passport/scripts/write_config.py
ENV XIAOZHI_HOME=/opt/xiaozhi-esp32-server
ENV PASSPORT_AUTH_FILE=/opt/passport/runtime/auth_key
EXPOSE 8000 8003
CMD ["sh", "-c", "python /opt/passport/scripts/write_config.py && python app.py"]
