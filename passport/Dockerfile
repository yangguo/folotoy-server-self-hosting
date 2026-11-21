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
RUN pip install --no-cache-dir -r /tmp/requirements-runtime.txt \
    && rm -f /tmp/requirements-runtime.txt

# Upstream v0.9.8 already vendors models/snakers4_silero-vad/src/silero_vad/data/silero_vad.onnx;
# verify its SHA-256 digest directly without pulling torch or silero_vad from PyPI.
RUN python -c "import hashlib, pathlib; p=pathlib.Path('/opt/xiaozhi-esp32-server/models/snakers4_silero-vad/src/silero_vad/data/silero_vad.onnx'); assert hashlib.sha256(p.read_bytes()).hexdigest() == '2623a2953f6ff3d2c1e61740c6cdb7168133479b267dfef114a4a3cc5bdd788f', p"

WORKDIR /opt/xiaozhi-esp32-server
COPY passport_server /opt/passport/passport_server
COPY config/server.config.example.yaml /opt/passport/config/server.config.example.yaml
COPY config/demo.config.yaml /opt/passport/config/demo.config.yaml
COPY scripts/write_config.py /opt/passport/scripts/write_config.py
COPY scripts/provision_device.py /opt/passport/scripts/provision_device.py
COPY scripts/entrypoint.sh /opt/passport/scripts/entrypoint.sh
RUN chmod +x /opt/passport/scripts/entrypoint.sh /opt/passport/scripts/provision_device.py /opt/passport/passport_server/runner.py

ENV XIAOZHI_HOME=/opt/xiaozhi-esp32-server
ENV PASSPORT_MODE=real
ENV PASSPORT_CONFIG_FILE=/opt/passport/config/server.config.yaml
ENV PASSPORT_DEVICES_FILE=/opt/passport/runtime/devices.yaml
ENV PASSPORT_AUTH_FILE=/opt/passport/runtime/auth_key
EXPOSE 8000 8003
ENTRYPOINT ["/opt/passport/scripts/entrypoint.sh"]
