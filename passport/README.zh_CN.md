# AI Passport 独立语音服务

这是一套可选部署，不修改仓库根目录的旧玩具 `docker-compose.yml`。旧玩具继续使用 EMQX、`8085/udp` 和 `8082` 上的语音文件。Passport 不加入那个 Compose，也不共用它的卷和端口。

## 选型与上游封装说明

固件以 `yangguo/xiaozhi-esp32` 的 `e46aa91e8847206439da6e3b4135d694ca9372f1` 为准，**不修改设备固件**。设备实际刷入的 SHA 未知，不能把这次源码核对当成已刷固件的证明。

对话后端选用 [xinnan-tech/xiaozhi-esp32-server](https://github.com/xinnan-tech/xiaozhi-esp32-server) 的单模块 Python 服务，标签 `v0.9.8`，提交 `8f2dda09cf18f1c1ece0f906eee4cc2fabb7fb58`，许可证 MIT。运行时通过本仓库内的可审查包装包 [passport_server](passport_server/patches.py)（入口 [runner.py](passport_server/runner.py)）对固定上游提交做最小运行时包装（不直接改动上游检出源码）：

1. **OTA 预配设备身份验证与移除 `allowed_devices` 免验绕过**（[device_auth.py](passport_server/device_auth.py)、[provision_device.py](scripts/provision_device.py)）：
   - 只有在 `devices.yaml` 中已登记且启用的设备，并在 OTA 请求提供匹配的 per-device 凭据（设备专属 OTA 路径 `/xiaozhi/ota/d/<secret>/`、`X-OTA-Secret` 或 `Authorization: Bearer <secret>`）和 `Device-Id` / `Client-Id` 时才签发 WebSocket token。
   - WebSocket token 签名同时绑定 `client_id`、`device_id`、`ts` 与设备 `ota_secret_sha256`，并校验过期时间。
   - 彻底移除上游 `allowed_devices` 命中后跳过 token 校验的绕过，以及 `/mcp/vision/explain` 上的 `web_test_client` 硬编码后门。
2. **日志源头脱敏与最小化错误记录**（[redaction.py](passport_server/redaction.py)、[patches.py](passport_server/patches.py)）：
   - 在鉴权后、进入上游 `ConnectionHandler` 前清除 `Authorization` 等敏感请求头；禁用 `aiohttp` 默认 access log，防止设备专属 OTA 路径写入日志。
   - loguru 挂载全局脱敏 patcher 并对 stdout 与文件日志均关闭 `diagnose=False` / `backtrace=False`；stdlib 日志挂载脱敏过滤器；运行时注册配置中的供应商密钥与 URL 用户信息。
   - OpenAI ASR / TTS 失败仅记录状态码、脱敏端点（不含 `userinfo` 与查询参数）及响应字节数，**不原样打印供应商响应正文**；MCP 发送调试日志仅记录 `method` 与 `id`，不打印含 Vision JWT 的完整载荷。
3. **非阻塞、可超时与可取消的 OpenAI ASR**（[async_openai_asr.py](passport_server/async_openai_asr.py)）：
   - 用基于 `httpx.AsyncClient` 的异步实现替换上游在事件循环内阻塞的同步 `requests.post()`，强制配置连接/读取/写入/连接池和总超时（默认 `5/15/10/5/20` 秒）。
   - 音频上传直接以限长内存 WAV 缓冲完成；当显式保留本地音频文件时，将磁盘检查与写盘移入 `asyncio.to_thread()`，避免阻塞共享事件循环。
   - 手动录音 `listen.stop` 异步派发任务，不阻塞其他会话的 OTA/WebSocket/hello；`abort` 或断线时立即取消在途 ASR 请求。
   - `hello` 阶段等待连接后台组件与音频线程就绪后再返回服务端 `hello`，消除首轮音频窗口竞争；OTA 响应显式下发 `websocket.version: 1`，避免切服时保留旧协议版本。
4. **真实配置与演示模式隔离、强制鉴权、跨进程锁与原子写入**（[write_config.py](scripts/write_config.py)、[fs_utils.py](passport_server/fs_utils.py)、[entrypoint.sh](scripts/entrypoint.sh)）：
   - 默认 `PASSPORT_MODE=real`，读取只读模板 `passport/config/server.config.yaml` 渲染 `data/.config.yaml`；若真实配置缺失或 `server.auth.enabled` 未显式为 `true`，在配置渲染及运行时初始化阶段均拒绝启动（fail closed），**绝不**跳过设备鉴权或静默切回假供应商。
   - 本地演示（`run_isolated.sh`）使用 `passport/runtime-demo/`，Compose 演示（`docker-compose.demo.yml`）使用独立项目名 `folotoy-passport-demo` 与 `passport/runtime-compose-demo/`，**绝不读取或删除真实 `passport/runtime/devices.yaml`、`auth_key` 或真实配置**。
   - `auth_key`、`devices.yaml` 与 `data/.config.yaml` 均通过 `tempfile.mkstemp` + `os.fchmod(0o600)` + `os.replace` 原子写入，并对 `devices.yaml` 和首次 `auth_key` 创建使用侧车锁文件 `flock` 跨进程加锁。
   - 容器入口通过 `exec python /opt/passport/passport_server/runner.py` 接管 PID 1，确保收到 `SIGTERM` 优雅清理退出。
   - Silero VAD 直接使用固定上游仓库内自带的 `silero_vad.onnx`（启动与构建时校验其 SHA-256 摘要），配合 `onnxruntime` 运行，不再安装 `silero_vad` 或拉入 `torch`。

## 固件在这一提交里的实际行为

- 板型 `folotoy/ai-passport`：ESP32-C3、8 MB、无 PSRAM、ES8311、ST7789。I2S 输入输出都是 24000 Hz。见 [config.h](https://github.com/yangguo/xiaozhi-esp32/blob/e46aa91e8847206439da6e3b4135d694ca9372f1/main/boards/folotoy/ai-passport/config.h#L14-L17)。
- 编码器仍把麦克风重采样到 16000 Hz，WebSocket hello 也声明 `sample_rate: 16000`、`frame_duration: 60`。见 [audio_service.cc](https://github.com/yangguo/xiaozhi-esp32/blob/e46aa91e8847206439da6e3b4135d694ca9372f1/main/audio/audio_service.cc#L62-L75) 和 [websocket_protocol.cc](https://github.com/yangguo/xiaozhi-esp32/blob/e46aa91e8847206439da6e3b4135d694ca9372f1/main/protocols/websocket_protocol.cc#L210-L228)。
- `websocket.version` 为 1 时二进制帧是裸 Opus（未下发该键时会保留设备 NVS 旧值，因此自建 OTA 显式下发 `version: 1`）。见 [ota.cc](https://github.com/yangguo/xiaozhi-esp32/blob/e46aa91e8847206439da6e3b4135d694ca9372f1/main/ota.cc#L180-L196) 与 [websocket_protocol.cc](https://github.com/yangguo/xiaozhi-esp32/blob/e46aa91e8847206439da6e3b4135d694ca9372f1/main/protocols/websocket_protocol.cc#L79-L86)。
- 默认 OTA 是 `https://api.tenclass.net/xiaozhi/ota/`。NVS `wifi/ota_url` 可在设备配网门户中改写，**无需改固件代码**。
- OTA 若只返回 `websocket.url`、`websocket.token` 和 `websocket.version`，设备走 WebSocket，并把 token 放进 `Authorization` 请求头。

## 真实配置模式（默认）vs 演示/测试模式（显式）

### 模式 A：真实部署（`PASSPORT_MODE=real`，默认）

1. 复制真实配置模板（`server.config.yaml` 已被 `.gitignore` 忽略，不会提交到仓库）：

   ```sh
   cp passport/config/server.config.example.yaml passport/config/server.config.yaml
   ```

   按实际情况修改其中的 `ASR`、`LLM`、`TTS` 地址和密钥，以及对外可达的 `server.websocket`（建议 `wss://...`）与 `server.vision_explain`（建议 `https://...`）。**不要手动修改生成的 `data/.config.yaml`**，重启时它会由只读的 `server.config.yaml` 重新渲染，真实供应商设置会在重启/重建容器后完整保持。

2. 预配设备（不改固件，参见下文“预配设备与设备侧接入”）。

3. 启动真实模式 Compose（不会启动 `fake-provider`）：

   ```sh
   cd passport
   docker compose up --build
   ```

### 模式 B：演示 / 回归验收模式（显式 `PASSPORT_MODE=demo`）

演示模式使用本地 `fake_provider.py`（只返回固定文字和正弦波 WAV，不是语音理解或真实合成音色），仅用于隔离契约/回归测试：

- **本地无 Docker 运行**（启动 pinned 上游服务 + `fake_provider.py`，运行契约测试与完整回归测试；所有演示状态、日志与演示专用 venv 写入隔离目录 `passport/runtime-demo/`，每次运行先解除已有输出文件的软/硬链接再重建；已有 `passport/runtime/venv` 与上游检出仅以只读方式复用，演示 `pip` 使用 `PIP_CONFIG_FILE=/dev/null` 与 `--isolated` 受控配置并在安装前校验解析目标目录位于 `passport/runtime-demo/venv` 内；演示忽略环境中的 `PASSPORT_AUTH_KEY`，只使用 `passport/runtime-demo/auth_key`；不会修改真实 `passport/runtime/devices.yaml`）：

  ```sh
  sh passport/scripts/run_isolated.sh
  ```

- **Docker 演示模式**（使用独立项目名 `folotoy-passport-demo` 与独立目录 `passport/runtime-compose-demo/`，不挂载真实 `./runtime`，并把 `PASSPORT_AUTH_KEY` 覆盖为空）。务必显式传 `-p`，否则环境中的 `COMPOSE_PROJECT_NAME` 会覆盖文件内的 `name:` 而复用真实项目：

  ```sh
  cd passport
  docker compose -p folotoy-passport-demo -f docker-compose.yml -f docker-compose.demo.yml up --build
  ```

  在演示模式下，`fake-provider` 仅对 Compose 内部网络可见，不向宿主机发布端口。

## 预配设备与设备侧接入（无需改固件）

未修改的固件会在 OTA POST 时自动带上 `Device-Id`（MAC 地址）和 `Client-Id`（设备 UUID），并向配置的 `wifi/ota_url` 发起请求。通过服务端预配按设备生成高熵一次性 OTA 路径凭据，即可在不改动固件代码的前提下完成设备身份绑定：

1. **新增预配设备**：

   ```sh
   python3 passport/scripts/provision_device.py add \
     --device-id "<设备MAC，如 aa:bb:cc:dd:ee:01>" \
     --client-id "<可选，绑定设备UUID>" \
     --name "my-passport" \
     --ota-base "https://<你的Passport域名>"
   ```

   - `passport/runtime/devices.yaml`（`0600`）只保存 `ota_secret_sha256` 摘要，不落盘明文 secret。
   - 命令终端会输出一次专属 OTA URL：`https://<你的Passport域名>/xiaozhi/ota/d/<device-secret>/`。

2. **将专属 OTA URL 填入设备**：
   在设备配网门户的高级设置中，把 OTA URL（NVS `wifi/ota_url`）设为上一步输出的设备专属 OTA URL 并保存重启。

3. **设备管理命令**：
   - 查看已登记设备：`python3 passport/scripts/provision_device.py list`
   - 轮换设备密钥（旧 OTA URL 与旧 WS token 立即失效）：`python3 passport/scripts/provision_device.py rotate --device-id "<设备MAC>" --ota-base "https://<你的Passport域名>"`
   - 吊销设备（立即拒绝 OTA 与 WS 连接）：`python3 passport/scripts/provision_device.py revoke --device-id "<设备MAC>"`

4. **回退到官方服务器**：
   将设备 `wifi/ota_url` 改回 `https://api.tenclass.net/xiaozhi/ota/`（或清空使用编译默认值）并重启。

## 网络与安全部署建议

- 默认 Compose 仅将 `18010`（WebSocket）和 `18013`（HTTP OTA/Vision）发布在宿主机 `127.0.0.1` 上。注意：在 Docker Engine 低于 `28.0.0` 的环境中，同二层网络主机的回环端口隔离较弱，切勿直接将未保护的端口暴露到不可信局域网或公网。
- **生产/局域网设备接入建议**：在 Passport 前放置反向代理提供 **HTTPS（`/xiaozhi/ota/`）与 WSS（`/xiaozhi/v1/`）**，或限制在受控私网/VPN 内访问。明文 `http://` / `ws://` 会使路径中的 OTA secret、响应中的 Bearer token 和语音流在网络上明文传输，并存在中间人篡改风险。
- **反向代理日志隔离（必须采用模板配置，勿使用默认 `combined` 格式）**：
  - 设备专属 OTA URL 形如 `/xiaozhi/ota/d/<device-secret>/`，默认反向代理访问日志会把完整 URI 中的凭据落盘。请直接采用仓库提供的配置模板：
    - Nginx：[proxy/nginx-passport.conf.example](proxy/nginx-passport.conf.example)（对 `/xiaozhi/ota/d/` 关闭 `access_log` 并将 `error_log` 重定向至 `/dev/null emerg`，通过内部重写提取到 `X-OTA-Secret` 请求头后转发给 `/xiaozhi/ota/`；其余路径使用 `map` + `log_format passport_safe` 脱敏 URI、省略原始 `Referer`（固定输出 `"-"`），并清除 `X-Original-URI` / `X-Original-URL` / `X-Rewrite-URL` / `X-Forwarded-Uri` / `X-Envoy-Original-Path` / `Referer`；由于 Nginx 错误日志无法过滤字段且会在上游故障以及 `access_log` 写入失败（`[alert]`）时附加原始 `referrer` 与请求行，模板在 server rewrite 阶段通过严格白名单 `if ($passport_unsafe_referer) { return 400; }`（仅放行空 `Referer` 或裸源站 `scheme://host[:port][/]`）先拦截字面与等价编码的 OTA `Referer`、userinfo 与查询串，同时在所有 `passport_access.log` 写入点加上 `if=$passport_log_access` 对白名单拒绝请求及进入 `/xiaozhi/ota/d/` 前的 server 级拦截跳过访问日志写入，避免磁盘满或短写时经 `alert` 错误日志泄露原始 `Referer`；可观测性权衡：被 `$passport_unsafe_referer` 拒绝的 `400` 请求不会记录到 `passport_access.log`，放行的正常流量仍保留脱敏访问日志与错误日志）。
    - Caddy v2：[proxy/Caddyfile.example](proxy/Caddyfile.example)（对 `/xiaozhi/ota/d/*` 配置 `log_skip`，其余路由通过 `format filter` 脱敏 `request>uri`、`request>orig_uri` 与认证请求头，并剥离链路追踪 URI 头；全局 `log` 选项把 `http.log.error` / `http.handlers.reverse_proxy` 运行时错误日志（后端失败时会带改写前的原始 `request.uri`）从未过滤的默认日志中排除，改写入同样脱敏的 `passport_error.log`）。
  - 若上游还接入了 WAF、OpenTelemetry 或 APM 探针，需同时禁用或脱敏 `/xiaozhi/ota/d/*` 的 `http.target`、`url.path`、`url.full`、`http.url` 字段。
- **real 模式不可关闭鉴权**：`PASSPORT_MODE=real` 及运行时入口会强制检查 `server.auth.enabled: true` 与有效 `auth_key` / `devices_file`，关闭或缺失鉴权将拒绝启动。
- 本仓库所有示例模板、脚本和文档均不包含真实供应商密钥或测试 token；`passport/runtime/`、`passport/runtime-demo/`、`passport/runtime-compose-demo/`、`passport/config/server.config.yaml` 和 `passport/.env` 均已加入 `.gitignore`。

## 验证边界

| 层级 | 已验证内容 | 边界说明 |
| --- | --- | --- |
| 真实上游 Python 进程 + 本地假供应商 + 用户态 Nginx 1.28.0（若可用） | 已通过 `run_isolated.sh` 实跑 `contract_test.py` 与 `regression_test.py`：隔离目录不修改真实 `runtime/` 状态、`run_isolated.sh` 在有/无共享 `runtime/venv` 入口下受控安装不写入共享环境、OTA 预配鉴权/拒绝、`allowed_devices` 不免验、real 模式关闭鉴权拒绝启动、过期/并发吊销锁定、Nginx 模板实际进程验收（`nginx -t`、正常拒绝与实时转发、上游 `502` 故障、`/dev/full` 访问日志写入失败下的 `[alert]` 抑制与负对照）、Caddy 模板解析与代理日志隔离、stdout 与文件日志在 INFO/DEBUG 及 ASR/TTS 失败路径下强制存在且零泄漏、内存 WAV 与非阻塞慢盘 ASR、`abort` 及断线快速取消、0 ms 首轮、长音频基线对照打断与完整尾帧观察、重连与 `SIGTERM` 退出 | 依赖本地假供应商（及 Caddy 的进程内替身），不代表真实 ASR/LLM/TTS 识别与合成质量；Nginx 实跑仅使用用户态 loopback HTTP 端口（未启用真实 TLS 证书） |
| Docker 构建、Compose 与宿主机 Caddy | 已更新 `Dockerfile`、`entrypoint.sh`、`docker-compose.yml`、`docker-compose.demo.yml` 与代理配置模板 | 当前环境无 Docker daemon 及 `caddy` 二进制，未实跑容器构建与真实 `caddy` 进程 |
| 真机端到端 | 未做 | 设备实际刷入 SHA 未知，仍需在真机上完成配网、OTA、首轮录音、播放、打断、重连与官方回退验收 |
