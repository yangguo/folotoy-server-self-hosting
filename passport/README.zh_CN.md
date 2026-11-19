# AI Passport 独立语音服务（第一版）

这是一套可选部署，不修改仓库根目录的旧玩具 `docker-compose.yml`。旧玩具继续使用 EMQX、`8085/udp` 和 `8082` 上的语音文件。Passport 不加入那个 Compose，也不共用它的卷和端口。

## 选型

固件以 `yangguo/xiaozhi-esp32` 的 `e46aa91e8847206439da6e3b4135d694ca9372f1` 为准。设备实际刷入的 SHA 未知，不能把这次源码核对当成已刷固件的证明。

对话后端选用 [xinnan-tech/xiaozhi-esp32-server](https://github.com/xinnan-tech/xiaozhi-esp32-server) 的单模块 Python 服务，标签 `v0.9.8`，提交 `8f2dda09cf18f1c1ece0f906eee4cc2fabb7fb58`，许可证 MIT。它已经实现小智 WebSocket、OTA 和 Opus，不需要在本仓库重写语音链路，也不引入 MQTT 网关。Java 管理端和 MySQL 不在第一版里。

上游镜像名 `server_latest` 没有固定版本，所以这里从该提交构建或检出源码，不用 `latest`。运行时依赖写在 `requirements-runtime.txt`，版本取自该提交的 `requirements.txt`，但去掉了 Torch、FunASR 和 ModelScope。当前配置走 Silero ONNX 和本机 HTTP 供应商。若改回 FunASR，需要自行安装上游完整依赖和模型。

## 固件在这一提交里的实际行为

- 板型 `folotoy/ai-passport`：ESP32-C3、8 MB、无 PSRAM、ES8311、ST7789。I2S 输入输出都是 24000 Hz。见 [config.h](https://github.com/yangguo/xiaozhi-esp32/blob/e46aa91e8847206439da6e3b4135d694ca9372f1/main/boards/folotoy/ai-passport/config.h#L14-L17)。
- 编码器仍把麦克风重采样到 16000 Hz，WebSocket hello 也声明 `sample_rate: 16000`、`frame_duration: 60`。见 [audio_service.cc](https://github.com/yangguo/xiaozhi-esp32/blob/e46aa91e8847206439da6e3b4135d694ca9372f1/main/audio/audio_service.cc#L62-L75) 和 [websocket_protocol.cc](https://github.com/yangguo/xiaozhi-esp32/blob/e46aa91e8847206439da6e3b4135d694ca9372f1/main/protocols/websocket_protocol.cc#L210-L228)。
- 未配置 `websocket.version` 时二进制帧是裸 Opus（协议版本 1），不是 MQTT 网关的 16 字节头。见 [websocket_protocol.h](https://github.com/yangguo/xiaozhi-esp32/blob/e46aa91e8847206439da6e3b4135d694ca9372f1/main/protocols/websocket_protocol.h#L27) 和 [SendAudio](https://github.com/yangguo/xiaozhi-esp32/blob/e46aa91e8847206439da6e3b4135d694ca9372f1/main/protocols/websocket_protocol.cc#L24-L53)。
- 默认 OTA 是 `https://api.tenclass.net/xiaozhi/ota/`。NVS `wifi/ota_url` 可以改成自建地址。见 [Kconfig.projbuild](https://github.com/yangguo/xiaozhi-esp32/blob/e46aa91e8847206439da6e3b4135d694ca9372f1/main/Kconfig.projbuild#L3-L7) 和 [ota.cc](https://github.com/yangguo/xiaozhi-esp32/blob/e46aa91e8847206439da6e3b4135d694ca9372f1/main/ota.cc#L56-L62)。
- OTA 若只返回 `websocket.url` 和 `websocket.token`，设备走 WebSocket，并把 token 放进 `Authorization`。没有空格时固件会加上 `Bearer `。见 [ota.cc](https://github.com/yangguo/xiaozhi-esp32/blob/e46aa91e8847206439da6e3b4135d694ca9372f1/main/ota.cc#L170-L186) 与 [OpenAudioChannel](https://github.com/yangguo/xiaozhi-esp32/blob/e46aa91e8847206439da6e3b4135d694ca9372f1/main/protocols/websocket_protocol.cc#L79-L106)。
- 长按 OK 约 1 秒进入手动听写，松开结束。点击仍是原来的对话开关。唤醒词在该板构建里关闭。屏幕和额外 MCP 不在这一版的验收范围。

因此服务端 `xiaozhi.audio_params.sample_rate` 固定为 16000。设备会把下行 Opus 从 16 kHz 重采样到 24 kHz 喇叭。这和“喇叭时钟本身是 24 kHz”不矛盾。

## 怎么启动

契约测试用的 ASR、LLM、TTS 是 `fake_provider.py`。它只返回固定文字和一段正弦波，用来让真正的 xiaozhi-server 走完会话。它不是语音理解，也不是可用的合成音色。

不安装 Docker 时：

```sh
sh passport/scripts/run_isolated.sh
```

脚本会把 `v0.9.8` 检到 `passport/runtime/`（已忽略），安装 `requirements-runtime.txt`，在 `127.0.0.1:18019` 启动假供应商，在 `127.0.0.1:18010` / `18013` 启动上游服务，然后跑 `scripts/contract_test.py`。认证密钥写在 `passport/runtime/auth_key`，不要提交。

已安装 Docker 时，在 `passport/` 目录：

```sh
docker compose up --build
```

容器只把 `18010`、`18013`、`18019` 发布到宿主机的 `127.0.0.1`。容器内服务监听 `8000` 和 `8003`。假供应商只给 xiaozhi-server 调用。

要给局域网设备用，必须同时改三处，并自己承担暴露面：`PASSPORT_PUBLIC_WS`、端口发布地址，以及设备里的 OTA URL。默认配置没有这一步。认证默认开启，设备白名单为空，所以每个设备都要拿 OTA 下发的 token。不要把示例里的 `replace-with-a-long-random-string` 当成密钥。

## 设备侧切换和回退

1. 确认服务已启动后，把设备 OTA URL 改成 `http://<主机>:18013/xiaozhi/ota/`。固件保存的键是 `wifi/ota_url`。本仓库不负责刷机，也不替你改设备。
2. 设备重启后会 POST 这个地址。响应里的 `websocket.url` 必须是设备能访问的地址。
3. 回退：把 `ota_url` 设回 `https://api.tenclass.net/xiaozhi/ota/`，或清空该项让固件使用编译默认值，然后重启设备。官方账号和原服务器不受这套 Compose 影响。
4. 停掉 Passport 不会改变根目录的旧玩具栈。旧玩具不要指向 `18013`。

风险：刷入固件若不是 `e46aa91e`，协议细节可能不同。自建 OTA 不会自动升级固件，除非另外放入上游认识的 `data/bin` 文件；默认配置不提供固件包。假供应商不能当成日常对话。把端口发布到公网等于让任何能访问 OTA 的人领取 token。

## 验证边界

| 层级 | 这一版做了什么 |
| --- | --- |
| 上游进程 + 本地假供应商 | `run_isolated.sh` 的目标。通过只说明协议会话，不说明模型或喇叭 |
| Docker 构建 | 提供了 Compose。本环境若没有 Docker，就不能声称容器已启动 |
| 真实 ASR/LLM/TTS | 未做。需要自己把 `data/.config.yaml` 里的供应商换成有密钥的地址，且不要提交密钥 |
| 真机 | 未做。按键、打断、重连、回退官方地址都还要在设备上单独验收 |
