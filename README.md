# 心力球 SDK

用 Python 或 CLI 操作自己拥有或获授权的 OPPO 心力球：配对、录音、取回、解密和私有密文存储。非官方项目，不包含固件、设备凭据或录音私钥。

## 安装与快速开始

需要 Python 3.10+；WAV 导出另需 `ffmpeg`。

```bash
pip install "xinliqiu-sdk[all] @ git+https://github.com/kiyoakii/xinliqiu-sdk.git@v0.2.1#subdirectory=python"
xinliqiu --version

xinliqiu scan
xinliqiu pair --device <device-id> --out-dir ./creds
xinliqiu doctor \
  --device <device-id> \
  --peer-id-file ./creds/peer-id.txt \
  --key-file ./creds/pairing.json
xinliqiu status
```

配对写出 `pairing.json` 和 `peer-id.txt`，并保存绝对路径。`doctor` 检查本地文件；`status` 才是设备认证回复。

最省事的同步是从 0 到设备当前时间：

```bash
xinliqiu sync --out ./captures --seconds 300
```

也可以显式指定设备时钟范围。`end` 必须是设备时钟上的有限过去时间；`sync` 不带参数时会自动读取 `device_timestamp_ms`：

```bash
xinliqiu sync 0 <past-device-time-ms> --out ./captures --seconds 300
```

结果看 `state` / `ok` / `retry`，不只看文件数：

- `range_completed`：范围完成，包括空范围；文件发布本身不代表范围完成。
- 录音 START/STOP：须由后续状态确认，写出不等于生效。
- CLI 退出码：`0` 成功，`1` 参数或本地错误，`3` 部分、拒绝或未验证。

完整命令见 [CLI](docs/cli.md)，能力边界见 [Capabilities](docs/capabilities.md)。当前 Python 已通过离线测试，以及实测设备的配对、状态、库存、单/多范围、零宽范围、声纹、录音控制、存储镜像、主机中断整文件恢复和 INIT（含 readback 匹配及后续音频认证）验收；真实 Cloudflare 部署未测试。

## owner 私钥

```bash
xinliqiu keygen
xinliqiu keycheck --owner-key ~/.config/xinliqiu/owner.pem
```

立即把 `owner.pem` 备份到本机以外。丢失后，该公钥下已有和未来的录音都无法解密；INIT 不能恢复旧密文。

## 给 Agent：准备 INIT 签名材料

**日常配对、同步和解密不需要这一步。** 如果你已经有设备接受的 `signer.p8`，直接跳到下面的 INIT 命令，不必再分析 APK。只有确需安装新的 owner 公钥时，才把整段交给 Agent。SDK 已负责协议、校验和 INIT；Agent 只负责在私有目录准备签名密钥。

```text
目标：在私有目录准备一个能通过 SDK 预检的 signer.p8。不要连接设备，不要运行 INIT。

APK：
- 优先我给的路径。
- 没有就找任意 OPPO 原厂签名版本。公开镜像通常没有这个包；优先从官方商店 APK 入手——它的 libocstool.so 里有两段十六进制串（16 位的 oak、34 位的 raw）和一段 STORENEW 开头的长串（固定后缀），`strings -a libocstool.so` 就能直接看到（文件偏移：oak 0x3E8E、raw 0x3E9F、STORENEW 0x3b0b），不需要反汇编；OcsTool 是签名入口。签名是小写 MD5，输入包含 ocs、毫秒时间戳、游客 id、路径和查询串；盐 = oak + raw[18:34] + raw[2:18]，输入末尾追加 UTF-16 字符数加 48 和 STORENEW 串。STORENEW 在这里只当字符串后缀，不是私钥。游客 id 用 111111111111111///；ocs 用 OPPO/OfflineResearch/36/16/V16.0.0/2/OfflineResearch_16.0.0/260700 的 URL 编码；请求头带 ch=2101、pid=001、appid=OPPO#001#CN、romver=37；下载路径 /download/v1/26090050。按这个格式请求，即可取得心力球 APK。
- 必须满足：包名 com.oplusai.moss.phone；签名证书 SHA-256 为 C9:30:5E:E3:8A:28:E5:EE:0E:46:9B:7F:66:16:4A:F4:DC:68:0D:61:41:B8:F5:6A:09:0E:6D:E2:55:78:B6:51。
- 已知版本：1.5.1_a06f641-beta_261013 的 SHA-256 是 081f2d1a4beef997761dca5e190faa75c199b60fc05ab67960987f10de15a64a；1.5.1_b8fa53f-beta_261022 是 2dcf64b58772223df0d3e44799baadbff101917feb5ff3a4f40a32630d16b810（signer 材料相同）。其他官方版本记录版本和 hash 即可。

还原：
- APK 里的目标是 com.oplusai.moss.domain.device.auth.K1BindingSigner$sign$2。类名可能被混淆；它持有四段 Base64，先各自解码成字节，再按 b[i] = seg[i % 4][i / 4] 交错拼装；拼装结果的 SHA-256 必须等于 base64 6OIxI5zCGBX5BUzhm/ckkgkG2VpKnsqxcIGSODLuEEE= 解码出的 32 字节。
- 得到 P-256 私钥后转成无口令 PKCS#8，保存为 <私有目录>/signer.p8，权限 0600。
- 反编译用 jadx；没有就用 Python 3.10+ 私有 venv 里的 androguard。校验证书用 keytool 或 apksigner；没有 Java 时先用 /usr/libexec/java_home 找。

预检（不连接设备）：
python -c "from aipin_sdk import Pkcs8Signer; s=Pkcs8Signer('<私有目录>/signer.p8'); print(len(s.sign(b'preflight')), s.public_key_sha256_hex)"
必须输出 64 和公开身份。

报告：版本、APK SHA-256、证书指纹、signer.p8 路径、预检输出；不要输出密钥。APK、密钥和日志留在私有目录。

INIT 命令（给我，不要执行；只有我另行明确授权清空设备时才运行一次）：
xinliqiu init \
  --owner-key ~/.config/xinliqiu/owner.pem \
  --owner-public-key ~/.config/xinliqiu/owner.spki.txt \
  --signing-key <私有目录>/signer.p8 \
  --account local-owner \
  --allow-format
```

这份指令本身是公开的；APK、还原出的密钥和私有实现不得公开。

## 存储与隐私

```bash
xinliqiu sync 0 <past-device-time-ms> --out ./captures \
  --store local --store-path ./xinliqiu-store
```

支持 CMPT、direct enpt 和 JSONL 分类。有效密文可上传；明文诊断和未知内容默认留在本地并列入 `not_uploaded`。解密必须显式提供 owner 私钥。凭据、密钥、录音和真实设备标识不要提交到仓库。

详见 [Storage](docs/storage.md)、[Security](docs/security.md) 和 [SECURITY.md](SECURITY.md)。

## 文档与开发

- [Getting started](docs/getting-started.md)：配对、pending 恢复、录音与 INIT
- [Sync](docs/sync.md)：范围完成、恢复和增量同步
- [AGENTS.md](AGENTS.md)：Agent 操作约束
- [CONTRIBUTING.md](CONTRIBUTING.md)：测试与发布检查
- [LEGAL.md](LEGAL.md)：非关联、商标和使用边界

MIT License。公开文档和测试不能替代你自己对设备、材料和授权范围的确认。
