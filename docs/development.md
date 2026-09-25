# 开发指南

要求 Go 1.26.3 或更新版本。Windows 已完成实机验证；Windows、Linux、macOS 的 amd64/arm64 构建已在 Windows 上使用 Go 1.27.0、`CGO_ENABLED=0` 交叉编译通过。Linux、macOS 和 Windows arm64 的运行、登录及 VPN 连接仍待目标平台验证。登录、配置与排障见 [使用说明](usage.md)，后续方向见 [阶段计划](roadmap.md)。

## 实现概览

- 固定 XMU API/组织/客户端身份，Sheeta 签名、AES-CBC、RSA 包装。
- 浏览器 SSO + 手动粘贴回调 URL；可注入 `SL_CALLBACK_URL`。
- JSON 会话缓存、到期前五分钟刷新、设备 ID 持久化。
- SecureLink profile 规范化、`UV_*` peer-info、上游 parser 兼容性测试。
- 固定 go-openvpn 与 netstack 版本；依赖补丁暴露原始 PUSH_REPLY，并修复控制消息与握手字段兼容性。
- 不可变、默认拒绝的 ACL 快照；支持实测的 IPv4 CIDR、`proto:any/tcp`、`port:any`/单端口/分号列表。支持精确域名和子域名通配授权；数字 IPv4 被放在 domain 字段时按单地址处理。
- `check` 无 TUN 握手诊断；`probe` 仅通过 netstack 对 ACL 授权的 IPv4:端口建立 TCP 连接，随后关闭，不发送应用层数据。
- SOCKS5 NO AUTH + IPv4/DOMAIN CONNECT、双向传输和 TCP 半关闭。
- 有界指数退避重连；断线或 PUSH 策略更新撤销旧 ACL，取消未完成拨号并关闭旧连接，重新获取完整 ACL 后才 Ready。

不会创建 TUN/TAP/DCO/Wintun，不修改主机路由或 DNS，不提供 DIRECT 回退。VPN remote 和测试目标只接受 IPv4 字面量；固定 HTTPS 控制面主机名仍由 HTTP transport 正常解析。目标域名的 A/CNAME 查询仅经用户态隧道发送到服务器下发的 DNS；不读取系统 hosts 或使用系统解析器。DNS 查询有超时、报文和别名链长度限制，不缓存跨会话授权。

## 本机构建与离线检查

Windows:

```powershell
go test ./...
go vet ./...
go -C third_party/go-openvpn test ./...
New-Item -ItemType Directory -Force bin | Out-Null
go build -o bin/securelink2socks.exe ./cmd/securelink2socks
./bin/securelink2socks.exe --help
```

Linux/macOS:

```sh
go test ./...
go vet ./...
go -C third_party/go-openvpn test ./...
mkdir -p bin
go build -o bin/securelink2socks ./cmd/securelink2socks
./bin/securelink2socks --help
```

首次构建会下载已固定版本的依赖；测试本身不访问 XMU。测试数据全部为合成数据，见 [testdata/securelink](../testdata/securelink/README.md)。上游依赖测试可能使用本地回环网络/内存连接。

初期离线测试结果及上游并发测试的超时记录见 [离线验证记录](offline-validation.md)。

## 交叉编译与 tag 产物

项目不依赖 CGO。可在 Windows PowerShell 中指定目标平台，例如：

```powershell
$env:CGO_ENABLED = '0'
$env:GOOS = 'linux'
$env:GOARCH = 'arm64'
New-Item -ItemType Directory -Force bin | Out-Null
go build -o bin/securelink2socks-linux-arm64 ./cmd/securelink2socks
```

在 Linux/macOS shell 中交叉编译 Windows 示例：

```sh
mkdir -p bin
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/securelink2socks-windows-amd64.exe ./cmd/securelink2socks
```

支持的构建目标及 [构建 workflow](../.github/workflows/build-binaries.yml) 的 artifact 名称：

| 目标系统 | 架构 | artifact 名称 |
| --- | --- | --- |
| Windows | amd64、arm64 | `securelink2socks-windows-amd64`、`securelink2socks-windows-arm64` |
| Linux | amd64、arm64 | `securelink2socks-linux-amd64`、`securelink2socks-linux-arm64` |
| macOS | amd64、arm64 | `securelink2socks-darwin-amd64`、`securelink2socks-darwin-arm64` |

## 联网验证

普通测试不访问 XMU。使用自己的会话和有权访问的资源时，可显式运行以下回归：

```powershell
$env:SECURELINK2SOCKS_E2E = '1'
$env:SECURELINK2SOCKS_TEST_TARGET = '<授权的IPv4>:<端口>'
go test ./internal/app -run '^TestLiveSOCKS$' -count=1 -v
```

如会话位于自定义目录，沿用 `SECURELINK2SOCKS_HOME`。该测试会创建并关闭自己的 VPN 会话，验证 SOCKS 连接、连接撤销和重连恢复。

真实环境的历史问题、修复过程和验证边界见 [实机验证记录](live-validation.md)。离线记录反映各次检查时的代码与环境，不作为当前测试覆盖率承诺。

## 协议与依赖

- [协议调查](protocol-notes.md)：握手、数据通道、ACL 与域名解析策略。
- [上游补丁](upstream-patch.md)：固定依赖及本地兼容性修改。
- [NOTICE](../NOTICE) 与 [第三方许可证](../LICENSES/)：参考项目和依赖归属。

提交测试材料时使用合成数据，不包含 token、会话 Cookie、完整回调 URL、原始 profile 或 PUSH 内容。
