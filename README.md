# securelink2socks

厦门大学 SecureLink → 用户态 TCP/IP → SOCKS5 网关。要求 Go 1.26.3 或更新版本，优先支持 Windows。

**当前是兼容性验证阶段，尚不是可用的 SOCKS 代理。** 真实 SSO、API 刷新、TLS 验证、AES-128-GCM 握手、IPv4 分配和结构化 ACL 已成功；已成功解密网关 keepalive。按初始计划，仍需完成已知授权校内服务的用户态 TCP 对照测试，才能进入 SOCKS/重连服务实现。

## 已实现

- 固定 XMU API/组织/客户端身份，Sheeta 签名、AES-CBC、RSA 包装。
- 浏览器 SSO + 手动粘贴回调 URL；可注入 `SL_CALLBACK_URL`。
- JSON 会话缓存、到期前五分钟刷新、设备 ID 持久化。
- SecureLink profile 规范化、`UV_*` peer-info、上游 parser 兼容性测试。
- 固定 go-openvpn 与 netstack 版本；依赖补丁暴露原始 PUSH_REPLY，并修复控制消息与握手字段兼容性。
- 不可变、默认拒绝的 ACL 快照；支持实测的 IPv4 CIDR、`proto:any/tcp`、`port:any`/单端口/分号列表。域名授权不会产生 IPv4 授权。
- `check` 无 TUN 握手诊断；`probe` 仅通过 netstack 对 ACL 授权的 IPv4:端口建立 TCP 连接，随后关闭，不发送应用层数据。

不会创建 TUN/TAP/DCO/Wintun，不修改主机路由或 DNS，不提供 DIRECT 回退。VPN remote 和测试目标只接受 IPv4 字面量；固定 HTTPS 控制面主机名仍由 HTTP transport 正常解析。不存在目标域名解析或 DNS 服务。

## 离线构建和测试

```powershell
go test ./...
go vet ./...
go -C third_party/go-openvpn test ./...
go build -o bin/securelink2socks.exe ./cmd/securelink2socks
./bin/securelink2socks.exe --help
```

首次构建会下载已固定版本的依赖；测试本身不访问 XMU。测试数据全部为合成数据，见 [testdata/securelink](testdata/securelink/README.md)。上游依赖测试可能使用本地回环网络/内存连接。

本次测试结果及上游并发测试的超时记录见 [离线验证记录](docs/offline-validation.md)。

## 后续实机验证

在本人有权使用的 XMU 账号和资源上，显式开启联网诊断：

```powershell
$env:SECURELINK2SOCKS_E2E = '1'
./bin/securelink2socks.exe login
./bin/securelink2socks.exe check
# 保留此前诊断命令；现在与 check 使用相同的已验证策略：
./bin/securelink2socks.exe check --aead-probe
# 将下面的文档示例地址替换为本人有权访问的真实地址：
./bin/securelink2socks.exe probe 192.0.2.10:443
```

`login` 会复用或刷新缓存；没有有效会话时打开浏览器，等待手动粘贴完整回调 URL。登录成功不代表 VPN 兼容性验证成功。`check` 输出握手阶段、实验标记、传输协议、remote、cipher、分配的 IPv4 和 ACL 条数；不会输出 profile、token、原始 PUSH_REPLY 或服务端错误正文。VPN 认证拒绝时最多刷新会话并重试一次。

`check` 和 `probe` 按 XMU profile 的内嵌 CA 和 `remote-cert-tls server` 验证服务器，要求明确的 serverAuth EKU；允许没有 tls-auth/tls-crypt 的外层报文，内部仍使用已验证的 TLS。它们只声明已实现的 AEAD 算法，不支持或回退到 CBC，不修改原始 profile。密钥派生按服务端 PUSH 选择 TLS-EKM 或 OpenVPN PRF。`check` 还要求在限时内收到已验证的 AEAD 数据包，输出 `data_channel_verified`；只完成 TLS 握手不算通过。

状态目录默认为 `~/.securelink2socks/`，可用 `SECURELINK2SOCKS_HOME` 覆盖。会话使用临时文件 + 同目录替换保存。Unix 文件模式为 0600；Windows 使用目录继承的访问控制，应保存在自己的用户目录中。

当前不支持 `SECURELINK2SOCKS_LISTEN`、日志级别或 ACL dump；这些随后续服务阶段实现。`SL_CALLBACK_URL` 可跳过手动输入，但回调通常短时有效且只能使用一次。

## 尚待验证/实现

- 超出已观察 ACL 格式的协议/端口扩展和运行时 PUSH 更新。
- 真实 XMU 私网 TCP 可达性、主机网络状态不变的实机证据。
- SOCKS5 listener/CONNECT、ACL 原子替换和旧连接终止、生命周期与重连。
- Mihomo E2E 和至少 100 Mbps 的性能验收。

当前已证明真实网关接受仅 AEAD 客户端，但尚未证明校内 TCP 与完整代理服务可用。详情见 [协议调查](docs/protocol-notes.md)、[实机调查](docs/live-validation.md) 和 [依赖补丁](docs/upstream-patch.md)。

## 许可证

AGPL-3.0-or-later。Rust 控制面参考的 GPL-3.0 许可及上游归属保留在 [NOTICE](NOTICE)、[LICENSES](LICENSES/) 和依赖目录中。
