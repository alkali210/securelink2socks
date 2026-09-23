# securelink2socks

厦门大学 SecureLink → 用户态 TCP/IP → SOCKS5 网关。要求 Go 1.26.3 或更新版本，优先支持 Windows。

**当前是兼容性验证阶段，尚不是可用的 SOCKS 代理。** 按初始计划，真实 XMU 握手、原始 ACL 和用户态 TCP 验证完成前，不进入 SOCKS/重连服务实现。本阶段已实现 Go 控制面、离线测试和无 TUN 的诊断入口。未进行真实登录或网络验收。

## 已实现

- 固定 XMU API/组织/客户端身份，Sheeta 签名、AES-CBC、RSA 包装。
- 浏览器 SSO + 手动粘贴回调 URL；可注入 `SL_CALLBACK_URL`。
- JSON 会话缓存、到期前五分钟刷新、设备 ID 持久化。
- SecureLink profile 规范化、`UV_*` peer-info、上游 parser 兼容性测试。
- 固定 go-openvpn 与 netstack 版本；最小补丁暴露原始 PUSH_REPLY。
- 不可变、默认拒绝的 ACL 快照；仅实现参考资料已记录的 `proto:any` 与 `port:any`/单端口。
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
# 将下面的文档示例地址替换为本人有权访问的真实地址：
./bin/securelink2socks.exe probe 192.0.2.10:443
```

`login` 会复用或刷新缓存；没有有效会话时打开浏览器，等待手动粘贴完整回调 URL。登录成功不代表 VPN 兼容性验证成功。`check` 的输出仅包含传输协议、remote、cipher、分配的 IPv4 和 ACL 条数；不会输出 profile、token、原始 PUSH_REPLY 或服务端错误正文。

状态目录默认为 `~/.securelink2socks/`，可用 `SECURELINK2SOCKS_HOME` 覆盖。会话使用临时文件 + 同目录替换保存。Unix 文件模式为 0600；Windows 使用目录继承的访问控制，应保存在自己的用户目录中。

当前不支持 `SECURELINK2SOCKS_LISTEN`、日志级别或 ACL dump；这些随后续服务阶段实现。`SL_CALLBACK_URL` 可跳过手动输入，但回调通常短时有效且只能使用一次。

## 尚待验证/实现

- 真实 API 登录、刷新和配置获取；服务端证书身份、控制通道保护、实际 AEAD 协商。
- 原始 `app` 报文格式、端口/协议扩展及 PUSH 分段行为。
- 真实 XMU 私网 TCP 可达性、主机网络状态不变的实机证据。
- SOCKS5 listener/CONNECT、ACL 原子替换和旧连接终止、生命周期与重连。
- Mihomo E2E 和至少 100 Mbps 的性能验收。

没有实机证据时不会移除 CBC、放宽证书验证或猜测 ACL 语义。详情见 [协议调查](docs/protocol-notes.md) 和 [依赖补丁](docs/upstream-patch.md)。

## 许可证

AGPL-3.0-or-later。Rust 控制面参考的 GPL-3.0 许可及上游归属保留在 [NOTICE](NOTICE)、[LICENSES](LICENSES/) 和依赖目录中。
