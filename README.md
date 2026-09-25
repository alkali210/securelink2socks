# securelink2socks

厦门大学 SecureLink → 用户态 TCP/IP → SOCKS5 网关。要求 Go 1.26.3 或更新版本，优先支持 Windows。

已实现 IPv4/域名 TCP SOCKS5、ACL 授权与重连管理。真实 XMU、用户态 TCP 和独立 Mihomo 代理链已验证；吞吐量与长期稳定性尚未验收。

## 启动

```powershell
$env:SECURELINK2SOCKS_E2E = '1'
# 如果之前使用了独立会话目录，保持相同设置：
# $env:SECURELINK2SOCKS_HOME = "$env:USERPROFILE/.securelink2socks-fresh"
./bin/securelink2socks.exe login
./bin/securelink2socks.exe serve
```

服务立即监听 `127.0.0.1:1080`；出现 `VPN state: Ready` 后允许授权连接。连接中/重连时监听保留，新请求立即失败；不会通过主机网络直连回退。Ctrl-C 关闭监听、连接、用户态栈和 VPN。

Mihomo 完整配置见 [mihomo.yaml](mihomo.yaml)。退出旧进程并启动本仓库重新构建的 SecureLink 服务后导入配置，使用**规则模式**，应用代理地址为 `127.0.0.1:7890`。普通互联网走 DIRECT；`xmu.edu.cn` 和列出的校内 IPv4 走 XMU；SecureLink 进程、登录 API、`ids.xmu.edu.cn` 统一认证入口和 VPN 网关优先直连，防止代理循环。校园请求失败不会回退直连。FlClash 可能覆盖 YAML 的 TUN、DNS 和端口设置，应以其运行配置为准。

SOCKS 支持 IPv4 和域名 TCP CONNECT。域名仅经当前 VPN 下发的 DNS 解析为 IPv4，再按域名+端口 ACL 或目标 IPv4+端口 ACL 授权；不存在系统 DNS／公网 DNS 回退。精确域名和 `*.example.edu` 子域名授权均支持，域名授权不会变成可供任意请求使用的 IP 授权。DNS 仅为内部查询，不开放 DNS 监听或 SOCKS UDP。

示例将检测页的 `ip4.xmu.edu.cn` 设置为 `ip.xmu.edu.cn` 的域名别名，两者为同一检测服务；这样使用服务器下发的主页域名授权，HTTPS 仍验证原始主机名。其他校园域名无需手工填写 IP，但必须通过上述 ACL 检查。不要把只有域名授权的目标用静态 `hosts` 转成 IP 请求。

2026-09-25 已通过用户的 9090 内核验证：普通公网 200，已知校内服务完整跳转到统一认证登录页 200，`ip.xmu.edu.cn` 页面及 IPv4 检测接口 200，接口返回 `is_in_xmu: true`。验证记录见 [实机记录](docs/live-validation.md)。IPv6 请求返回 `0x08`，BIND/UDP 返回 `0x07`；未就绪返回 `0x03`，ACL 拒绝返回 `0x02`。

可用 `SECURELINK2SOCKS_LISTEN=127.0.0.1:其他端口` 更改端口，不能绑定其他地址。遇到 `NeedsLogin`，在同一会话目录的另一终端执行 `login --force`；服务等待会话文件更新后恢复，不反复请求失败的认证。

## 已实现

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

当前日志仅输出状态，不支持原始 ACL dump。`SL_CALLBACK_URL` 可跳过手动输入，但回调通常短时有效且只能使用一次。

## 尚待验证/实现

- 超出已观察 ACL 格式的协议/端口扩展。
- 无其他 VPN 时“主机直连失败、用户态成功”的对照；本次用户确认还有其他 VPN 在线。
- 长时间运行、物理网络断开/恢复和至少 100 Mbps 的性能验收。

当前已完成真实 SOCKS/Mihomo TCP 验证；测试的具体范围与未验收项见 [实机调查](docs/live-validation.md)。协议细节见 [协议调查](docs/protocol-notes.md) 和 [依赖补丁](docs/upstream-patch.md)。

## 致谢

- [go-openvpn](https://github.com/n0madic/go-openvpn)
- [xmu_secure_link](https://github.com/XMU-MoYu-Club/xmu_secure_link)

## 许可证

AGPL-3.0-or-later
