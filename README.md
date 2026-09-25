# securelink2socks

将厦门大学 SecureLink 接入转换为本地 SOCKS5 代理，方便配合 Mihomo 等客户端访问获授权的校内资源。Windows 已完成实机验证；Linux 和 macOS 已通过交叉编译，仍待目标平台实测。

## 功能

- 浏览器 SSO 登录、会话缓存与自动刷新。
- SOCKS5 TCP 代理，支持 IPv4 地址和域名目标。
- 按服务器下发的 IP／域名及端口 ACL 授权，校园域名经 VPN 内 DNS 解析。
- 自动重连；断线或权限更新时撤销旧连接，校园请求失败不回退直连。
- 纯用户态网络栈，本程序不创建 TUN/TAP，也不修改系统路由或 DNS。

当前不支持 SOCKS UDP、IPv6 或 BIND。用户已确认当前阶段功能验证成功；长期稳定性和吞吐量仍待专项验收。

## 使用

安装 Go 1.26 或更新版本，在仓库目录构建并启动。Windows:

```powershell
New-Item -ItemType Directory -Force bin | Out-Null
go build -o bin/securelink2socks.exe ./cmd/securelink2socks
$env:SECURELINK2SOCKS_E2E = '1'
./bin/securelink2socks.exe login
./bin/securelink2socks.exe serve
```

Linux/macOS:

```sh
mkdir -p bin
go build -o bin/securelink2socks ./cmd/securelink2socks
export SECURELINK2SOCKS_E2E=1
./bin/securelink2socks login
./bin/securelink2socks serve
```

或者在 Actions 下载构建的二进制文件，然后直接运行。

按提示完成浏览器登录并粘贴回调 URL。出现 `VPN state: Ready` 后，可使用本地 SOCKS5 地址 `127.0.0.1:1080`。Ctrl-C 退出。

配合 Mihomo 时，导入 [mihomo.yaml](mihomo.yaml)，使用**规则模式**，应用代理地址为 `127.0.0.1:7890`。示例将校园资源送入 SecureLink，普通互联网和必要的认证入口直连。升级程序后需重启旧进程；更新 YAML 后需重新导入或更新客户端保存的副本。

会话默认保存在 `~/.securelink2socks/`，可用 `SECURELINK2SOCKS_HOME` 指定目录；登录与服务须使用同一目录。出现 `NeedsLogin` 时，在另一终端执行 `login --force`。

详细配置、诊断命令和常见问题见 [使用与排障](docs/usage.md)；完整构建目标和命令见 [开发指南](docs/development.md)。

## 文档与计划

- [开发指南](docs/development.md)：构建、测试与协议资料。
- [实机验证记录](docs/live-validation.md)：验证结果及边界。
- [阶段计划](docs/roadmap.md)：下一阶段考虑基于 ACL 自动生成 Mihomo 分流规则。

## 致谢

- [go-openvpn](https://github.com/n0madic/go-openvpn)：OpenVPN 协议与用户态网络栈集成。
- [xmu_secure_link](https://github.com/XMU-MoYu-Club/xmu_secure_link)：XMU SecureLink 控制面参考实现。

其他参考和依赖归属见 [NOTICE](NOTICE)。

## 许可证

[AGPL-3.0-or-later](LICENSE)。第三方许可证保留在 [LICENSES](LICENSES/) 中。
