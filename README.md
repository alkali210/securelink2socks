# securelink2socks

将厦门大学 SecureLink 接入转换为本地 SOCKS5 代理，方便配合 Mihomo 等客户端访问获授权的校内资源。Windows 已完成实机验证；Linux 和 macOS 已通过交叉编译，仍待目标平台实测。

## 功能

- 浏览器 SSO 登录、会话缓存与自动刷新。
- SOCKS5 TCP 代理，支持 IPv4 地址和域名目标。
- 按服务器下发的 IP／域名及端口 ACL 授权，校园域名经 VPN 内 DNS 解析。
- 自动重连；断线或权限更新时撤销旧连接，校园请求失败不回退直连。
- 纯用户态网络栈，本程序不创建 TUN/TAP，也不修改系统路由或 DNS。

当前不支持 SOCKS UDP、IPv6 或 BIND。此前核心功能已通过用户实机验收；长期稳定性和吞吐量仍待专项验收。

## 使用

从 Actions 下载对应平台的二进制文件。Windows 直接双击 `securelink2socks.exe`，或在终端运行：

```powershell
./securelink2socks.exe
```

Linux/macOS 在终端运行 `./securelink2socks`。无需设置环境变量或指定子命令：程序自动复用或刷新会话；需要登录时打开浏览器，按提示粘贴回调 URL，随后进入服务。

出现 `VPN state: Ready` 后，可使用本地 SOCKS5 地址 `127.0.0.1:1080`。运行期间保持终端窗口打开，按 Ctrl-C 或关闭窗口即可退出。

原有 `login`、`login --force`、`serve`、`check`、`probe IPv4:port` 仍可单独使用，帮助见 `--help`。源码构建步骤见 [开发指南](docs/development.md)。

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
