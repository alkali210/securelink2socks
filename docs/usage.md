# 使用与排障

Windows:

```powershell
$env:SECURELINK2SOCKS_E2E = '1'
# 如果之前使用了独立会话目录，保持相同设置：
# $env:SECURELINK2SOCKS_HOME = "$env:USERPROFILE/.securelink2socks-fresh"
./bin/securelink2socks.exe login
./bin/securelink2socks.exe serve
```

Linux/macOS:

```sh
export SECURELINK2SOCKS_E2E=1
./bin/securelink2socks login
./bin/securelink2socks serve
```

服务立即监听 `127.0.0.1:1080`；出现 `VPN state: Ready` 后允许授权连接。连接中/重连时监听保留，新请求立即失败；不会通过主机网络直连回退。Ctrl-C 关闭监听、连接、用户态栈和 VPN。

Mihomo 完整配置见 [mihomo.yaml](../mihomo.yaml)。退出旧进程并启动本仓库重新构建的 SecureLink 服务后导入配置，使用**规则模式**，应用代理地址为 `127.0.0.1:7890`。普通互联网走 DIRECT；`xmu.edu.cn` 和列出的校内 IPv4 走 XMU；SecureLink 进程、登录 API、`ids.xmu.edu.cn` 统一认证入口和 VPN 网关优先直连，防止代理循环。校园请求失败不会回退直连。FlClash 可能覆盖 YAML 的 TUN、DNS 和端口设置，应以其运行配置为准。

SOCKS 支持 IPv4 和域名 TCP CONNECT。域名仅经当前 VPN 下发的 DNS 解析为 IPv4，再按域名+端口 ACL 或目标 IPv4+端口 ACL 授权；不存在系统 DNS／公网 DNS 回退。精确域名和 `*.example.edu` 子域名授权均支持，域名授权不会变成可供任意请求使用的 IP 授权。DNS 仅为内部查询，不开放 DNS 监听或 SOCKS UDP。

示例将检测页的 `ip4.xmu.edu.cn` 设置为 `ip.xmu.edu.cn` 的域名别名，两者为同一检测服务；这样使用服务器下发的主页域名授权，HTTPS 仍验证原始主机名。其他校园域名无需手工填写 IP，但必须通过上述 ACL 检查。不要把只有域名授权的目标用静态 `hosts` 转成 IP 请求。

2026-09-25 已通过用户的 9090 内核验证：普通公网 200，已知校内服务完整跳转到统一认证登录页 200，`ip.xmu.edu.cn` 页面及 IPv4 检测接口 200，接口返回 `is_in_xmu: true`。验证记录见 [实机记录](live-validation.md)。IPv6 请求返回 `0x08`，BIND/UDP 返回 `0x07`；未就绪返回 `0x03`，ACL 拒绝返回 `0x02`。

FlClash 导入本地 YAML 后可能保存独立副本；仓库文件更新不会自动更新导入副本。遇到统一认证页 TLS EOF 时，确认实际应用的规则中 `DOMAIN,ids.xmu.edu.cn,DIRECT` 位于校园域名规则之前。

测试有登录跳转的网站应使用携带 Cookie 的 GET，不能仅凭 `curl -LI` 判断网站失败。Windows 示例（`NUL` 丢弃 Cookie 文件和响应正文）：

```powershell
curl.exe -sS -L --max-time 30 --cookie-jar NUL -A "Mozilla/5.0" --proxy http://127.0.0.1:7890 -o NUL -w "HTTP %{http_code}\n" https://lnt.xmu.edu.cn/
```

该命令已对 `lnt.xmu.edu.cn` 和给定校内 IP 验证到登录页 200。`-c/--cookie-jar` 会开启 curl 的 Cookie 引擎，参见 [curl Cookie 文档](https://curl.se/docs/http-cookies.html)。自动化验证止于登录页；用户已确认当前阶段功能验证成功。

可用 `SECURELINK2SOCKS_LISTEN=127.0.0.1:其他端口` 更改端口，不能绑定其他地址。遇到 `NeedsLogin`，在同一会话目录的另一终端执行 `login --force`；服务等待会话文件更新后恢复，不反复请求失败的认证。


## 诊断与会话管理

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

`login` 会复用或刷新缓存；没有有效会话时打开浏览器，等待手动粘贴完整回调 URL。登录、隧道握手和目标资源连接是不同阶段，可分别用上述命令诊断。`check` 输出握手阶段、实验标记、传输协议、remote、cipher、分配的 IPv4 和 ACL 条数；不会输出 profile、token、原始 PUSH_REPLY 或服务端错误正文。VPN 认证拒绝时最多刷新会话并重试一次。

`check` 和 `probe` 按 XMU profile 的内嵌 CA 和 `remote-cert-tls server` 验证服务器，要求明确的 serverAuth EKU；允许没有 tls-auth/tls-crypt 的外层报文，内部仍使用已验证的 TLS。它们只声明已实现的 AEAD 算法，不支持或回退到 CBC，不修改原始 profile。密钥派生按服务端 PUSH 选择 TLS-EKM 或 OpenVPN PRF。`check` 还要求在限时内收到已验证的 AEAD 数据包，输出 `data_channel_verified`；只完成 TLS 握手不算通过。

状态目录默认为 `~/.securelink2socks/`，可用 `SECURELINK2SOCKS_HOME` 覆盖。会话使用临时文件 + 同目录替换保存。Unix 文件模式为 0600；Windows 使用目录继承的访问控制，应保存在自己的用户目录中。

当前日志仅输出状态，不支持原始 ACL dump。`SL_CALLBACK_URL` 可跳过手动输入，但回调通常短时有效且只能使用一次。
