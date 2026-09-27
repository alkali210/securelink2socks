# 自动生成 Mihomo 分流规则

## 导出与使用

先停止本程序已有的服务，再运行：

```powershell
./securelink2socks.exe export-mihomo
```

命令会复用或刷新会话，需要时进行浏览器 SSO，临时连接 VPN 并验证数据通道。
只有取得完整、有效且非空的 ACL 后才写文件，随后关闭临时隧道，不启动 SOCKS 服务。
不要与同账号的其他 VPN 会话并行导出，以免触发服务端并发限制。

默认输出在会话目录的 `mihomo.generated.yaml`（通常为 `~/.securelink2socks/`）；
终端显示绝对路径。导入该文件后，无参数启动 securelink2socks，等待 `Ready`。
完整配置使用本地 SOCKS、规则模式、mixed-port 7890，TUN 默认关闭，普通公网 DIRECT。
`SECURELINK2SOCKS_LISTEN` 如有设置，导出和服务启动须使用相同值。

自定义输出位置：

```powershell
./securelink2socks.exe export-mihomo --output ./mihomo.generated.yaml
```

仅支持 `.yaml`／`.yml`，指定路径已有文件会在生成成功后替换。请勿指向自己的综合代理配置。
默认无参数启动仍只负责登录与服务，不自动写配置、不调用 Clash 控制接口。

## 合并到现有公网代理配置

```powershell
./securelink2socks.exe export-mihomo --fragment
```

默认生成 `mihomo.fragment.yaml`；可同时指定 `--output`。这是合并片段，不能直接替换完整配置：

1. 将 `proxies` 中的 `XMU` 节点加入原配置；如已有同名节点，替换该节点，避免重复。
2. 如片段包含 `hosts`，合并域名别名，避免改为静态 IP。
3. 将片段的整组 `rules` 按原顺序放在已有规则之前；保留已有公网规则、代理组和末尾 MATCH。
4. 使用 `mode: rule` 和 `find-process-mode: always`，让校园域名以域名形式送入 SOCKS。

片段不含 DNS、端口、TUN 设置或兜底 MATCH，不会重新定义你的公网代理策略。
不得将 XMU 放入失败后会切换到 DIRECT／公网代理的 fallback 组。

## 规则语义与边界

- 精确域名、IPv4 CIDR、单端口／端口列表、任意端口均从解析后的 ACL 生成。
- `*.example.edu` 只包含子域，不包含 `example.edu` 本身；输出使用 AND/NOT 明确保留这个边界。
- 所有允许规则先于拒绝规则，以免一个较宽的拒绝规则遮蔽另一个有效授权。
- 仅 TCP 获得 XMU 路由；已知 ACL 目标的其他端口及 UDP 明确 REJECT。未匹配的 XMU 域名也 REJECT。
- IP 规则使用 `no-resolve`，不会为匹配 ACL IP 而主动使用主机 DNS。域名的最终解析和授权仍由网关通过 VPN 完成。
- 直连例外独立于 ACL：程序进程名、SecureLink 控制面、`ids.xmu.edu.cn`、当前 VPN 网关、IPv4 回环地址。
- 当 ACL 授权 `ip.xmu.edu.cn` 时，保留检测服务 `ip4.xmu.edu.cn` 的已验证别名，并沿用相同端口限制。这是明确维护的 XMU 例外，不是通用别名推断。
- 导出器不知道 ACL 之外的校内 IP，也不能推导全部业务认证跳转。新增站点例外须单独验证；完整配置中其他未匹配地址走 DIRECT。

Mihomo 规则只决定出口，不授予访问权限。用户态网关始终按当前隧道 ACL 再检查；
断线、重连、PUSH 策略变化的旧连接撤销机制保持不变。
规则语法依据 [Mihomo 路由文档](https://wiki.metacubex.one/config/rules/)。

## 更新与文件处理

文件顶部记录 UTC 生成时间。账号、授权、VPN 网关或 SOCKS 监听端口变化后，重新导出并重新导入／合并。
FlClash 等客户端可能保存导入副本，修改源 YAML 不会自动更新副本。
本阶段不自动刷新或热重载规则；旧文件不是当前授权证明。

相同 ACL、监听地址、网关和生成时间产生相同内容，规则排序固定并去重。
生成或写入失败会保留旧文件；通过同目录临时文件写入后替换，避免写入半份 YAML。
输出不含 token、Cookie、私钥、原始 profile 或 PUSH；规则仍反映账号资源权限，应本地保管，不提交到仓库。

## 验证

离线测试覆盖不可变 ACL 导出、端口／通配边界、去重排序、重叠授权、失效输入、取消和文件替换。
可显式指定本机 Mihomo 可执行文件运行额外的离线互操作测试：

```powershell
$env:SECURELINK2SOCKS_MIHOMO = 'C:/path/to/mihomo.exe'
go test ./internal/mihomo -run TestMihomoCore -count=1 -v
```

测试使用独立临时端口、合成 ACL 和本地模拟 SOCKS 服务，不使用校园账号或外部 DNS，
验证完整配置加载、片段合并、实际路由和保留原有公网代理。默认普通测试跳过此项。

2026-09-28：Mihomo v1.19.31 的离线互操作测试通过。使用已有授权会话导出的真实配置也加载成功；
独立代理验证检测接口返回 `is_in_xmu: true`，校内 `172.27.75.118:8090` 与 `lnt.xmu.edu.cn`
带 Cookie 跳转到登录页均返回 200，公网请求返回 200。未提交登录表单，未改动正在运行的 Clash 配置。
