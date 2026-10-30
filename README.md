# CDN Accelerator（本地 DNS 优选加速器）

一个轻量的本地加速软件，替代 Steam++ 的加速功能：**自动为网站优选最快的连接节点，全自动，无需手动换节点**。

纯 Python 标准库实现，常驻内存，占用极小（无 GUI、无依赖安装）。

## 工作原理

程序在本地监听 DNS（`127.0.0.1:53` + `::1:53`），接管系统 DNS。电脑上任何域名解析都先经过它，按域名类型自动分层处理：

| 域名类型 | 处理方式 |
| --- | --- |
| 已知 CDN（Cloudflare / Fastly / Akamai / 微软等）| 每 5 分钟实测 CDN 优选 IP 池，返回当前连接最快的节点（TTL 60）|
| 未知但多 IP 的域名 | 首次解析时并发实测所有 IP 的连接速度，返回最快的一个（缓存 5 分钟）|
| 单 IP / 其他记录类型 | 透明转发给原 DNS，不做手脚 |
| CDN 域名的 AAAA 查询 | 返回空，强制走 IPv4 优选线路 |

所有"优选"都是 **TCP + TLS 握手实测**（不只是 TCP 通，还要求 HTTPS 真的能握上手），并且：

- **节点健康自动复检**：每 30 秒对正在返回的优选节点做一次 TLS 实测，节点失效立即重新挑选 / 丢弃失效缓存，不会把坏节点用满 5 分钟
- **启动即预热**：程序启动立刻全池测速排序，不用等第一个 5 分钟
- **单飞去重**：同一域名并发查询（Windows 会同时走 ::1 和 127.0.0.1）只实测一次
- **并发处理**：慢查询不会卡住其他网站（32 线程池）
- **转发兜底**：上游 DNS 逐个重试，全部失败返回 SERVFAIL 而不是假成功

适用场景：CDN 站点直连绕路、超时、抖动（典型如 Cloudflare 网站在国内直连时好时坏）。被墙网站（Google / YouTube 等）优选无法解决，仍需代理/WARP——本程序替代的是"手动换节点"这件事，不是代理。

## 安装

> 前置：Windows 10/11，Python 3.10+（安装时勾选 "Add python.exe to PATH"；或把便携版 Python 放进 `python\` 目录）

1. 拷贝整个文件夹到目标电脑
2. 右键 **`install.bat` → 以管理员身份运行**
3. 看到 "安装完成" 即生效

安装脚本会自动：备份当前 DNS（v4/v6）→ 将系统 DNS 切到本地 → 注册开机自启（计划任务 `cdn_accelerator`）→ 立即启动并验证 UDP 53 监听。

## 卸载 / 紧急恢复

右键 **`uninstall.bat` → 以管理员身份运行**（或 `uninstall.ps1`）。会停止程序、删除开机自启、恢复原 DNS。若电脑突然断网（程序未运行但 DNS 仍是 127.0.0.1），运行它即可恢复。

## 手动操作

- 启动：`pythonw.exe cdn-accelerator.py --upstream <原DNS>`（不传则用默认公共 DNS）
- 暂停自启：`schtasks /Change /TN cdn_accelerator /DISABLE`
- 查看日志：`cdn-accelerator.log`（`Q`=收到查询 / `OPT`=优选 / `REFRESH`=优选池刷新）

## 注意事项

1. **hosts 文件优先级高于本程序**。hosts 里有记录的域名不走优选；若要完全交给本程序，需把对应 hosts 记录移除。
2. **WARP / V2RayN / SwitchyOmega 开启时由它们接管流量**，本程序自动让位；关闭后本程序生效，互补不冲突。
3. **IPv6 链路本地 DNS（fe80::1）是常见的"漏网之鱼"**：Windows 会合并使用 IPv4+IPv6 的 DNS 列表，若只接管 IPv4，路由器 IPv6 DNS 会抢答并绕过优选。本程序安装时会把 IPv6 DNS 一并切到 `::1`，卸载时恢复。
4. **浏览器"安全 DNS（DoH）"会绕过本程序**。Chrome/Edge 若开启 Secure DNS，请改为"使用系统 DNS"。
5. 被墙网站（Google / YouTube 等）仍需 WARP 或代理。

## 文件清单

| 文件 | 用途 |
| --- | --- |
| `cdn-accelerator.py` | 主程序（双栈监听，纯标准库）|
| `install.ps1` / `install.bat` | 安装（双击入口）|
| `uninstall.ps1` / `uninstall.bat` | 卸载 / 应急恢复（双击入口）|
| `dns-backup.txt` / `dns-backup-v6.txt` | 安装时的原 DNS 备份（本地生成，不入库）|
| `cdn-accelerator.log` | 运行日志（本地生成，不入库）|

## 隐私

本程序所有 DNS 查询与优选测速均在本地完成；日志只记录查询的域名（用于排障）。备份文件与日志默认不入库（见 `.gitignore`）。
