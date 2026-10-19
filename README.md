# ksing-ui

AnyTLS 中控面板：纯官方 sing-box 裸核节点 + 集中配置下发 + v2ray api 流量统计 + 三级分流。

后端仅依赖 Python 3 标准库，前端 Vue 3 已预构建（`web/dist`），克隆即用。

## 架构

```
┌─────────────┐  长轮询下发(HTTPS+CA钉扎)  ┌──────────────┐
│  中控面板     │ ◀────────────────────── │  节点 VPS     │
│  server.py   │  ──────────────────────▶ │  sing-box裸核 │
│  (本仓库)     │   流量/心跳上报            │  + agent.py   │
└─────────────┘                          └──────────────┘
```

- 中控只做管理，不做代理
- 节点跑官方源码构建的 sing-box（仅多开 `with_v2ray_api` 官方构建开关）
- 配置变更 **秒级**下发到节点并自动重启生效（长轮询 + `sing-box check` 校验后切换）

## 功能

- **节点管理**：一键安装命令接入（脚本 sha256 + CA 指纹双校验）；在线/同步状态；按节点分配用户；双栈 / 仅 IPv4 / 纯 IPv6
- **三级分流**：全局规则 / 节点级（对该节点全体用户生效）/ 用户级（单独增删），出站为 Shadowsocks 节点池
- **证书管理**：节点 sing-box 原生 ACME(Let's Encrypt）自动申请续签；IPv4/IPv6 使用不同域名并分别校验 A/AAAA，IPv6 未就绪只暂停该族；也支持 IP 自签（selfip）与显式 unsafe
- **Cloudflare DNS**：CF Token 只存中控（接口只写不回显），节点上报 IP 后中控自动建 A/AAAA 记录并随 IP 变化更新；v4/v6 域名强制分离
- **流量统计**：v2ray StatsService(gRPC）按用户/节点累计，仪表盘排名
- **订阅**：按用户生成，sing-box / mihomo(Clash) / v2rayN 三格式（UA 嗅探或 `?type=`);mihomo 配置 fakeip + 防 DNS 泄露；自定义订阅 host/路径，一键重置换发
- **面板账号**：管理员 + 多用户独立登录（用户只见自己的节点与订阅）；亮/暗主题；移动端适配

## 快速开始

### 1. 中控面板（一台机器）

```bash
curl -fsSL https://raw.githubusercontent.com/sparkfade/ksing-ui/main/install_panel.sh | sudo bash
# 或自定义端口: sudo bash install_panel.sh install 8080 9443
```

面板日常管理（升级/重启/状态/卸载，已安装时重复执行 install 会拒绝以防覆盖）:

```bash
bash /opt/ksing-ui/install_panel.sh upgrade    # 拉最新代码并重启 (--with-binaries 同时重构节点内核)
bash /opt/ksing-ui/install_panel.sh restart
bash /opt/ksing-ui/install_panel.sh status
bash /opt/ksing-ui/install_panel.sh uninstall  # [--purge 连数据一起删]
```

手动安装则：

```bash
git clone --depth 1 https://github.com/sparkfade/ksing-ui /opt/ksing-ui
mkdir -p /etc/ksing-ui
python3 /opt/ksing-ui/server.py --dir /etc/ksing-ui --listen 0.0.0.0 --port 8080
```

打开 `http://<IP>:8080`，首次访问设置管理员密码。

> 注意：面板本身是明文 HTTP，公网使用请套 TLS 反代或仅监听可信网络。节点与面板共用面板端口；HTTPS 部署时使用自签 CA + 指纹钉扎，明文 HTTP 会明确提示风险。

### 2. 接入节点（每台 VPS)

面板 → 服务器节点 → 添加节点，只需填 **名称 / 端口 / 绑定域名**:

- **网络模式**：默认双栈（节点安装时自动检测 IPv4/IPv6）；也可选仅 IPv4 或纯 IPv6
- **Cloudflare 自动 DNS（推荐）**：在 设置 页配置 CF API Token（Zone.DNS Edit）后，节点开启「自动 DNS」即可——节点上报公网 IP，**中控**自动创建记录（Token 不出中控）。支持普通用户 Token 与账号级 Token（`cfat_`）：账号级 Token 校验时需同时填写可选 Account ID，DNS 记录操作本身不需要 Account ID：
  - 有 IPv4：绑定域名创建 A 记录（如 `hk1.example.com`）
  - 还有 IPv6：自动使用首段加 `-v6` 的独立域名创建 AAAA 记录（`hk1-v6.example.com`）
  - 严禁同一域名同时有 A 和 AAAA；同名冲突记录会被自动纠正
  - IP 变化自动更新（DDNS）；删除节点时自动清理记录
  - DNS 就绪以中控 CF 同步结果为准；本机递归解析超时/负缓存不会停用协议族。订阅只包含已就绪的族，双栈节点会拆成 IPv4/IPv6 两条
- **域名证书**：记录就绪后由节点 sing-box 原生 ACME(Let's Encrypt）自动申请续签，放行 80 端口供验证
- **IP 自签证书**：无域名时生成含 IPv4/IPv6 SAN 的自签证书，客户端需 allowInsecure
- **不安全模式**：需显式确认，自签假域名证书

提交后得到一键安装命令，在节点上以 root 执行即可（装 sing-box + agent + systemd，自动拉起并自动识别 v4/v6）。

### 3. 日常使用

- **出站节点**：导入 ss:// 链接（支持 `ss://base64(method:password)@host:port#name` 等格式）
- **分流规则**：全局页管全局；节点「分流」抽屉管节点级；用户「分流」抽屉管用户级 + 专属默认出口
- **规则集**：内置 sing-geoip / sing-geosite / meta-rules-dat / cn-domain-list 等来源，`sbtool.py update` 全量下载，面板可搜索
- **用户**：添加用户（可设面板密码让其登录看自己订阅）；订阅三格式地址一键复制/重置
- **证书页**：所有节点证书状态一览（过期时间/剩余天数/签发者）

## CLI（可选）

面板数据层的全部能力也有命令行（`sbtool.py`):

```bash
python3 sbtool.py --dir /etc/ksing-ui user add alice          # 加用户
python3 sbtool.py --dir /etc/ksing-ui srv add hk --port 443 --domain hk4.example.com --domain6 hk6.example.com  # 双栈节点
python3 sbtool.py --dir /etc/ksing-ui srv add v6 --port 443 --ip-mode ipv6 --domain6 hk6.example.com        # 纯 IPv6 节点
python3 sbtool.py --dir /etc/ksing-ui node import 'ss://...'  # 导入 SS 出站
python3 sbtool.py --dir /etc/ksing-ui route add --suffix .cn --to direct
python3 sbtool.py --dir /etc/ksing-ui update                  # 下载全部规则集
python3 sbtool.py --dir /etc/ksing-ui search geoip cn         # 查规则集
```

## 目录

| 文件 | 说明 |
|---|---|
| `server.py` | 面板后端（管理 API + agent HTTPS 下发通道） |
| `sbtool.py` | 数据层/CLI（用户、出站、规则、节点配置生成、流量记账） |
| `agent.py` | 节点侧 agent（长轮询拉配置、校验重启、gRPC 流量上报） |
| `install_panel.sh` | 中控一键安装 |
| `install_node.sh` | 节点一键安装（由面板下发，静态无占位符） |
| `tools/build_node_binary.sh` | 构建节点用 sing-box（官方源码 + with_v2ray_api) |
| `web/` | 前端（Vue 3 + Vite,`web/dist` 已预构建） |

## 开发

```bash
# 前端改动后重新构建
cd web && npm install && npm run build && cd ..

# 本地起面板（开发）
python3 server.py --dir ./sbdata --listen 127.0.0.1 --port 8080
```

## 安全说明

- 节点安装令牌一次性使用，激活后换成永久节点 token；面板只存哈希，重置后旧 token 立即失效
- agent 通道与面板共用监听地址；HTTPS 部署时使用自签 CA + 证书钉扎，安装命令还校验脚本哈希
- 数据目录（含全部密码/凭据）权限 600/700，请做好备份
- 面板 HTTP 明文仅限可信网络；公网部署务必加 TLS 反代
