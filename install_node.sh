#!/bin/bash
# ksing-ui 节点一键安装: 裸核 sing-box (官方源码 + with_v2ray_api) + ksing-agent
# 用法(由面板生成, 含脚本哈希与 CA 指纹校验):
#   curl -fsSLk '<面板>/agent/install.sh' -o /tmp/ks-i.sh \
#     && echo '<脚本sha256>  /tmp/ks-i.sh' | sha256sum -c \
#     && bash /tmp/ks-i.sh '<面板url>' '<sid>' '<安装令牌>' '<CA指纹sha256>'
# 第 3 个参数是一次性安装令牌: 兑换成永久节点令牌后立即作废, 重放安装命令无效
set -euo pipefail

PANEL_URL="${1:?缺少面板地址}"
SID="${2:?缺少 sid}"
TOKEN="${3:?缺少 token}"
CA_FP="${4:?缺少 CA 指纹}"
DIR=/etc/ksing
BIN=/usr/local/bin/k-sing
PYBIN="$(command -v python3 || true)"

[ "$(id -u)" = "0" ] || { echo "需要 root 运行"; exit 1; }
for c in curl openssl systemctl sha256sum; do
  command -v "$c" >/dev/null || { echo "缺少命令: $c"; exit 1; }
done
[ -n "$PYBIN" ] || { echo "缺少 python3"; exit 1; }
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "不支持的架构: $(uname -m)"; exit 1 ;;
esac
[[ "$PANEL_URL" =~ ^https?://[A-Za-z0-9.:-]+$ ]] || { echo "面板地址非法"; exit 1; }
[[ "$PANEL_URL" =~ ^http:// ]] && echo "!! 警告: 面板为明文 HTTP, 节点与面板间通信(含节点 token)不加密, 生产环境请用 nginx 反代加 TLS"
[[ "$SID" =~ ^[0-9a-f]{8}$ ]] || { echo "sid 非法"; exit 1; }
[[ "$TOKEN" =~ ^[0-9a-f]{64}$ ]] || { echo "token 非法"; exit 1; }
[[ "$CA_FP" =~ ^[0-9a-f]{64}$ ]] || { echo "CA 指纹非法"; exit 1; }

mkdir -p "$DIR/rulesets"
chmod 700 "$DIR"

USE_PANEL_CA=0
if [[ "$PANEL_URL" =~ ^https:// ]]; then
  if curl -fsSL --max-time 15 "$PANEL_URL/agent/ca.pem" -o /dev/null 2>/dev/null; then
    echo "面板使用公开受信证书 (如 nginx 反代), 走系统 CA 校验"
    rm -f "$DIR/panel-ca.pem"
  else
    # 面板自签证书: 下载 CA 并校验指纹 (TOFU 通道上防 MITM 换证书)
    curl -fsSLk "$PANEL_URL/agent/ca.pem" -o "$DIR/panel-ca.pem"
    GOT_FP="$(openssl x509 -in "$DIR/panel-ca.pem" -outform DER | sha256sum | cut -d' ' -f1)"
    [ "$GOT_FP" = "$CA_FP" ] || { echo "面板 CA 指纹不匹配! 期望 $CA_FP 实际 $GOT_FP , 可能遭遇中间人攻击, 终止。"; rm -f "$DIR/panel-ca.pem"; exit 1; }
    chmod 644 "$DIR/panel-ca.pem"
    USE_PANEL_CA=1
  fi
else
  echo "!! 面板为明文 HTTP, agent 通信不加密, 强烈建议用 nginx 反代加 TLS"
  rm -f "$DIR/panel-ca.pem"
fi
# 面板证书 CN=ksing-panel-agent 为固定信任锚; 用 --resolve 把该名字指到面板地址,
# 使 TLS 主机名校验对任意面板 IP/域名都能通过 (等效证书钉扎)
URLHOSTPORT="${PANEL_URL#*://}"          # 去 scheme
case "$URLHOSTPORT" in
  \[*\]:*) PHOST="${URLHOSTPORT%%\]*}"; PHOST="${PHOST#\[}"; PPORT="${URLHOSTPORT##*:}" ;;
  \[*\])   PHOST="${URLHOSTPORT#\[}"; PHOST="${PHOST%\]}"; PPORT="" ;;
  *:*)       PHOST="${URLHOSTPORT%%:*}"; PPORT="${URLHOSTPORT##*:}" ;;
  *)         PHOST="$URLHOSTPORT"; PPORT="" ;;
esac
PPORT="${PPORT:-443}"
[[ "$PHOST" =~ ^[A-Za-z0-9.-]+$ ]] || [[ "$PHOST" =~ ^[0-9a-fA-F:]+$ ]] || { echo "面板主机非法: $PHOST"; exit 1; }
# curl --resolve 只接受 IP: 域名先解析 (优先 IPv4, 兜底 IPv6)
if ! [[ "$PHOST" =~ ^[0-9.]+$ ]] && ! [[ "$PHOST" =~ ^[0-9a-fA-F:]+$ ]]; then
  RIP="$(getent ahostsv4 "$PHOST" | awk 'NR==1{print $1}')"
  [ -n "$RIP" ] || RIP="$(getent ahostsv6 "$PHOST" | awk 'NR==1{print $1}')"
  [ -n "$RIP" ] || { echo "面板域名解析失败: $PHOST"; exit 1; }
  PHOST="$RIP"
fi
case "$PHOST" in *:*) RHOST="[$PHOST]" ;; *) RHOST="$PHOST" ;; esac  # IPv6 需方括号
if [ "$USE_PANEL_CA" = "1" ]; then
  CURL="curl -fsSL --cacert $DIR/panel-ca.pem --resolve ksing-panel-agent:$PPORT:$RHOST"
else
  CURL="curl -fsSL"   # 系统 CA (https) 或明文 (http)
fi
PINNED_URL="https://ksing-panel-agent:$PPORT"

# 一次性安装令牌兑换永久节点令牌: 每个安装命令只能执行一次, 兑换即作废
if [ "$USE_PANEL_CA" = "1" ]; then API_URL="$PINNED_URL"; else API_URL="$PANEL_URL"; fi
echo "[0/5] 兑换永久节点令牌 (安装令牌一次性, 已自动作废) ..."
ACT="$($CURL -X POST -H "Authorization: Bearer $TOKEN" "$API_URL/agent/activate")" || {
  echo "!! 安装令牌无效或已被使用 (每个安装命令只能执行一次)。"
  echo "!! 请在面板对该节点执行「重新部署」获取新的安装命令。"
  exit 1
}
TOKEN="$($PYBIN -c 'import json,sys; print(json.load(sys.stdin).get("token",""))' <<<"$ACT")"
[[ "$TOKEN" =~ ^[0-9a-f]{64}$ ]] || { echo "令牌兑换响应异常: ${ACT:0:200}"; exit 1; }

echo "[1/5] 下载 sing-box ($ARCH) ..."
$CURL -H "Authorization: Bearer $TOKEN" "$API_URL/agent/binary/$ARCH" -o "$BIN.new"
chmod 755 "$BIN.new"
mv "$BIN.new" "$BIN"
"$BIN" version

# 节点元信息: 证书模式/域名/端口等 (面板统一管理)
META="$($CURL -H "Authorization: Bearer $TOKEN" "$API_URL/agent/node-meta")"
CERT_MODE="$($PYBIN -c 'import json,sys; print(json.load(sys.stdin).get("cert_mode",""))' <<<"$META")"
SNI="$($PYBIN -c 'import json,sys; print(json.load(sys.stdin).get("sni",""))' <<<"$META")"
DOMAIN="$($PYBIN -c 'import json,sys; print(json.load(sys.stdin).get("domain",""))' <<<"$META")"
SNI="${SNI:-anytls.example.com}"

echo "[2/5] 证书处理 (模式: ${CERT_MODE:-未知}) ..."
case "$CERT_MODE" in
  acme)
    [ -n "$DOMAIN" ] || { echo "acme 模式但面板未配置域名"; exit 1; }
    echo "  使用 ACME 自动证书: $DOMAIN (由 sing-box 申请并自动续签)"
    echo "  请确认: ① 域名 $DOMAIN 已解析到本机 ② 本机 80 端口空闲且放行 (HTTP-01 验证)"
    if ss -tln 2>/dev/null | grep -qE ':(80)\s'; then
      echo "  警告: 80 端口已被占用, ACME HTTP-01 验证可能失败"
    fi
    rm -f "$DIR/cert.pem" "$DIR/key.pem" 2>/dev/null || true
    ;;
  selfip)
    # IP 自签证书 (SAN 含节点 IP); 客户端需允许不安全连接
    IP="$(curl -4fsSL --max-time 10 https://ifconfig.me 2>/dev/null || curl -4fsSL --max-time 10 https://api.ipify.org 2>/dev/null || true)"
    [[ "$IP" =~ ^[0-9.]{7,45}$ ]] || { echo "无法确定节点公网 IP"; exit 1; }
    echo "  生成 IP 自签证书 (SAN: IP:$IP); 客户端需开启 allowInsecure"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
      -subj "/CN=$IP" -addext "subjectAltName=IP:$IP" \
      -keyout "$DIR/key.pem" -out "$DIR/cert.pem" 2>/dev/null
    chmod 600 "$DIR/key.pem"
    ;;
  unsafe)
    echo "  !! unsafe 模式: 使用无域名自签证书, 流量特征明显, 客户端必须跳过证书校验 !!"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
      -subj "/CN=$SNI" -keyout "$DIR/key.pem" -out "$DIR/cert.pem" 2>/dev/null
    chmod 600 "$DIR/key.pem"
    ;;
  *)
    echo "面板未配置证书模式 (cert_mode), 请先在面板编辑该节点"; exit 1 ;;
esac

echo "[3/5] 写入 agent 配置 ..."
cat > "$DIR/agent.json" <<EOF
{"panel": "$PANEL_URL", "sid": "$SID", "token": "$TOKEN",
 "ca": "$([ "$USE_PANEL_CA" = "1" ] && echo "$DIR/panel-ca.pem")", "dir": "$DIR", "bin": "$BIN",
 "pull_interval": 30, "push_interval": 10}
EOF
chmod 600 "$DIR/agent.json"

echo "[4/5] 安装 agent ..."
$CURL -H "Authorization: Bearer $TOKEN" "$API_URL/agent/agent.py" -o "$DIR/agent.py"
chmod 700 "$DIR/agent.py"

echo "[5/5] 注册并启动 systemd 服务 ..."
# 迁移旧版 unit: 我们以前装的 sing-box.service (含 ksing 标记) 停掉删除, 与官版 sing-box 并存不冲突
if [ -f /etc/systemd/system/sing-box.service ] && grep -q "ksing node" /etc/systemd/system/sing-box.service; then
  echo "  迁移旧版 sing-box.service → k-sing.service"
  systemctl disable --now sing-box 2>/dev/null || true
  rm -f /etc/systemd/system/sing-box.service
fi
cat > /etc/systemd/system/k-sing.service <<EOF
[Unit]
Description=k-sing (ksing node)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
ExecStart=$BIN run -c $DIR/config.json
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/ksing-agent.service <<EOF
[Unit]
Description=ksing-ui node agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
ExecStart=$PYBIN $DIR/agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

# 重新部署场景: 先停旧服务, 避免 --once 与运行中的 agent 触发单实例锁冲突
systemctl stop ksing-agent k-sing 2>/dev/null || true

# 首次拉取配置 (生成 $DIR/config.json) 后启动
if $PYBIN "$DIR/agent.py" --once; then
  systemctl enable --now k-sing ksing-agent
  sleep 3
  BAD=0
  for u in k-sing ksing-agent; do
    if ! systemctl is-active --quiet "$u"; then
      echo "!! $u 未能正常运行, 最近日志:"
      journalctl -u "$u" -n 30 --no-pager 2>/dev/null || true
      BAD=1
    fi
  done
  if [ "$BAD" = "0" ]; then
    echo "完成: 节点已接入面板并在线。"
  else
    echo "请根据上方日志排查; 修复后执行: systemctl restart k-sing ksing-agent"
    exit 1
  fi
else
  echo "首次配置拉取失败, 请检查面板连通性后重试: $PYBIN $DIR/agent.py --once"
  exit 1
fi
