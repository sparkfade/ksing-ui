#!/bin/bash
# ksing-ui 节点一键安装: 裸核 sing-box (官方源码 + with_v2ray_api) + ksing-agent
# 用法(由面板生成, 含脚本哈希与 CA 指纹校验):
#   curl -fsSLk '<面板>/agent/install.sh' -o /tmp/ks-i.sh \
#     && echo '<脚本sha256>  /tmp/ks-i.sh' | sha256sum -c \
#     && bash /tmp/ks-i.sh '<面板url>' '<sid>' '<token>' '<CA指纹sha256>'
set -euo pipefail

PANEL_URL="${1:?缺少面板地址}"
SID="${2:?缺少 sid}"
TOKEN="${3:?缺少 token}"
CA_FP="${4:?缺少 CA 指纹}"
DIR=/etc/ksing
BIN=/usr/local/bin/sing-box
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
[[ "$PANEL_URL" =~ ^https://[A-Za-z0-9.:-]+$ ]] || { echo "面板地址非法"; exit 1; }
[[ "$SID" =~ ^[0-9a-f]{8}$ ]] || { echo "sid 非法"; exit 1; }
[[ "$TOKEN" =~ ^[0-9a-f]{64}$ ]] || { echo "token 非法"; exit 1; }
[[ "$CA_FP" =~ ^[0-9a-f]{64}$ ]] || { echo "CA 指纹非法"; exit 1; }

mkdir -p "$DIR/rulesets"
chmod 700 "$DIR"

# 下载面板 CA 并校验指纹 (TOFU 通道上防 MITM 换证书)
curl -fsSLk "$PANEL_URL/agent/ca.pem" -o "$DIR/panel-ca.pem"
GOT_FP="$(openssl x509 -in "$DIR/panel-ca.pem" -outform DER | sha256sum | cut -d' ' -f1)"
[ "$GOT_FP" = "$CA_FP" ] || { echo "面板 CA 指纹不匹配! 期望 $CA_FP 实际 $GOT_FP , 可能遭遇中间人攻击, 终止。"; rm -f "$DIR/panel-ca.pem"; exit 1; }
chmod 644 "$DIR/panel-ca.pem"
# 面板证书 CN=ksing-panel-agent 为固定信任锚; 用 --resolve 把该名字指到面板地址,
# 使 TLS 主机名校验对任意面板 IP/域名都能通过 (等效证书钉扎)
PHOST="$(echo "$PANEL_URL" | sed 's|https://||; s|:[0-9]*$||; s|^\[||; s|\]$||')"
PPORT="$(echo "$PANEL_URL" | grep -oE '[0-9]+$' || true)"
PPORT="${PPORT:-443}"
[[ "$PHOST" =~ ^[A-Za-z0-9.-]+$ ]] || [[ "$PHOST" =~ ^[0-9a-fA-F:]+$ ]] || { echo "面板主机非法: $PHOST"; exit 1; }
CURL="curl -fsSL --cacert $DIR/panel-ca.pem --resolve ksing-panel-agent:$PPORT:$PHOST"
PINNED_URL="https://ksing-panel-agent:$PPORT"

echo "[1/5] 下载 sing-box ($ARCH) ..."
$CURL -H "Authorization: Bearer $TOKEN" "$PINNED_URL/agent/binary/$ARCH" -o "$BIN.new"
chmod 755 "$BIN.new"
mv "$BIN.new" "$BIN"
"$BIN" version

# 节点元信息: 证书模式/域名/端口等 (面板统一管理)
META="$($CURL -H "Authorization: Bearer $TOKEN" "$PINNED_URL/agent/node-meta")"
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
 "ca": "$DIR/panel-ca.pem", "dir": "$DIR", "bin": "$BIN",
 "pull_interval": 30, "push_interval": 30}
EOF
chmod 600 "$DIR/agent.json"

echo "[4/5] 安装 agent ..."
$CURL -H "Authorization: Bearer $TOKEN" "$PINNED_URL/agent/agent.py" -o "$DIR/agent.py"
chmod 700 "$DIR/agent.py"

echo "[5/5] 注册并启动 systemd 服务 ..."
cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box (ksing node)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN run -c $DIR/config.json
Restart=on-failure
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

[Service]
ExecStart=$PYBIN $DIR/agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

# 首次拉取配置 (生成 $DIR/config.json) 后启动
if $PYBIN "$DIR/agent.py" --once; then
  systemctl enable --now sing-box ksing-agent
  echo "完成: 节点已接入面板并在线。"
else
  echo "首次配置拉取失败, 请检查面板连通性后重试: $PYBIN $DIR/agent.py --once"
  exit 1
fi
