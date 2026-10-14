#!/bin/bash
# ksing-ui 中控面板一键安装 (systemd 常驻)
# 用法: curl -fsSL https://raw.githubusercontent.com/sparkfade/ksing-ui/main/install_panel.sh | sudo bash
#   或: sudo bash install_panel.sh [面板端口=8080] [agent端口=9443]
set -euo pipefail

REPO="https://github.com/sparkfade/ksing-ui.git"
APP_DIR=/opt/ksing-ui
DATA_DIR=/etc/ksing-ui
PANEL_PORT="${1:-8080}"
AGENT_PORT="${2:-9443}"
PYBIN="$(command -v python3 || true)"

[ "$(id -u)" = "0" ] || { echo "需要 root 运行"; exit 1; }
for c in git openssl curl; do
  command -v "$c" >/dev/null || { echo "缺少命令: $c"; exit 1; }
done
[ -n "$PYBIN" ] || { echo "缺少 python3"; exit 1; }

echo "[1/4] 拉取面板代码 ..."
if [ -d "$APP_DIR/.git" ]; then
  git -C "$APP_DIR" pull --ff-only
else
  git clone --depth 1 "$REPO" "$APP_DIR"
fi

echo "[2/4] 初始化数据目录 $DATA_DIR ..."
mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"
python3 "$APP_DIR/sbtool.py" --dir "$DATA_DIR" set --panel-listen :: --panel-port "$PANEL_PORT" --agent-port "$AGENT_PORT" >/dev/null

echo "[3/4] 构建节点用 sing-box 二进制 (官方源码 + with_v2ray_api) ..."
if [ -x "$DATA_DIR/bin/sing-box-linux-amd64" ]; then
  echo "  已存在, 跳过 (重新构建: bash $APP_DIR/tools/build_node_binary.sh $DATA_DIR/bin)"
else
  bash "$APP_DIR/tools/build_node_binary.sh" "$DATA_DIR/bin"
fi

echo "[4/4] 注册并启动 systemd 服务 ..."
cat > /etc/systemd/system/ksing-ui.service <<EOF
[Unit]
Description=ksing-ui 中控面板
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$APP_DIR
ExecStart=$PYBIN $APP_DIR/server.py --dir $DATA_DIR
Environment=PYTHONUNBUFFERED=1
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now ksing-ui

echo ""
echo "完成! 面板地址: http://<本机IP>:$PANEL_PORT  (首次打开请设置管理员密码)"
echo "agent 下发通道: 端口 $AGENT_PORT (节点安装时自动使用)"
echo "请在防火墙放行 $PANEL_PORT 和 $AGENT_PORT 端口。"
echo "数据目录: $DATA_DIR  (含全部密码与凭据, 注意备份与权限)"
