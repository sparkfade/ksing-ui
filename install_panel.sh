#!/bin/bash
# ksing-ui 中控面板管理脚本
# 用法:
#   安装(全新):  curl -fsSL https://raw.githubusercontent.com/sparkfade/ksing-ui/main/install_panel.sh | sudo bash
#               或 sudo bash install_panel.sh install [面板端口=8080] [agent端口=9443]
#   升级:        sudo bash /opt/ksing-ui/install_panel.sh upgrade
#   重启:        sudo bash /opt/ksing-ui/install_panel.sh restart
#   状态:        sudo bash /opt/ksing-ui/install_panel.sh status
#   卸载:        sudo bash /opt/ksing-ui/install_panel.sh uninstall [--purge 连数据一起删]
set -euo pipefail

REPO="https://github.com/sparkfade/ksing-ui.git"
APP_DIR=/opt/ksing-ui
DATA_DIR=/etc/ksing-ui
SERVICE=/etc/systemd/system/ksing-ui.service
PYBIN="$(command -v python3 || true)"

ACTION="install"
case "${1:-}" in
  install|upgrade|restart|status|uninstall) ACTION="$1"; shift ;;
  "" ) ;;
  * )
    if [[ "${1:-}" =~ ^[0-9]+$ ]]; then :  # 兼容 install <port> [agent_port] 直接给端口的旧用法
    else echo "未知操作: $1"; exit 1; fi ;;
esac

[ "$(id -u)" = "0" ] || { echo "需要 root 运行"; exit 1; }

case "$ACTION" in

restart)
  systemctl restart ksing-ui && echo "已重启" ;;

status)
  systemctl status ksing-ui --no-pager ;;

upgrade)
  [ -d "$APP_DIR/.git" ] || { echo "未安装, 请先 install"; exit 1; }
  echo "拉取最新代码 ..."
  git -C "$APP_DIR" pull --ff-only
  if [ "${1:-}" = "--with-binaries" ]; then
    bash "$APP_DIR/tools/build_node_binary.sh" "$DATA_DIR/bin"
  fi
  systemctl restart ksing-ui
  echo "升级完成并已重启" ;;

uninstall)
  systemctl disable --now ksing-ui 2>/dev/null || true
  rm -f "$SERVICE"
  systemctl daemon-reload
  rm -rf "$APP_DIR"
  if [ "${1:-}" = "--purge" ]; then
    rm -rf "$DATA_DIR"
    echo "已卸载并删除数据目录 $DATA_DIR"
  else
    echo "已卸载; 数据目录保留在 $DATA_DIR (连同数据一起删: uninstall --purge)"
  fi ;;

install)
  PANEL_PORT="${1:-8080}"
  AGENT_PORT="${2:-9443}"
  if [ -f "$SERVICE" ]; then
    echo "检测到已安装, 为防止覆盖已停止操作。升级请用: bash $APP_DIR/install_panel.sh upgrade"
    exit 1
  fi
  for c in git openssl curl; do
    command -v "$c" >/dev/null || { echo "缺少命令: $c"; exit 1; }
  done
  [ -n "$PYBIN" ] || { echo "缺少 python3"; exit 1; }

  echo "[1/4] 拉取面板代码 ..."
  git clone --depth 1 "$REPO" "$APP_DIR"

  echo "[2/4] 初始化数据目录 $DATA_DIR ..."
  mkdir -p "$DATA_DIR"
  chmod 700 "$DATA_DIR"
  python3 "$APP_DIR/sbtool.py" --dir "$DATA_DIR" set --panel-listen :: --panel-port "$PANEL_PORT" --agent-port "$AGENT_PORT" >/dev/null
  echo "  预构建规则集清单 (仅清单不下载文件, 需访问 GitHub) ..."
  if timeout 180 python3 "$APP_DIR/sbtool.py" --dir "$DATA_DIR" index >/dev/null 2>&1; then
    echo "  规则集清单已就绪"
  else
    echo "  !! 清单构建失败 (网络问题, 不影响面板运行)" >&2
    echo "     面板启动后在「规则集」页点「刷新清单」即可补上。" >&2
  fi

  echo "[3/4] 构建节点用 sing-box 二进制 (官方源码 + with_v2ray_api) ..."
  if [ -x "$DATA_DIR/bin/sing-box-linux-amd64" ]; then
    echo "  已存在, 跳过 (重新构建: bash $APP_DIR/tools/build_node_binary.sh $DATA_DIR/bin)"
  elif ! bash "$APP_DIR/tools/build_node_binary.sh" "$DATA_DIR/bin"; then
    echo "  !! 二进制构建失败(多半是磁盘/网络不足)。面板本身可正常用," >&2
    echo "     但节点安装命令下载内核会 404。请在别的机器构建后上传到 $DATA_DIR/bin/ 再重试。" >&2
  fi

  echo "[4/4] 注册并启动 systemd 服务 ..."
  cat > "$SERVICE" <<EOF
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
  echo "日常管理: bash $APP_DIR/install_panel.sh {upgrade|restart|status|uninstall}" ;;
esac
