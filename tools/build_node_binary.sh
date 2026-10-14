#!/bin/bash
# 构建节点用 sing-box 二进制 (官方源码 + 官方 with_v2ray_api 构建开关, 供流量统计)
# 用法: bash tools/build_node_binary.sh [输出目录=./sbdata/bin]
set -euo pipefail

OUT="${1:-./sbdata/bin}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
SB_VERSION="${SB_VERSION:-v1.14.3}"
GO_VERSION="${GO_VERSION:-1.27.2}"
WORK=/tmp/ksing-build
TAGS="with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0,with_v2ray_api"
VER="${SB_VERSION#v}-ksing"

mkdir -p "$WORK"

# Go 工具链 (没有就下载到 /tmp, 不污染系统)
if command -v go >/dev/null; then
  GO=go
else
  case "$(uname -m)" in
    x86_64) GOARCH=amd64 ;;
    aarch64) GOARCH=arm64 ;;
    *) echo "不支持的构建架构: $(uname -m)"; exit 1 ;;
  esac
  if [ ! -x "$WORK/go/bin/go" ]; then
    echo "下载 Go $GO_VERSION ($GOARCH) ..."
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -o "$WORK/go.tgz"
    rm -rf "$WORK/go" && tar -C "$WORK" -xzf "$WORK/go.tgz"
  fi
  GO="$WORK/go/bin/go"
fi
echo "使用 $($GO version)"

# sing-box 官方源码
if [ -d "$WORK/sing-box/.git" ]; then
  git -C "$WORK/sing-box" fetch --depth 1 origin "refs/tags/$SB_VERSION" && git -C "$WORK/sing-box" checkout -q FETCH_HEAD
else
  git clone --depth 1 --branch "$SB_VERSION" https://github.com/SagerNet/sing-box "$WORK/sing-box"
fi

cd "$WORK/sing-box"
export CGO_ENABLED=0
for arch in amd64 arm64; do
  echo "构建 linux/$arch ..."
  GOOS=linux GOARCH=$arch "$GO" build -tags "$TAGS" -trimpath \
    -ldflags "-s -w -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=$VER" \
    -o "$OUT/sing-box-linux-$arch" ./cmd/sing-box
done
chmod 755 "$OUT"/sing-box-linux-*
echo "完成:"
"$OUT/sing-box-linux-amd64" version | head -3
