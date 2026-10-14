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
VER="${SB_VERSION#v}-ksing"

mkdir -p "$WORK"

# Go 构建需要约 3GB 临时空间 (工具链 + 模块缓存 + 编译缓存)
FREE_MB=$(df -Pm /tmp "$HOME" | awk 'NR>1 {print $4}' | sort -n | head -1)
if [ "$FREE_MB" -lt 3072 ]; then
  echo "错误: 磁盘剩余空间不足 3GB (当前约 ${FREE_MB}MB), 无法构建 sing-box。" >&2
  echo "处理办法:" >&2
  echo "  1) 清理后重试: rm -rf /tmp/ksing-build ~/.cache/go-build && df -h /" >&2
  echo "  2) 或在别的机器上构建后上传: 在其他 Linux 机器执行" >&2
  echo "       bash tools/build_node_binary.sh /tmp/sb-bin" >&2
  echo "     然后把 /tmp/sb-bin/sing-box-linux-* 上传到本面板数据目录的 bin/ 下即可" >&2
  exit 1
fi

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
# 用该版本仓库自带的官方构建 tags (去掉需要 CGO 的 naive), 再加 with_v2ray_api
TAGS="$(sed 's/with_naive_outbound,//; s/,,*/,/g; s/,$//; s/^,//' release/DEFAULT_BUILD_TAGS),with_v2ray_api"
echo "构建 tags: $TAGS"
export CGO_ENABLED=0
for arch in amd64 arm64; do
  echo "构建 linux/$arch ..."
  GOOS=linux GOARCH=$arch "$GO" build -tags "$TAGS" -trimpath \
    -ldflags "-s -w -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=$VER" \
    -o "$OUT/sing-box-linux-$arch" ./cmd/sing-box
done
chmod 755 "$OUT"/sing-box-linux-*
"$GO" clean -cache 2>/dev/null || true  # 释放编译缓存 (可达数 GB)
echo "完成:"
"$OUT/sing-box-linux-amd64" version | head -3
