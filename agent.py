#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ksing-ui 节点 agent (纯 Python 标准库, 无需第三方依赖)

职责:
  1. 周期性从面板拉取本节点的 sing-box 配置 (hash 增量), sing-box check 校验后切换
  2. 同步规则集 .srs 文件 (sha256 校验)
  3. 通过本机 v2ray api (gRPC StatsService) 查询用户流量 (reset 模式取增量) 并上报面板

配置: agent.json (install.sh 生成)
  {"panel": "https://1.2.3.4:9443", "sid": "...", "token": "...",
   "ca": "<面板CA路径>", "dir": "/etc/ksing", "bin": "/usr/local/bin/sing-box",
   "stats": "127.0.0.1:18899", "pull_interval": 30, "push_interval": 30}
"""

import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# 服务器常见 C/POSIX locale 会把 stdout 切成 latin-1, 中文日志会崩; 强制 UTF-8
for _f in (sys.stdout, sys.stderr):
    try:
        _f.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

VERSION = "1.5.0"

CFG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.json")
if not os.path.exists(CFG_PATH):
    CFG_PATH = "/etc/ksing/agent.json"

with open(CFG_PATH, "r", encoding="utf-8") as _f:
    _C = json.load(_f)

PANEL = _C["panel"].rstrip("/")
IS_HTTPS = PANEL.lower().startswith("https://")
if not IS_HTTPS:
    print("警告: 面板地址为明文 HTTP, agent 通信(含节点 token)不加密, 建议用 nginx 反代加 TLS", flush=True)
TOKEN = _C["token"]
DIR = _C.get("dir", "/etc/ksing")
BIN = _C.get("bin", "/usr/local/bin/sing-box")
CA = _C.get("ca", os.path.join(DIR, "panel-ca.pem"))
STATS = _C.get("stats", "127.0.0.1:18899")
PULL_INTERVAL = int(_C.get("pull_interval", 30))
PUSH_INTERVAL = int(_C.get("push_interval", 10))
STATE_PATH = os.path.join(DIR, "agent-state.json")
PENDING_PATH = os.path.join(DIR, "agent-pending.json")  # 未获面板确认的流量增量与目标累计值
BASELINE_PATH = os.path.join(DIR, "agent-baseline.json")  # 面板已确认的 core 累计计数器基线
RULESET_DIR = os.path.join(DIR, "rulesets")
HEALTH = {"ok_at": time.time()}  # 看门狗: 面板通信连续失败则退出让 systemd 重启
LAST_ERROR = [""]  # 最近一次错误, 随上报带给面板 (列表包一层便于跨线程改写)


def log(msg):
    print("[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg), flush=True)


# ------------------------------------------------------------------ 面板 HTTPS (CA 固定)

def make_ssl_ctx():
    if CA and os.path.exists(CA):
        # 只信任面板这张自签证书, 等效于证书指纹锁定; 故不再校验主机名
        ctx = ssl.create_default_context(cafile=CA)
        ctx.check_hostname = False
        return ctx
    # 无面板 CA: 系统 CA + 主机名校验 (面板用正式证书, 如 nginx 反代)
    return ssl.create_default_context()


SSL_CTX = make_ssl_ctx()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """禁止重定向: 避免节点凭据或公网 IP 查询被带往第三方"""

    def redirect_request(self, *args, **kwargs):
        return None


# ProxyHandler({}): 显式置空代理, 免疫节点环境里残留的 http_proxy/https_proxy 变量
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                      _NoRedirect(),
                                      urllib.request.HTTPSHandler(context=SSL_CTX))
# 公网 IP 查询独立通道: 不使用面板 CA, 也不继承环境代理/重定向
_PUBLIC_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def api(method, path, body=None, timeout=30):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(PANEL + path, data=data, method=method, headers={
        "Authorization": "Bearer " + TOKEN,
        "User-Agent": "ksing-agent/" + VERSION,
        "Content-Type": "application/json",
    })
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            out = r.read()
    except urllib.error.HTTPError as e:
        if e.code == 401:
            log("!! 节点 token 已失效(401): 请在面板对本节点执行「重新部署」获取新安装命令")
        elif e.code == 403:
            log("!! 节点已被面板禁用(403), 请在面板检查节点状态")
        raise
    HEALTH["ok_at"] = time.time()  # 面板通信成功, 喂看门狗
    return out


def api_json(method, path, body=None, timeout=30):
    return json.loads(api(method, path, body, timeout).decode("utf-8"))


# ------------------------------------------------------------------ 最小 HTTP/2 + gRPC 客户端
# 仅够调用 v2ray.core.app.stats.command.StatsService/QueryStats:
# HPACK 全部使用 "不索引字面量" 编码; 响应只取 DATA 帧, 忽略头部帧内容

class H2Error(Exception):
    pass


def _read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise H2Error("连接被关闭")
        buf += chunk
    return buf


def _frame(typ, flags, sid, payload):
    return len(payload).to_bytes(3, "big") + bytes([typ, flags]) + sid.to_bytes(4, "big") + payload


def _hpack_str(s):
    b = s.encode("utf-8")
    return bytes([len(b)]) + b  # 不使用 Huffman (最高位 0), 长度均 < 128


def _headers_block(headers):
    out = b""
    for k, v in headers:
        out += b"\x00" + _hpack_str(k) + _hpack_str(v)  # literal header field without indexing
    return out


def grpc_call(host, port, method_path, req_body, timeout=15):
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        # SETTINGS: 把流级初始窗口提到最大, 避免统计量大时漏发 WINDOW_UPDATE 卡死
        sock.sendall(_frame(0x4, 0, 0, (0x4).to_bytes(2, "big") + (16777215).to_bytes(4, "big")))
        sock.sendall(_frame(0x8, 0, 0, (16777215).to_bytes(4, "big")))  # 连接级窗口
        sock.sendall(_frame(0x1, 0x4, 1, _headers_block([  # HEADERS + END_HEADERS
            (":method", "POST"), (":scheme", "http"), (":path", method_path),
            (":authority", "%s:%d" % (host, port)),
            ("content-type", "application/grpc"), ("te", "trailers"),
        ])))
        msg = b"\x00" + len(req_body).to_bytes(4, "big") + req_body  # gRPC 帧: 压缩标志+长度+消息
        sock.sendall(_frame(0x0, 0x1, 1, msg))  # DATA + END_STREAM
        data = b""
        while True:
            hdr = _read_exact(sock, 9)
            ln = int.from_bytes(hdr[0:3], "big")
            if ln > 16 * 1024 * 1024:
                raise H2Error("帧过长")
            typ, flags = hdr[3], hdr[4]
            payload = _read_exact(sock, ln) if ln else b""
            if typ == 0x4:  # SETTINGS
                if not flags & 0x1:
                    sock.sendall(_frame(0x4, 0x1, 0, b""))  # ACK
            elif typ == 0x0:  # DATA
                data += payload
                if len(data) > 32 * 1024 * 1024:
                    raise H2Error("响应过大")
            elif typ == 0x1:  # HEADERS (grpc trailers)
                if flags & 0x1:  # END_STREAM: 响应结束
                    break
            elif typ == 0x3:  # RST_STREAM
                raise H2Error("stream reset: %s" % payload.hex())
            elif typ == 0x7:  # GOAWAY
                raise H2Error("goaway")
        return data
    finally:
        sock.close()


# ------------------------------------------------------------------ 最小 protobuf 编解码

def pb_varint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def pb_read_varint(buf, i):
    n = 0
    shift = 0
    while True:
        b = buf[i]
        i += 1
        n |= (b & 0x7F) << shift
        if not b & 0x80:
            return n, i
        shift += 7


def pb_skip(buf, i, wt):
    if wt == 0:
        _, i = pb_read_varint(buf, i)
        return i
    if wt == 1:
        return i + 8
    if wt == 2:
        ln, i = pb_read_varint(buf, i)
        return i + ln
    if wt == 5:
        return i + 4
    raise ValueError("未知 wire type %d" % wt)


def encode_query_stats_request(pattern, reset):
    out = b""
    if pattern:
        p = pattern.encode("utf-8")
        out += b"\x0a" + pb_varint(len(p)) + p  # field 1 (string)
    if reset:
        out += b"\x10\x01"  # field 2 (bool) = true
    return out


def decode_stat(buf):
    name, value, i = "", 0, 0
    while i < len(buf):
        key, i = pb_read_varint(buf, i)
        field, wt = key >> 3, key & 7
        if field == 1 and wt == 2:
            ln, i = pb_read_varint(buf, i)
            name = buf[i:i + ln].decode("utf-8", "replace")
            i += ln
        elif field == 2 and wt == 0:
            value, i = pb_read_varint(buf, i)
        else:
            i = pb_skip(buf, i, wt)
    return name, value


def decode_query_stats_response(msg):
    stats = {}
    i = 0
    while i < len(msg):
        key, i = pb_read_varint(msg, i)
        field, wt = key >> 3, key & 7
        if field == 1 and wt == 2:
            ln, i = pb_read_varint(msg, i)
            name, value = decode_stat(msg[i:i + ln])
            i += ln
            if name:
                stats[name] = value
        else:
            i = pb_skip(msg, i, wt)
    return stats


def query_traffic():
    """读取 core 累计计数器(不 reset), 返回 {user: [up, down]}。
    非破坏式读取消除了 reset 后到 pending 落盘前的丢账窗口。"""
    host, port = STATS.rsplit(":", 1)
    data = grpc_call(host, int(port),
                     "/v2ray.core.app.stats.command.StatsService/QueryStats",
                     encode_query_stats_request("", False))
    if len(data) < 5 or data[0] != 0:
        raise H2Error("gRPC 响应为空或被压缩")
    ln = int.from_bytes(data[1:5], "big")
    stats = decode_query_stats_response(data[5:5 + ln])
    out = {}
    for name, value in stats.items():
        m = re.fullmatch(r"user>>>(.+)>>>traffic>>>(uplink|downlink)", name)
        if not m or value <= 0:
            continue
        pair = out.setdefault(m.group(1), [0, 0])
        pair[0 if m.group(2) == "uplink" else 1] += value
    return out


# ------------------------------------------------------------------ 状态与配置应用

def load_state():
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state):
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_PATH)


def load_pending():
    try:
        with open(PENDING_PATH, "r", encoding="utf-8") as f:
            p = json.load(f)
        if isinstance(p.get("id"), str) and isinstance(p.get("stats"), dict):
            return p
    except (OSError, ValueError):
        pass
    return None


def save_pending(p):
    tmp = PENDING_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(p, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, PENDING_PATH)


def clear_pending():
    try:
        os.remove(PENDING_PATH)
    except OSError:
        pass


def load_baseline():
    try:
        with open(BASELINE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def save_baseline(counters):
    tmp = BASELINE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(counters, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, BASELINE_PATH)


def traffic_delta(baseline, current):
    """累计值差分; core 重启导致计数器回退时, 从回退后的当前值重新计起"""
    delta = {}
    for name, pair in current.items():
        old = baseline.get(name, [0, 0])
        up = pair[0] if pair[0] < old[0] else pair[0] - old[0]
        down = pair[1] if pair[1] < old[1] else pair[1] - old[1]
        if up > 0 or down > 0:
            delta[name] = [up, down]
    return delta


def sync_rulesets(metas):
    os.makedirs(RULESET_DIR, exist_ok=True)
    for m in metas:
        fname = os.path.basename(m["file"])  # 防路径穿越
        fp = os.path.join(RULESET_DIR, fname)
        try:
            with open(fp, "rb") as f:
                if hashlib.sha256(f.read()).hexdigest() == m["sha256"]:
                    continue
        except OSError:
            pass
        data = api("GET", "/agent/ruleset/" + urllib.parse.quote(m["tag"], safe=""), timeout=120)
        if hashlib.sha256(data).hexdigest() != m["sha256"]:
            raise RuntimeError("规则集 %s 校验和不匹配" % m["tag"])
        tmp = fp + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, fp)
        log("规则集已同步: %s (%d 字节)" % (m["tag"], len(data)))


def svc_name():
    """我们的 systemd 服务名: 新版 k-sing; 兼容旧部署(我们装的 sing-box.service, 含 ksing 标记)"""
    for base in ("/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"):
        if os.path.exists(os.path.join(base, "k-sing.service")):
            return "k-sing"
    p = "/etc/systemd/system/sing-box.service"
    if os.path.exists(p):
        try:
            if "ksing" in open(p, encoding="utf-8", errors="ignore").read():
                return "sing-box"
        except OSError:
            pass
    return ""


def have_systemd_unit():
    return (os.path.isdir("/run/systemd/system") and shutil.which("systemctl")
            and bool(svc_name()))


_RESTARTS = []  # 崩溃循环检测: 记录最近的拉起时间


def recent_core_log():
    """取 sing-box 最近几行日志, 用于把崩溃原因透出到面板"""
    if have_systemd_unit():
        try:
            r = subprocess.run(["journalctl", "-u", svc_name(), "-n", "8", "--no-pager"],
                               capture_output=True, text=True, timeout=10)
            lines = [l.strip() for l in (r.stdout or "").splitlines() if l.strip()]
            if lines:
                return " | ".join(lines[-3:])[:250]
        except Exception:  # noqa: BLE001
            pass
    try:
        with open(os.path.join(DIR, "sing-box.log"), "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 4096))
            data = f.read().decode("utf-8", "replace")
        lines = [l.strip() for l in data.splitlines() if l.strip()]
        return " | ".join(lines[-3:])[:250]
    except OSError:
        return ""


def wait_stats_ready(timeout=12):
    """等 sing-box 的统计端口就绪 (重启后立刻查询必然 connection refused)"""
    host, port = STATS.rsplit(":", 1)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, int(port)), timeout=2):
                return True
        except OSError:
            time.sleep(0.6)
    return False


def restart_singbox(relaunch=False):
    if relaunch:
        # 只有「存活检查发现没运行」的拉起才算崩溃迹象; 配置更新的正常重启不算
        _RESTARTS.append(time.time())
        del _RESTARTS[:-10]
        recent = [t for t in _RESTARTS if time.time() - t < 120]
        if len(recent) >= 3:
            tail = recent_core_log()
            LAST_ERROR[0] = ("sing-box 反复重启, 疑似配置或端口问题" +
                             (": " + tail if tail else ""))[:300]
    svc = svc_name()
    if have_systemd_unit():
        r = subprocess.run(["systemctl", "restart", svc], capture_output=True, text=True,
                           timeout=30)
        if r.returncode == 0:
            return
        log("systemctl restart %s 失败(%s), 改用直接进程管理" % (svc, (r.stderr or r.stdout).strip()[:200]))
    # 无 systemd 单元 (容器/调试): 直接管理进程
    pidfile = os.path.join(DIR, "sing-box.pid")
    try:
        with open(pidfile) as f:
            old = int(f.read().strip())
        os.kill(old, 15)
        time.sleep(0.5)
    except (OSError, ValueError):
        pass
    lf = open(os.path.join(DIR, "sing-box.log"), "ab", buffering=0)
    p = subprocess.Popen([BIN, "run", "-c", os.path.join(DIR, "config.json")],
                         stdout=lf, stderr=subprocess.STDOUT, start_new_session=True)
    with open(pidfile, "w") as f:
        f.write(str(p.pid))


def ensure_cert_files(cfg):
    """配置引用本地证书文件但文件缺失时(如面板切换了证书模式), 按节点元信息补生成"""
    try:
        tls = cfg["inbounds"][0]["tls"]
        cert, key = tls["certificate_path"], tls["key_path"]
    except (KeyError, IndexError, TypeError):
        return
    if os.path.isfile(cert) and os.path.isfile(key):
        return
    meta = api_json("GET", "/agent/node-meta")
    mode = meta.get("cert_mode", "unsafe")
    sni = meta.get("sni") or "anytls.example.com"
    ips = query_public_ips() if mode == "selfip" else {"ipv4": "", "ipv6": ""}
    subj = ips["ipv4"] or ips["ipv6"] or sni
    cmd = ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
           "-nodes", "-days", "3650", "-subj", "/CN=%s" % subj]
    sans = [ip for ip in (ips["ipv4"], ips["ipv6"]) if ip]
    if sans:
        cmd += ["-addext", "subjectAltName=" + ",".join("IP:%s" % ip for ip in sans)]
    cmd += ["-keyout", key, "-out", cert]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError("生成自签证书失败: %s" % (r.stderr or "").strip()[:200])
    os.chmod(key, 0o600)
    log("已补生成节点证书 (mode=%s, CN=%s)" % (mode, subj))


_PUBLIC_ENDPOINTS = {
    "ipv4": ("https://ipv4.icanhazip.com", "https://api.ipify.org"),
    "ipv6": ("https://ipv6.icanhazip.com", "https://api6.ipify.org"),
}


def query_public_ips(families=("ipv4", "ipv6")):
    """分别探测公网 IPv4/IPv6; 仅接受全球单播地址, 不走代理/重定向"""
    out = {"ipv4": "", "ipv6": ""}
    for family in families:
        urls = _PUBLIC_ENDPOINTS[family]
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
                with _PUBLIC_OPENER.open(req, timeout=10) as r:
                    ip = r.read(256).decode("ascii", "ignore").strip()
                addr = ipaddress.ip_address(ip)
                if addr.is_global and (addr.version == 4) == (family == "ipv4"):
                    out[family] = str(addr)
                    break
            except (OSError, ValueError, urllib.error.URLError):
                continue
    return out


def query_public_ip():
    return query_public_ips()["ipv4"]


_PUBLIC_IPS = {"value": {"ipv4": "", "ipv6": ""},
               "at": {"ipv4": 0.0, "ipv6": 0.0},
               "ok": {"ipv4": False, "ipv6": False}}
PUBLIC_IP_TTL = 6 * 3600     # 成功值有效期
PUBLIC_IP_RETRY = 60         # 失败族重试间隔 (不再被另一族的 6 小时 TTL 拖住)


def cached_public_ips():
    """低频获取公网 IPv4/IPv6; 分族独立计时, 失败时保留上次成功值避免链接抖动"""
    now = time.time()
    cur = _PUBLIC_IPS["value"]
    due = []
    for family in ("ipv4", "ipv6"):
        age = now - _PUBLIC_IPS["at"][family]
        ttl = PUBLIC_IP_TTL if _PUBLIC_IPS["ok"][family] else PUBLIC_IP_RETRY
        if not _PUBLIC_IPS["at"][family] or age >= ttl:
            due.append(family)
    if due:
        got = query_public_ips(tuple(due))
        for family in due:
            _PUBLIC_IPS["at"][family] = now
            if got[family]:
                cur[family] = got[family]
                _PUBLIC_IPS["ok"][family] = True
            else:
                _PUBLIC_IPS["ok"][family] = False
    return dict(cur)


def cached_public_ip():
    ips = cached_public_ips()
    return ips["ipv4"] or ips["ipv6"]


def self_update(resp):
    """面板下发的 agent_sha256 与自身不一致时, 从面板拉新版本并原地重启。
    仅 HTTPS 通道启用 (明文 HTTP 下 hash 与代码可被同时伪造, 禁用以防 RCE)。"""
    if not IS_HTTPS:
        return
    want = resp.get("agent_sha256")
    if not want:
        return
    try:
        with open(os.path.abspath(__file__), "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() == want:
                return
        data = api("GET", "/agent/agent.py")
        if hashlib.sha256(data).hexdigest() != want:
            log("agent 更新包校验失败, 跳过")
            return
        me = os.path.abspath(__file__)
        tmp = me + ".new"
        with open(tmp, "wb") as f:
            f.write(data)
        os.chmod(tmp, 0o700)
        os.replace(tmp, me)
        log("agent 已自更新, 重启")
        os.execv(sys.executable, [sys.executable, me] + sys.argv[1:])
    except Exception as e:  # noqa: BLE001
        log("agent 自更新失败: %s" % e)


def pull_config(state, wait=0):
    cur = state.get("hash", "")
    resp = api_json("GET", "/agent/config?hash=%s&wait=%d" % (cur, wait), timeout=wait + 45)
    self_update(resp)
    if resp.get("unchanged"):
        return False
    sync_rulesets(resp.get("rulesets", []))
    ensure_cert_files(resp["config"])
    cfg_path = os.path.join(DIR, "config.json")
    tmp = cfg_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(resp["config"], f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)  # 配置含全部密码
    try:
        # check 卡死会永久挂死拉取线程 (看门狗只覆盖主循环), 必须有超时
        r = subprocess.run([BIN, "check", "-c", tmp], capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        r = subprocess.CompletedProcess([], 1, "", "sing-box check 超时 (60s), 疑似二进制或存储异常")
    if r.returncode != 0:
        os.remove(tmp)
        log("配置校验失败, 保留旧配置: %s" % (r.stdout + r.stderr).strip()[-500:])
        return None  # 应用失败 (区别于未变更), 调用方需退避
    os.replace(tmp, cfg_path)
    restart_singbox()
    state["hash"] = resp["hash"]
    save_state(state)
    wait_stats_ready()  # 等统计端口就绪, 避免紧随其后的上报查不到流量
    log("配置已更新并重启 sing-box, hash=%s" % resp["hash"][:12])
    return True


def singbox_running():
    if have_systemd_unit():
        try:
            r = subprocess.run(["systemctl", "is-active", svc_name()],
                               capture_output=True, text=True, timeout=15)
            if r.stdout.strip() == "active":
                return True
        except Exception:  # noqa: BLE001
            pass
    # pidfile 兜底: 无 systemd, 或 restart 时 systemctl 失败后直管的进程
    pidfile = os.path.join(DIR, "sing-box.pid")
    try:
        with open(pidfile) as f:
            pid = int(f.read().strip())
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            cmd = f.read()
        # 只能读一次: 二次 f.read() 必为空, 会让 k-sing 回退检测永远失败 (误判未运行→反复重启)
        if b"sing-box" not in cmd and b"k-sing" not in cmd:
            return False
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        return False


def cert_info():
    """采集节点证书状态: acme 模式扫 certmagic 存储目录 (新/旧两种布局), 否则读 $DIR/cert.pem"""
    import glob
    candidates = glob.glob(os.path.join(DIR, "acme", "certificates", "*", "*", "*.crt"))  # certmagic 现行布局
    candidates += glob.glob(os.path.join(DIR, "acme", "*", "sites", "*", "*.crt"))        # 旧版布局
    candidates.append(os.path.join(DIR, "cert.pem"))
    best = None
    for fp in candidates:
        if not os.path.isfile(fp):
            continue
        try:
            r = subprocess.run(["openssl", "x509", "-enddate", "-issuer", "-noout", "-in", fp],
                               capture_output=True, text=True, timeout=10)
            if r.returncode != 0:
                continue
            m = re.search(r"notAfter=(.+)", r.stdout)
            if not m:
                continue
            import calendar
            exp = calendar.timegm(time.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z"))
            issuer = ""
            mi = re.search(r"issuer=.+", r.stdout)
            if mi:
                issuer = mi.group(0)[7:].strip()[:128]
            if not best or exp > best["not_after"]:
                best = {"not_after": exp, "issuer": issuer}
        except Exception:  # noqa: BLE001
            continue
    return best


def report(state):
    pending = load_pending()
    report_id = pending["id"] if pending else ""
    target = pending.get("target") if pending else None
    if pending:
        # 上轮未获确认: 重试同一 ID/增量; core 新流量仍累计, 不会丢失。
        stats = pending["stats"]
    else:
        stats = {}
        current = None
        for attempt in (0, 1):
            try:
                current = query_traffic()
                break
            except OSError as e:
                # sing-box 刚重启时统计端口尚未就绪, 等 3 秒重试一次
                if attempt == 0:
                    time.sleep(3)
                else:
                    log("流量查询失败(sing-box 可能未运行): %s" % e)
            except Exception as e:  # noqa: BLE001
                log("流量查询失败(sing-box 可能未运行): %s" % e)
                break
        if current is not None:
            baseline = load_baseline()
            if baseline is None:
                # 升级/首次运行只建立基线, 避免把旧 reset 模式已报过的累计值重复记账
                save_baseline(current)
            else:
                stats = traffic_delta(baseline, current)
                if stats:
                    report_id = secrets.token_hex(16)
                    target = current
                    save_pending({"id": report_id, "stats": stats, "target": target})
                elif current != baseline:
                    save_baseline(current)  # core 重启/用户移除后的零增量基线推进
    body = {
        "stats": stats,
        "applied_hash": state.get("hash", ""),
        "agent_version": VERSION,
        "last_error": LAST_ERROR[0],
        "sb_running": singbox_running(),
    }
    if report_id:
        body["report_id"] = report_id
    public_ips = cached_public_ips()
    body["public_ipv4"] = public_ips["ipv4"]
    body["public_ipv6"] = public_ips["ipv6"]
    if public_ips["ipv4"] or public_ips["ipv6"]:
        body["public_ip"] = public_ips["ipv4"] or public_ips["ipv6"]  # 兼容旧面板
    ci = cert_info()
    if ci:
        body["cert"] = ci
    resp = api_json("POST", "/agent/report", body)
    if report_id and not resp.get("accounted", True):
        raise RuntimeError("面板暂未确认流量记账, 下轮将按原报告 ID 重试")
    if report_id:
        if isinstance(target, dict):
            save_baseline(target)
        else:
            # 兼容旧版 pending(无 target): 确认后以当前累计值建基线, 避免下轮双计
            try:
                save_baseline(query_traffic())
            except Exception:  # noqa: BLE001
                pass
        clear_pending()
    LAST_ERROR[0] = ""
    if stats:
        total = sum(p[0] + p[1] for p in stats.values())
        log("已上报流量: %d 用户, 合计 %d 字节" % (len(stats), total))


def pull_loop(state):
    """长轮询线程: 面板配置一变更立即返回, 校验后秒级重启 sing-box 生效"""
    while True:
        try:
            ok = pull_config(state, wait=25)
            if ok is None:
                time.sleep(PULL_INTERVAL)  # 应用失败退避, 防热循环
        except Exception as e:  # noqa: BLE001
            LAST_ERROR[0] = str(e)[:300]
            log("拉取配置失败: %s" % e)
            time.sleep(PULL_INTERVAL)  # 出错退避


def acquire_instance_lock():
    """单实例锁: 防止重复部署/手动调试导致多个 agent 互踩 (重复重启 sing-box、上报互相覆盖)"""
    import fcntl
    fp = open(os.path.join(DIR, "agent.lock"), "w")
    try:
        fcntl.flock(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("已有另一个 ksing-agent 实例在运行, 本实例退出", flush=True)
        sys.exit(1)
    return fp  # 保持引用防 GC 关闭; flock 随 os.execv 自更新保留


_LOCK_F = None


def main():
    global _LOCK_F
    once = "--once" in sys.argv
    log("ksing-agent v%s 启动, 面板 %s" % (VERSION, PANEL))
    _LOCK_F = acquire_instance_lock()
    state = load_state()
    if once:
        # 先上报公网 IPv4/IPv6: 面板据此自动创建 Cloudflare DNS 记录,
        # 再拉配置才不会卡在 "ACME 域名 DNS 未就绪"
        try:
            report(state)
        except Exception as e:  # noqa: BLE001
            log("初始上报失败(稍后重试拉配置): %s" % e)
        deadline = time.time() + 180  # DNS 创建与生效需要时间, 最长等 3 分钟
        while True:
            try:
                pull_config(state)
                break
            except Exception as e:  # noqa: BLE001
                msg = str(e)
                LAST_ERROR[0] = msg[:300]
                # 只有 DNS/证书未就绪类错误值得等 (面板正在建记录); 其他错误重试无意义
                retryable = any(k in msg for k in ("DNS", "域名", "未就绪"))
                if not retryable or time.time() >= deadline:
                    raise
                log("首次拉取配置失败: %s (10 秒后重试, 等待面板 DNS 同步生效)" % msg)
                time.sleep(10)
        if not singbox_running():
            log("sing-box 未运行, 启动")
            restart_singbox(relaunch=True)
            wait_stats_ready()
        report(state)
        return
    threading.Thread(target=pull_loop, args=(state,), daemon=True).start()
    next_push = time.time() + 20  # 等 sing-box 就绪
    next_check = 0.0
    while True:
        now = time.time()
        if now - HEALTH["ok_at"] > 300:
            # 有 systemd 时退出重启可解开卡死线程; 无 supervisor 时必须继续重试,
            # 否则一次网络分区就会变成永久离线。
            if have_systemd_unit():
                log("与面板通信中断超过 5 分钟, 重启 agent 自愈")
                os._exit(1)
            log("与面板通信中断超过 5 分钟, 无 systemd, 继续后台重试")
            HEALTH["ok_at"] = now
        try:
            if now >= next_check:
                if not singbox_running():
                    log("sing-box 未运行, 拉起")
                    restart_singbox(relaunch=True)
                    wait_stats_ready(8)
                next_check = now + 30
        except Exception as e:  # noqa: BLE001
            log("存活检查失败: %s" % e)
            next_check = now + 30
        try:
            if now >= next_push:
                report(state)
                next_push = now + PUSH_INTERVAL
        except Exception as e:  # noqa: BLE001
            LAST_ERROR[0] = str(e)[:300]
            log("上报失败: %s" % e)
            next_push = now + PUSH_INTERVAL
        time.sleep(2)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:  # noqa: BLE001
        # 致命异常必须把 traceback 留进 journal, 否则节点"静默离线"无从排查
        import traceback
        traceback.print_exc()
        sys.exit(1)
