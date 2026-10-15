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
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request

# 服务器常见 C/POSIX locale 会把 stdout 切成 latin-1, 中文日志会崩; 强制 UTF-8
for _f in (sys.stdout, sys.stderr):
    try:
        _f.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

VERSION = "1.2.1"

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
RULESET_DIR = os.path.join(DIR, "rulesets")
HEALTH = {"ok_at": time.time()}  # 看门狗: 面板通信连续失败则退出让 systemd 重启


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
    """面板不做重定向; 拒绝跳转避免 Bearer token 被带往第三方"""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=SSL_CTX))


def api(method, path, body=None, timeout=30):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(PANEL + path, data=data, method=method, headers={
        "Authorization": "Bearer " + TOKEN,
        "User-Agent": "ksing-agent/" + VERSION,
        "Content-Type": "application/json",
    })
    with _OPENER.open(req, timeout=timeout) as r:
        out = r.read()
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
    """查询并重置计数器, 返回 {user: [up, down]} 增量"""
    host, port = STATS.rsplit(":", 1)
    data = grpc_call(host, int(port),
                     "/v2ray.core.app.stats.command.StatsService/QueryStats",
                     encode_query_stats_request("", True))
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
        data = api("GET", "/agent/ruleset/" + m["tag"], timeout=120)
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


def restart_singbox():
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
    ip = query_public_ip() if mode == "selfip" else ""
    subj = ip or sni
    cmd = ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
           "-nodes", "-days", "3650", "-subj", "/CN=%s" % subj]
    if mode == "selfip" and ip:
        cmd += ["-addext", "subjectAltName=IP:%s" % ip]
    cmd += ["-keyout", key, "-out", cert]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("生成自签证书失败: %s" % r.stderr.strip()[:200])
    os.chmod(key, 0o600)
    log("已补生成节点证书 (mode=%s, CN=%s)" % (mode, subj))


def query_public_ip():
    for url in ("https://ifconfig.me", "https://api.ipify.org"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
            with urllib.request.urlopen(req, timeout=10) as r:
                ip = r.read().decode().strip()
            if re.fullmatch(r"[0-9.]{7,45}", ip):
                return ip
        except Exception:  # noqa: BLE001
            continue
    return ""


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
    r = subprocess.run([BIN, "check", "-c", tmp], capture_output=True, text=True)
    if r.returncode != 0:
        os.remove(tmp)
        log("配置校验失败, 保留旧配置: %s" % (r.stdout + r.stderr).strip()[-500:])
        return None  # 应用失败 (区别于未变更), 调用方需退避
    os.replace(tmp, cfg_path)
    restart_singbox()
    state["hash"] = resp["hash"]
    save_state(state)
    log("配置已更新并重启 sing-box, hash=%s" % resp["hash"][:12])
    return True


def singbox_running():
    pidfile = os.path.join(DIR, "sing-box.pid")
    try:
        with open(pidfile) as f:
            os.kill(int(f.read().strip()), 0)
        return True
    except (OSError, ValueError):
        pass
    svc = svc_name()
    if svc:
        r = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True,
                           timeout=15)
        return r.stdout.strip() == "active"
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
    stats = {}
    try:
        stats = query_traffic()
    except Exception as e:  # noqa: BLE001
        log("流量查询失败(sing-box 可能未运行): %s" % e)
    body = {
        "stats": stats,
        "applied_hash": state.get("hash", ""),
        "agent_version": VERSION,
    }
    ci = cert_info()
    if ci:
        body["cert"] = ci
    api_json("POST", "/agent/report", body)
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
            log("拉取配置失败: %s" % e)
            time.sleep(PULL_INTERVAL)  # 出错退避


def main():
    once = "--once" in sys.argv
    log("ksing-agent v%s 启动, 面板 %s" % (VERSION, PANEL))
    state = load_state()
    if once:
        pull_config(state)
        if not singbox_running():
            log("sing-box 未运行, 启动")
            restart_singbox()
        report(state)
        return
    threading.Thread(target=pull_loop, args=(state,), daemon=True).start()
    next_push = time.time() + 20  # 等 sing-box 就绪
    next_check = 0.0
    while True:
        now = time.time()
        if now - HEALTH["ok_at"] > 300:
            # 5 分钟无法与面板通信 (卡死/网络分区), 退出由 systemd 重启自愈
            log("与面板通信中断超过 5 分钟, 重启 agent 自愈")
            os._exit(1)
        try:
            if now >= next_check:
                if not singbox_running():
                    log("sing-box 未运行, 拉起")
                    restart_singbox()
                next_check = now + 30
        except Exception as e:  # noqa: BLE001
            log("存活检查失败: %s" % e)
            next_check = now + 30
        try:
            if now >= next_push:
                report(state)
                next_push = now + PUSH_INTERVAL
        except Exception as e:  # noqa: BLE001
            log("上报失败: %s" % e)
            next_push = now + PUSH_INTERVAL
        time.sleep(2)


if __name__ == "__main__":
    main()
