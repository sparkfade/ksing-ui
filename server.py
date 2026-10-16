#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ksing-ui server - AnyTLS 入站 + Shadowsocks 分流出站 中控面板后端

仅使用 Python 标准库。数据层复用 sbtool.py (同目录)。
功能:
  - 管理员/普通用户登录 (HMAC 签名令牌, 用户仅可见自己的节点与订阅链接)
  - REST API: 出站(SS) / 用户(AnyTLS) / 分流规则(可按节点/用户) / 服务器节点 / 流量 / 设置 / 核心控制
  - 订阅: GET /sub/<token> (浏览器访问为落地页, 客户端拉取为 base64 订阅, 每节点一条链接)
  - 节点下发: 独立 HTTPS agent 通道 (自签证书 + 节点 token), 裸核 sing-box 拉取配置/上报流量
  - 静态托管 web/dist 前端 (SPA 回退到 index.html)

运行: python3 server.py [--dir <数据目录>] [--port <面板端口>]
"""

import base64
import hashlib
import html
import json
import hmac
import mimetypes
import os
import re
import secrets
import shutil
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# C/POSIX locale 的主机 stdout 是 latin-1, 中文输出会崩; 强制 UTF-8
for _f in (sys.stdout, sys.stderr):
    try:
        _f.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sbtool  # noqa: E402

# sbtool 为 CLI 管道把 SIGPIPE 恢复成了默认处置(终止进程); 面板是服务进程,
# 必须重新忽略: 客户端提前断开时写 socket 只应抛 BrokenPipeError (已被捕获),
# 否则一个提前关闭的连接就能让 SIGPIPE 杀掉整个面板 (未认证远程 DoS)
signal.signal(signal.SIGPIPE, signal.SIG_IGN)

ROOT = os.path.dirname(os.path.abspath(__file__))
WEB_DIST = os.path.join(ROOT, "web", "dist")
PANEL_NAME = "KSING-UI"
PANEL_VERSION = "1.0.0"
TOKEN_TTL = 7 * 86400

BASE = os.environ.get("SBTOOL_DIR") or os.path.join(ROOT, "sbdata")

PROC_LOCK = threading.RLock()  # 可重入: handler 持锁内还会调 sync_user_states


# ------------------------------------------------------------------ helpers

class ApiError(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def get_secret():
    """面板会话签名密钥: 首次使用时生成并持久化到 settings.json"""
    s = sbtool.get_settings(BASE)
    if s.get("panel_secret"):
        return s["panel_secret"]
    secret = b64url(os.urandom(32))
    raw = sbtool.load_json(sbtool.paths(BASE)["settings"], {})
    raw["panel_secret"] = secret
    sbtool.save_json(sbtool.paths(BASE)["settings"], raw)
    return secret


def make_token(role, name, ver=""):
    payload = {"role": role, "name": name, "ver": ver, "exp": int(time.time()) + TOKEN_TTL}
    body = b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = b64url(hmac.new(get_secret().encode(), body.encode(), "sha256").digest())
    return "%s.%s" % (body, sig)


def parse_token(token):
    try:
        body, sig = token.split(".", 1)
        want = b64url(hmac.new(get_secret().encode(), body.encode(), "sha256").digest())
        if not hmac.compare_digest(sig, want):
            return None
        payload = json.loads(b64url_decode(body))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


def admin_ver():
    """管理员凭据版本: 密码变更后旧会话全部失效"""
    h = sbtool.get_settings(BASE).get("admin_pass_hash", "")
    return hashlib.sha256(h.encode()).hexdigest()[:16] if h else ""


def check_session(user, role):
    """校验令牌角色与凭据版本(密码修改/用户禁用后旧令牌立即失效)"""
    if user.get("role") != role:
        raise ApiError("无权访问", 403)
    if role == "admin":
        if user.get("ver") != admin_ver():
            raise ApiError("凭据已变更, 请重新登录", 401)
    else:
        u = sbtool.load_users(BASE).get(user.get("name", ""))
        if not u or not u.get("enable", True) or str(u.get("sv", 0)) != str(user.get("ver", "")):
            raise ApiError("账号不可用或凭据已变更, 请重新登录", 401)


LOGIN_FAILS = {}  # ip -> [失败时间戳...], 登录/初始化限流
LOGIN_WINDOW = 300
LOGIN_MAX_FAILS = 10
LOGIN_MAX_TRACKED = 10000  # 最多跟踪的 IP 数 (防海量源 IP 如 IPv6 把内存撑爆)


def _prune_login_fails(now):
    """条目超限时清理过期/最旧记录 (迭代前快照, 防并发修改)"""
    if len(LOGIN_FAILS) <= LOGIN_MAX_TRACKED:
        return
    for ip, ts in list(LOGIN_FAILS.items()):
        if not ts or now - ts[-1] > LOGIN_WINDOW:
            LOGIN_FAILS.pop(ip, None)
    if len(LOGIN_FAILS) > LOGIN_MAX_TRACKED:
        oldest = sorted(LOGIN_FAILS.items(), key=lambda kv: kv[1][-1] if kv[1] else 0)
        for ip, _ in oldest[: len(oldest) // 2]:
            LOGIN_FAILS.pop(ip, None)


def rate_limit_check(ip):
    now = time.time()
    _prune_login_fails(now)
    fails = [t for t in LOGIN_FAILS.get(ip, []) if now - t < LOGIN_WINDOW]
    LOGIN_FAILS[ip] = fails
    if len(fails) >= LOGIN_MAX_FAILS:
        raise ApiError("尝试过于频繁, 请 %d 分钟后再试" % (LOGIN_WINDOW // 60), 429)


def rate_limit_fail(ip):
    _prune_login_fails(time.time())
    LOGIN_FAILS.setdefault(ip, []).append(time.time())


def sub_base_url(s):
    """订阅链接的对外基础地址: 优先 host 设置, 否则取请求 Host"""
    host = s.get("host") or ""
    return host


# ------------------------------------------------------------------ agent 通道 (节点下发)

def agent_cert_paths():
    d = os.path.join(BASE, "agent")
    return d, os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")


def ensure_agent_cert():
    """agent 通道自签证书: 同时作为 agent 的信任锚 (CA 固定, 等效证书指纹锁定)"""
    d, cert, key = agent_cert_paths()
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key
    os.makedirs(d, exist_ok=True)
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "3650", "-subj", "/CN=ksing-panel-agent",
                        "-addext", "basicConstraints=critical,CA:TRUE",
                        "-addext", "subjectAltName=DNS:ksing-panel-agent",
                        "-keyout", key, "-out", cert],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise ApiError("生成 agent 证书失败(需要 openssl): %s" % r.stderr.strip(), 500)
    os.chmod(key, 0o600)
    os.chmod(cert, 0o644)
    return cert, key


def agent_cert_pem():
    _, cert, _ = agent_cert_paths()
    with open(cert, "r", encoding="ascii") as f:
        return f.read().strip()


def agent_cert_fingerprint():
    ensure_agent_cert()
    _, cert, _ = agent_cert_paths()
    r = subprocess.run(["openssl", "x509", "-in", cert, "-outform", "DER"],
                       capture_output=True)
    return hashlib.sha256(r.stdout).hexdigest()


def auth_agent(headers):
    """agent 通道认证: Bearer <节点token>, 常量时间比对 sha256; 返回 (sid, srv)"""
    auth = headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise ApiError("未认证", 401)
    token = auth[7:].strip()
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ApiError("令牌非法", 401)
    th = sbtool.hash_server_token(token)
    servers = sbtool.load_servers(BASE)
    for sid, srv in servers.items():
        if srv.get("token_hash") and hmac.compare_digest(th, srv["token_hash"]):
            if not srv.get("enabled", True):
                raise ApiError("节点已禁用", 403)
            return sid, srv, token
    raise ApiError("令牌无效", 401)


def auth_agent_install(headers):
    """安装令牌认证: 一次性, 仅供 /agent/activate 兑换永久节点令牌"""
    auth = headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise ApiError("未认证", 401)
    token = auth[7:].strip()
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ApiError("令牌非法", 401)
    ih = sbtool.hash_server_token(token)
    servers = sbtool.load_servers(BASE)
    for sid, srv in servers.items():
        if srv.get("install_hash") and hmac.compare_digest(ih, srv["install_hash"]):
            return sid, srv, token
    raise ApiError("安装令牌无效或已使用", 401)


def touch_server(sid, **fields):
    """更新节点运行状态字段 (last_seen / applied_hash / reported_ip 等)"""
    ip = fields.get("reported_ip")
    if ip and ip.startswith("::ffff:"):
        fields["reported_ip"] = ip[7:]  # IPv4-mapped IPv6 归一化
    P = sbtool.paths(BASE)
    with PROC_LOCK:
        servers = sbtool.load_servers(BASE)
        if sid not in servers:
            return
        servers[sid].update(fields)
        sbtool.save_servers(BASE, servers)


def install_script_hash():
    with open(os.path.join(ROOT, "install_node.sh"), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def install_command(sid, token, hostport, scheme="http"):
    """一键部署命令: 脚本哈希 + CA 指纹双校验, 闭合 TOFU 引导链。
    面板与 agent 同端口; hostport 含对外端口 (反代友好)。"""
    url = "%s://%s" % (scheme, hostport)
    return ("curl -fsSLk '%s/agent/install.sh' -o /tmp/ks-install.sh"
            " && echo '%s  /tmp/ks-install.sh' | sha256sum -c"
            " && bash /tmp/ks-install.sh '%s' '%s' '%s' '%s'"
            % (url, install_script_hash(), url, sid, token, agent_cert_fingerprint()))


_BUNDLE_CACHE = {}  # sid -> (cache_key, bundle_hash); 输入文件 mtime 不变则复用
_KEY_CACHE = {"at": 0.0, "key": None}  # 全局输入指纹, 5 秒内复用, 长轮询每秒 tick 只花几次 stat
_CONFPULL = {}  # sid -> 进行中的长轮询数
_CONFPULL_LOCK = threading.Lock()


def _input_key(sid, srv):
    if time.time() - _KEY_CACHE["at"] < 5 and _KEY_CACHE["key"] is not None:
        g = _KEY_CACHE["key"]
    else:
        P = sbtool.paths(BASE)
        g = []
        # traffic 也纳入: 流量耗尽即刻失效缓存重算下发, 不必等 janitor 翻 exceeded 标志
        for k in ("routes", "users", "nodes", "settings", "catalog", "traffic"):
            try:
                g.append(os.path.getmtime(P[k]))
            except OSError:
                g.append(0)
        # 规则集内容变化必经 update 重写 catalog.json, 用其 mtime 代理数千个文件的 stat
        _KEY_CACHE.update(at=time.time(), key=tuple(g))
    return tuple(map(str, g)) + (str(srv.get("port")),
                                 str(tuple(srv.get("users") or [])),
                                 str(bool(srv.get("enabled", True))),
                                 str(srv.get("domain")), str(srv.get("cert_mode")),
                                 str(srv.get("acme_email")))


def desired_hash(sid):
    """节点当前期望配置 hash (两级缓存, 长轮询每秒 tick 几乎零成本)"""
    servers = sbtool.load_servers(BASE)
    srv = servers.get(sid)
    if not srv:
        return ""
    key = _input_key(sid, srv)
    hit = _BUNDLE_CACHE.get(sid)
    if hit and hit[0] == key:
        return hit[1]
    try:
        h = sbtool.server_bundle(BASE, sid)["hash"]
    except Exception:
        h = ""
    _BUNDLE_CACHE[sid] = (key, h)
    return h


def server_view(sid, srv, traffic=None):
    t = (traffic or {}).get("servers", {}).get(sid, {})
    applied = srv.get("applied_hash", "")
    want = desired_hash(sid) if srv.get("enabled", True) else ""
    return {
        "sid": sid,
        "name": srv.get("name", sid),
        "port": srv.get("port"),
        "domain": srv.get("domain", ""),
        "cert_mode": srv.get("cert_mode") or "",
        "acme_email": srv.get("acme_email", ""),
        "cert_not_after": srv.get("cert_not_after", 0),
        "cert_issuer": srv.get("cert_issuer", ""),
        "reported_ip": srv.get("reported_ip") or "",
        "users": srv.get("users", []),
        "note": srv.get("note", ""),
        "enabled": bool(srv.get("enabled", True)),
        "created_at": srv.get("created_at", 0),
        "last_seen": srv.get("last_seen", 0),
        "online": bool(srv.get("last_seen")) and time.time() - srv["last_seen"] < 120,
        "applied_hash": applied,
        "desired_hash": want,
        "synced": bool(applied and want and applied == want),
        "agent_version": srv.get("agent_version", ""),
        "sb_running": srv.get("sb_running"),
        "last_error": srv.get("last_error", ""),
        "traffic": {"up": t.get("up", 0), "down": t.get("down", 0)},
    }


def user_server_links(name, u):
    """用户可见节点列表: [(节点名, anytls链接)], 只含已启用且分配了该用户的节点"""
    return [(n["name"], n["link"]) for n in user_nodes(name, u)]


def fmt_sub_size(n):
    """订阅信息节点的流量文本: 512 M / 1.5 G / 100 G"""
    if not n or n <= 0:
        return "0 B"
    units = ["B", "KB", "M", "G", "T"]
    v = float(n)
    i = 0
    while v >= 1024 and i < len(units) - 1:
        v /= 1024
        i += 1
    s = ("%.1f" % v).rstrip("0").rstrip(".")
    return "%s %s" % (s, units[i])


INFO_SOCKS_ADDR = "127.0.0.1"   # 信息节点地址: 客户端本机回环, 连不上 = 不可用
INFO_SOCKS_PORT = 65535         # port 0 会被部分客户端当无效节点过滤掉, 用 65535
INFO_SOCKS_USERINFO = base64.b64encode(b":").decode().rstrip("=")  # "Og": socks:// 分享链接的空用户信息 (base64("user:pass") 去补位)


def sub_info_nodes(v):
    """订阅信息节点: 两个不可用的 socks (127.0.0.1:65535), 名称即流量/到期状态,
    常驻显示在客户端节点列表里, 每次拉订阅随流量/时间更新;
    过期/耗尽后订阅只剩这两个节点, 客户端一眼可见原因"""
    nodes = []
    used = v["traffic"]["up"] + v["traffic"]["down"]
    limit = v["traffic_limit"]
    if limit:
        remain = max(0, limit - used)
        prefix = "流量已耗尽 | " if remain <= 0 else ""
        nodes.append({"name": "%s已使用 %s/剩余 %s | 总流量 %s"
                      % (prefix, fmt_sub_size(used), fmt_sub_size(remain),
                         fmt_sub_size(limit)),
                      "server": INFO_SOCKS_ADDR, "port": INFO_SOCKS_PORT, "socks": True})
    else:
        nodes.append({"name": "已使用 %s | 总流量 不限" % fmt_sub_size(used),
                      "server": INFO_SOCKS_ADDR, "port": INFO_SOCKS_PORT, "socks": True})
    exp = v["expire_at"]
    if exp:
        d = time.strftime("%Y年%m月%d日", time.localtime(exp))
        if exp < time.time():
            name = "订阅已过期 | %s已到期" % d
        else:
            days = max(0, int(-((time.time() - exp) // 86400)))
            name = "订阅剩余 %d 天 | %s到期" % (days, d)
    else:
        name = "订阅永久有效 | 不过期"
    nodes.append({"name": name, "server": INFO_SOCKS_ADDR, "port": INFO_SOCKS_PORT, "socks": True})
    return nodes


def user_nodes(name, u):
    """用户可见节点详情 [{name, server, port, password, sni, insecure}]"""
    if not sbtool.user_active(BASE, name, u):
        return []
    s = sbtool.get_settings(BASE)
    servers = sbtool.load_servers(BASE)
    out = []
    for sid, srv in servers.items():
        if not srv.get("enabled", True):
            continue
        assigned = srv.get("users") or []
        if assigned and name not in assigned:
            continue
        addr = sbtool.server_addr(srv)
        if not addr:
            continue  # 节点尚未上报地址, 无法生成链接
        sni = sbtool.server_sni(s, srv)
        insecure = sbtool.server_insecure(srv)
        q = "security=tls&type=tcp&headerType=none"
        if sni:
            q = "security=tls&sni=%s&type=tcp&headerType=none" % urllib.parse.quote(sni, safe="")
        if insecure:
            q += "&allowInsecure=1&insecure=1"
        link = "anytls://%s@%s:%d?%s#%s" % (
            urllib.parse.quote(u["password"], safe=""), addr, srv["port"], q,
            urllib.parse.quote(srv.get("name", sid), safe=""))
        out.append({"name": srv.get("name", sid), "server": addr, "port": srv["port"],
                    "password": u["password"], "sni": sni, "insecure": insecure,
                    "link": link})
    return out



def call_sbtool(fn, *args, **kwargs):
    """调用 sbtool 的函数, 把 die() 的 SystemExit + stderr 消息转成 ApiError 透传到前端"""
    import contextlib
    import io
    buf = io.StringIO()
    try:
        with contextlib.redirect_stderr(buf):
            return fn(*args, **kwargs)
    except SystemExit:
        msg = buf.getvalue().strip() or "操作失败"
        raise ApiError(msg)


def split_host_port(h):
    """拆 host[:port], 支持 [v6]:port; 返回 (host, port或None)"""
    h = (h or "").strip()
    if h.startswith("["):
        m = re.match(r"^\[[0-9a-fA-F:]+\](?::(\d+))?$", h)
        return (h, int(m.group(1)) if m and m.group(1) else None) if m else ("", None)
    m = re.match(r"^([A-Za-z0-9.\-]+)(?::(\d+))?$", h)
    if not m:
        return "", None
    return m.group(1), int(m.group(2)) if m.group(2) else None


def request_host_port(headers):
    """请求的 Host 整串 (含端口), 校验后返回; 非法返回空"""
    h = (headers.get("Host", "") or "").strip()
    host, _ = split_host_port(h)
    return h if host else ""


def request_host(ctx_headers):
    """取请求的 Host 主机名 (校验白名单, 防 Host 头注入); 非法时回退 settings.host"""
    host, _ = split_host_port(ctx_headers.get("Host", "") or "")
    if host:
        return host
    s = sbtool.get_settings(BASE)
    h, _ = split_host_port(s.get("host") or "")
    return h or "127.0.0.1"


def sub_base(s, req_hostport="", scheme="http"):
    """订阅地址的对外 base。
    优先自定义 sub_host[:port]; 其次 host 设置; 默认跟随请求 Host (含反代后的对外端口)。
    sub_port 非 0 时强制覆盖端口。"""
    panel_port = int(s.get("panel_port") or 8080)
    sub_port = int(s.get("sub_port") or 0)
    if s.get("sub_host") or s.get("host"):
        raw = s.get("sub_host") or s.get("host")
        host, port = split_host_port(raw)
        port = sub_port or port or panel_port
    else:
        host, port = split_host_port(req_hostport)
        if not host:
            host, port = "127.0.0.1", panel_port
        port = sub_port or port  # 跟随请求 Host 的端口 (反代友好); Host 无端口则省略
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        return "%s://%s:%d" % (scheme, host, port)
    return "%s://%s" % (scheme, host)


def sub_url_for(s, token, req_host="", scheme="http"):
    return "%s/%s/%s" % (sub_base(s, req_host, scheme), s.get("sub_path") or "sub", token)


def user_view(name, u, s, req_host="", scheme="http"):
    links = user_server_links(name, u) if u.get("enable") else []
    sub_url = sub_url_for(s, u["token"], req_host, scheme)
    tr = sbtool.effective_usage(BASE, name)
    servers = sbtool.load_servers(BASE)
    member = [sid for sid, srv in servers.items()
              if srv.get("enabled", True) and (not (srv.get("users") or []) or name in srv["users"])]
    active = sbtool.user_active(BASE, name, u)
    return {
        "name": name,
        "enable": bool(u.get("enable", True)),
        "active": active,
        "password": u["password"],
        "token": u["token"],
        "note": u.get("note", ""),
        "created_at": u.get("created_at", 0),
        "has_panel_password": bool(u.get("panel_password_hash")),
        "link": links[0][1] if links else "",
        "links": [l for _, l in links],
        "servers": member,
        "sub_url": sub_url,
        "sub_urls": {"singbox": sub_url + "?type=singbox", "clash": sub_url + "?type=clash",
                     "v2ray": sub_url} if sub_url else {},
        "traffic": {"up": tr.get("up", 0), "down": tr.get("down", 0)},
        "traffic_limit": int(u.get("traffic_limit") or 0),
        "expire_at": int(u.get("expire_at") or 0),
        "reset_day": int(u.get("reset_day") or 0),
    }


# ------------------------------------------------------------------ API handlers
# 每个 handler: fn(ctx) -> (status_code, obj) ; ctx 含 .body .query .user .match

def h_meta(ctx):
    s = sbtool.get_settings(BASE)
    return 200, {
        "name": PANEL_NAME, "version": PANEL_VERSION,
        "setup_needed": not s.get("admin_pass_hash"),
    }


def h_setup(ctx):
    rate_limit_check(ctx.client_ip)
    s = sbtool.get_settings(BASE)
    if s.get("admin_pass_hash"):
        raise ApiError("管理员已初始化", 403)
    username = (ctx.body.get("username") or "").strip() or "admin"
    password = ctx.body.get("password") or ""
    if not re.fullmatch(r"[A-Za-z0-9_\-]{1,32}", username):
        raise ApiError("用户名仅限字母/数字/_/-, 1-32 位")
    if len(password) < 6:
        raise ApiError("密码至少 6 位")
    with PROC_LOCK:  # 防并发重复初始化
        raw = sbtool.load_json(sbtool.paths(BASE)["settings"], {})
        if raw.get("admin_pass_hash"):
            raise ApiError("管理员已初始化", 403)
        raw["admin_user"] = username
        raw["admin_pass_hash"] = sbtool.hash_password(password)
        sbtool.save_json(sbtool.paths(BASE)["settings"], raw)
    return 200, {"token": make_token("admin", username, admin_ver()), "role": "admin", "name": username}


def h_login(ctx):
    rate_limit_check(ctx.client_ip)
    username = (ctx.body.get("username") or "").strip()
    password = ctx.body.get("password") or ""
    s = sbtool.get_settings(BASE)
    if not s.get("admin_pass_hash"):
        raise ApiError("面板未初始化, 请先设置管理员密码", 403)
    if username == s.get("admin_user", "admin"):
        if sbtool.verify_password(password, s["admin_pass_hash"]):
            LOGIN_FAILS.pop(ctx.client_ip, None)
            return 200, {"token": make_token("admin", username, admin_ver()),
                         "role": "admin", "name": username}
        rate_limit_fail(ctx.client_ip)
        time.sleep(0.5)
        raise ApiError("用户名或密码错误", 401)
    users = sbtool.load_users(BASE)
    u = users.get(username)
    if u and u.get("panel_password_hash") and u.get("enable", True):
        if sbtool.verify_password(password, u["panel_password_hash"]):
            LOGIN_FAILS.pop(ctx.client_ip, None)
            return 200, {"token": make_token("user", username, str(u.get("sv", 0))),
                         "role": "user", "name": username}
    rate_limit_fail(ctx.client_ip)
    time.sleep(0.5)
    raise ApiError("用户名或密码错误", 401)


def h_status(ctx):
    s = sbtool.get_settings(BASE)
    users = sbtool.load_users(BASE)
    nodes = sbtool.load_json(sbtool.paths(BASE)["nodes"], {})
    servers = sbtool.load_servers(BASE)
    online = sum(1 for sv in servers.values()
                 if sv.get("last_seen") and time.time() - sv["last_seen"] < 120)
    rc = sbtool.load_json(sbtool.paths(BASE)["routes"], {"rules": []})
    cat = sbtool.load_json(sbtool.paths(BASE)["catalog"], {})
    return 200, {
        "counts": {"users": len(users), "nodes": len(nodes),
                   "servers": len(servers), "servers_online": online,
                   "rules": len(rc.get("rules", [])), "rulesets": len(cat)},
        "server": {"host": s.get("host") or "", "sni": s.get("sni") or "",
                   "panel_port": s.get("panel_port", 8080)},
    }


# ---- nodes

def h_nodes_list(ctx):
    return 200, sbtool.load_json(sbtool.paths(BASE)["nodes"], {})


def h_nodes_add(ctx):
    b = ctx.body
    tag = (b.get("tag") or "").strip()
    if not tag:
        raise ApiError("需要 tag")
    node = {
        "server": (b.get("server") or "").strip(),
        "server_port": int(b.get("server_port") or 0),
        "method": (b.get("method") or "").strip(),
        "password": b.get("password") or "",
    }
    if not node["server"]:
        raise ApiError("需要 server")
    if b.get("udp_over_tcp"):
        node["udp_over_tcp"] = True
    if b.get("plugin"):
        node["plugin"] = b["plugin"]
        node["plugin_opts"] = b.get("plugin_opts", "")
    with PROC_LOCK:
        nodes = sbtool.load_json(sbtool.paths(BASE)["nodes"], {})
        call_sbtool(sbtool.add_node, nodes, tag, node, force=bool(b.get("force")))
        sbtool.save_json(sbtool.paths(BASE)["nodes"], nodes)
    return 200, {"ok": True}


def h_nodes_update(ctx):
    tag = ctx.match.group(1)
    with PROC_LOCK:
        nodes = sbtool.load_json(sbtool.paths(BASE)["nodes"], {})
        if tag not in nodes:
            raise ApiError("节点不存在", 404)
        b = ctx.body
        node = nodes[tag]
        for k in ("server", "method", "password", "plugin", "plugin_opts"):
            if k in b:
                node[k] = b[k]
        if "server_port" in b:
            node["server_port"] = int(b["server_port"])
        if "udp_over_tcp" in b:
            if b["udp_over_tcp"]:
                node["udp_over_tcp"] = True
            else:
                node.pop("udp_over_tcp", None)
        call_sbtool(sbtool.validate_node, node["method"], node["password"], node["server_port"])
        new_tag = (b.get("new_tag") or "").strip()
        if new_tag and new_tag != tag:
            if new_tag in nodes or new_tag in ("direct", "block", "dns-out"):
                raise ApiError("新 tag 不可用")
            del nodes[tag]
            nodes[new_tag] = node
            # 同步引用该 tag 的分流规则
            rc = sbtool.load_json(sbtool.paths(BASE)["routes"], {"rules": [], "final": None, "user_final": {}})
            changed = False
            for r in rc.get("rules", []):
                if r.get("outbound") == tag:
                    r["outbound"] = new_tag
                    changed = True
            if rc.get("final") == tag:
                rc["final"] = new_tag
                changed = True
            for u, t in rc.get("user_final", {}).items():
                if t == tag:
                    rc["user_final"][u] = new_tag
                    changed = True
            if changed:
                sbtool.save_json(sbtool.paths(BASE)["routes"], rc)
        sbtool.save_json(sbtool.paths(BASE)["nodes"], nodes)
    return 200, {"ok": True}


def h_nodes_del(ctx):
    tag = ctx.match.group(1)
    with PROC_LOCK:
        nodes = sbtool.load_json(sbtool.paths(BASE)["nodes"], {})
        if tag not in nodes:
            raise ApiError("节点不存在", 404)
        # 检查引用
        rc = sbtool.load_json(sbtool.paths(BASE)["routes"], {"rules": [], "final": None, "user_final": {}})
        refs = [i for i, r in enumerate(rc.get("rules", [])) if r.get("outbound") == tag]
        if rc.get("final") == tag or tag in rc.get("user_final", {}).values() or refs:
            raise ApiError("节点仍被分流规则/默认出口引用, 请先调整相关规则")
        del nodes[tag]
        sbtool.save_json(sbtool.paths(BASE)["nodes"], nodes)
    return 200, {"ok": True}


def h_nodes_import(ctx):
    text = ctx.body.get("text") or ""
    links = [l.strip() for l in text.splitlines() if l.strip().lower().startswith("ss://")]
    if not links:
        raise ApiError("未找到 ss:// 链接")
    results = []
    with PROC_LOCK:
        nodes = sbtool.load_json(sbtool.paths(BASE)["nodes"], {})
        for link in links:
            try:
                info = call_sbtool(sbtool.parse_ss_link, link)
                tag = info["tag"]
                if not tag:
                    i = 1
                    while "ss%d" % i in nodes:
                        i += 1
                    tag = "ss%d" % i
                node = {"server": info["server"], "server_port": info["port"],
                        "method": info["method"], "password": info["password"]}
                if ctx.body.get("uot"):
                    node["udp_over_tcp"] = True
                if info["plugin"]:
                    node["plugin"] = info["plugin"]
                    node["plugin_opts"] = info["plugin_opts"]
                if tag in nodes:
                    results.append({"tag": tag, "ok": False, "error": "tag 已存在"})
                    continue
                call_sbtool(sbtool.add_node, nodes, tag, node)
                results.append({"tag": tag, "ok": True,
                                "server": "%s:%d" % (node["server"], node["server_port"])})
            except ApiError as e:
                results.append({"tag": "", "ok": False, "error": str(e)})
            except Exception as e:
                results.append({"tag": "", "ok": False, "error": str(e)})
        sbtool.save_json(sbtool.paths(BASE)["nodes"], nodes)
    return 200, {"results": results}


# ---- users

def h_users_list(ctx):
    s = sbtool.get_settings(BASE)
    users = sbtool.load_users(BASE)
    host = request_host_port(ctx.headers)
    scheme = "https" if ctx.headers.get("X-Forwarded-Proto") == "https" else "http"
    return 200, [user_view(n, u, s, host, scheme) for n, u in users.items()]


def h_users_add(ctx):
    b = ctx.body
    name = (b.get("name") or "").strip()
    if not name or not re.fullmatch(r"[A-Za-z0-9_\-]{1,32}", name):
        raise ApiError("用户名仅限字母/数字/_/-, 1-32 位")
    if name == sbtool.get_settings(BASE).get("admin_user", "admin"):
        raise ApiError("用户名与管理员冲突")
    try:
        traffic_limit = max(0, int(b.get("traffic_limit") or 0))
        expire_at = max(0, int(b.get("expire_at") or 0))
        reset_day = min(31, max(0, int(b.get("reset_day") or 0)))
    except (TypeError, ValueError):
        raise ApiError("流量限制/到期时间/重置日 必须是数字")
    pw = b.get("password") or sbtool.gen_password()
    with PROC_LOCK:
        users = sbtool.load_users(BASE)
        if name in users:
            raise ApiError("用户已存在")
        users[name] = {
            "password": pw,
            "enable": True,
            "token": sbtool.gen_token(),
            "panel_password_hash": sbtool.hash_password(b["panel_password"]) if b.get("panel_password") else "",
            "note": b.get("note") or "",
            "traffic_limit": traffic_limit,
            "expire_at": expire_at,
            "reset_day": reset_day,
            "created_at": int(time.time()),
        }
        sbtool.save_users(BASE, users)
    return 200, {"ok": True, "password": pw}


def h_users_update(ctx):
    name = ctx.match.group(1)
    b = ctx.body
    with PROC_LOCK:
        return _users_update_locked(name, b)


def _users_update_locked(name, b):
    users = sbtool.load_users(BASE)
    if name not in users:
        raise ApiError("用户不存在", 404)
    u = users[name]
    if "enable" in b:
        new_enable = bool(b["enable"])
        if new_enable != u.get("enable", True):
            u["sv"] = u.get("sv", 0) + 1  # 禁用/启用后旧会话失效
        u["enable"] = new_enable
    if b.get("password"):
        u["password"] = b["password"]
    if "panel_password" in b:
        u["panel_password_hash"] = sbtool.hash_password(b["panel_password"]) if b["panel_password"] else ""
        u["sv"] = u.get("sv", 0) + 1  # 面板密码变更后旧会话失效
    if "note" in b:
        u["note"] = b["note"]
    try:
        if "traffic_limit" in b:
            u["traffic_limit"] = max(0, int(b["traffic_limit"] or 0))
        if "expire_at" in b:
            u["expire_at"] = max(0, int(b["expire_at"] or 0))
        if "reset_day" in b:
            rd = int(b["reset_day"] or 0)
            if not (0 <= rd <= 31):
                raise ApiError("每月重置日需在 0-31 (0=不重置)")
            u["reset_day"] = rd
        if "renew_days" in b:  # 一键续期: 从 max(现在, 当前到期) 顺延 N 天
            days = int(b["renew_days"] or 0)
            if days <= 0 or days > 3650:
                raise ApiError("续期天数非法")
            u["expire_at"] = int(max(time.time(), u.get("expire_at") or 0)) + days * 86400
    except (TypeError, ValueError):
        raise ApiError("流量限制/到期时间/重置日 必须是数字")
    if b.get("refresh_token"):
        u["token"] = sbtool.gen_token()
    sbtool.save_users(BASE, users)
    sbtool.sync_user_states(BASE, users_lock=PROC_LOCK)  # 立即重算超额/到期标志
    return 200, {"ok": True, "token": u["token"], "password": u["password"],
                 "expire_at": u.get("expire_at", 0), "traffic_limit": u.get("traffic_limit", 0)}


def h_users_servers(ctx):
    """从用户视角分配节点: body {servers: [sid...]} 为该用户可见的节点集合。
    节点 users 为空表示"全部用户", 排除某用户时转为显式列表。"""
    name = ctx.match.group(1)
    with PROC_LOCK:
        users = sbtool.load_users(BASE)
        if name not in users:
            raise ApiError("用户不存在", 404)
        want = set(str(x).strip() for x in (ctx.body.get("servers") or []) if str(x).strip())
        servers = sbtool.load_servers(BASE)
        unknown = want - set(servers)
        if unknown:
            raise ApiError("节点不存在: %s" % ", ".join(sorted(unknown)))
        allnames = set(users.keys())
        for sid, srv in servers.items():
            cur = srv.get("users") or []
            has_user = (not cur) or (name in cur)
            if sid in want and not has_user:
                srv["users"] = cur + [name]
            elif sid not in want and has_user:
                if not cur:
                    srv["users"] = sorted(allnames - {name})
                else:
                    srv["users"] = [u for u in cur if u != name]
        sbtool.save_servers(BASE, servers)
    return 200, {"ok": True}


def h_users_reset_usage(ctx):
    """一键重置用户流量 (当前周期清零, 自动解除超额状态)"""
    name = ctx.match.group(1)
    with PROC_LOCK:
        users = sbtool.load_users(BASE)
        if name not in users:
            raise ApiError("用户不存在", 404)
        sbtool.reset_user_usage(BASE, name)
        sbtool.sync_user_states(BASE, users_lock=PROC_LOCK)
    return 200, {"ok": True}


def h_users_del(ctx):
    name = ctx.match.group(1)
    with PROC_LOCK:
        return _users_del_locked(name)


def _users_del_locked(name):
    users = sbtool.load_users(BASE)
    if name not in users:
        raise ApiError("用户不存在", 404)
    rc = sbtool.load_json(sbtool.paths(BASE)["routes"], {"rules": [], "user_final": {}})
    refs = [i for i, r in enumerate(rc.get("rules", [])) if name in (r.get("users") or [])]
    if refs or name in rc.get("user_final", {}):
        raise ApiError("用户仍被分流规则/专属出口引用, 请先调整相关规则")
    del users[name]
    sbtool.save_users(BASE, users)
    # 从所有节点的分配列表中移除
    servers = sbtool.load_servers(BASE)
    changed = False
    for srv in servers.values():
        if name in (srv.get("users") or []):
            srv["users"] = [u for u in srv["users"] if u != name]
            changed = True
    if changed:
        sbtool.save_servers(BASE, servers)
    return 200, {"ok": True}


# ---- routes

def routes_data():
    rc = sbtool.load_json(sbtool.paths(BASE)["routes"],
                          {"rules": [], "final": None, "user_final": {}})
    rc.setdefault("rules", [])
    rc.setdefault("user_final", {})
    return rc


def h_routes_list(ctx):
    rc = routes_data()
    s = sbtool.get_settings(BASE)
    rc["effective_final"] = rc.get("final") or s.get("final", "direct")
    return 200, rc


def h_routes_add(ctx):
    b = ctx.body
    entry = {}
    if b.get("rule_set"):
        sets = [t for t in b["rule_set"] if t]
        cat = sbtool.load_json(sbtool.paths(BASE)["catalog"], {})
        missing = [t for t in sets if t not in cat]
        if missing:
            raise ApiError("规则集不存在: %s" % ", ".join(missing))
        entry["rule_set"] = sets
    mf = {}
    for key in ("domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr"):
        vals = [v.strip() for v in (b.get(key) or []) if str(v).strip()]
        if vals:
            mf[key] = vals
    if b.get("port"):
        mf["port"] = [int(p) for p in b["port"]]
    entry.update(mf)
    if not entry.get("rule_set") and not mf:
        raise ApiError("需要至少一个匹配条件")
    users = [u.strip() for u in (b.get("users") or []) if u.strip()]
    if users:
        all_users = sbtool.load_users(BASE)
        unknown = [u for u in users if u not in all_users]
        if unknown:
            raise ApiError("用户不存在: %s" % ", ".join(unknown))
        entry["users"] = users
    nodes_scope = [str(n).strip() for n in (b.get("nodes") or []) if str(n).strip()]
    if nodes_scope:
        servers = sbtool.load_servers(BASE)
        unknown = [n for n in nodes_scope if n not in servers]
        if unknown:
            raise ApiError("节点不存在: %s" % ", ".join(unknown))
        entry["nodes"] = nodes_scope
    if b.get("action") == "reject":
        entry["action"] = "reject"
    else:
        outbound = (b.get("outbound") or "").strip()
        nodes = sbtool.load_json(sbtool.paths(BASE)["nodes"], {})
        if outbound != "direct" and outbound not in nodes:
            raise ApiError("出站不存在: %s" % outbound)
        entry["action"] = "route"
        entry["outbound"] = outbound
    if b.get("dns") in ("remote", "remote-us"):
        entry["dns"] = b["dns"]
    with PROC_LOCK:
        rc = routes_data()
        rc["rules"].append(entry)
        sbtool.save_json(sbtool.paths(BASE)["routes"], rc)
    return 200, {"ok": True, "index": len(rc["rules"]) - 1}


def h_routes_del(ctx):
    idx = int(ctx.match.group(1))
    with PROC_LOCK:
        rc = routes_data()
        if not (0 <= idx < len(rc["rules"])):
            raise ApiError("序号越界", 404)
        del rc["rules"][idx]
        sbtool.save_json(sbtool.paths(BASE)["routes"], rc)
    return 200, {"ok": True}


def h_routes_move(ctx):
    b = ctx.body
    idx = int(b.get("index", -1))
    d = int(b.get("dir", 0))
    with PROC_LOCK:
        rc = routes_data()
        j = idx + d
        if not (0 <= idx < len(rc["rules"])) or not (0 <= j < len(rc["rules"])):
            raise ApiError("无法移动")
        rc["rules"][idx], rc["rules"][j] = rc["rules"][j], rc["rules"][idx]
        sbtool.save_json(sbtool.paths(BASE)["routes"], rc)
    return 200, {"ok": True}


def h_routes_final(ctx):
    b = ctx.body
    outbound = (b.get("outbound") or "").strip()
    user = (b.get("user") or "").strip()
    nodes = sbtool.load_json(sbtool.paths(BASE)["nodes"], {})
    if outbound not in ("direct", "reject") and outbound not in nodes:
        raise ApiError("出站不存在: %s" % outbound)
    if user:
        all_users = sbtool.load_users(BASE)
        if user not in all_users:
            raise ApiError("用户不存在: %s" % user)
    with PROC_LOCK:
        rc = routes_data()
        if user:
            rc["user_final"][user] = outbound
        else:
            rc["final"] = outbound
        sbtool.save_json(sbtool.paths(BASE)["routes"], rc)
    return 200, {"ok": True}


def h_routes_final_del(ctx):
    user = (ctx.body.get("user") or "").strip()
    with PROC_LOCK:
        rc = routes_data()
        if user:
            rc.get("user_final", {}).pop(user, None)
        else:
            rc["final"] = None
        sbtool.save_json(sbtool.paths(BASE)["routes"], rc)
    return 200, {"ok": True}


# ---- rulesets

def h_rulesets(ctx):
    q = (ctx.query.get("q") or "").lower()
    source = ctx.query.get("source") or ""
    cat = sbtool.load_json(sbtool.paths(BASE)["catalog"], {})
    kws = [k for k in q.split() if k]
    out = []
    for tag in sorted(cat):
        ent = cat[tag]
        if source and ent["source"] != source:
            continue
        tl = tag.lower()
        if kws and not all(k in tl for k in kws):
            continue
        out.append({"tag": tag, "source": ent["source"], "url": ent["url"],
                    "path": os.path.join(BASE, ent["file"])})
        if len(out) >= 200:
            break
    return 200, {"total": len(cat), "results": out}


def h_ruleset_sources(ctx):
    return 200, [{"key": k, "desc": v["desc"], "optional": bool(v.get("optional"))}
                 for k, v in sbtool.SOURCES.items()]


# ---- settings

SETTINGS_EDITABLE = ("final", "host", "sni",
                     "private_action", "auto_detect_interface", "log_level",
                     "panel_listen", "panel_port",
                     "sub_host", "sub_port", "sub_path")

def h_settings_get(ctx):
    s = sbtool.get_settings(BASE)
    out = {k: s.get(k) for k in SETTINGS_EDITABLE}
    out["admin_user"] = s.get("admin_user", "admin")
    return 200, out


def h_settings_put(ctx):
    b = ctx.body
    s = sbtool.get_settings(BASE)
    raw = sbtool.load_json(sbtool.paths(BASE)["settings"], {})
    for k in SETTINGS_EDITABLE:
        if k in b:
            v = b[k]
            if k == "panel_port":
                v = int(v)
                if not (1 <= v <= 65535):
                    raise ApiError("端口非法")
            if k == "sub_port":
                v = int(v or 0)
                if not (0 <= v <= 65535):
                    raise ApiError("订阅端口非法")
            if k == "auto_detect_interface":
                v = bool(v)
            if k == "private_action" and v not in ("reject", "direct", "off"):
                raise ApiError("private_action 非法")
            if k == "final":
                nodes = sbtool.load_json(sbtool.paths(BASE)["nodes"], {})
                if v not in ("direct", "reject") and v not in nodes:
                    raise ApiError("默认出站不存在: %s" % v)
            if k == "sni" and v and not re.fullmatch(r"[A-Za-z0-9.\-]{1,128}", str(v)):
                raise ApiError("SNI 仅限字母/数字/./-")
            if k == "sub_path":
                v = str(v).strip().strip("/")
                if not re.fullmatch(r"[A-Za-z0-9_\-]{1,32}", v):
                    raise ApiError("订阅路径仅限字母/数字/_/-, 1-32 位")
                if v == "api" or v == "agent":
                    raise ApiError("订阅路径不能是 api/agent")
            if k == "sub_host":
                v = str(v).strip().rstrip("/")
                if v and not re.fullmatch(r"[A-Za-z0-9.\-]+(:\d{1,5})?|\[[0-9a-fA-F:]+\](:\d{1,5})?", v):
                    raise ApiError("订阅地址仅限 域名/IP[:端口]")
                if v and ":" in v and not (1 <= int(v.rsplit(":", 1)[1]) <= 65535):
                    raise ApiError("订阅地址端口非法")
            raw[k] = v
            s[k] = v
    sbtool.save_json(sbtool.paths(BASE)["settings"], raw)
    return 200, {"ok": True}


def h_settings_admin(ctx):
    b = ctx.body
    s = sbtool.get_settings(BASE)
    if not sbtool.verify_password(b.get("old_password") or "", s.get("admin_pass_hash", "")):
        raise ApiError("原密码错误", 403)
    raw = sbtool.load_json(sbtool.paths(BASE)["settings"], {})
    new_name = (b.get("new_username") or "").strip() or s.get("admin_user", "admin")
    if not re.fullmatch(r"[A-Za-z0-9_\-]{1,32}", new_name):
        raise ApiError("用户名仅限字母/数字/_/-, 1-32 位")
    if b.get("new_password"):
        if len(b["new_password"]) < 6:
            raise ApiError("新密码至少 6 位")
        raw["admin_pass_hash"] = sbtool.hash_password(b["new_password"])
    raw["admin_user"] = new_name
    sbtool.save_json(sbtool.paths(BASE)["settings"], raw)
    # 凭据变更后旧令牌自动失效(admin_ver 随密码哈希变化), 签发新令牌保持当前会话
    return 200, {"ok": True, "token": make_token("admin", new_name, admin_ver()),
                 "name": new_name}


# ---- servers (远端服务器节点, 配置下发)

def _validate_server_payload(b, partial=False):
    out = {}
    if "name" in b or not partial:
        name = (b.get("name") or "").strip()
        if not name or len(name) > 32:
            raise ApiError("节点名必填且不超过 32 字符")
        out["name"] = name
    if "port" in b or not partial:
        try:
            port = int(b.get("port") or 0)
        except (TypeError, ValueError):
            raise ApiError("端口非法")
        if not (1 <= port <= 65535):
            raise ApiError("端口非法")
        out["port"] = port
    if "sni" in b or "address" in b:
        raise ApiError("SNI 与订阅地址已改为自动生成: acme 用域名, 自签用全局设置, 地址取节点上报 IP")
    if "domain" in b:
        domain = (b.get("domain") or "").strip().lower()[:253]
        if domain and not re.fullmatch(r"[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+", domain):
            raise ApiError("域名格式非法")
        out["domain"] = domain
    if "cert_mode" in b or not partial:
        cm = (b.get("cert_mode") or "").strip()
        if not cm and not partial:
            cm = "acme" if b.get("domain") else ""
        if cm not in ("acme", "selfip", "unsafe"):
            raise ApiError("证书模式必填: acme(域名自动证书) / selfip(IP自签) / unsafe(自签不安全)")
        if cm == "unsafe" and not b.get("unsafe_ok"):
            raise ApiError("unsafe 模式需要显式确认(unsafe_ok): 明文特征明显, 不建议生产使用")
        out["cert_mode"] = cm
    if "acme_email" in b:
        email = (b.get("acme_email") or "").strip()[:128]
        if email and not re.fullmatch(r"[^@\s]+@[^@\s]+", email):
            raise ApiError("邮箱格式非法")
        out["acme_email"] = email
    if "users" in b:
        ul = [str(u).strip() for u in (b.get("users") or []) if str(u).strip()]
        all_users = sbtool.load_users(BASE)
        unknown = [u for u in ul if u not in all_users]
        if unknown:
            raise ApiError("用户不存在: %s" % ", ".join(unknown))
        out["users"] = ul
    if "note" in b:
        out["note"] = (b.get("note") or "")[:200]
    if "enabled" in b:
        out["enabled"] = bool(b["enabled"])
    return out


def h_servers_list(ctx):
    servers = sbtool.load_servers(BASE)
    traffic = sbtool.load_traffic(BASE)
    return 200, [server_view(sid, srv, traffic) for sid, srv in servers.items()]


def h_servers_add(ctx):
    fields = _validate_server_payload(ctx.body)
    if fields.get("cert_mode") == "acme" and not fields.get("domain"):
        raise ApiError("acme 模式需要绑定域名")
    with PROC_LOCK:
        servers = sbtool.load_servers(BASE)
        sid = secrets.token_hex(4)
        while sid in servers:  # 防 sid 碰撞
            sid = secrets.token_hex(4)
        token = sbtool.gen_server_token()  # 一次性安装令牌 (激活时烧毁, 永久令牌届时生成)
        srv = {"install_hash": sbtool.hash_server_token(token),
               "created_at": int(time.time()), "enabled": True}
        srv.update(fields)
        servers[sid] = srv
        sbtool.save_servers(BASE, servers)
    return 200, {"sid": sid, "token": token,
                 "install_command": install_command(sid, token, request_host_port(ctx.headers),
                                                  "https" if ctx.headers.get("X-Forwarded-Proto") == "https" else "http")}


def h_servers_update(ctx):
    sid = ctx.match.group(1)
    fields = _validate_server_payload(ctx.body, partial=True)
    with PROC_LOCK:
        servers = sbtool.load_servers(BASE)
        if sid not in servers:
            raise ApiError("节点不存在", 404)
        merged = dict(servers[sid])
        merged.update(fields)
        if merged.get("cert_mode") == "acme" and not merged.get("domain"):
            raise ApiError("acme 模式需要绑定域名")
        servers[sid].update(fields)
        sbtool.save_servers(BASE, servers)
    return 200, {"ok": True}


def h_servers_del(ctx):
    sid = ctx.match.group(1)
    with PROC_LOCK:
        servers = sbtool.load_servers(BASE)
        if sid not in servers:
            raise ApiError("节点不存在", 404)
        del servers[sid]
        sbtool.save_servers(BASE, servers)
        # 清理分流规则中对该节点的引用
        rc = routes_data()
        changed = False
        for r in rc.get("rules", []):
            if r.get("nodes") and sid in r["nodes"]:
                r["nodes"] = [n for n in r["nodes"] if n != sid]
                if not r["nodes"]:
                    r.pop("nodes")
                changed = True
        if changed:
            sbtool.save_json(sbtool.paths(BASE)["routes"], rc)
    return 200, {"ok": True}


def h_servers_token(ctx):
    """重新生成部署命令: 新一次性安装令牌, 旧安装令牌与旧节点令牌立即失效"""
    sid = ctx.match.group(1)
    token = sbtool.gen_server_token()
    with PROC_LOCK:
        servers = sbtool.load_servers(BASE)
        if sid not in servers:
            raise ApiError("节点不存在", 404)
        servers[sid]["install_hash"] = sbtool.hash_server_token(token)
        servers[sid].pop("token_hash", None)  # 旧节点令牌立即失效, 重装激活时轮换新令牌
        sbtool.save_servers(BASE, servers)
    return 200, {"ok": True, "token": token,
                 "install_command": install_command(sid, token, request_host_port(ctx.headers),
                                                  "https" if ctx.headers.get("X-Forwarded-Proto") == "https" else "http")}


def h_servers_config(ctx):
    """预览下发给节点的完整配置 (管理员调试)"""
    sid = ctx.match.group(1)
    servers = sbtool.load_servers(BASE)
    if sid not in servers:
        raise ApiError("节点不存在", 404)
    return 200, call_sbtool(sbtool.server_bundle, BASE, sid)


def h_traffic(ctx):
    t = sbtool.load_traffic(BASE)
    t["rates"] = current_rates()
    return 200, t


# ------------------------------------------------------------------ 实时带宽速率

_RATES_LOCK = threading.Lock()
_RATES = {"total": {"at": 0, "rate_up": 0.0, "rate_down": 0.0}, "servers": {}}


def note_report_rates(sid, clean):
    """每次节点上报时按增量/间隔计算即时速率 (B/s)"""
    now = time.time()
    up = sum(p[0] for p in clean.values())
    down = sum(p[1] for p in clean.values())
    with _RATES_LOCK:
        for key in ("total", sid):
            cur = _RATES["total"] if key == "total" else _RATES["servers"].setdefault(
                key, {"at": 0, "rate_up": 0.0, "rate_down": 0.0})
            if cur["at"]:
                dt = max(now - cur["at"], 1.0)
                cur["rate_up"] = up / dt
                cur["rate_down"] = down / dt
            cur["at"] = now


def current_rates():
    now = time.time()
    with _RATES_LOCK:
        def pack(r):
            if not r["at"] or now - r["at"] > 90:  # 超过 90 秒没上报, 速率归零
                return {"rate_up": 0.0, "rate_down": 0.0}
            return {"rate_up": round(r["rate_up"], 1), "rate_down": round(r["rate_down"], 1)}
        return {"total": pack(_RATES["total"]),
                "servers": {sid: pack(r) for sid, r in _RATES["servers"].items()}}


# ------------------------------------------------------------------ 系统状态 (3x-ui 风格)

_SYS_PREV = {"cpu": None}


def h_system(ctx):
    """面板主机的 CPU/内存/磁盘/负载 (读 /proc, 纯标准库)"""
    out = {"cpu": 0.0, "mem": {}, "disk": {}, "load": [], "uptime": 0}
    try:
        with open("/proc/stat") as f:
            parts = f.readline().split()[1:]
        vals = list(map(int, parts))
        idle = vals[3] + vals[4]
        total = sum(vals)
        prev = _SYS_PREV["cpu"]
        if prev:
            dt = total - prev[1]
            di = idle - prev[0]
            out["cpu"] = round(max(0.0, min(100.0, (1 - di / dt) * 100)), 1) if dt > 0 else 0.0
        _SYS_PREV["cpu"] = (idle, total)
    except OSError:
        pass
    try:
        mem = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, v = line.partition(":")
                mem[k.strip()] = int(v.strip().split()[0]) * 1024
        total = mem.get("MemTotal", 0)
        avail = mem.get("MemAvailable", 0)
        out["mem"] = {"total": total, "used": total - avail,
                      "percent": round((total - avail) / total * 100, 1) if total else 0}
    except (OSError, ValueError):
        pass
    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        out["disk"] = {"total": total, "used": total - free,
                       "percent": round((total - free) / total * 100, 1) if total else 0}
    except OSError:
        pass
    try:
        out["load"] = list(os.getloadavg())
    except OSError:
        pass
    try:
        with open("/proc/uptime") as f:
            out["uptime"] = int(float(f.read().split()[0]))
    except OSError:
        pass
    return 200, out


def h_agent_info(ctx):
    """agent 通道信息: CA 指纹(供操作员在节点侧人工比对)与端口"""
    return 200, {"ca_fingerprint": agent_cert_fingerprint()}


def h_certs(ctx):
    """证书管理: 各节点证书状态一览 (申请/续签由节点 sing-box ACME 自动完成)"""
    servers = sbtool.load_servers(BASE)
    now = time.time()
    out = []
    for sid, srv in servers.items():
        exp = srv.get("cert_not_after") or 0
        days = round((exp - now) / 86400, 1) if exp else None
        if not exp:
            status = "pending"     # 未上报/申请中
        elif days < 0:
            status = "expired"
        elif days < 10:
            status = "expiring"
        else:
            status = "ok"
        out.append({
            "sid": sid, "name": srv.get("name", sid),
            "domain": srv.get("domain", ""),
            "cert_mode": srv.get("cert_mode") or "",
            "issuer": srv.get("cert_issuer", ""),
            "not_after": exp, "days_left": days, "status": status,
            "online": bool(srv.get("last_seen")) and now - srv["last_seen"] < 120,
        })
    return 200, out


# ---- agent 通道处理器 (仅 agent HTTPS 监听口, Bearer 节点 token 认证)

class Raw:
    """二进制/文本直出响应"""
    def __init__(self, data, ctype="application/octet-stream"):
        self.data = data
        self.ctype = ctype


def h_agent_config(ctx):
    """长轮询配置下发: hash 不变则挂起至变更或超时, 实现配置秒级下发"""
    cur = ctx.query.get("hash", "")
    try:
        wait = min(max(int(ctx.query.get("wait") or 0), 0), 45)
    except ValueError:
        wait = 0
    touch_server(ctx.sid, last_seen=int(time.time()), reported_ip=ctx.client_ip)  # 心跳前置
    if wait:  # 限制单节点并发长轮询, 防被攻陷 token 耗尽面板线程
        with _CONFPULL_LOCK:
            n = _CONFPULL.get(ctx.sid, 0)
            if n >= 2:
                raise ApiError("并发长轮询超限", 429)
            _CONFPULL[ctx.sid] = n + 1
    try:
        deadline = time.time() + wait
        h = desired_hash(ctx.sid)
        while cur and h == cur and time.time() < deadline:
            time.sleep(1)
            h = desired_hash(ctx.sid)
    finally:
        if wait:
            with _CONFPULL_LOCK:
                left = _CONFPULL.get(ctx.sid, 1) - 1
                if left:
                    _CONFPULL[ctx.sid] = left
                else:
                    _CONFPULL.pop(ctx.sid, None)
    touch_server(ctx.sid, last_seen=int(time.time()), reported_ip=ctx.client_ip)
    if cur and cur == h:
        # 即使配置未变也带上 agent 版本信息, 便于节点自更新
        return 200, {"unchanged": True, "hash": h, "agent_sha256": agent_py_sha256()}
    bundle = call_sbtool(sbtool.server_bundle, BASE, ctx.sid)
    bundle["agent_sha256"] = agent_py_sha256()
    return 200, bundle


_AGENT_SHA = {"at": 0, "sha": ""}


def agent_py_sha256():
    if time.time() - _AGENT_SHA["at"] > 30 or not _AGENT_SHA["sha"]:
        try:
            with open(os.path.join(ROOT, "agent.py"), "rb") as f:
                _AGENT_SHA["sha"] = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            pass
        _AGENT_SHA["at"] = time.time()
    return _AGENT_SHA["sha"]


def h_agent_ruleset(ctx):
    tag = ctx.match.group(1)
    cat = sbtool.load_json(sbtool.paths(BASE)["catalog"], {})
    ent = cat.get(tag)
    if not ent:
        raise ApiError("规则集不存在", 404)
    fp = os.path.normpath(os.path.join(BASE, ent["file"]))
    if not fp.startswith(os.path.join(os.path.abspath(BASE), "rulesets") + os.sep):
        raise ApiError("路径非法", 400)
    try:
        with open(fp, "rb") as f:
            return 200, Raw(f.read())
    except OSError:
        raise ApiError("规则集文件缺失", 404)


def h_agent_binary(ctx):
    arch = ctx.match.group(1)
    fp = os.path.join(BASE, "bin", "sing-box-linux-%s" % arch)
    if not os.path.isfile(fp):
        raise ApiError("面板未托管该架构的 sing-box 二进制", 404)
    with open(fp, "rb") as f:
        return 200, Raw(f.read())


def h_agent_agentpy(ctx):
    with open(os.path.join(ROOT, "agent.py"), "rb") as f:
        return 200, Raw(f.read(), "text/x-python")


def h_agent_install(ctx):
    """静态安装脚本 (不含任何机密; 完整性由安装命令中的 sha256 校验保证)"""
    with open(os.path.join(ROOT, "install_node.sh"), "rb") as f:
        return 200, Raw(f.read(), "text/x-shellscript")


def h_agent_activate(ctx):
    """一次性安装令牌兑换永久节点令牌: 原子烧毁安装令牌并轮换永久令牌。
    永久令牌仅此一次以明文返回 (面板只存哈希), 安装命令泄露/重放均无法二次使用。"""
    with PROC_LOCK:
        servers = sbtool.load_servers(BASE)
        srv = servers.get(ctx.sid)
        ih = sbtool.hash_server_token(ctx.token)
        if not srv or not srv.get("install_hash") or \
                not hmac.compare_digest(ih, srv["install_hash"]):
            raise ApiError("安装令牌无效或已使用", 401)
        token = sbtool.gen_server_token()
        srv["token_hash"] = sbtool.hash_server_token(token)
        srv.pop("install_hash", None)  # 烧毁: 一次性
        sbtool.save_servers(BASE, servers)
    return 200, {"ok": True, "token": token}


def h_agent_ca(ctx):
    ensure_agent_cert()
    _, cert, _ = agent_cert_paths()
    with open(cert, "rb") as f:
        return 200, Raw(f.read(), "application/x-pem-file")


def h_agent_report(ctx):
    b = ctx.body
    stats = b.get("stats")
    if not isinstance(stats, dict) or len(stats) > 10000:
        raise ApiError("stats 非法", 400)
    # 心跳先行: 记账/状态维护等任何后续故障都不能把节点打成离线
    fields = {"last_seen": int(time.time()),
              "applied_hash": str(b.get("applied_hash") or "")[:64],
              "agent_version": str(b.get("agent_version") or "")[:32],
              "last_error": str(b.get("last_error") or "")[:300],
              "sb_running": bool(b.get("sb_running")),
              "reported_ip": ctx.client_ip}
    cert = b.get("cert")
    if isinstance(cert, dict):  # agent 上报的证书状态
        try:
            fields["cert_not_after"] = int(cert.get("not_after") or 0)
        except (TypeError, ValueError):
            pass
        fields["cert_issuer"] = str(cert.get("issuer") or "")[:128]
    touch_server(ctx.sid, **fields)
    # 流量记账 best-effort: 只接受本节点真实分配的用户
    try:
        allowed = set(sbtool.server_users(BASE, ctx.srv))
        clean = {}
        for name, pair in stats.items():
            name = str(name)
            if name not in allowed:
                continue
            if isinstance(pair, list) and len(pair) == 2:
                clean[name] = pair
        sbtool.add_traffic(BASE, ctx.sid, clean)
        note_report_rates(ctx.sid, clean)
        sbtool.sync_user_states(BASE, users_lock=PROC_LOCK)  # 维护 超额/到期/月重置
    except Exception:
        import traceback
        traceback.print_exc()  # report 流量记账失败不影响心跳
    return 200, {"ok": True}


def h_agent_node_meta(ctx):
    s = sbtool.get_settings(BASE)
    return 200, {"sni": sbtool.server_sni(s, ctx.srv) or "anytls.example.com",
                 "name": ctx.srv.get("name", ctx.sid),
                 "domain": ctx.srv.get("domain", ""),
                 "cert_mode": ctx.srv.get("cert_mode") or "unsafe",
                 "port": ctx.srv.get("port")}



# ---- user (self)

def h_me(ctx):
    name = ctx.user["name"]
    users = sbtool.load_users(BASE)
    u = users.get(name)
    if not u:
        raise ApiError("用户不存在", 404)
    s = sbtool.get_settings(BASE)
    host = request_host_port(ctx.headers)
    scheme = "https" if ctx.headers.get("X-Forwarded-Proto") == "https" else "http"
    v = user_view(name, u, s, host, scheme)
    # 我的出口信息
    rc = routes_data()
    my_final = rc.get("user_final", {}).get(name) or rc.get("final") or s.get("final", "direct")
    my_rules = [r for r in rc.get("rules", []) if name in (r.get("users") or [])]
    v["exit"] = my_final
    v["my_rules"] = len(my_rules)
    v["server_port"] = s["port"]
    v["sni"] = s.get("sni") or ""
    return 200, v


def h_me_password(ctx):
    name = ctx.user["name"]
    with PROC_LOCK:
        return _me_password_locked(name, ctx.body)


def _me_password_locked(name, b):
    users = sbtool.load_users(BASE)
    u = users.get(name)
    if not u:
        raise ApiError("用户不存在", 404)
    if u.get("panel_password_hash"):
        if not sbtool.verify_password(b.get("old") or "", u["panel_password_hash"]):
            raise ApiError("原密码错误", 403)
    new = b.get("new") or ""
    if len(new) < 6:
        raise ApiError("新密码至少 6 位")
    u["panel_password_hash"] = sbtool.hash_password(new)
    u["sv"] = u.get("sv", 0) + 1  # 使旧会话失效
    sbtool.save_users(BASE, users)
    return 200, {"ok": True, "token": make_token("user", name, str(u["sv"]))}


def h_me_refresh_token(ctx):
    """一键重置订阅链接: 换 token, 旧订阅地址立即失效"""
    name = ctx.user["name"]
    with PROC_LOCK:
        users = sbtool.load_users(BASE)
        u = users.get(name)
        if not u:
            raise ApiError("用户不存在", 404)
        u["token"] = sbtool.gen_token()
        sbtool.save_users(BASE, users)
    s = sbtool.get_settings(BASE)
    host = request_host_port(ctx.headers)
    scheme = "https" if ctx.headers.get("X-Forwarded-Proto") == "https" else "http"
    v = user_view(name, u, s, host, scheme)
    return 200, {"ok": True, "token": u["token"], "sub_url": v["sub_url"]}


# ------------------------------------------------------------------ routing

ROUTES = [
    # method, pattern, handler, role (None=公开, "admin", "user", "any")
    ("GET", r"/api/meta", h_meta, None),
    ("POST", r"/api/setup", h_setup, None),
    ("POST", r"/api/login", h_login, None),
    ("GET", r"/api/status", h_status, "admin"),
    ("GET", r"/api/nodes", h_nodes_list, "admin"),
    ("POST", r"/api/nodes", h_nodes_add, "admin"),
    ("POST", r"/api/nodes/import", h_nodes_import, "admin"),
    ("PUT", r"/api/nodes/([^/]+)", h_nodes_update, "admin"),
    ("DELETE", r"/api/nodes/([^/]+)", h_nodes_del, "admin"),
    ("GET", r"/api/servers", h_servers_list, "admin"),
    ("POST", r"/api/servers", h_servers_add, "admin"),
    ("PUT", r"/api/servers/([0-9a-f]{8})", h_servers_update, "admin"),
    ("DELETE", r"/api/servers/([0-9a-f]{8})", h_servers_del, "admin"),
    ("POST", r"/api/servers/([0-9a-f]{8})/token", h_servers_token, "admin"),
    ("GET", r"/api/servers/([0-9a-f]{8})/config", h_servers_config, "admin"),
    ("GET", r"/api/traffic", h_traffic, "admin"),
    ("GET", r"/api/system", h_system, "admin"),
    ("GET", r"/api/certs", h_certs, "admin"),
    ("GET", r"/api/agent-info", h_agent_info, "admin"),
    ("GET", r"/api/users", h_users_list, "admin"),
    ("POST", r"/api/users", h_users_add, "admin"),
    ("PUT", r"/api/users/([^/]+)", h_users_update, "admin"),
    ("PUT", r"/api/users/([^/]+)/servers", h_users_servers, "admin"),
    ("POST", r"/api/users/([^/]+)/reset_usage", h_users_reset_usage, "admin"),
    ("DELETE", r"/api/users/([^/]+)", h_users_del, "admin"),
    ("GET", r"/api/routes", h_routes_list, "admin"),
    ("POST", r"/api/routes", h_routes_add, "admin"),
    ("POST", r"/api/routes/move", h_routes_move, "admin"),
    ("DELETE", r"/api/routes/(\d+)", h_routes_del, "admin"),
    ("POST", r"/api/routes/final", h_routes_final, "admin"),
    ("DELETE", r"/api/routes/final", h_routes_final_del, "admin"),
    ("GET", r"/api/rulesets", h_rulesets, "admin"),
    ("GET", r"/api/rulesets/sources", h_ruleset_sources, "admin"),
    ("GET", r"/api/settings", h_settings_get, "admin"),
    ("PUT", r"/api/settings", h_settings_put, "admin"),
    ("POST", r"/api/settings/admin", h_settings_admin, "admin"),
    ("GET", r"/api/me", h_me, "user"),
    ("POST", r"/api/me/password", h_me_password, "user"),
    ("POST", r"/api/me/refresh_token", h_me_refresh_token, "user"),
]

SUB_HTML = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:#0f1115;color:#e6e8eb;font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}
.card{width:min(680px,92vw);background:#171a21;border:1px solid #262b36;border-radius:14px;padding:28px}
h1{font-size:20px;margin:0 0 4px}.brand{color:#4cc2ff}
.sub{color:#8b93a3;font-size:13px;margin-bottom:18px}
.row{margin:14px 0}.label{font-size:12px;color:#8b93a3;margin-bottom:6px}
.box{background:#0d0f13;border:1px solid #262b36;border-radius:8px;padding:12px;
word-break:break-all;font-family:ui-monospace,Menlo,monospace;font-size:12px;line-height:1.6}
button{margin-top:8px;background:#4cc2ff;border:none;color:#04121c;border-radius:6px;
padding:8px 16px;font-size:13px;cursor:pointer}
button:hover{opacity:.85}.warn{color:#e2b93d;font-size:13px}
</style></head><body><div class="card">
<h1><span class="brand">KSING</span>-UI · 订阅</h1>
<div class="sub">用户 __NAME__ __STATE__</div>
__BODY__
</div>
<script>
function cp(id,btn){navigator.clipboard.writeText(document.getElementById(id).textContent).then(()=>{btn.textContent='已复制';setTimeout(()=>btn.textContent='复制',1500)})}
</script></body></html>"""


def sub_page(name, links, sub_url):
    name = html.escape(name)
    rows = []
    if sub_url:
        subs = [("sing-box", sub_url + "?type=singbox"),
                ("mihomo / Clash", sub_url + "?type=clash"),
                ("v2rayN", sub_url)]
        box = []
        for i, (label, url) in enumerate(subs):
            box.append('<div class="label">%s 订阅地址</div>'
                       '<div class="box" id="sub%d">%s</div>'
                       '<button onclick="cp(\'sub%d\',this)">复制</button>'
                       % (label, i, html.escape(url), i))
        rows.append('<div class="row">%s</div>' % "\n".join(box))
    if links:
        box = []
        for i, link in enumerate(links):
            box.append('<div class="box" style="margin-bottom:6px" id="link%d">%s</div>'
                       '<button onclick="cp(\'link%d\',this)">复制</button>'
                       % (i, html.escape(link), i))
        rows.append('<div class="row"><div class="label">节点链接 (AnyTLS, 共 %d 条)</div>%s</div>'
                    % (len(links), "\n".join(box)))
    if not links:
        rows.append('<div class="warn">该用户已禁用或暂无可用节点。</div>')
    page = SUB_HTML.replace("__TITLE__", "KSING-UI 订阅")
    page = page.replace("__NAME__", name)
    page = page.replace("__STATE__", "" if links else "(不可用)")
    page = page.replace("__BODY__", "\n".join(rows))
    return page


# ------------------------------------------------------------------ 订阅格式渲染

def render_clash(nodes):
    """mihomo/Clash 订阅: 完整配置, fakeip + DNS 防泄露 + 国内直连/国外代理 (与服务端分流互不干扰)。
    规则集经代理下载 (proxy: 节点选择), 解决 GitHub 直连被墙导致规则下载失败、全部流量落 MATCH 的问题。"""
    lines = [
        "# ksing-ui 订阅 (mihomo)",
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: warning",
        "external-controller: 127.0.0.1:9090",
        "geodata-mode: true",          # geosite:cn 等需要 geosite.dat
        "geo-auto-update: true",
        "geo-update-interval: 24",
        "geox-url:",
        "  geosite: https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
        "  geoip: https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",
        "  mmdb: https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb",
        "tun:",
        "  enable: true",
        "  stack: mixed",
        "  auto-route: true",
        "  auto-detect-interface: true",
        "  dns-hijack:",            # 拦截所有 DNS 请求, 防泄露
        "    - any:53",
        "    - tcp://any:53",
        "dns:",
        "  enable: true",
        "  listen: 0.0.0.0:1053",
        "  enhanced-mode: fake-ip",  # fakeip 兜底: 域名先路由后解析, 不把域名泄露给本地 DNS
        "  fake-ip-range: 198.18.0.1/16",
        "  fake-ip-filter:",         # 国内域名不走 fakeip, 直接用国内 DNS 出真实 IP
        "    - '*.lan'",
        "    - '*.local'",
        "    - 'localhost.*'",
        "    - 'geosite:cn'",
        "  default-nameserver:",     # 仅用于解析下面的 DoH 服务器域名
        "    - 223.5.5.5",
        "    - 119.29.29.29",
        "  nameserver:",
        "    - https://223.6.6.6/dns-query",
        "    - https://119.29.29.29/dns-query",
        "  proxy-server-nameserver:",  # 节点域名解析只用国内 DNS
        "    - https://223.6.6.6/dns-query",
        "  respect-rules: true",       # DNS 查询遵循路由规则 (#节点选择 后缀走代理)
        "  nameserver-policy:",
        "    'rule-set:cn-site':",
        "      - https://223.6.6.6/dns-query",
        "      - https://119.29.29.29/dns-query",
        "    'rule-set:gfw-site':",
        "      - https://1.1.1.1/dns-query#节点选择",
        "      - https://8.8.8.8/dns-query#节点选择",
        "proxies:",
    ]
    for n in nodes:
        lines.append("  - name: %s" % json.dumps(n["name"], ensure_ascii=False))
        if n.get("socks"):  # 信息节点: 不可用, 名称即状态
            lines.append("    type: socks5")
            lines.append("    server: %s" % json.dumps(n["server"]))
            lines.append("    port: %d" % n["port"])
            lines.append("    udp: true")
            continue
        lines.append("    type: anytls")
        lines.append("    server: %s" % json.dumps(n["server"]))
        lines.append("    port: %d" % n["port"])
        lines.append("    password: %s" % json.dumps(n["password"]))
        if n["sni"]:
            lines.append("    sni: %s" % json.dumps(n["sni"]))
        lines.append("    skip-cert-verify: %s" % ("true" if n["insecure"] else "false"))
        lines.append("    udp: true")
    names = [json.dumps(n["name"], ensure_ascii=False) for n in nodes]
    lines += [
        "proxy-groups:",
        "  - name: 节点选择",
        "    type: select",
        "    proxies: [自动选择%s]" % "".join(", " + x for x in names),
        "  - name: 自动选择",
        "    type: url-test",
        "    url: http://www.gstatic.com/generate_204",
        "    interval: 300",
        "    proxies: [%s]" % ", ".join(names),
        "rule-providers:",   # 全部经代理下载, 避免 GitHub 直连被墙导致规则为空
        "  cn-site:",
        "    type: http",
        "    behavior: domain",
        "    format: mrs",
        "    proxy: 节点选择",
        "    url: https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/geolocation-cn.mrs",
        "    path: ./rules/ksing-cn-site.mrs",
        "    interval: 86400",
        "  gfw-site:",
        "    type: http",
        "    behavior: domain",
        "    format: mrs",
        "    proxy: 节点选择",
        "    url: https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/geolocation-!cn.mrs",
        "    path: ./rules/ksing-gfw-site.mrs",
        "    interval: 86400",
        "  cn-ip:",
        "    type: http",
        "    behavior: ipcidr",
        "    format: mrs",
        "    proxy: 节点选择",
        "    url: https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs",
        "    path: ./rules/ksing-cn-ip.mrs",
        "    interval: 86400",
        "rules:",
        "  - RULE-SET,cn-site,DIRECT",
        "  - RULE-SET,gfw-site,节点选择",
        "  - RULE-SET,cn-ip,DIRECT",
        "  - MATCH,节点选择",
    ]
    return "\n".join(lines) + "\n"


def render_singbox(nodes):
    """sing-box 完整客户端配置订阅 (等价分流: 国内直连/国外代理, DNS 国内外分离)"""
    tags = [n["name"] for n in nodes]
    outbounds = [
        {"type": "selector", "tag": "selector", "outbounds": ["urltest"] + tags,
         "default": "urltest"},
        {"type": "urltest", "tag": "urltest", "outbounds": tags,
         "url": "http://www.gstatic.com/generate_204", "interval": "3m"},
    ]
    for n in nodes:
        if n.get("socks"):  # 信息节点: 不可用, 名称即状态
            outbounds.append({"type": "socks", "tag": n["name"],
                              "server": n["server"], "server_port": n["port"]})
            continue
        outbounds.append({
            "type": "anytls", "tag": n["name"],
            "server": n["server"], "server_port": n["port"],
            "password": n["password"],
            "tls": {"enabled": True, "server_name": n["sni"], "insecure": n["insecure"]},
        })
    outbounds.append({"type": "direct", "tag": "direct"})

    def rs(tag, url):
        return {"type": "remote", "format": "binary", "tag": tag, "url": url}

    gh = "https://raw.githubusercontent.com"
    cfg = {
        "log": {"level": "info"},
        "experimental": {"cache_file": {"enabled": True, "store_dns": True}},
        "dns": {
            "servers": [
                {"type": "https", "tag": "local", "server": "223.6.6.6", "server_port": 443,
                 "path": "/dns-query", "tls": {"enabled": True, "server_name": "dns.alidns.com"}},
                {"type": "https", "tag": "remote", "server": "1.1.1.1",
                 "path": "/dns-query", "detour": "selector",
                 "tls": {"enabled": True, "server_name": "cloudflare-dns.com"}},
                {"type": "https", "tag": "remote-us", "server": "8.8.8.8",
                 "path": "/dns-query", "detour": "selector",
                 "tls": {"enabled": True, "server_name": "dns.google"}},
            ],
            "rules": [
                {"action": "route", "rule_set": "geosite-google", "server": "remote-us"},
                {"action": "route", "rule_set": "geosite-cn", "server": "local"},
                {"action": "route", "rule_set": "ext-cn-domain", "server": "local"},
            ],
            "final": "remote",
            "strategy": "prefer_ipv4",
            "optimistic": {"enabled": True, "timeout": "10m"},
        },
        "http_clients": [{"tag": "rule-set-downloader", "detour": "selector"}],
        "inbounds": [{
            "type": "tun", "tag": "tun-in",
            "interface_name": "ksing0",
            "address": ["172.19.0.1/30", "fdfe:dcba:9875::1/126"],
            "auto_route": True, "strict_route": True,
        }],
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": {"server": "local"},
            "default_http_client": "rule-set-downloader",
            "rule_set": [
                rs("geoip-cn", gh + "/SagerNet/sing-geoip/rule-set/geoip-cn.srs"),
                rs("geosite-cn", gh + "/SagerNet/sing-geosite/rule-set/geosite-geolocation-cn.srs"),
                rs("ext-cn-domain", gh + "/xmdhs/cn-domain-list/rule-set/ext-cn-list.srs"),
                rs("geosite-!cn", gh + "/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs"),
                rs("geosite-google", gh + "/SagerNet/sing-geosite/rule-set/geosite-google.srs"),
                rs("geoip-google", gh + "/MetaCubeX/meta-rules-dat/sing/geo/geoip/google.srs"),
            ],
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_is_private": True, "action": "route", "outbound": "direct"},
                {"rule_set": "geosite-cn", "action": "route", "outbound": "direct"},
                {"rule_set": "ext-cn-domain", "action": "route", "outbound": "direct"},
                {"rule_set": "geosite-!cn", "action": "route", "outbound": "urltest"},
                {"action": "resolve", "strategy": "prefer_ipv4"},
                {"type": "logical", "mode": "and",
                 "rules": [{"rule_set": "geoip-cn"},
                           {"rule_set": "geosite-!cn", "invert": True}],
                 "action": "route", "outbound": "direct"},
            ],
            "final": "urltest",
        },
    }
    return json.dumps(cfg, ensure_ascii=False, indent=2)


def sub_format(handler):
    """订阅格式: ?type= 优先, 否则 UA 嗅探; 返回 singbox / clash / v2ray"""
    t = (handler.sub_query.get("type") or handler.sub_query.get("format") or "").lower()
    if t in ("singbox", "sing-box", "sfa", "sfi"):
        return "singbox"
    if t in ("clash", "mihomo", "yaml"):
        return "clash"
    if t in ("v2ray", "v2rayn", "b64", "links", "raw"):
        return "v2ray"
    ua = handler.headers.get("User-Agent", "").lower()
    if "clash" in ua or "mihomo" in ua or "stash" in ua:
        return "clash"
    if "sing-box" in ua or "sfa" in ua or "sfi" in ua:
        return "singbox"
    return "v2ray"


def handle_sub(handler, token):
    users = sbtool.load_users(BASE)
    found = None
    for name, u in users.items():
        tok = u.get("token") or ""
        if hmac.compare_digest(tok.encode("utf-8"), token.encode("utf-8")):
            found = (name, u)
            break
    if not found:
        handler.send_json(404, {"error": "订阅不存在"})
        return
    name, u = found
    s = sbtool.get_settings(BASE)
    req_host = request_host_port(handler.headers)
    scheme = "https" if handler.headers.get("X-Forwarded-Proto") == "https" else "http"
    v = user_view(name, u, s, req_host, scheme)
    accept = handler.headers.get("Accept", "")
    if "text/html" in accept and not handler.sub_query.get("type"):
        handler.send_html(200, sub_page(name, v["links"], v["sub_url"]))
        return
    # 信息节点置顶 (流量/到期状态常驻客户端); 过期/耗尽/禁用后真实节点已被剔除, 只剩状态
    nodes = sub_info_nodes(v) + (user_nodes(name, u) if u.get("enable") else [])
    tr = v["traffic"]
    info_hdr = {"Subscription-Userinfo": "upload=%d; download=%d; total=%d; expire=%d"
                                         % (tr["up"], tr["down"],
                                            v["traffic_limit"], v["expire_at"]),
                "Profile-Update-Interval": "12"}
    fmt = sub_format(handler)
    if fmt == "clash":
        handler._send(200, render_clash(nodes), "application/x-yaml; charset=utf-8",
                      dict(info_hdr, **{
                          "Content-Disposition": "attachment; filename*=UTF-8''ksing.yaml"}))
        return
    if fmt == "singbox":
        handler._send(200, render_singbox(nodes), "application/json; charset=utf-8",
                      dict(info_hdr, **{
                          "Content-Disposition": "attachment; filename*=UTF-8''ksing.json"}))
        return
    links = ["socks://%s@%s:%d#%s" % (INFO_SOCKS_USERINFO, n["server"], n["port"],
                                      urllib.parse.quote(n["name"], safe=""))
             for n in nodes if n.get("socks")] + v["links"]
    if handler.sub_query.get("format") == "raw":
        handler.send_text(200, "\n".join(links) + "\n")
        return
    raw = "\n".join(links) + "\n"
    body = base64.b64encode(raw.encode()).decode()
    handler.send_text(200, body, headers=dict(info_hdr, **{
        "Content-Disposition": "attachment; filename*=UTF-8''ksing-ui"}))


# ------------------------------------------------------------------ HTTP server

class Ctx:
    def __init__(self, handler, body, query, user, match):
        self.handler = handler
        self.body = body
        self.query = query
        self.user = user
        self.match = match
        self.headers = handler.headers
        self.client_ip = handler.client_address[0]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ksing-ui"

    def setup(self):
        super().setup()
        self.connection.settimeout(30)  # 防慢速连接占用线程

    def log_message(self, fmt, *args):
        pass

    # ---- response helpers
    def _send(self, code, body, ctype, extra=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if ctype.startswith("application/json"):
            self.send_header("Cache-Control", "no-store")
        if self.close_connection:
            self.send_header("Connection", "close")  # 告知客户端勿复用即将关闭的连接
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def send_json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    def send_html(self, code, html):
        self._send(code, html, "text/html; charset=utf-8")

    def send_text(self, code, text, headers=None):
        self._send(code, text, "text/plain; charset=utf-8", headers)

    # ---- request helpers
    def read_body(self, max_bytes=4 * 1024 * 1024):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0:
            return {}
        if n > max_bytes:
            self.close_connection = True  # 残留 body 不读, 断开防破坏 keep-alive 解析
            raise ApiError("请求体过大", 413)
        raw = self.rfile.read(n)
        try:
            obj = json.loads(raw.decode("utf-8"))
        except Exception:
            raise ApiError("请求体必须是 JSON")
        if not isinstance(obj, dict):
            raise ApiError("请求体必须是 JSON 对象")
        return obj

    def handle_agent(self, path, query):
        """agent 通道: /agent/* 接口, 节点 token 认证。返回 True 表示已处理。"""
        for method, pattern, fn in AGENT_ROUTES_PUBLIC:
            if method == self.command and re.fullmatch(pattern, path):
                code, obj = fn(Ctx(self, {}, query, None, None))
                self._send(code, obj.data, obj.ctype)
                return True
        for method, pattern, fn in AGENT_ROUTES_INSTALL:
            if method != self.command:
                continue
            m = re.fullmatch(pattern, path)
            if not m:
                continue
            try:
                sid, srv, token = auth_agent_install(self.headers)  # 先认证再读 body
            except ApiError:
                self._drop_unread_body()
                raise
            body = {}
            if self.command in ("POST", "PUT", "DELETE"):
                body = self.read_body(16 * 1024)
            ctx = Ctx(self, body, query, None, m)
            ctx.sid = sid
            ctx.srv = srv
            ctx.token = token
            code, obj = fn(ctx)
            self.send_json(code, obj)
            return True
        for method, pattern, fn in AGENT_ROUTES:
            if method != self.command:
                continue
            m = re.fullmatch(pattern, path)
            if not m:
                continue
            try:
                sid, srv, token = auth_agent(self.headers)  # 先认证再读 body, 防未认证资源消耗
            except ApiError:
                self._drop_unread_body()
                raise
            body = {}
            if self.command in ("POST", "PUT", "DELETE"):
                body = self.read_body()
            ctx = Ctx(self, body, query, None, m)
            ctx.sid = sid
            ctx.srv = srv
            ctx.token = token
            code, obj = fn(ctx)
            if isinstance(obj, Raw):
                self._send(code, obj.data, obj.ctype)
            else:
                self.send_json(code, obj)
            return True
        return False

    def auth_user(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return parse_token(auth[7:].strip())
        return None

    def _drop_unread_body(self):
        """请求体尚未读取时关闭连接: 残留字节会被 keep-alive 误当成下一个请求"""
        if self.command in ("POST", "PUT", "DELETE"):
            self.close_connection = True

    def dispatch(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        query = {k: v[0] for k, v in query.items()}

        # agent 通道 (与面板同端口): /agent/*
        if path.startswith("/agent/") and self.handle_agent(path, query):
            return

        # 订阅 (路径可通过设置 sub_path 自定义)
        sub_path = re.escape(sbtool.get_settings(BASE).get("sub_path") or "sub")
        m = re.fullmatch(r"/%s/([A-Za-z0-9_\-]+)" % sub_path, path)
        if m and self.command == "GET":
            self.sub_query = query
            handle_sub(self, m.group(1))
            return

        # API
        if path.startswith("/api/"):
            for method, pattern, fn, role in ROUTES:
                if method != self.command:
                    continue
                m = re.fullmatch(pattern, path)
                if not m:
                    continue
                user = None
                if role is not None:
                    try:
                        user = self.auth_user()
                        if not user:
                            raise ApiError("未登录或会话已过期", 401)
                        if role != "any":
                            check_session(user, role)
                    except ApiError:
                        self._drop_unread_body()  # body 未读, 断开防残留字节破坏 keep-alive
                        raise
                # 认证通过后再读 body (公开接口给小额度), 防未认证资源消耗
                body = {}
                if self.command in ("POST", "PUT", "DELETE"):
                    body = self.read_body(64 * 1024 if role is None else 4 * 1024 * 1024)
                ctx = Ctx(self, body, query, user, m)
                code, obj = fn(ctx)
                self.send_json(code, obj)
                return
            self._drop_unread_body()
            raise ApiError("接口不存在", 404)

        # 静态文件 + SPA
        if self.command == "GET":
            self.serve_static(path)
            return
        self._drop_unread_body()
        raise ApiError("Not Found", 404)

    def serve_static(self, path):
        if path == "/":
            path = "/index.html"
        rel = os.path.normpath(path).lstrip("/")
        fp = os.path.join(WEB_DIST, rel)
        if not fp.startswith(os.path.abspath(WEB_DIST) + os.sep) and rel != "index.html":
            fp = os.path.join(WEB_DIST, "index.html")
        if not os.path.isfile(fp):
            fp = os.path.join(WEB_DIST, "index.html")
        if not os.path.isfile(fp):
            self.send_text(503, "前端未构建: 请先 cd web && npm run build")
            return
        ctype = mimetypes.guess_type(fp)[0] or "application/octet-stream"
        if fp.endswith(".js"):
            ctype = "application/javascript"
        with open(fp, "rb") as f:
            data = f.read()
        headers = {}
        if "/assets/" in fp:
            headers["Cache-Control"] = "public, max-age=31536000, immutable"
        self._send(200, data, ctype, headers)

    def _handle(self):
        try:
            self.dispatch()
        except ApiError as e:
            self.send_json(e.code, {"error": str(e)})
        except BrokenPipeError:
            pass
        except Exception:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            try:
                self.send_json(500, {"error": "服务器内部错误"})
            except Exception:
                pass

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle


class LimitedHTTPServer(ThreadingHTTPServer):
    """带并发连接上限: 超限时立即回 503 并关闭, 防未认证连接泛洪耗尽线程/内存"""
    daemon_threads = True
    max_conns = 256
    request_queue_size = 128  # 监听 backlog (默认 5, 瞬时并发连接会被内核直接拒绝)

    def __init__(self, *args, **kwargs):
        self._conns = 0
        self._conn_lock = threading.Lock()
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        with self._conn_lock:
            over = self._conns >= self.max_conns
            if not over:
                self._conns += 1
        if over:
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\n"
                                b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self._conn_lock:
                self._conns -= 1
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._conn_lock:
                self._conns -= 1


class V6Server(LimitedHTTPServer):
    address_family = __import__("socket").AF_INET6

    def server_bind(self):
        import socket
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError:
            pass
        super().server_bind()


# ------------------------------------------------------------------ agent HTTPS 服务

AGENT_ROUTES_PUBLIC = [  # 无需认证 (内容公开且静态)
    ("GET", r"/agent/install\.sh", h_agent_install),
    ("GET", r"/agent/ca\.pem", h_agent_ca),
]

AGENT_ROUTES_INSTALL = [  # Bearer 一次性安装令牌认证 (仅激活兑换)
    ("POST", r"/agent/activate", h_agent_activate),
]

AGENT_ROUTES = [  # Bearer 节点 token 认证
    ("GET", r"/agent/config", h_agent_config),
    ("GET", r"/agent/node-meta", h_agent_node_meta),
    ("GET", r"/agent/ruleset/([A-Za-z0-9_.\-]{1,128})", h_agent_ruleset),
    ("GET", r"/agent/binary/(amd64|arm64)", h_agent_binary),
    ("GET", r"/agent/agent\.py", h_agent_agentpy),
    ("POST", r"/agent/report", h_agent_report),
]


def _janitor():
    """每分钟维护用户状态 (到期/超额/按月重置), 触发节点配置更新"""
    while True:
        time.sleep(60)
        try:
            sbtool.sync_user_states(BASE, users_lock=PROC_LOCK)
        except Exception:
            pass


def main():
    global BASE
    import argparse
    ap = argparse.ArgumentParser(prog="server.py", description="ksing-ui 面板服务")
    ap.add_argument("--dir", help="数据目录 (默认 ./sbdata 或 SBTOOL_DIR)")
    ap.add_argument("--port", type=int, help="面板端口 (默认取设置 panel_port=8080)")
    ap.add_argument("--listen", help="监听地址 (默认取设置 panel_listen=::)")
    args = ap.parse_args()
    if args.dir:
        BASE = os.path.abspath(args.dir)
    os.makedirs(BASE, exist_ok=True)
    s = sbtool.get_settings(BASE)
    listen = args.listen or s.get("panel_listen") or "::"
    port = args.port or int(s.get("panel_port") or 8080)
    get_secret()
    threading.Thread(target=_janitor, daemon=True).start()
    if ":" in listen:
        srv = V6Server((listen, port), Handler)
    else:
        srv = LimitedHTTPServer((listen, port), Handler)
    print("%s v%s 面板已启动: http://[%s]:%d (数据目录 %s)" % (PANEL_NAME, PANEL_VERSION, listen, port, BASE))
    if not s.get("admin_pass_hash"):
        print("首次运行: 请打开面板页面设置管理员密码")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
