#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sbtool - sing-box AnyTLS 入站 + Shadowsocks 出站分流 配置生成与规则集管理工具

功能:
  update   预下载全部规则集 (SagerNet/sing-geoip, SagerNet/sing-geosite,
           MetaCubeX/meta-rules-dat, xmdhs/cn-domain-list) 并建立本地目录索引
  search   查询规则集, 输出 tag / 本地路径 / 下载 URL
  path     只输出某规则集 tag 的本地文件路径
  url      只输出某规则集 tag 的远程 URL
  node     管理 Shadowsocks 出站节点 (add/import/del/list), tag 自定义;
           import 支持 ss:// 链接 (base64/base64url/明文 userinfo, 可带 plugin 参数)
  user     管理 AnyTLS 入站用户 (add/del/list), 支持多用户
  route    管理分流规则 (add/rm/list/clear/final), 将规则集/域名指到指定出站;
           加 --user 可对指定 AnyTLS 用户单独配置分流规则与默认出口
  set      查看/修改全局设置 (端口/证书/默认出站/导出链接用的 host 与 sni 等)
  gen      生成 sing-box config.json (自动用 sing-box check 校验)
  export   按用户导出 anytls:// 客户端链接 (支持 --user 筛选, --host/--sni 覆盖)

数据目录默认 ./sbdata (可用 --dir 或环境变量 SBTOOL_DIR 修改)。
仅使用 Python 标准库。
"""

import argparse
import base64
import concurrent.futures as cf
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

signal.signal(signal.SIGPIPE, signal.SIG_DFL)

VERSION = "1.0.0"

# config.json 示例中给定的 AnyTLS padding scheme, 固定使用
PADDING_SCHEME = [
    "stop=6",
    "1=250-650",
    "2=280-650,c,130-450",
    "3=150-300",
    "4=320-800",
    "5=450-900,c,300-550",
]

SS_METHODS = [
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
    "none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "rc4-md5",
    "chacha20-ietf", "xchacha20",
]

GH_API = "https://api.github.com"
GH_RAW = "https://raw.githubusercontent.com"

# 规则集来源定义
# dirs: 需要枚举的子目录 ("" 表示仓库根, 只取 .srs 文件)
# tagfn: 由仓库内相对路径生成规则集 tag
def _basename_tag(path):
    return os.path.splitext(os.path.basename(path))[0]

def _meta_tag(prefix):
    def fn(path):
        # geo/geoip/google.srs -> meta-geoip-google ; geo/geosite/x.srs -> meta-geosite-x
        parts = path.split("/")
        kind = parts[-2]  # geoip / geosite
        name = _basename_tag(path)
        return "%s-%s-%s" % (prefix, kind, name)
    return fn

SOURCES = {
    "sing-geoip": {
        "repo": "SagerNet/sing-geoip", "branch": "rule-set", "dirs": [""],
        "tagfn": _basename_tag, "desc": "SagerNet GeoIP 规则集 (geoip-*)",
    },
    "sing-geosite": {
        "repo": "SagerNet/sing-geosite", "branch": "rule-set", "dirs": [""],
        "tagfn": _basename_tag, "desc": "SagerNet Geosite 规则集 (geosite-*)",
    },
    "meta-geo": {
        "repo": "MetaCubeX/meta-rules-dat", "branch": "sing",
        "dirs": ["geo/geoip", "geo/geosite"],
        "tagfn": _meta_tag("meta"), "desc": "MetaCubeX meta-rules-dat 完整 geo/geosite (meta-geoip-*, meta-geosite-*)",
    },
    "meta-geo-lite": {
        "repo": "MetaCubeX/meta-rules-dat", "branch": "sing",
        "dirs": ["geo-lite/geoip", "geo-lite/geosite"],
        "tagfn": _meta_tag("meta-lite"), "desc": "MetaCubeX meta-rules-dat 精简版 (meta-lite-*)",
    },
    "meta-asn": {
        "repo": "MetaCubeX/meta-rules-dat", "branch": "sing", "dirs": ["asn"],
        "tagfn": lambda p: "asn-" + _basename_tag(p).lower(),
        "desc": "MetaCubeX meta-rules-dat ASN 规则 (约 4.6 万个文件, 默认不下载)",
        "optional": True,
    },
    "cn-domain-list": {
        "repo": "xmdhs/cn-domain-list", "branch": "rule-set", "dirs": [""],
        "tagfn": _basename_tag, "desc": "xmdhs 中国域名列表 (ext-cn-list, ext-not-cn-list)",
    },
}
DEFAULT_SOURCES = [k for k, v in SOURCES.items() if not v.get("optional")]

# ---------------------------------------------------------------- 工具函数

def data_dir(args):
    d = args.dir or os.environ.get("SBTOOL_DIR") or os.path.join(os.getcwd(), "sbdata")
    return os.path.abspath(d)

def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default

def save_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.chmod(tmp, 0o600)  # 数据文件含密码/凭据, 仅属主可读写
    os.replace(tmp, path)

def die(msg, code=1):
    print("错误: %s" % msg, file=sys.stderr)
    sys.exit(code)

def http_get(url, mirror="", timeout=30, retries=3):
    if mirror:
        url = mirror.rstrip("/") + "/" + url
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "sbtool/%s" % VERSION})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(1 + i)
    raise RuntimeError("下载失败 %s : %s" % (url, last))

# ---------------------------------------------------------------- 状态文件

def paths(base):
    return {
        "catalog": os.path.join(base, "catalog.json"),
        "nodes": os.path.join(base, "nodes.json"),
        "servers": os.path.join(base, "servers.json"),
        "traffic": os.path.join(base, "traffic.json"),
        "users": os.path.join(base, "users.json"),
        "routes": os.path.join(base, "routes.json"),
        "settings": os.path.join(base, "settings.json"),
        "rulesets": os.path.join(base, "rulesets"),
        "config": os.path.join(base, "config.json"),
        "bin": os.path.join(base, "bin"),
    }

DEFAULT_SETTINGS = {
    "listen": "::",
    "port": 8443,
    "cert": "",            # TLS fullchain 路径, 必填
    "key": "",             # TLS 私钥路径, 必填
    "final": "direct",     # 默认出站
    "host": "",            # 服务器地址(IP/域名), 仅用于导出客户端链接
    "sni": "",             # SNI/证书域名, 仅用于导出客户端链接
    "private_action": "reject",  # 私网 IP 目的地: reject / direct / off
    "auto_detect_interface": True,  # 绑定默认网卡防回环; 若本机 DNS 在 tailscale 等虚拟网卡后需关闭
    "log_level": "info",
    # ---- ksing-ui 面板 ----
    "panel_listen": "::",      # 面板监听地址
    "panel_port": 8080,        # 面板端口
    "admin_user": "admin",     # 面板管理员用户名
    "admin_pass_hash": "",     # 管理员密码哈希 (空 = 未初始化, 首次登录页引导设置)
    "panel_secret": "",        # 面板会话签名密钥 (空 = 自动生成)
    # ---- 节点下发 (agent 通道) ----
    "agent_listen": "::",      # agent 专用 HTTPS 监听地址
    "agent_port": 9443,        # agent 专用 HTTPS 端口 (面板 UI 不经过此端口)
    # ---- 订阅发布 ----
    "sub_host": "",            # 订阅地址的主机 (域名或 IP, 可带 :端口; 空=跟随请求 Host)
    "sub_port": 0,             # 订阅地址的端口 (0=跟随 sub_host 或请求; 反代到 443 时很有用)
    "sub_path": "sub",         # 订阅路径 (如 sub → /sub/<token>; 改后旧订阅地址失效)
}

def get_settings(base):
    s = dict(DEFAULT_SETTINGS)
    s.update(load_json(paths(base)["settings"], {}))
    return s

# ---------------------------------------------------------------- update

def gh_tree(repo, ref_or_sha, mirror):
    url = "%s/repos/%s/git/trees/%s" % (GH_API, repo, ref_or_sha)
    data = json.loads(http_get(url, mirror).decode("utf-8"))
    if "tree" not in data:
        raise RuntimeError("GitHub API 返回异常: %s" % json.dumps(data)[:300])
    return data["tree"]

def enum_source(src_key, mirror):
    """枚举一个来源的全部 .srs 文件: 返回 [(repo_path, size, sha)]"""
    src = SOURCES[src_key]
    repo, branch = src["repo"], src["branch"]
    root = gh_tree(repo, branch, mirror)
    by_path = {e["path"]: e for e in root}
    out = []
    for d in src["dirs"]:
        if d == "":
            entries = [e for e in root if e["type"] == "blob"]
        else:
            entries = None
            cur = root
            for part in d.split("/"):
                node = by_path.get(part) if cur is root else next(
                    (e for e in cur if e["path"] == part), None)
                if node is None or node["type"] != "tree":
                    die("来源 %s 中找不到目录 %s" % (src_key, d))
                cur = gh_tree(repo, node["sha"], mirror)
            entries = [e for e in cur if e["type"] == "blob"]
        for e in entries:
            if not e["path"].endswith(".srs"):
                continue
            repo_path = ("%s/%s" % (d, e["path"])) if d else e["path"]
            out.append((repo_path, e.get("size", 0), e.get("sha", "")))
    return out

def cmd_update(args):
    base = data_dir(args)
    P = paths(base)
    os.makedirs(P["rulesets"], exist_ok=True)
    src_keys = []
    if args.source:
        for s in args.source:
            if s not in SOURCES:
                die("未知来源 %s, 可选: %s" % (s, ", ".join(SOURCES)))
            src_keys.append(s)
    else:
        src_keys = list(DEFAULT_SOURCES)
        if args.with_asn:
            src_keys.append("meta-asn")
    catalog = load_json(P["catalog"], {})
    total_new, total_skip, total_fail = 0, 0, 0
    for sk in src_keys:
        src = SOURCES[sk]
        print("[%s] 枚举文件列表 ..." % sk)
        files = enum_source(sk, args.mirror)
        todo = []
        for repo_path, size, sha in files:
            tag = src["tagfn"](repo_path)
            local_rel = os.path.join("rulesets", sk, repo_path)
            local_abs = os.path.join(base, local_rel)
            url = "%s/%s/%s/%s" % (GH_RAW, src["repo"], src["branch"], repo_path)
            ent = {"source": sk, "file": local_rel, "url": url, "size": size, "sha": sha}
            old = catalog.get(tag)
            if (not args.force and old and old.get("sha") == sha
                    and os.path.exists(local_abs)
                    and (size == 0 or os.path.getsize(local_abs) == size)):
                catalog[tag] = ent
                total_skip += 1
                continue
            todo.append((tag, repo_path, url, local_abs, ent))
        print("[%s] 共 %d 个规则集, 需下载 %d 个" % (sk, len(files), len(todo)))
        fails = []

        def dl(item):
            tag, repo_path, url, local_abs, ent = item
            os.makedirs(os.path.dirname(local_abs), exist_ok=True)
            blob = http_get(url, args.mirror, timeout=60)
            if ent["size"] and len(blob) != ent["size"]:
                raise RuntimeError("大小不符 %s: %d != %d" % (tag, len(blob), ent["size"]))
            with open(local_abs, "wb") as f:
                f.write(blob)
            return tag, ent

        done = 0
        with cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
            futs = {ex.submit(dl, it): it for it in todo}
            for fut in cf.as_completed(futs):
                it = futs[fut]
                try:
                    tag, ent = fut.result()
                    catalog[tag] = ent
                    total_new += 1
                except Exception as e:  # noqa: BLE001
                    fails.append((it[0], str(e)))
                    total_fail += 1
                done += 1
                if done % 200 == 0:
                    print("[%s] 进度 %d/%d" % (sk, done, len(todo)))
        for t, e in fails[:10]:
            print("  失败: %s -> %s" % (t, e), file=sys.stderr)
        if len(fails) > 10:
            print("  ... 共 %d 个失败" % len(fails), file=sys.stderr)
        save_json(P["catalog"], catalog)
        print("[%s] 完成" % sk)
    print("结束: 新增/更新 %d, 跳过 %d, 失败 %d; 目录共 %d 个规则集"
          % (total_new, total_skip, total_fail, len(catalog)))
    if total_fail:
        sys.exit(2)

# ---------------------------------------------------------------- search / path / url

def iter_catalog(base, source=None):
    cat = load_json(paths(base)["catalog"], {})
    if not cat:
        die("目录为空, 请先运行: sbtool.py update")
    for tag in sorted(cat):
        ent = cat[tag]
        if source and ent["source"] != source:
            continue
        yield tag, ent

def cmd_search(args):
    base = data_dir(args)
    kws = [k.lower() for k in args.keywords]
    rows = []
    for tag, ent in iter_catalog(base, args.source):
        if kws and not all(k in tag.lower() for k in kws):
            continue
        rows.append((tag, ent["source"], os.path.join(base, ent["file"]), ent["url"]))
    if not rows:
        print("无匹配结果")
        return
    w1 = max(len(r[0]) for r in rows)
    w2 = max(len(r[1]) for r in rows)
    print("%-*s  %-*s  %d 条" % (w1, "TAG", w2, "SOURCE", len(rows)))
    for tag, src, f, u in rows:
        print("%-*s  %-*s" % (w1, tag, w2, src))
        print("  path: %s" % f)
        print("  url : %s" % u)

def cmd_path(args):
    base = data_dir(args)
    cat = load_json(paths(base)["catalog"], {})
    ent = cat.get(args.tag)
    if not ent:
        die("未知 tag %s (用 search 查询)" % args.tag)
    print(os.path.join(base, ent["file"]))

def cmd_url(args):
    base = data_dir(args)
    cat = load_json(paths(base)["catalog"], {})
    ent = cat.get(args.tag)
    if not ent:
        die("未知 tag %s (用 search 查询)" % args.tag)
    print(ent["url"])

def cmd_sources(args):
    for k, v in SOURCES.items():
        mark = " (可选, update --with-asn 或 --source 指定)" if v.get("optional") else ""
        print("%-15s %s%s" % (k, v["desc"], mark))

# ---------------------------------------------------------------- node

SS_PLUGINS = ("obfs-local", "v2ray-plugin")

def _b64_maybe(text):
    """尝试 base64/base64url 解码 (自动补填充); 解码结果含 ':' 且可打印才返回 str, 否则 None"""
    if not text or not re.fullmatch(r"[A-Za-z0-9_\-+/=]+", text):
        return None
    padded = text + "=" * (-len(text) % 4)
    for fn in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            out = fn(padded.encode("ascii")).decode("utf-8")
        except Exception:
            continue
        if ":" in out and all(c.isprintable() for c in out):
            return out
    return None

def parse_ss_link(link):
    """解析 ss:// 链接, 支持:
      ss://base64url(method:password)@host:port?plugin=...#name   (SIP002)
      ss://method:password@host:port#name                         (明文 userinfo)
      ss://base64(method:password@host:port)#name                 (旧版整体编码)
    """
    raw = link.strip()
    if not raw.lower().startswith("ss://"):
        die("不是 ss:// 链接: %s" % raw[:50])
    body = raw[5:]
    tag = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        tag = urllib.parse.unquote(frag).strip()
    plugin = plugin_opts = ""
    if "?" in body:
        body, query = body.split("?", 1)
        qs = urllib.parse.parse_qs(query)
        if qs.get("plugin"):
            parts = qs["plugin"][0].split(";")
            plugin, plugin_opts = parts[0], ";".join(parts[1:])
    if "@" in body:
        # SIP002: '@' 前是 base64url(method:password) 或明文 method:password
        userinfo, hostport = body.rstrip("/").rsplit("@", 1)
        decoded = _b64_maybe(userinfo)
        if decoded is not None:
            method, password = decoded.split(":", 1)
        elif ":" in userinfo:
            method, password = userinfo.split(":", 1)
            method = urllib.parse.unquote(method)
            password = urllib.parse.unquote(password)
        else:
            die("无法解析链接 userinfo 部分: %s" % raw[:50])
    else:
        # 旧版: 整段 base64(method:password@host:port)
        decoded = _b64_maybe(body) or _b64_maybe(body.rstrip("/"))
        if not decoded or "@" not in decoded:
            die("无法解析 ss 链接 (无 @ 且整体 base64 解码失败): %s" % raw[:50])
        userinfo, hostport = decoded.rsplit("@", 1)
        method, password = userinfo.split(":", 1)
    hostport = hostport.strip().rstrip("/")
    if hostport.startswith("["):
        m = re.match(r"^\[([^\]]+)\]:(\d+)$", hostport)
        if not m:
            die("无法解析地址: %s" % hostport)
        server, port = m.group(1), int(m.group(2))
    else:
        server, sep, ps = hostport.rpartition(":")
        if not sep or not server or not ps.isdigit():
            die("无法解析地址: %s" % hostport)
        port = int(ps)
    method = method.strip()
    if method not in SS_METHODS:
        die("不支持的加密方式 %s\n可选: %s" % (method, ", ".join(SS_METHODS)))
    if plugin and plugin not in SS_PLUGINS:
        die("sing-box 仅支持插件 %s, 该链接为 %s" % ("/".join(SS_PLUGINS), plugin))
    return {"tag": tag, "server": server, "port": port, "method": method,
            "password": password, "plugin": plugin, "plugin_opts": plugin_opts}

def validate_node(method, password, port):
    if method not in SS_METHODS:
        die("不支持的 method %s\n可选: %s" % (method, ", ".join(SS_METHODS)))
    if method.startswith("2022-blake3-"):
        need = 16 if "aes-128" in method else 32
        try:
            rawkey = base64.b64decode(password, validate=True)
        except Exception:
            die("%s 需要 base64 编码的 %d 字节密钥" % (method, need))
        if len(rawkey) != need:
            die("%s 需要 base64 编码的 %d 字节密钥 (当前解码后 %d 字节)"
                % (method, need, len(rawkey)))
    if not (1 <= port <= 65535):
        die("端口非法: %d" % port)

def add_node(nodes, tag, node, force=False):
    if tag in ("direct", "block", "dns-out"):
        die("tag %s 为内置保留名" % tag)
    if tag in nodes and not force:
        die("节点 %s 已存在 (用 --force 覆盖)" % tag)
    validate_node(node["method"], node["password"], node["server_port"])
    nodes[tag] = node

def cmd_node(args):
    base = data_dir(args)
    P = paths(base)
    nodes = load_json(P["nodes"], {})
    if args.node_cmd == "add":
        node = {
            "server": args.server, "server_port": args.port,
            "method": args.method, "password": args.password,
        }
        if args.uot:
            node["udp_over_tcp"] = True
        add_node(nodes, args.tag, node, args.force)
        save_json(P["nodes"], nodes)
        print("已添加节点 %s -> %s:%d (%s)" % (args.tag, args.server, args.port, args.method))
    elif args.node_cmd == "import":
        if args.tag and len(args.links) > 1:
            die("--tag 只能用于单个链接")
        for link in args.links:
            info = parse_ss_link(link)
            tag = args.tag or info["tag"]
            if not tag:
                i = 1
                while "ss%d" % i in nodes:
                    i += 1
                tag = "ss%d" % i
                print("链接无 #name, 自动分配 tag: %s" % tag)
            node = {
                "server": info["server"], "server_port": info["port"],
                "method": info["method"], "password": info["password"],
            }
            if args.uot:
                node["udp_over_tcp"] = True
            if info["plugin"]:
                node["plugin"] = info["plugin"]
                node["plugin_opts"] = info["plugin_opts"]
            add_node(nodes, tag, node, args.force)
            print("已导入 %s -> %s:%d (%s%s)" % (
                tag, node["server"], node["server_port"], node["method"],
                " plugin=%s" % info["plugin"] if info["plugin"] else ""))
        save_json(P["nodes"], nodes)
    elif args.node_cmd == "del":
        if args.tag not in nodes:
            die("节点 %s 不存在" % args.tag)
        del nodes[args.tag]
        save_json(P["nodes"], nodes)
        print("已删除节点 %s" % args.tag)
    elif args.node_cmd == "list":
        if not nodes:
            print("(无节点, 用 node add / node import 添加)")
            return
        for tag, n in nodes.items():
            extra = ""
            if n.get("udp_over_tcp"):
                extra += " uot"
            if n.get("plugin"):
                extra += " plugin=%s(%s)" % (n["plugin"], n.get("plugin_opts", ""))
            print("%-20s %s:%s %s%s" % (tag, n["server"], n["server_port"], n["method"], extra))

# ---------------------------------------------------------------- user

def gen_password():
    return base64.b64encode(secrets.token_bytes(16)).decode("ascii")

def gen_token():
    return secrets.token_urlsafe(12)

def hash_password(pw):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 100000)
    return "pbkdf2$%d$%s$%s" % (100000, base64.b64encode(salt).decode(),
                                base64.b64encode(dk).decode())

def verify_password(pw, stored):
    try:
        _, iters, salt_b64, dk_b64 = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"),
                                 base64.b64decode(salt_b64), int(iters))
        return hmac.compare_digest(dk, base64.b64decode(dk_b64))
    except Exception:
        return False

def load_users(base):
    """读取 users.json 并归一化为 {name: {password, enable, token, panel_password_hash, note, created_at}};
    兼容旧格式 {name: "密码字符串"}"""
    raw = load_json(paths(base)["users"], {})
    out = {}
    for name, v in raw.items():
        if isinstance(v, str):
            out[name] = {"password": v}
        else:
            out[name] = dict(v)
        u = out[name]
        u.setdefault("password", gen_password())
        u.setdefault("enable", True)
        u.setdefault("token", gen_token())
        u.setdefault("panel_password_hash", "")
        u.setdefault("note", "")
        u.setdefault("created_at", 0)
        u.setdefault("sv", 0)  # 会话版本: 密码变更/禁用后递增使旧令牌失效
    return out

def save_users(base, users):
    save_json(paths(base)["users"], users)

def cmd_user(args):
    base = data_dir(args)
    users = load_users(base)
    if args.user_cmd == "add":
        if not re.fullmatch(r"[A-Za-z0-9_\-]{1,32}", args.name):
            die("用户名仅限字母/数字/_/-, 1-32 位")
        if args.name in users:
            die("用户 %s 已存在" % args.name)
        pw = args.password or gen_password()
        users[args.name] = {
            "password": pw, "enable": True, "token": gen_token(),
            "panel_password_hash": hash_password(args.panel_password) if args.panel_password else "",
            "note": args.note or "", "created_at": int(time.time()),
        }
        save_users(base, users)
        print("已添加用户 %s, 密码: %s, 订阅 token: %s" % (args.name, pw, users[args.name]["token"]))
    elif args.user_cmd == "del":
        if args.name not in users:
            die("用户 %s 不存在" % args.name)
        del users[args.name]
        save_users(base, users)
        print("已删除用户 %s" % args.name)
    elif args.user_cmd == "set":
        if args.name not in users:
            die("用户 %s 不存在" % args.name)
        u = users[args.name]
        if args.password:
            u["password"] = args.password
            print("已重置 %s 的 AnyTLS 密码" % args.name)
        if args.panel_password:
            u["panel_password_hash"] = hash_password(args.panel_password)
            print("已设置 %s 的面板登录密码" % args.name)
        if args.refresh_token:
            u["token"] = gen_token()
            print("已刷新 %s 的订阅 token: %s" % (args.name, u["token"]))
        if args.enable is not None:
            u["enable"] = args.enable == "on"
            print("%s 已%s" % (args.name, "启用" if u["enable"] else "禁用"))
        if args.note is not None:
            u["note"] = args.note
        save_users(base, users)
    elif args.user_cmd == "list":
        if not users:
            print("(无用户, 用 user add 添加)")
            return
        for name, u in users.items():
            flags = "" if u["enable"] else " [禁用]"
            panel = " 面板密码:已设" if u.get("panel_password_hash") else " 面板密码:未设"
            print("%-20s %-26s token:%s%s%s" % (name, u["password"], u["token"], flags, panel))

# ---------------------------------------------------------------- route

def is_geoip_tag(tag):
    return bool(re.match(r"^(geoip-|meta-geoip-|meta-lite-geoip-|asn-)", tag))

def cmd_route(args):
    base = data_dir(args)
    P = paths(base)
    rc = load_json(P["routes"], {"rules": [], "final": None, "user_final": {}})
    rc.setdefault("user_final", {})
    if args.route_cmd == "add":
        entry = {}
        if args.set:
            sets = [s.strip() for s in ",".join(args.set).split(",") if s.strip()]
            cat = load_json(paths(base)["catalog"], {})
            missing = [s for s in sets if s not in cat]
            if missing:
                die("规则集不存在: %s (先 update, 用 search 查询正确 tag)" % ", ".join(missing))
            entry["rule_set"] = sets
        mf = {}
        for key, vals in (("domain", args.domain), ("domain_suffix", args.suffix),
                          ("domain_keyword", args.keyword), ("domain_regex", args.regex),
                          ("ip_cidr", args.ipcidr)):
            if vals:
                mf[key] = vals
        if args.port:
            mf["port"] = args.port
        if mf:
            entry.update(mf)
        if not entry.get("rule_set") and not mf:
            die("需要至少一个匹配条件: --set 或 --domain/--suffix/--keyword/--regex/--ipcidr/--port")
        if args.user:
            ul = parse_users_arg(base, args.user)
            entry["users"] = ul
        if getattr(args, "nodes", None):
            nl = [n.strip() for n in ",".join(args.nodes).split(",") if n.strip()]
            servers = load_servers(base)
            unknown = [n for n in nl if n not in servers]
            if unknown:
                die("节点不存在: %s (srv list 查看)" % ", ".join(unknown))
            entry["nodes"] = nl
        if args.reject:
            entry["action"] = "reject"
        else:
            if not args.to:
                die("需要 --to 指定出站 tag (或加 --reject)")
            entry["action"] = "route"
            entry["outbound"] = args.to
        if args.dns:
            entry["dns"] = args.dns
        rc["rules"].append(entry)
        save_json(P["routes"], rc)
        print("已添加规则 #%d" % (len(rc["rules"]) - 1))
    elif args.route_cmd == "rm":
        if not (0 <= args.index < len(rc["rules"])):
            die("序号越界: %d" % args.index)
        del rc["rules"][args.index]
        save_json(P["routes"], rc)
        print("已删除规则 #%d" % args.index)
    elif args.route_cmd == "clear":
        rc["rules"] = []
        rc["user_final"] = {}
        save_json(P["routes"], rc)
        print("已清空全部规则(含按用户默认出口)")
    elif args.route_cmd == "final":
        if args.user:
            ul = parse_users_arg(base, args.user)
            if args.delete:
                for u in ul:
                    rc["user_final"].pop(u, None)
                print("已删除用户 %s 的专属默认出口" % ", ".join(ul))
            else:
                if not args.outbound:
                    die("需要指定出站 tag (或加 --del 删除)")
                for u in ul:
                    rc["user_final"][u] = args.outbound
                print("用户 %s 的默认出口 = %s" % (", ".join(ul), args.outbound))
        else:
            if not args.outbound:
                die("需要指定出站 tag")
            rc["final"] = args.outbound
            print("默认出站(final) = %s" % args.outbound)
        save_json(P["routes"], rc)
    elif args.route_cmd == "list":
        print("final: %s" % (rc.get("final") or "(跟随 set final / 默认 direct)"))
        for u, t in sorted(rc["user_final"].items()):
            print("final(user=%s): %s" % (u, t))
        if not rc["rules"]:
            print("(无规则)")
        for i, r in enumerate(rc["rules"]):
            target = "reject" if r.get("action") == "reject" else "-> %s" % r.get("outbound")
            dns = " dns:%s" % r["dns"] if r.get("dns") else ""
            cond = []
            if r.get("rule_set"):
                cond.append("set=%s" % ",".join(r["rule_set"]))
            for k in ("domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr", "port"):
                if r.get(k):
                    cond.append("%s=%s" % (k, ",".join(str(x) for x in r[k])))
            if r.get("users"):
                cond.append("user=%s" % ",".join(r["users"]))
            if r.get("nodes"):
                cond.append("nodes=%s" % ",".join(r["nodes"]))
            print("#%-3d %-30s %s%s" % (i, target, "; ".join(cond), dns))

def parse_users_arg(base, user_args):
    users_file = load_users(base)
    ul = [u.strip() for u in ",".join(user_args).split(",") if u.strip()]
    unknown = [u for u in ul if u not in users_file]
    if unknown:
        die("用户不存在: %s (先用 user add 添加)" % ", ".join(unknown))
    return ul

# ---------------------------------------------------------------- 服务器节点 (配置下发)

SERVER_DIR = os.environ.get("KSING_SERVER_DIR", "/etc/ksing")  # 节点上的安装目录 (install.sh 约定)
STATS_LISTEN = "127.0.0.1:18899"     # 节点上 v2ray api gRPC 监听 (仅回环, agent 本地查询)


def gen_server_token():
    return secrets.token_hex(32)


def hash_server_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def load_servers(base):
    raw = load_json(paths(base)["servers"], {})
    out = {}
    for sid, v in raw.items():
        if not isinstance(v, dict):
            continue
        srv = dict(v)
        srv.setdefault("name", sid)
        srv.setdefault("token_hash", "")
        srv.setdefault("port", 443)
        srv.setdefault("sni", "")
        srv.setdefault("domain", "")           # 节点域名 (acme 模式必填, 用户已自行解析到节点 IP)
        srv.setdefault("cert_mode", "")        # acme / selfip / unsafe
        srv.setdefault("acme_email", "")
        srv.pop("sni", None)                   # 伪装 SNI 已废弃: acme 用域名, 自签用全局设置
        srv.pop("address", None)               # 订阅地址不再手填: 域名或上报 IP
        srv.setdefault("reported_ip", "")
        srv.setdefault("users", [])         # 空 = 全部启用用户
        srv.setdefault("note", "")
        srv.setdefault("enabled", True)
        srv.setdefault("created_at", 0)
        srv.setdefault("last_seen", 0)
        srv.setdefault("applied_hash", "")
        srv.setdefault("agent_version", "")
        srv.setdefault("cert_not_after", 0)  # agent 上报的证书过期时间 (unix 秒)
        srv.setdefault("cert_issuer", "")
        out[sid] = srv
    return out


def save_servers(base, servers):
    save_json(paths(base)["servers"], servers)


def server_addr(srv):
    """订阅链接中节点的地址: acme 模式用域名, 否则用 agent 上报的 IP (中控统一生成, 无每节点手填)"""
    if srv.get("cert_mode") == "acme" and srv.get("domain"):
        return srv["domain"]
    return srv.get("reported_ip") or ""


def server_sni(s, srv):
    """节点 SNI: acme 即域名本身; 自签模式用全局伪装 SNI (可为空)"""
    if srv.get("cert_mode") == "acme" and srv.get("domain"):
        return srv["domain"]
    return s.get("sni") or ""


def server_insecure(srv):
    """客户端是否需要跳过证书校验 (非 ACME 正式证书都要)"""
    return srv.get("cert_mode") != "acme"


def server_users(base, srv):
    """该节点实际下发的用户 {name: user} (交集: 启用用户 ∩ 节点分配用户; 空列表=全部)"""
    users = {k: u for k, u in load_users(base).items() if u.get("enable", True)}
    want = [u for u in srv.get("users", []) if u]
    if not want:
        return users
    return {k: users[k] for k in want if k in users}


_SRS_SHA_CACHE = {}  # path -> (mtime, size, sha256)


def file_sha256(fp):
    st = os.stat(fp)
    hit = _SRS_SHA_CACHE.get(fp)
    if hit and hit[0] == st.st_mtime and hit[1] == st.st_size:
        return hit[2]
    with open(fp, "rb") as f:
        h = hashlib.sha256(f.read()).hexdigest()
    _SRS_SHA_CACHE[fp] = (st.st_mtime, st.st_size, h)
    return h


def build_server_config(base, sid):
    """生成下发给某节点的完整 sing-box 配置 (裸核, 仅 anytls 入站 + ss 分流出站)。
    返回 (cfg, meta), meta 含 rulesets 同步清单 [{tag,file,sha256,size}]"""
    P = paths(base)
    s = get_settings(base)
    servers = load_servers(base)
    if sid not in servers:
        die("节点不存在: %s" % sid)
    srv = servers[sid]
    users = server_users(base, srv)
    nodes = load_json(P["nodes"], {})  # ss 出站池 (全节点共享)
    rc = load_json(P["routes"], {"rules": [], "final": None, "user_final": {}})
    rc.setdefault("user_final", {})
    cat = load_json(P["catalog"], {})

    final = rc.get("final") or s["final"]
    valid_outs = set(nodes) | {"direct"}
    if final != "reject" and final not in valid_outs:
        die("final 出站 %s 不存在" % final)

    unames = set(users)
    # 过滤规则: 按节点 (nodes 为空=所有节点) 与按用户 (取交集, 交集空则规则不生效)
    rules_in = []
    for r in rc.get("rules", []):
        nscope = [x for x in (r.get("nodes") or []) if x]
        if nscope and sid not in nscope:
            continue
        r = dict(r)
        if r.get("users"):
            uscope = [u for u in r["users"] if u in unames]
            if not uscope:
                continue
            r["users"] = uscope
        if r.get("action") != "reject" and r.get("outbound") not in valid_outs:
            die("规则的出站 %s 不存在" % r.get("outbound"))
        rules_in.append(r)

    used_sets = []
    for r in rules_in:
        for t in r.get("rule_set", []):
            if t not in used_sets:
                used_sets.append(t)
    missing = [t for t in used_sets if t not in cat]
    if missing:
        die("规则集未下载: %s (先运行 update)" % ", ".join(missing))
    rulesets_meta = []
    for t in used_sets:
        fp = os.path.join(base, cat[t]["file"])
        if not os.path.exists(fp):
            die("规则集文件缺失: %s (重新运行 update)" % t)
        rulesets_meta.append({"tag": t, "file": os.path.basename(cat[t]["file"]),
                              "sha256": file_sha256(fp), "size": os.path.getsize(fp)})

    outbounds = []
    for tag, n in nodes.items():
        ob = {"type": "shadowsocks", "tag": tag,
              "server": n["server"], "server_port": n["server_port"],
              "method": n["method"], "password": n["password"]}
        if n.get("udp_over_tcp"):
            ob["udp_over_tcp"] = True
        if n.get("plugin"):
            ob["plugin"] = n["plugin"]
            ob["plugin_opts"] = n.get("plugin_opts", "")
        outbounds.append(ob)
    outbounds.append({"type": "direct", "tag": "direct"})

    rules = [{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"}]
    if s["private_action"] == "reject":
        rules.append({"ip_is_private": True, "action": "reject"})
    elif s["private_action"] == "direct":
        rules.append({"ip_is_private": True, "action": "route", "outbound": "direct"})

    resolved_inserted = False
    for r in rules_in:
        rule = {}
        if r.get("rule_set"):
            if not resolved_inserted and any(is_geoip_tag(t) for t in r["rule_set"]):
                rules.append({"action": "resolve", "strategy": "prefer_ipv4"})
                resolved_inserted = True
            rule["rule_set"] = r["rule_set"] if len(r["rule_set"]) > 1 else r["rule_set"][0]
        for k in ("domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr", "port"):
            if r.get(k):
                rule[k] = r[k] if len(r[k]) > 1 else r[k][0]
        if r.get("users"):
            rule["auth_user"] = r["users"] if len(r["users"]) > 1 else r["users"][0]
        if r.get("action") == "reject":
            rule["action"] = "reject"
        else:
            rule["action"] = "route"
            rule["outbound"] = r["outbound"]
        rules.append(rule)

    for uname, uout in sorted(rc.get("user_final", {}).items()):
        if uname not in unames:
            continue
        if uout == "reject":
            rules.append({"auth_user": uname, "action": "reject"})
        elif uout in valid_outs:
            rules.append({"auth_user": uname, "action": "route", "outbound": uout})

    rule_sets = [{"type": "local", "format": "binary", "tag": m["tag"],
                  "path": os.path.join(SERVER_DIR, "rulesets", m["file"])}
                 for m in rulesets_meta]

    dns_rules = []
    for r in rules_in:
        if not r.get("dns"):
            continue
        dr = {}
        if r.get("rule_set"):
            sets = [t for t in r["rule_set"] if not is_geoip_tag(t)]
            if sets:
                dr["rule_set"] = sets if len(sets) > 1 else sets[0]
        for k in ("domain", "domain_suffix", "domain_keyword", "domain_regex"):
            if r.get(k):
                dr[k] = r[k] if len(r[k]) > 1 else r[k][0]
        if not dr:
            continue
        if r.get("users"):
            dr["auth_user"] = r["users"] if len(r["users"]) > 1 else r["users"][0]
        dr["action"] = "route"
        dr["server"] = r["dns"]
        dns_rules.append(dr)

    # TLS: acme (证书自动申请续签) 或本地证书文件 (selfip/unsafe 由 install.sh 生成)
    cert_mode = srv.get("cert_mode") or "unsafe"
    if cert_mode == "acme":
        domain = srv.get("domain", "")
        if not domain:
            die("节点 %s 使用 acme 证书但未配置域名" % sid)
        tls = {"enabled": True, "certificate_provider": "acme"}
        cert_providers = [{
            "type": "acme", "tag": "acme",
            "domain": [domain],
            "data_directory": os.path.join(SERVER_DIR, "acme"),
            "email": srv.get("acme_email") or "",
            "provider": "letsencrypt",
        }]
    else:
        tls = {"enabled": True,
               "certificate_path": os.path.join(SERVER_DIR, "cert.pem"),
               "key_path": os.path.join(SERVER_DIR, "key.pem")}
        cert_providers = []

    cfg = {
        "log": {"level": s["log_level"], "timestamp": True},
        "experimental": {
            "cache_file": {"enabled": True, "path": os.path.join(SERVER_DIR, "cache.db")},
            "v2ray_api": {
                "listen": STATS_LISTEN,
                "stats": {
                    "enabled": True,
                    "inbounds": ["anytls-in"],
                    "outbounds": sorted(valid_outs),
                    "users": sorted(unames),
                },
            },
        },
        "dns": {
            "servers": [
                {"type": "https", "tag": "remote", "server": "1.1.1.1",
                 "path": "/dns-query", "tls": {"enabled": True, "server_name": "cloudflare-dns.com"}},
                {"type": "https", "tag": "remote-us", "server": "8.8.8.8",
                 "path": "/dns-query", "tls": {"enabled": True, "server_name": "dns.google"}},
            ],
            "rules": dns_rules,
            "final": "remote",
            "strategy": "prefer_ipv4",
        },
        "certificate_providers": cert_providers,
        "inbounds": [
            {
                "type": "anytls", "tag": "anytls-in",
                "listen": "::", "listen_port": srv["port"],
                "users": [{"name": n, "password": u["password"]} for n, u in sorted(users.items())],
                "padding_scheme": PADDING_SCHEME,
                "tls": tls,
            }
        ],
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": s["auto_detect_interface"],
            "default_domain_resolver": {"server": "remote"},
            "rules": rules,
            "rule_set": rule_sets,
            "final": final,
        },
    }
    if not cert_providers:
        cfg.pop("certificate_providers")
    meta = {"rulesets": rulesets_meta, "users": sorted(unames), "sni": server_sni(s, srv),
            "domain": srv.get("domain", ""), "cert_mode": cert_mode}
    return cfg, meta


def server_bundle(base, sid):
    """agent 拉取的完整包: {hash, config, rulesets}; hash 变化即需重新应用"""
    cfg, meta = build_server_config(base, sid)
    rs = {m["tag"]: m["sha256"] for m in meta["rulesets"]}
    h = hashlib.sha256(json.dumps({"config": cfg, "rulesets": rs},
                                  sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"hash": h, "config": cfg, "rulesets": meta["rulesets"]}

# ---------------------------------------------------------------- 流量记账

def add_traffic(base, sid, stats):
    """累加一次节点上报的流量增量 stats={user: [up, down]}; 带文件锁保证并发安全"""
    import fcntl
    P = paths(base)
    os.makedirs(base, exist_ok=True)
    with open(P["traffic"] + ".lock", "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            t = load_json(P["traffic"], {})
            t.setdefault("users", {})
            t.setdefault("servers", {})
            sv = t["servers"].setdefault(sid, {"up": 0, "down": 0, "users": {}})
            for name, pair in stats.items():
                try:
                    up, down = int(pair[0]), int(pair[1])
                except (TypeError, ValueError, IndexError):
                    continue
                if up < 0 or down < 0 or up > (1 << 60) or down > (1 << 60):
                    continue
                u = t["users"].setdefault(name, {"up": 0, "down": 0})
                u["up"] += up
                u["down"] += down
                sv["up"] += up
                sv["down"] += down
                su = sv["users"].setdefault(name, {"up": 0, "down": 0})
                su["up"] += up
                su["down"] += down
            save_json(P["traffic"], t)
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def load_traffic(base):
    t = load_json(paths(base)["traffic"], {})
    t.setdefault("users", {})
    t.setdefault("servers", {})
    return t

# ---------------------------------------------------------------- set

def cmd_set(args):
    base = data_dir(args)
    P = paths(base)
    s = get_settings(base)
    changed = False
    for k, v in (("listen", args.listen), ("port", args.port), ("cert", args.cert),
                 ("key", args.key), ("final", args.final), ("host", args.host),
                 ("sni", args.sni), ("panel_listen", args.panel_listen),
                 ("panel_port", args.panel_port), ("admin_user", args.admin_user),
                 ("agent_listen", args.agent_listen), ("agent_port", args.agent_port),
                 ("private_action", args.private_action), ("log_level", args.log_level)):
        if v is not None:
            s[k] = v
            changed = True
    if args.admin_pass:
        s["admin_pass_hash"] = hash_password(args.admin_pass)
        changed = True
    if args.auto_detect_interface is not None:
        s["auto_detect_interface"] = args.auto_detect_interface == "on"
        changed = True
    if changed:
        # 只落盘非默认项, 但管理员相关字段除外(便于检查)
        out = {k: v for k, v in s.items() if k in (
            "admin_user", "admin_pass_hash", "panel_secret") or v != DEFAULT_SETTINGS.get(k)}
        save_json(P["settings"], out)
        print("设置已更新")
    for k in DEFAULT_SETTINGS:
        if k == "admin_pass_hash":
            print("%-15s = %s" % (k, "(已设置)" if s[k] else "(未设置)"))
            continue
        if k == "panel_secret":
            print("%-15s = %s" % (k, "(已设置)" if s[k] else "(自动生成)"))
            continue
        print("%-15s = %s" % (k, s[k]))

# ---------------------------------------------------------------- export

def anytls_link(name, pw, s, host=None, sni=None):
    host = host or s.get("host") or "<服务器IP>"
    sni = sni or s.get("sni") or "<证书域名>"
    q = "security=tls"
    if sni:
        q += "&sni=" + urllib.parse.quote(sni, safe="")
    q += "&type=tcp&headerType=none"
    return "anytls://%s@%s:%d?%s#%s" % (
        urllib.parse.quote(pw, safe=""), host, s["port"], q,
        urllib.parse.quote(name, safe=""))

def cmd_export(args):
    base = data_dir(args)
    s = get_settings(base)
    users = {k: u for k, u in load_users(base).items() if u.get("enable", True)}
    if not users:
        die("没有 AnyTLS 用户, 先用 user add 添加")
    if args.user:
        wanted = [u.strip() for a in args.user for u in a.split(",") if u.strip()]
        unknown = [u for u in wanted if u not in users]
        if unknown:
            die("用户不存在(或已禁用): %s" % ", ".join(unknown))
        users = {k: users[k] for k in wanted}
    if not (args.host or s.get("host")) or not (args.sni or s.get("sni")):
        print("提示: 可用 set --host <服务器地址> --sni <证书域名> 保存, 导出时自动带上",
              file=sys.stderr)
    for name, u in users.items():
        print("# %s" % name)
        print(anytls_link(name, u["password"], s, args.host, args.sni))

# ---------------------------------------------------------------- gen

def build_config(base):
    P = paths(base)
    s = get_settings(base)
    all_users = load_users(base)
    users = {k: u for k, u in all_users.items() if u.get("enable", True)}
    nodes = load_json(P["nodes"], {})
    rc = load_json(P["routes"], {"rules": [], "final": None})
    cat = load_json(P["catalog"], {})

    if not users:
        die("没有已启用的 AnyTLS 用户, 先用 user add 添加")
    if not s["cert"] or not s["key"]:
        die("未配置 TLS 证书, 先运行: sbtool.py set --cert /path/fullchain.cer --key /path/cert.key")
    final = rc.get("final") or s["final"]
    valid_outs = set(nodes) | {"direct"}
    if final != "reject" and final not in valid_outs:
        die("final 出站 %s 不存在 (可选: direct 或 node list 中的 tag)" % final)
    for i, r in enumerate(rc["rules"]):
        if r.get("action") != "reject" and r.get("outbound") not in valid_outs:
            die("规则 #%d 的出站 %s 不存在" % (i, r.get("outbound")))

    # 收集引用的规则集
    used_sets = []
    for r in rc["rules"]:
        for t in r.get("rule_set", []):
            if t not in used_sets:
                used_sets.append(t)
    missing = [t for t in used_sets if t not in cat]
    if missing:
        die("规则集未下载: %s (先运行 update, 或 search 确认 tag)" % ", ".join(missing))
    missing_files = [t for t in used_sets if not os.path.exists(os.path.join(base, cat[t]["file"]))]
    if missing_files:
        die("本地文件缺失: %s (重新运行 update)" % ", ".join(missing_files))

    # outbounds
    outbounds = []
    for tag, n in nodes.items():
        ob = {
            "type": "shadowsocks", "tag": tag,
            "server": n["server"], "server_port": n["server_port"],
            "method": n["method"], "password": n["password"],
        }
        if n.get("udp_over_tcp"):
            ob["udp_over_tcp"] = True
        if n.get("plugin"):
            ob["plugin"] = n["plugin"]
            ob["plugin_opts"] = n.get("plugin_opts", "")
        outbounds.append(ob)
    outbounds.append({"type": "direct", "tag": "direct"})

    # route rules
    rules = [{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"}]
    if s["private_action"] == "reject":
        rules.append({"ip_is_private": True, "action": "reject"})
    elif s["private_action"] == "direct":
        rules.append({"ip_is_private": True, "action": "route", "outbound": "direct"})

    resolved_inserted = False
    for r in rc["rules"]:
        rule = {}
        if r.get("rule_set"):
            # geoip/asn 规则需要先把域名解析成 IP
            if not resolved_inserted and any(is_geoip_tag(t) for t in r["rule_set"]):
                rules.append({"action": "resolve", "strategy": "prefer_ipv4"})
                resolved_inserted = True
            rule["rule_set"] = r["rule_set"] if len(r["rule_set"]) > 1 else r["rule_set"][0]
        for k in ("domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr", "port"):
            if r.get(k):
                rule[k] = r[k] if len(r[k]) > 1 else r[k][0]
        if r.get("users"):
            rule["auth_user"] = r["users"] if len(r["users"]) > 1 else r["users"][0]
        if r.get("action") == "reject":
            rule["action"] = "reject"
        else:
            rule["action"] = "route"
            rule["outbound"] = r["outbound"]
        rules.append(rule)

    # 按用户的默认出口: 排在所有具体规则之后、全局 final 之前
    for uname, uout in sorted(rc.get("user_final", {}).items()):
        if uname not in all_users:
            die("按用户默认出口引用了不存在的用户 %s (先用 user add 添加)" % uname)
        if uout == "reject":
            rules.append({"auth_user": uname, "action": "reject"})
        else:
            if uout not in valid_outs:
                die("用户 %s 的默认出口 %s 不存在" % (uname, uout))
            rules.append({"auth_user": uname, "action": "route", "outbound": uout})

    rule_sets = []
    for t in used_sets:
        rule_sets.append({
            "type": "local", "format": "binary", "tag": t,
            "path": os.path.join(base, cat[t]["file"]),
        })

    # DNS
    dns_rules = []
    for r in rc["rules"]:
        if not r.get("dns"):
            continue
        dr = {}
        if r.get("rule_set"):
            sets = [t for t in r["rule_set"] if not is_geoip_tag(t)]
            if sets:
                dr["rule_set"] = sets if len(sets) > 1 else sets[0]
        for k in ("domain", "domain_suffix", "domain_keyword", "domain_regex"):
            if r.get(k):
                dr[k] = r[k] if len(r[k]) > 1 else r[k][0]
        if not dr:
            continue
        if r.get("users"):
            dr["auth_user"] = r["users"] if len(r["users"]) > 1 else r["users"][0]
        dr["action"] = "route"
        dr["server"] = r["dns"]
        dns_rules.append(dr)

    cfg = {
        "log": {"level": s["log_level"], "timestamp": True},
        "experimental": {
            "cache_file": {"enabled": True, "store_dns": True,
                           "path": os.path.join(base, "cache.db")},
        },
        "dns": {
            "servers": [
                {
                    "type": "https", "tag": "remote",
                    "server": "1.1.1.1", "path": "/dns-query",
                    "tls": {"enabled": True, "server_name": "cloudflare-dns.com"},
                },
                {
                    "type": "https", "tag": "remote-us",
                    "server": "8.8.8.8", "path": "/dns-query",
                    "tls": {"enabled": True, "server_name": "dns.google"},
                },
            ],
            "rules": dns_rules,
            "final": "remote",
            "strategy": "prefer_ipv4",
        },
        "inbounds": [
            {
                "type": "anytls", "tag": "anytls-in",
                "listen": s["listen"], "listen_port": s["port"],
                "users": [{"name": n, "password": u["password"]} for n, u in users.items()],
                "padding_scheme": PADDING_SCHEME,
                "tls": {
                    "enabled": True,
                    "certificate_path": s["cert"],
                    "key_path": s["key"],
                },
            }
        ],
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": s["auto_detect_interface"],
            "default_domain_resolver": {"server": "remote"},
            "rules": rules,
            "rule_set": rule_sets,
            "final": final,
        },
    }
    return cfg, s, users

def cmd_gen(args):
    base = data_dir(args)
    cfg, s, users = build_config(base)
    out = args.output or paths(base)["config"]
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.chmod(out, 0o600)  # 配置含全部密码
    print("已生成: %s" % os.path.abspath(out))

    sb = shutil.which("sing-box")
    if sb:
        r = subprocess.run([sb, "check", "-c", out], capture_output=True, text=True)
        if r.returncode == 0:
            print("sing-box check: 通过")
        else:
            print("sing-box check 失败:", file=sys.stderr)
            print((r.stdout + r.stderr).strip(), file=sys.stderr)
            sys.exit(2)
    else:
        print("提示: 未找到 sing-box 命令, 跳过配置校验")

    print("\n== 客户端连接信息 (AnyTLS) ==")
    for name, u in users.items():
        print("用户 %s 密码 %s" % (name, u["password"]))
        print("  " + anytls_link(name, u["password"], s, args.host, args.sni))
    print("端口: %d  证书: %s" % (s["port"], s["cert"]))

# ---------------------------------------------------------------- srv CLI

def cmd_srv(args):
    base = data_dir(args)
    servers = load_servers(base)
    if args.srv_cmd == "add":
        sid = secrets.token_hex(4)
        while sid in servers:
            sid = secrets.token_hex(4)
        token = gen_server_token()
        users = parse_users_arg(base, args.user) if args.user else []
        cert_mode = args.cert_mode or ("acme" if args.domain else "")
        if not cert_mode:
            die("未绑定域名时必须显式选择 --cert-mode selfip 或 unsafe")
        if cert_mode == "acme" and not args.domain:
            die("acme 模式需要 --domain")
        servers[sid] = {
            "name": args.name, "token_hash": hash_server_token(token),
            "port": args.port,
            "domain": args.domain or "", "cert_mode": cert_mode,
            "acme_email": args.acme_email or "",
            "users": users, "note": args.note or "", "enabled": True,
            "created_at": int(time.time()),
        }
        save_servers(base, servers)
        print("已添加节点 %s (%s), 证书模式 %s" % (args.name, sid, cert_mode))
        print("节点 token (仅显示一次): %s" % token)
    elif args.srv_cmd == "del":
        if args.sid not in servers:
            die("节点不存在: %s" % args.sid)
        del servers[args.sid]
        save_servers(base, servers)
        print("已删除节点 %s" % args.sid)
    elif args.srv_cmd == "token":
        if args.sid not in servers:
            die("节点不存在: %s" % args.sid)
        token = gen_server_token()
        servers[args.sid]["token_hash"] = hash_server_token(token)
        save_servers(base, servers)
        print("已重置节点 %s 的 token (仅显示一次): %s" % (args.sid, token))
    elif args.srv_cmd == "config":
        if args.sid not in servers:
            die("节点不存在: %s" % args.sid)
        bundle = server_bundle(base, args.sid)
        print(json.dumps(bundle["config"], ensure_ascii=False, indent=2))
        print("hash: %s" % bundle["hash"], file=sys.stderr)
    elif args.srv_cmd == "list":
        if not servers:
            print("(无节点, 用 srv add 添加)")
            return
        for sid, srv in servers.items():
            st = "在线" if time.time() - srv.get("last_seen", 0) < 120 else "离线"
            flags = "" if srv.get("enabled", True) else " [禁用]"
            print("%s  %-16s port:%-6d users:%-8s %s%s" % (
                sid, srv["name"], srv["port"],
                ",".join(srv.get("users", [])) or "全部", st, flags))

# ---------------------------------------------------------------- argparse

def main():
    ap = argparse.ArgumentParser(prog="sbtool.py",
                                 description="sing-box AnyTLS + Shadowsocks 分流配置工具")
    ap.add_argument("--dir", help="数据目录 (默认 ./sbdata, 或环境变量 SBTOOL_DIR)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("update", help="下载/更新全部规则集")
    p.add_argument("--source", action="append", help="只更新指定来源: %s" % ", ".join(SOURCES))
    p.add_argument("--with-asn", action="store_true", help="同时下载 meta-rules-dat 的 ASN 规则(约4.6万文件)")
    p.add_argument("-j", "--jobs", type=int, default=16, help="并发下载数 (默认16)")
    p.add_argument("--mirror", default=os.environ.get("SBTOOL_MIRROR", ""),
                   help="GitHub 镜像前缀, 如 https://gh-proxy.com (也可用环境变量 SBTOOL_MIRROR)")
    p.add_argument("--force", action="store_true", help="强制重新下载")
    p.set_defaults(fn=cmd_update)

    p = sub.add_parser("search", help="查询规则集, 输出 tag/路径/url")
    p.add_argument("keywords", nargs="*", help="关键字(可多个, 与逻辑), 如: search geoip cn")
    p.add_argument("--source", help="只看某来源")
    p.set_defaults(fn=cmd_search)

    p = sub.add_parser("path", help="输出某规则集的本地路径")
    p.add_argument("tag")
    p.set_defaults(fn=cmd_path)

    p = sub.add_parser("url", help="输出某规则集的远程 URL")
    p.add_argument("tag")
    p.set_defaults(fn=cmd_url)

    p = sub.add_parser("sources", help="列出全部规则集来源")
    p.set_defaults(fn=cmd_sources)

    p = sub.add_parser("node", help="管理 Shadowsocks 出站节点")
    ns = p.add_subparsers(dest="node_cmd", required=True)
    pa = ns.add_parser("add")
    pa.add_argument("tag", help="自定义出站 tag, 如 us1")
    pa.add_argument("--server", required=True)
    pa.add_argument("--port", type=int, required=True)
    pa.add_argument("--method", required=True, help="加密方式, 如 2022-blake3-aes-128-gcm")
    pa.add_argument("--password", required=True)
    pa.add_argument("--uot", action="store_true", help="启用 UDP over TCP")
    pa.add_argument("--force", action="store_true")
    pa = ns.add_parser("import", help="从 ss:// 链接导入节点 (可一次多个)")
    pa.add_argument("links", nargs="+", help="ss:// 链接, 可多个")
    pa.add_argument("--tag", help="自定义 tag (仅单个链接时可用; 默认取链接 #name)")
    pa.add_argument("--uot", action="store_true", help="启用 UDP over TCP")
    pa.add_argument("--force", action="store_true")
    pa = ns.add_parser("del")
    pa.add_argument("tag")
    ns.add_parser("list")
    p.set_defaults(fn=cmd_node)

    p = sub.add_parser("user", help="管理 AnyTLS 用户")
    us = p.add_subparsers(dest="user_cmd", required=True)
    pa = us.add_parser("add")
    pa.add_argument("name")
    pa.add_argument("password", nargs="?", help="省略则自动生成")
    pa.add_argument("--panel-password", help="面板登录密码 (不设则无法登录面板)")
    pa.add_argument("--note", help="备注")
    pa = us.add_parser("del")
    pa.add_argument("name")
    pa = us.add_parser("set", help="修改用户属性")
    pa.add_argument("name")
    pa.add_argument("--password", help="重置 AnyTLS 密码")
    pa.add_argument("--panel-password", help="重置面板登录密码")
    pa.add_argument("--refresh-token", action="store_true", help="刷新订阅 token (旧订阅链接失效)")
    pa.add_argument("--enable", choices=["on", "off"], help="启用/禁用 (禁用后无法连接)")
    pa.add_argument("--note", help="备注")
    us.add_parser("list")
    p.set_defaults(fn=cmd_user)

    p = sub.add_parser("route", help="管理分流规则")
    rs = p.add_subparsers(dest="route_cmd", required=True)
    pa = rs.add_parser("add", help="添加规则: --set 规则集 或 域名条件, 指向 --to 出站")
    pa.add_argument("--set", action="append", help="规则集 tag, 逗号分隔可多个")
    pa.add_argument("--to", help="出站 tag (node 的 tag 或 direct)")
    pa.add_argument("--reject", action="store_true", help="拒绝连接")
    pa.add_argument("--domain", action="append")
    pa.add_argument("--suffix", action="append", help="域名后缀, 如 .cn")
    pa.add_argument("--keyword", action="append")
    pa.add_argument("--regex", action="append")
    pa.add_argument("--ipcidr", action="append")
    pa.add_argument("--port", type=int, action="append")
    pa.add_argument("--dns", choices=["remote", "remote-us"],
                    help="同时生成 DNS 分流规则 (remote=1.1.1.1, remote-us=8.8.8.8)")
    pa.add_argument("--user", action="append",
                    help="只对指定 AnyTLS 用户生效 (可多个或用逗号分隔)")
    pa.add_argument("--nodes", action="append",
                    help="只在指定节点生效 (节点 sid, 可多个/逗号分隔; 默认所有节点)")
    pa = rs.add_parser("rm")
    pa.add_argument("index", type=int)
    rs.add_parser("list")
    rs.add_parser("clear")
    pa = rs.add_parser("final")
    pa.add_argument("outbound", nargs="?", help="默认出站 tag (direct / 节点 tag / reject)")
    pa.add_argument("--user", action="append", help="设置指定用户的专属默认出口 (可多个/逗号分隔)")
    pa.add_argument("--del", dest="delete", action="store_true", help="删除用户的专属默认出口")
    p.set_defaults(fn=cmd_route)

    p = sub.add_parser("srv", help="管理远端服务器节点 (配置下发)")
    ss = p.add_subparsers(dest="srv_cmd", required=True)
    pa = ss.add_parser("add", help="添加节点, 生成一次性 token")
    pa.add_argument("name", help="节点名, 如 香港-01")
    pa.add_argument("--port", type=int, required=True, help="AnyTLS 监听端口")
    pa.add_argument("--domain", help="节点域名 (需已解析到节点 IP, 自动申请/续签证书)")
    pa.add_argument("--cert-mode", choices=["acme", "selfip", "unsafe"],
                    help="证书模式: acme=域名正式证书(默认) selfip=IP自签 unsafe=自签(不安全)")
    pa.add_argument("--acme-email", help="ACME 账号邮箱")
    pa.add_argument("--user", action="append", help="只下放指定用户 (可多个/逗号分隔; 默认全部)")
    pa.add_argument("--note", help="备注")
    pa = ss.add_parser("del")
    pa.add_argument("sid")
    pa = ss.add_parser("token", help="重置节点 token (旧 token 立即失效)")
    pa.add_argument("sid")
    pa = ss.add_parser("config", help="打印下发给节点的配置 (调试)")
    pa.add_argument("sid")
    ss.add_parser("list")
    p.set_defaults(fn=cmd_srv)

    p = sub.add_parser("set", help="查看/修改全局设置")
    p.add_argument("--listen")
    p.add_argument("--port", type=int)
    p.add_argument("--cert", help="TLS 证书 fullchain 路径")
    p.add_argument("--key", help="TLS 私钥路径")
    p.add_argument("--final", help="默认出站 (可被 route final 覆盖)")
    p.add_argument("--host", help="服务器地址(IP/域名), 用于导出客户端链接")
    p.add_argument("--sni", help="SNI/证书域名, 用于导出客户端链接")
    p.add_argument("--private-action", choices=["reject", "direct", "off"],
                   help="目的地为私网 IP 时的处理 (默认 reject)")
    p.add_argument("--auto-detect-interface", choices=["on", "off"],
                   help="绑定默认网卡防回环; 本机 DNS 在虚拟网卡(如 tailscale)后时设为 off")
    p.add_argument("--log-level")
    p.add_argument("--panel-listen", help="面板监听地址")
    p.add_argument("--panel-port", type=int, help="面板端口 (默认 8080)")
    p.add_argument("--agent-listen", help="节点 agent 专用 HTTPS 监听地址")
    p.add_argument("--agent-port", type=int, help="节点 agent 专用 HTTPS 端口 (默认 9443)")
    p.add_argument("--admin-user", help="面板管理员用户名")
    p.add_argument("--admin-pass", help="面板管理员密码 (设置后用于登录面板)")
    p.set_defaults(fn=cmd_set)

    p = sub.add_parser("gen", help="生成 sing-box 配置")
    p.add_argument("-o", "--output", help="输出路径 (默认 <dir>/config.json)")
    p.add_argument("--host", help="服务器地址(仅用于打印客户端链接, 默认取 set --host)")
    p.add_argument("--sni", help="SNI/证书域名(仅用于打印客户端链接, 默认取 set --sni)")
    p.set_defaults(fn=cmd_gen)

    p = sub.add_parser("export", help="按用户导出 anytls:// 客户端链接")
    p.add_argument("--host", help="服务器地址 (默认取 set --host)")
    p.add_argument("--sni", help="SNI/证书域名 (默认取 set --sni)")
    p.add_argument("--user", action="append", help="只导出指定用户 (可多个/逗号分隔, 默认全部)")
    p.set_defaults(fn=cmd_export)

    args = ap.parse_args()
    args.fn(args)

if __name__ == "__main__":
    main()
