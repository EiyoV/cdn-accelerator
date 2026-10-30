# -*- coding: utf-8 -*-
"""
CDN Accelerator - local DNS optimizer
-------------------------------------
A tiny local DNS server that makes every website auto-connect to its fastest
reachable server IP (CDN optimized) without any per-site configuration.

How it works:
  1. It listens on UDP 53 (set your system DNS to 127.0.0.1 to use it).
  2. For a domain it has never seen: it forwards the query to the real DNS
     upstream, takes ALL returned A records, quickly TCP-probes each IP and
     remembers the fastest one. From then on it answers that IP directly.
  3. For Cloudflare domains (pokebonk.com etc.) it answers from a measured
     pool of fast Cloudflare anycast IPs, so the site rides the best edge.
  4. Non-CDN / single-IP domains are simply forwarded unchanged (transparent).
  5. A health worker re-probes the currently-returned best node every 30s;
     when a node goes bad it immediately re-picks or drops the cache entry,
     so a stale slow/dead node never lingers for minutes.

No third-party dependencies. Pure standard library.
Run:  python cdn-accelerator.py [--port 53] [--upstream 1.1.1.1,8.8.8.8]
"""

import os
import re
import sys
import time
import ssl
import json
import socket
import struct
import threading
import logging
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
LISTEN_ADDR = "127.0.0.1"
LISTEN_PORT = 53
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cdn-accelerator.log")
LOG_MAX_BYTES = 1024 * 1024          # 1 MB, then rotate (truncate)
REFRESH_INTERVAL = 300               # seconds between full CF pool re-measure
HEALTH_INTERVAL = 8                   # seconds between health re-probes of live nodes
TCP_TIMEOUT = 4.0                     # seconds per probe (hard total budget; SSL ctx is cached so this is a true budget). 4s: a "slow-but-live" edge (github TTFB ~3s during degraded international windows) must count as live - a 1.5s budget killed the ONLY reachable GitHub edge and fail-open then handed out a truly dead raw IP (the exact "GitHub down = accelerator's fault" case). Fast edges return on first success, so this only delays all-dead/slow rounds - being able to open beats being fast to fail.
TCP_CONNECT_TIMEOUT = 2.0             # separate SHORT budget for the TCP connect phase only. v2.17: when a
                                      # whole segment is dead most candidates fail at connect; failing them in
                                      # 2.0s instead of 4.0s halves worker blocking. A 4s-every-probe flood
                                      # starved the 32-worker pool and took Bilibili/Doubao (passthrough,
                                      # same pool) offline with it - the "suddenly everything is down" bug.
CACHE_TTL = 60                         # answer cache validity (queries hit cache -> instant; liveness is kept fresh by health_worker)
ANSWER_TTL = 15                        # TTL handed to the client (browser re-asks after 15s; health cycle is 8s)
MAX_CACHE = 2000                     # hard cap for domain cache entries
MAX_WORKERS = 64                     # concurrent query handlers per socket (2 sockets -> 128 max).
                                     # v2.17: raised from 32. An all-dead probe round holds a worker
                                     # for ~2s now (TCP fast-fail); with 32 workers a browser burst
                                     # (Bilibili + Doubao + game pages = dozens of names) could still
                                     # exhaust the pool and starve even passthrough queries.
CF_POOL = [
    "104.16.0.1", "104.16.1.1", "104.16.16.1", "104.16.32.1", "104.16.64.1",
    "104.16.96.1", "104.16.128.1", "104.16.132.229", "104.16.160.1", "104.16.192.82",
    "104.16.193.1", "104.18.0.1", "104.18.10.1", "104.19.5.2", "104.19.6.2",
    "104.21.25.26", "104.21.80.103",
    "162.159.128.233", "162.159.135.233", "162.159.152.4", "162.159.192.5",
    "162.159.195.4", "162.159.198.5", "162.159.200.4", "162.159.209.4",
    "162.159.210.4", "162.159.214.4", "162.159.215.4", "162.159.220.4",
    "172.64.0.1", "172.64.32.1", "172.64.48.1", "172.64.96.1", "172.64.128.1",
    "172.64.160.1", "172.64.192.1", "172.64.224.1",
    "172.67.0.1", "172.67.16.1", "172.67.32.1", "172.67.64.1", "172.67.128.1",
    "172.67.192.1", "172.67.222.12", "172.67.223.1",
    "188.114.96.1", "188.114.98.1", "188.114.100.1", "188.114.104.1",
]

# ---------------------------------------------------------------------------
# CDN network detection (by A-record IP). True if ip is inside any listed net.
# ---------------------------------------------------------------------------
CDN_NETS = [
    # Cloudflare
    "104.16.0.0/13", "172.64.0.0/13", "162.159.0.0/16", "188.114.96.0/20",
    "198.41.128.0/17", "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20",
    "197.234.240.0/22",
    # Fastly
    "199.232.0.0/16", "146.75.0.0/17",
    # Microsoft / Azure CDN
    "13.107.0.0/16", "204.79.195.0/24", "23.96.0.0/11",
    # Akamai (partial)
    "23.32.0.0/11", "184.84.0.0/14",
]
_cdn_nets = [ipaddress.ip_network(n) for n in CDN_NETS]


def is_cdn_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version != 4:
            return False
        for net in _cdn_nets:
            if ip in net:
                return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# Preferred IP pools (community/known candidate lists). Used only as an extra
# candidate pool - every candidate is still HTTP-probed live before use, so
# stale IPs are filtered out automatically. Missing file = no preferred pool.
# ---------------------------------------------------------------------------
PREF_IPS = {}
_HERE = os.path.dirname(os.path.abspath(__file__))
_PREF_FILE = os.path.join(_HERE, "preferred_ips.json")
try:
    with open(_PREF_FILE, "r", encoding="utf-8") as _f:
        _raw = json.load(_f)
    for _k, _v in _raw.items():
        if isinstance(_v, list):
            PREF_IPS[_k.lower()] = [str(i).strip() for i in _v if str(i).strip()]
except Exception as _ex:
    PREF_IPS = {}


def fetch_live_pool():
    """On startup, quietly refresh the preferred pool from GitHub520's
    community-maintained hosts list (updated daily, so static IPs go stale
    within hours on jittery routes). Runs in a daemon thread - any failure
    is ignored and the local pool stays in effect; every candidate is still
    HTTP-probed live before use, so stale IPs can never be handed out."""
    try:
        import urllib.request
        url = "https://raw.githubusercontent.com/521xueweihan/GitHub520/master/hosts"
        req = urllib.request.Request(url, headers={"User-Agent": "cdn-accelerator/2.9"})
        with urllib.request.urlopen(req, timeout=6) as r:
            text = r.read().decode("utf-8", "ignore")
        merged = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2 and ":" not in parts[0]:
                merged.setdefault(parts[1].lower(), []).append(parts[0])
        if not merged:
            log.info("LIVE-POOL: GitHub520 returned nothing, keeping local pool")
            return
        updated = 0
        for host, ips in merged.items():
            if host in PREF_IPS or "github" in host or "raw" in host or "objects" in host:
                cur = list(PREF_IPS.get(host) or [])
                for ip in ips:
                    if ip not in cur:
                        cur.append(ip)
                PREF_IPS[host] = cur
                updated += 1
        with open(_PREF_FILE, "w", encoding="utf-8") as f:
            json.dump({k: v for k, v in PREF_IPS.items()}, f, indent=2)
        log.info("LIVE-POOL: refreshed %d GitHub520 hosts, pool now %d domains" % (updated, len(PREF_IPS)))
    except Exception as ex:
        log.info("LIVE-POOL: fetch failed (%s), keeping local pool" % ex)

# Domains warmed up on startup (parse via multi-source DNS + probe, cache the
# best). Includes the preferred-pool domains plus common gaming/social/dev
# platforms whose IPs are gathered automatically at runtime.
WARMUP_DOMAINS = [
    # Steam 家族（含 Akamai CDN 全域）
    "store.steampowered.com", "steamcommunity.com", "www.steamcommunity.com",
    "help.steampowered.com", "api.steampowered.com", "login.steampowered.com",
    "checkout.steampowered.com", "media.steampowered.com",
    "steamcdn-a.akamaihd.net", "steampipe-a.akamaihd.net",
    "steamuserimages-a.akamaihd.net", "origin-a.akamaihd.net",
    "cdn.akamai.steamstatic.com", "community.akamai.steamstatic.com",
    "avatars.akamai.steamstatic.com", "store.akamai.steamstatic.com",
    "community.steamstatic.com", "steamstatic.com", "steamcontent.com",
    "client-update.akamai.steamstatic.com",
    "shared.st.dl.eccdnx.com", "clan.st.dl.eccdnx.com", "store.st.dl.eccdnx.com",
    "avatars.st.dl.eccdnx.com", "media.st.dl.eccdnx.com", "video.st.dl.eccdnx.com",
    # GitHub 家族
    "github.com", "api.github.com", "raw.githubusercontent.com",
    "assets-cdn.github.com", "github.global.ssl.fastly.net",
    "avatars.githubusercontent.com", "avatars0.githubusercontent.com",
    "avatars1.githubusercontent.com", "avatars2.githubusercontent.com",
    "avatars3.githubusercontent.com", "codeload.github.com", "gist.github.com",
    "github.githubassets.com", "support-assets.githubassets.com",
    "education.github.com", "resources.github.com", "uploads.github.com",
    "archiveprogram.github.com", "raw.github.com", "githubusercontent.com",
    "camo.githubusercontent.com", "cloud.githubusercontent.com",
    "user-images.githubusercontent.com", "objects.githubusercontent.com",
    "private-user-images.githubusercontent.com", "pages.github.com",
    "github.dev", "githubapp.com", "github.io", "www.github.io",
    "hub.docker.com", "greasyfork.org", "update.greasyfork.org",
    "huggingface.co",
    # Twitch
    "twitch.tv", "www.twitch.tv", "m.twitch.tv", "app.twitch.tv",
    "api.twitch.tv", "assets.twitch.tv", "passport.twitch.tv",
    "id.twitch.tv", "id-cdn.twitch.tv", "clips.twitch.tv",
    "gql.twitch.tv", "dev.twitch.tv", "blog.twitch.tv", "help.twitch.tv",
    "link.twitch.tv", "player.twitch.tv", "panels.twitch.tv",
    "badges.twitch.tv", "inspector.twitch.tv", "stream.twitch.tv",
    "trowel.twitch.tv", "countess.twitch.tv", "pubster.twitch.tv",
    "extension-files.twitch.tv", "vod-metro.twitch.tv", "vod-secure.twitch.tv",
    "vod-storyboards.twitch.tv", "pubsub-edge.twitch.tv",
    "supervisor.ext-twitch.tv", "client-event-reporter.twitch.tv",
    "gds-vhs-drops-campaign-images.twitch.tv", "cvp.twitch.tv",
    "music.twitch.tv", "dashboard.twitch.tv", "discuss.dev.twitch.tv",
    "irc-ws.chat.twitch.tv", "irc-ws-r.chat.twitch.tv",
    "abs.hls.ttvnw.net", "video-edge-00252e.pdx01.abs.hls.ttvnw.net",
    "us-west-2.uploads-regional.twitch.tv",
    # Discord / 游戏平台
    "discord.com", "discordapp.com", "epicgames.com", "fortnite.com",
    "ea.com", "origin.com", "ubisoft.com", "uplay.com", "store.ubisoft.com",
    "rockstargames.com", "riotgames.com", "leagueoflegends.com",
    "blizzard.com", "battle.net", "xbox.com", "playstation.com",
    "nintendo.com", "minecraft.net", "minecraft.com",
    "hcaptcha.com", "assets.hcaptcha.com", "imgs.hcaptcha.com",
    "www.hcaptcha.com", "docs.hcaptcha.com", "js.hcaptcha.com",
    "newassets.hcaptcha.com", "imgs3.hcaptcha.com",
    "client-api.arkoselabs.com", "epic-games-api.arkoselabs.com",
    "cdn.arkoselabs.com", "prod-ireland.arkoselabs.com",
    # Google 服务 / 通用
    "fonts.googleapis.com", "fonts.gstatic.com", "ajax.googleapis.com",
    "themes.googleusercontent.com", "translate.googleapis.com",
    "translate-pa.googleapis.com", "translate.google.cn",
    "translate.google.com", "google.com", "www.google.com",
    "gravatar.com", "secure.gravatar.com", "www.gravatar.com",
    "maxcdn.bootstrapcdn.com", "img.youtube.com",
    # Spotify / 网盘 / 其他
    "spotify.com", "www.spotify.com", "open.spotify.com",
    "apresolve.spotify.com", "api-partner.spotify.com",
    "storage.live.com", "skyapi.onedrive.live.com", "onedrive.live.com",
    "onedrive.live", "mega.co.nz", "www.mega.co.nz", "mega.io", "mega.nz",
    "www.mega.nz", "g.cdn1.mega.co.nz", "g.api.mega.co.nz",
    "g.static.mega.co.nz", "userstroage.mega.co.nz",
    "dropbox.com", "www.dropbox.com", "aem.dropbox.com",
    "dl.dropboxusercontent.com", "uc07aaf207f16a978a3dbc24a1c9.dl.dropboxusercontent.com",
    "uc87442e427766fe8cf2a7a07827.dl.dropboxusercontent.com",
    "uc957f785cc03b9b273234fd24f9.dl.dropboxusercontent.com",
    "ucc541451e9df780e40777d477eb.dl.dropboxusercontent.com",
    "ucb277f9a438d6b3f4ea2147ac26.dl.dropboxusercontent.com",
    "uc4b4b602d4b01e27782f92ce984.dl.dropboxusercontent.com",
    "uc9c83355d6aa8bc75f7f597c7d6.dl.dropboxusercontent.com",
    "ucaf37cba09486e69c215bdfe2e2.dl.dropboxusercontent.com",
    "uca3a40eb53259715309022eb9fd.dl.dropboxusercontent.com",
    # 图站 / 社区 / Mod
    "imgur.com", "www.imgur.com", "i.imgur.com", "s.imgur.com", "m.imgur.com",
    "api.imgur.com", "p.imgur.com", "t.imgur.com", "blog.imgur.com",
    "fufufu23.imgur.com", "thepoy.imgur.com", "cellcow.imgur.com",
    "i.stack.imgur.com",
    "pinterest.com", "www.pinterest.com", "pinimg.com", "sm.pinimg.com",
    "s.pinimg.com", "i.pinimg.com", "s2.pinimg.com", "de.pinterest.com",
    "pinterest.jp", "pinterest.kr", "pinterest.info",
    "artstation.com", "www.artstation.com", "cdn.artstation.com",
    "cdna.artstation.com", "cdnb.artstation.com", "cdn-learning.artstation.com",
    "aleksi.artstation.com", "aroll.artstation.com", "dya.artstation.com",
    "yourihoek.artstation.com", "rishablue.artstation.com",
    "ww.artstation.com", "magazine.artstation.com",
    "fandom.com", "www.fandom.com",
    "nexusmods.com", "www.nexusmods.com", "staticdelivery.nexusmods.com",
    "cf-files.nexusmods.com", "staticstats.nexusmods.com", "users.nexusmods.com",
    "files.nexus-cdn.com", "premium-files.nexus-cdn.com",
    "supporter-files.nexus-cdn.com", "binary.lge.modcdn.io",
    "mod.io", "static.mod.io", "api.mod.io", "docs.mod.io",
    "beta.mod.io", "blog.mod.io", "auth.mod.io",
    # Roblox
    "roblox.com", "www.roblox.com", "web.roblox.com", "apis.roblox.com",
    "games.roblox.com", "auth.roblox.com", "accountsettings.roblox.com",
    "presence.roblox.com", "friends.roblox.com", "users.roblox.com",
    "gameinternationalization.roblox.com", "gamejoin.roblox.com",
    "locale.roblox.com", "metrics.roblox.com", "economy.roblox.com",
    "groups.roblox.com", "develop.roblox.com",
    "versioncompatibility.api.roblox.com", "clientsettings.api.roblox.com",
    "ephemeralcounters.api.roblox.com", "nl.roblox.com", "badges.roblox.com",
    "chat.roblox.com", "ecsv2.roblox.com", "thumbnails.roblox.com",
    "twostepverification.roblox.com", "trades.roblox.com",
    "notifications.roblox.com", "realtime-signalr.roblox.com",
    "assetgame.roblox.com", "contacts.roblox.com", "t.email.roblox.com",
    # 其他
    "appcenter.ms", "in.appcenter.ms", "vercel.app",
    "pixiv.net", "reddit.com", "gitee.com",
]
for _k in PREF_IPS:
    if _k not in WARMUP_DOMAINS:
        WARMUP_DOMAINS.append(_k)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def setup_logging():
    logger = logging.getLogger("cdnacc")
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fmt = logging.Formatter("%(asctime)s %(message)s")
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger


def rotate_log():
    try:
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > LOG_MAX_BYTES:
            os.remove(LOG_FILE)
    except Exception:
        pass


log = setup_logging()
rotate_log()


# ---------------------------------------------------------------------------
# Minimal DNS packet handling (A / AAAA only; everything else is forwarded)
# ---------------------------------------------------------------------------
def parse_question(data):
    if len(data) < 12:
        return None
    qid = struct.unpack(">H", data[0:2])[0]
    start = 12
    off = 12
    labels = []
    while off < len(data):
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0:                      # compressed pointer in query: bail
            return None
        labels.append(data[off + 1: off + 1 + ln].decode("ascii", "ignore"))
        off += 1 + ln
    if off + 4 > len(data):
        return None
    raw_qname = data[start:off]            # original DNS wire encoding (with length prefixes)
    qtype, qclass = struct.unpack(">HH", data[off: off + 4])
    return {"id": qid, "qname_bytes": raw_qname,
            "qname": ".".join(labels).rstrip("."),
            "qtype": qtype, "qclass": qclass, "end": off + 4}


def build_response(question, rcode, answers):
    """answers: list of (name_bytes, type, class, ttl, rdlen, rdata)"""
    flags = 0x8000 | 0x0100 | 0x0080 | (rcode & 0xF)   # QR + RD + RA + rcode
    header = struct.pack(">HHHHHH", question["id"], flags, 0x0001, len(answers), 0, 0)
    buf = bytearray(header)
    buf += question["qname_bytes"] + struct.pack(">HH", question["qtype"], question["qclass"])
    for (nb, t, c, ttl, rdlen, rdata) in answers:
        buf += nb + struct.pack(">HHIH", t, c, ttl, rdlen) + rdata
    return bytes(buf)


def rewrite_id(data, qid):
    """Patch the ID of an upstream response to match the client's query ID."""
    if len(data) >= 2:
        return struct.pack(">H", qid) + data[2:]
    return data


def make_a_answer(qname_bytes, ip_str, ttl=ANSWER_TTL):
    return (qname_bytes, 1, 1, ttl, 4, socket.inet_aton(ip_str))


def make_aaaa_answer(qname_bytes, ip_str, ttl=ANSWER_TTL):
    return (qname_bytes, 28, 1, ttl, 16, socket.inet_pton(socket.AF_INET6, ip_str))


def empty_response(question):
    """NOERROR with no answers (used for AAAA of CDN domains -> v4 only)."""
    return build_response(question, 0, [])


def servfail_response(question):
    """SERVFAIL - upstream unreachable."""
    return build_response(question, 2, [])


# ---------------------------------------------------------------------------
# Upstream forwarding (UDP, with retry across all upstreams)
# ---------------------------------------------------------------------------
UPSTREAMS = []  # set at install / start: [original DNS servers]


def forward_raw(query, upstream, timeout=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(query, (upstream, 53))
        data, _ = s.recvfrom(4096)
        return data
    except Exception:
        return None
    finally:
        s.close()


def forward_upstream(data, retries=2):
    """Forward a raw query to upstreams (each tried `retries` times).
    Returns response bytes, or None when every upstream failed."""
    upstreams = UPSTREAMS or ["223.5.5.5"]
    for up in upstreams:
        for _ in range(retries):
            resp = forward_raw(data, up)
            if resp:
                return resp
    return None


def resolve_upstream_all(qname, qtype):
    """Return A answers from upstream(s). Returns as soon as ONE upstream
    answers (typical 10-100ms) - wide multi-source merging is done by
    resolve_multi_source where a wider pool actually matters (pref/CDN)."""
    query = make_query(qname, qtype)

    def _collect(up):
        for attempt in range(2):
            resp = forward_raw(query, up, timeout=0.8)
            if resp:
                return extract_a_records(resp)
        return []

    ex = ThreadPoolExecutor(max_workers=max(1, len(UPSTREAMS)))
    futs = {ex.submit(_collect, up): up for up in UPSTREAMS}
    try:
        for f in as_completed(futs):
            try:
                answers = f.result()
            except Exception:
                continue
            if answers:
                return answers
        return []
    finally:
        # Critical: NEVER block the query worker on slow resolvers. `with
        # ThreadPoolExecutor` would shutdown(wait=True) and wait for every
        # straggler (a dead router DNS retries 2x0.8s), turning a 0.8s
        # first-answer into a 1.6s+ lookup - exactly the latency that made
        # pages feel dead. Cancel outstanding and return now.
        for f in futs:
            f.cancel()
        ex.shutdown(wait=False)


PUBLIC_DNS = ["223.5.5.5", "119.29.29.29", "114.114.114.114"]


def resolve_multi_source(qname, qtype):
    """Query upstream + public DNS in parallel, return IPs from the FIRST
    source that answers (a slow/unreachable resolver must never stall the
    reply). The preferred-pool already carries the wide Akamai/CF candidate
    set, so extra merging buys little but costs up to ~1.2s."""
    sources = [up for up in UPSTREAMS] + PUBLIC_DNS

    def _collect(server):
        query = make_query(qname, qtype)
        resp = forward_raw(query, server, timeout=1.2)
        if not resp:
            return []
        return extract_a_records(resp)

    ex = ThreadPoolExecutor(max_workers=len(sources))
    futs = {ex.submit(_collect, srv): srv for srv in sources}
    try:
        for f in as_completed(futs):
            try:
                answers = f.result()
            except Exception:
                continue
            if answers:
                return [(ip, 60) for ip, _ in answers if ":" not in ip]
        return []
    finally:
        # never block the query worker on slow resolvers (see resolve_upstream_all)
        for f in futs:
            f.cancel()
        ex.shutdown(wait=False)


def make_query(qname, qtype):
    # encode qname from dotted form
    qb = b""
    for label in qname.split("."):
        if label:
            qb += bytes([len(label)]) + label.encode("ascii", "ignore")
    qb += b"\x00"
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    return header + qb + struct.pack(">HH", qtype, 1)


def extract_a_records(resp):
    """Return [(ip_str, ttl)] for A records in a response (no compression walk
    beyond pointers used by answers; simple enough for our upstreams)."""
    if len(resp) < 12:
        return []
    try:
        ancount = struct.unpack(">H", resp[6:8])[0]
        off = 12
        # skip question
        while off < len(resp):
            ln = resp[off]
            if ln == 0:
                off += 1
                break
            if ln & 0xC0:
                off += 2
                break
            off += 1 + ln
        off += 4  # type + class of question
        out = []
        for _ in range(ancount):
            if off + 10 > len(resp):
                break
            # name (may be pointer)
            if resp[off] & 0xC0:
                off += 2
            else:
                while off < len(resp) and resp[off] != 0:
                    off += 1 + resp[off]
                off += 1
            if off + 10 > len(resp):
                break
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", resp[off: off + 10])
            off += 10
            if off + rdlen > len(resp):
                break
            rdata = resp[off: off + rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:
                out.append((socket.inet_ntoa(rdata), ttl))
            elif rtype == 28 and rdlen == 16:
                try:
                    out.append((socket.inet_ntop(socket.AF_INET6, rdata), ttl))
                except Exception:
                    pass
        return out
    except Exception:
        return []


# ---------------------------------------------------------------------------
# TCP + TLS probing (TLS handshake means the node is truly usable, not just
# TCP-reachable - catches nodes that accept TCP but fail HTTPS, e.g. some
# GitHub anycast IPs on certain ISP routes).
# ---------------------------------------------------------------------------
# SSL context is cached globally: create_default_context() reloads the whole
# system CA store on EVERY call (~hundreds of ms), which blew the probe
# deadline and made every all-dead lookup take ~1.8s instead of ~1s.
_SSL_CTX = None
_SSL_LOCK = threading.Lock()

# Windows system stores here expose only ~35 roots, so a live GitHub/Azure
# edge fails validation ("unable to get issuer certificate") and gets
# misjudged dead -> ALLDEAD -> fail-open hands out a truly dead raw IP
# (GitHub "down" that is really a CA bug). Load a full CA bundle on top:
# prefer the one bundled with the app, fall back to common install paths.
_CA_CANDIDATES = [
    os.path.join(_HERE, "cacert.pem"),
    r"C:\Program Files\Git\mingw64\etc\ssl\cert.pem",
    r"C:\Program Files\Git\usr\ssl\cert.pem",
    r"C:\Program Files\Python312\Lib\site-packages\certifi\cacert.pem",
    r"C:\Python312\Lib\site-packages\certifi\cacert.pem",
]

def _get_ssl_ctx():
    global _SSL_CTX
    with _SSL_LOCK:
        if _SSL_CTX is None:
            c = ssl.create_default_context()
            c.check_hostname = True
            c.verify_mode = ssl.CERT_REQUIRED
            for _ca in _CA_CANDIDATES:
                try:
                    if os.path.isfile(_ca):
                        c.load_verify_locations(_ca)
                        log.info("SSL: loaded extra CA bundle: %s" % _ca)
                        break
                except Exception:
                    continue
            _SSL_CTX = c
    return _SSL_CTX


def probe_conn(ip, host=None, port=443, timeout=TCP_TIMEOUT):
    """TCP connect + TLS handshake (fully verified). Returns ms, or None."""
    st = time.time()
    s = None
    ss = None
    try:
        ctx = _get_ssl_ctx()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        ss = ctx.wrap_socket(s, server_hostname=host)
        ss.do_handshake()
        return (time.time() - st) * 1000.0
    except Exception:
        return None
    finally:
        try:
            if ss:
                ss.close()
        except Exception:
            pass
        try:
            if s:
                s.close()
        except Exception:
            pass


def probe_http(ip, host, port=443, timeout=TCP_TIMEOUT, tcp_timeout=TCP_CONNECT_TIMEOUT):
    """TCP + TLS(fully verified, needs bundled/system CA) + real HTTP HEAD.
    A node is healthy only if it answers HTTP 2xx/3xx AND its certificate
    validates for `host`. Filters cross-tenant CDN nodes whose handshake
    works but whose cert belongs to another site (privacy errors).
    `timeout` is the HARD total budget for TLS+HTTP (kept at 4.0s so a
    slow-but-live edge with TTFB ~3s still counts as live); `tcp_timeout`
    is a SEPARATE short budget for the TCP connect phase (2.0s). Two-phase
    budgets matter: when the whole segment is dead, most candidates fail at
    TCP connect - failing them in 2.0s instead of 4.0s halves how long a
    worker thread is blocked, and a worker pool flooded by all-dead probes
    starves every other query (Bilibili etc. are plain passthrough but share
    the same pool -> whole machine appears offline). Fast edges connect in
    ms, so nothing real is harmed; slow-but-live edges still connect well
    under 2.0s and then get the full TLS+HTTP budget."""
    st = time.time()
    deadline = st + timeout
    s = None
    ss = None
    try:
        ctx = _get_ssl_ctx()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(tcp_timeout)
        s.connect((ip, port))
        ss = ctx.wrap_socket(s, server_hostname=host)
        ss.settimeout(max(0.2, deadline - time.time()))
        ss.do_handshake()
        if time.time() > deadline:
            return None
        ss.settimeout(max(0.2, deadline - time.time()))
        req = ("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: cdn-accelerator/1.0\r\n"
               "Connection: close\r\n\r\n") % host
        ss.sendall(req.encode("ascii"))
        data = b""
        while b"\r\n\r\n" not in data:
            if time.time() > deadline:
                return None
            ss.settimeout(max(0.2, deadline - time.time()))
            chunk = ss.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 16384:
                break
        head = data.split(b"\r\n", 1)[0]
        parts = head.split(b" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            code = int(parts[1])
            # 2xx-4xx = the edge answered: the cert already validated for the
            # host, and a 400/403/404 from GitHub/Akamai is just a UA/referrer
            # policy, not a dead node. Requiring strict 2xx/3xx made real
            # GitHub edges (api.github.com -> 403 without UA) look all-dead.
            if 200 <= code <= 499:
                return (time.time() - st) * 1000.0
        return None
    except Exception:
        return None
    finally:
        try:
            if ss:
                ss.close()
        except Exception:
            pass
        try:
            if s:
                s.close()
        except Exception:
            pass


def probe_fastest(ips, workers=20, timeout=TCP_TIMEOUT, host=None, collect_ms=300, top=3):
    """Probe candidates in parallel. Return up to `top` LIVE candidates sorted
    by measured latency (best first). Successes inside a short collect window
    (default 300ms from probe start) are all kept, so the DNS answer can carry
    several A records and the browser/system fail over automatically when the
    best edge dies mid-session - the same robustness authoritative DNS gives.
    If nothing succeeds inside the window, return the first success as it
    arrives (line-recovery nodes handshake slowly and must not add 300ms to
    every lookup). All-dead -> (None, None) after the budget. A single
    candidate is still probed - returning it unprobed could hand out a dead
    IP."""
    if not ips:
        return (None, None)
    if len(ips) == 1:
        ms = probe_http(ips[0], host, 443, timeout)
        return ([(ips[0], ms)] if ms is not None else [], None)
    st = time.time()
    deadline_collect = st + (collect_ms / 1000.0)
    ok = []
    with ThreadPoolExecutor(max_workers=min(workers, len(ips))) as ex:
        futures = {ex.submit(probe_http, ip, host, 443, timeout): ip for ip in ips}
        for f in as_completed(futures):
            ip = futures[f]
            ms = f.result()
            if ms is not None:
                ok.append((ip, ms))
                if time.time() >= deadline_collect:
                    break
    if not ok:
        return (None, None)
    ok.sort(key=lambda x: x[1])
    return (ok[:top], None)


# ---------------------------------------------------------------------------
# Domain routing state
# ---------------------------------------------------------------------------
# cache: qname -> {"ips": [..], "best": ip, "addrs": [best, alt...], "updated": ts, "cdn": bool}
_cache = {}
_cache_lock = threading.Lock()
# probe-in-flight marker: qname -> True while a background probe is queued/running.
# Used to dedupe (Windows queries both ::1 and 127.0.0.1 at the same time) and to
# decide whether a fresh query must wait for the optimized answer or fall back fast.
_inflight = {}
# v2.17: probes NEVER block a query worker. A bounded executor runs the slow HTTP
# probe rounds off the query path; the query thread answers immediately with the
# last known-good edges (or raw resolver IPs) and the probe result lands in the
# cache for the browser's retry / next asset. Without this, an all-dead round
# (2-4s per name) flooded the shared 64-worker pool during a browser burst and
# starved even passthrough names (Bilibili/Doubao) -> "everything is offline".
_probe_executor = ThreadPoolExecutor(max_workers=16, thread_name_prefix="probe")
# name -> (ts, [ip, ...]): last set of live IPs from a successful probe round.
# Used as fail-open preference: when a probe round comes back all-dead during
# a line flake, hand out the last known-good edges (the way Steam++ pins its
# community-picked IPs) instead of raw resolver IPs that may be dead right now.
_last_live = {}
_last_live_lock = threading.Lock()
_LAST_LIVE_TTL = 600  # seconds before a last-live hint expires

# pool: sorted list of ("ip", ms) for Cloudflare anycast, refreshed by worker
_cf_sorted = [(ip, 0.0) for ip in CF_POOL]
_cf_sorted_lock = threading.Lock()


def _background_probe(name, cand, pool, qname_bytes):
    """One probe round off the query path. Publishes winners into the cache
    (+ last-live) so the browser's retry / next asset gets the optimized IP.
    Called via the bounded _probe_executor, so an all-dead round (2-4s) can
    never hold up a query worker or starve passthrough names."""
    try:
        winners, _ = probe_fastest(cand, timeout=TCP_TIMEOUT, host=name)
        now = time.time()
        if winners:
            chosen = winners[0][0]
            with _cache_lock:
                entry = _cache.get(name)
                if entry is None:
                    entry = {"ips": cand, "best": chosen, "updated": now, "cdn": True}
                else:
                    entry["ips"] = cand
                    entry["best"] = chosen
                    entry["updated"] = now
                    entry["cdn"] = True
                entry["addrs"] = [ip for ip, _ in winners[:3]]
                _cache[name] = entry
            prune_cache()   # outside the lock: prune_cache acquires _cache_lock itself
            with _last_live_lock:
                _last_live[name] = (now, [ip for ip, _ in winners])
            log.info("OPT  %s -> %s (pool of %d)" % (name, chosen, len(cand)))
        else:
            with _last_live_lock:
                last = _last_live.get(name)
            if last and now - last[0] < _LAST_LIVE_TTL:
                log.warning("ALLDEAD %s (cand %d); fail-open last-live %d" % (name, len(cand), len(last[1])))
            elif pool:
                log.warning("ALLDEAD %s (cand %d); fallback raw %d" % (name, len(cand), len(pool)))
            else:
                log.warning("ALLDEAD %s (cand %d)" % (name, len(cand)))
    except Exception as ex:
        log.info("bg probe error %s: %s" % (name, ex))
    finally:
        with _cache_lock:
            _inflight.pop(name, None)


def get_cf_best():
    with _cf_sorted_lock:
        if _cf_sorted:
            return _cf_sorted[0][0]
    return CF_POOL[0] if CF_POOL else None


def get_cf_fast(n=4):
    with _cf_sorted_lock:
        return [x[0] for x in _cf_sorted[:n]] if _cf_sorted else CF_POOL[:n]


def prune_cache():
    """Keep _cache under MAX_CACHE: drop the oldest half when over."""
    with _cache_lock:
        if len(_cache) <= MAX_CACHE:
            return
        items = sorted(_cache.items(), key=lambda kv: kv[1].get("updated", 0))
        for k, _ in items[: len(items) // 2]:
            del _cache[k]
        log.info("CACHE pruned -> %d entries" % len(_cache))


# ---------------------------------------------------------------------------
# Main request handling
# ---------------------------------------------------------------------------
def handle_query(data, addr):
    q = parse_question(data)
    if not q:
        return None
    name = q["qname"]
    qtype = q["qtype"]
    log.info("Q %s type=%d from %s" % (name, qtype, addr[0]))

    # Only handle A/AAAA; forward everything else (MX, TXT, NS ...)
    if qtype not in (1, 28):
        resp = forward_upstream(data)
        return rewrite_id(resp, q["id"]) if resp else servfail_response(q)

    with _cache_lock:
        cached = _cache.get(name)

    now = time.time()

    # --- AAAA for known CDN domains: answer empty so clients fall back to v4
    if qtype == 28:
        if cached and cached.get("cdn"):
            return empty_response(q)
        # unknown domain: forward AAAA upstream, pass through
        resp = forward_upstream(data)
        return rewrite_id(resp, q["id"]) if resp else servfail_response(q)

    # --- A record
    if cached and (now - cached["updated"] < CACHE_TTL):
        best = cached.get("best")
        if best:
            addrs = cached.get("addrs") or [best]
            return build_response(q, 0, [make_a_answer(q["qname_bytes"], ip) for ip in addrs[:3]])
        resp = forward_upstream(data)
        return rewrite_id(resp, q["id"]) if resp else servfail_response(q)

    # A probe may already be queued for this name (Windows queries both ::1
    # and 127.0.0.1 at once). Never wait on it - answer last-live / raw now;
    # the background probe updates the cache and the browser retry hits the
    # optimized IP. The inflight marker is set inside the pref/CDN branches
    # right before they submit the probe.
    with _cache_lock:
        probing = _inflight.get(name)
    if probing:
        with _last_live_lock:
            last = _last_live.get(name)
        if last and now - last[0] < _LAST_LIVE_TTL:
            return build_response(q, 0, [make_a_answer(q["qname_bytes"], ip) for ip in last[1]])
        resp = forward_upstream(data)
        return rewrite_id(resp, q["id"]) if resp else servfail_response(q)

    try:
        # Fresh lookup: resolve upstream, probe, remember
        answers = resolve_upstream_all(name, 1)   # A records
        if not answers:
            # fall back to plain forward
            resp = forward_upstream(data)
            return rewrite_id(resp, q["id"]) if resp else servfail_response(q)

        ips = [ip for ip, _ in answers if ":" not in ip]   # v4 only
        if not ips:
            resp = forward_upstream(data)
            return rewrite_id(resp, q["id"]) if resp else servfail_response(q)

        # Preferred-pool hit (community/known candidates): probe pref + resolved
        # IPs IN THE BACKGROUND (bounded executor). The query answers instantly
        # with last-live / raw; the winner lands in the cache for the retry.
        pref = PREF_IPS.get(name)
        if pref:
            t_r = time.time()
            extra = resolve_multi_source(name, 1)
            pool = [ip for ip, _ in extra if ":" not in ip]
            cand = [p for p in pref if p not in pool] + pool
            t_p = time.time()
            log.info("TIMING %s resolve=%.0fms probe=async cand=%d" % (
                name, (t_p - t_r) * 1000, len(cand)))
            with _cache_lock:
                already = _inflight.get(name)
            if already:
                with _last_live_lock:
                    last = _last_live.get(name)
                if last and now - last[0] < _LAST_LIVE_TTL:
                    return build_response(q, 0, [make_a_answer(q["qname_bytes"], ip) for ip in last[1]])
                if pool:
                    return build_response(q, 0, [make_a_answer(q["qname_bytes"], ip) for ip in pool])
                return servfail_response(q)
            with _cache_lock:
                _inflight[name] = True
            _probe_executor.submit(_background_probe, name, cand, pool, q["qname_bytes"])
            with _last_live_lock:
                last = _last_live.get(name)
            if last and now - last[0] < _LAST_LIVE_TTL:
                log.info("FASTFALLBACK %s last-live %d (bg probing)" % (name, len(last[1])))
                return build_response(q, 0, [make_a_answer(q["qname_bytes"], ip) for ip in last[1]])
            if pool:
                log.info("FASTFALLBACK %s raw %d (bg probing)" % (name, len(pool)))
                return build_response(q, 0, [make_a_answer(q["qname_bytes"], ip) for ip in pool])
            return servfail_response(q)

        # CDN if any resolved IP sits in a known CDN range (single-IP counts
        # too - DNS load balancing often returns one edge that may be dead)
        cdn = any(is_cdn_ip(ip) for ip in ips[:6])

        if cdn:
            # Wider candidate pool for CDN names: measured CF edges + the
            # domain-specific IPs from upstream/public DNS (a reachable edge
            # may only be returned by one resolver) + last known-good edges.
            # ONE combined probe round, run IN THE BACKGROUND (bounded
            # executor) - the query answers instantly with last-live / raw
            # and the winner lands in the cache for the browser retry.
            extra = resolve_multi_source(name, 1)
            pool = list(ips)
            for ip, _ in extra:
                if ":" not in ip and ip not in pool:
                    pool.append(ip)
            cf_candidates = get_cf_fast(24)
            cand = []
            for ip in cf_candidates + pool:
                if ip not in cand:
                    cand.append(ip)
            # fold in the last known-good edges so a live node that fell out of
            # the rotation still gets probed this round (else we would probe
            # 24 dead CFs and fail open to it anyway)
            with _last_live_lock:
                last = _last_live.get(name)
            if last and now - last[0] < _LAST_LIVE_TTL:
                for ip in last[1]:
                    if ip not in cand:
                        cand.append(ip)
            cand = cand[:32]
            with _cache_lock:
                already = _inflight.get(name)
            if already:
                if last and now - last[0] < _LAST_LIVE_TTL:
                    return build_response(q, 0, [make_a_answer(q["qname_bytes"], ip) for ip in last[1]])
                if pool:
                    return build_response(q, 0, [make_a_answer(q["qname_bytes"], ip) for ip in pool])
                return servfail_response(q)
            with _cache_lock:
                _inflight[name] = True
            _probe_executor.submit(_background_probe, name, cand, pool, q["qname_bytes"])
            # answer fast: last known-good edges, else raw multi-source IPs so
            # the browser can still try direct (Steam++-style fail-open)
            if last and now - last[0] < _LAST_LIVE_TTL:
                log.info("FASTFALLBACK %s last-live %d (bg probing)" % (name, len(last[1])))
                return build_response(q, 0, [make_a_answer(q["qname_bytes"], ip) for ip in last[1]])
            if pool:
                log.info("FASTFALLBACK %s raw %d (bg probing)" % (name, len(pool)))
                return build_response(q, 0, [make_a_answer(q["qname_bytes"], ip) for ip in pool])
            return servfail_response(q)

        # Non-CDN multi-IP: pass through the resolved IPs without probing.
        # These are domestic/regular sites whose DNS answer is already optimal
        # for the local route; probing them only adds latency (probes can take
        # ~2s when candidates time out, making every page feel slow).
        v4 = [ip for ip in ips if ":" not in ip]
        if not v4:
            resp = forward_upstream(data)
            return rewrite_id(resp, q["id"]) if resp else servfail_response(q)
        entry = {"ips": v4, "best": v4[0], "updated": now, "cdn": False}
        with _cache_lock:
            _cache[name] = entry
        return build_response(q, 0, [make_a_answer(q["qname_bytes"], ip) for ip in v4])
    finally:
        # _inflight cleanup is owned by _background_probe (it pops the marker
        # when the probe round finishes); passthrough paths never set it.
        pass


# ---------------------------------------------------------------------------
# Background workers
# ---------------------------------------------------------------------------
def refresh_cf_pool():
    """Measure every CF pool IP and keep the sorted list of live ones."""
    global _cf_sorted
    with _cf_sorted_lock:
        pool_now = list(_cf_sorted)
    ips = [x[0] for x in pool_now]
    probed = []
    with ThreadPoolExecutor(max_workers=24) as ex:
        futs = {ex.submit(probe_http, ip, "cloudflare.com", 443, TCP_TIMEOUT): ip for ip in ips}
        for f in futs:
            ms = f.result()
            if ms is not None:
                probed.append((futs[f], ms))
    probed.sort(key=lambda x: x[1])
    if probed:
        with _cf_sorted_lock:
            _cf_sorted = probed
        log.info("POOL refreshed: best=%s %.0fms (ok %d/%d)" % (
            probed[0][0], probed[0][1], len(probed), len(ips)))


def refresh_cached_domains():
    """Re-check the best node of every cached domain. Conservative: keep the
    current node while it still answers HTTP; only re-pick when it's dead
    (prevents a good node being swapped for a bad one on every refresh)."""
    with _cache_lock:
        snapshot = [(k, v["ips"]) for k, v in _cache.items() if v.get("cdn") and v["ips"]]
    for name, ips in snapshot:
        with _cache_lock:
            cur_best = _cache.get(name, {}).get("best")
        if cur_best and probe_http(cur_best, name, 443, TCP_TIMEOUT) is not None:
            continue
        winners, _ = probe_fastest(ips, timeout=TCP_TIMEOUT, host=name)
        chosen = winners[0][0] if winners else None
        if chosen:
            with _cache_lock:
                e = _cache.get(name)
                if e:
                    e["best"] = chosen
                    e["updated"] = time.time()
                    log.info("REFRESH %s -> %s (old best dead)" % (name, chosen))


def refresh_worker():
    # warm up the CF pool immediately on start (no 5-minute wait)
    try:
        refresh_cf_pool()
        log.info("WARMUP done: cf best=%s" % get_cf_best())
    except Exception as ex:
        log.info("warmup error: %s" % ex)
    while True:
        time.sleep(REFRESH_INTERVAL)
        try:
            refresh_cf_pool()
            refresh_cached_domains()
        except Exception as ex:
            log.info("refresh error: %s" % ex)


def health_worker():
    """Every HEALTH_INTERVAL seconds re-probe the nodes we are actually
    returning, in parallel. If a live best node is dead, immediately re-pick
    from the remaining candidates, so clients re-resolving (short TTL) always
    get a live node within one health cycle."""
    while True:
        time.sleep(HEALTH_INTERVAL)
        try:
            # 1) current CF pool favourite
            with _cf_sorted_lock:
                cur = _cf_sorted[0][0] if _cf_sorted else None
            if cur:
                ms = probe_http(cur, "cloudflare.com", 443, TCP_TIMEOUT)
                if ms is None:
                    log.info("HEALTH cf best %s dead -> re-pick" % cur)
                    refresh_cf_pool()

            # 2) cached CDN/pref domains only (pass-through domains are already
            # optimal for the local route - probing them wastes bandwidth)
            with _cache_lock:
                snapshot = [(k, dict(v)) for k, v in list(_cache.items()) if v.get("cdn")]
            if not snapshot:
                continue

            def check_and_repick(item):
                name, e = item
                best = e.get("best")
                if not best:
                    return None
                ms = probe_http(best, name, 443, TCP_TIMEOUT)
                if ms is not None:
                    return None
                ips = e.get("ips") or []
                winners, _ = probe_fastest(ips, timeout=TCP_TIMEOUT, host=name)
                chosen = winners[0][0] if winners else None
                return (name, best, chosen)

            with ThreadPoolExecutor(max_workers=12) as ex:
                results = list(ex.map(check_and_repick, snapshot))
            for res in results:
                if res is None:
                    continue
                name, old_best, chosen = res
                if not chosen:
                    with _cache_lock:
                        _cache.pop(name, None)
                    log.info("DROPPED %s (all ips dead)" % name)
                    continue
                with _cache_lock:
                    cur_e = _cache.get(name)
                    if cur_e is None:
                        continue
                    cur_e["best"] = chosen
                    cur_e["updated"] = time.time()
                    log.info("REPICK %s: %s -> %s" % (name, old_best, chosen))
        except Exception as ex:
            log.info("health error: %s" % ex)


def warmup_worker():
    """On start, resolve + probe the warm-up domain list so first visits hit
    a pre-optimized answer instead of waiting for the first-lookup probe."""
    def _warm(name):
        try:
            extra = resolve_multi_source(name, 1)
            ips = [ip for ip, _ in extra if ":" not in ip]
            if not ips:
                return
            pref = PREF_IPS.get(name) or []
            cand = [p for p in pref if p not in ips] + ips
            if len(cand) == 1:
                ms = probe_http(cand[0], name, 443, TCP_TIMEOUT)
                chosen = cand[0] if ms is not None else None
            else:
                winners, _ = probe_fastest(cand, timeout=TCP_TIMEOUT, host=name)
                chosen = winners[0][0] if winners else None
            if chosen:
                with _cache_lock:
                    _cache[name] = {"ips": cand, "best": chosen,
                                    "updated": time.time(), "cdn": True}
                log.info("WARM %s -> %s (pool %d)" % (name, chosen, len(cand)))
        except Exception as _ex:
            pass

    # warm-up throttled: only the first N core domains, delayed start so the
    # DNS server answers queries immediately after boot (no start-up storm),
    # low concurrency to keep first-visit lookups snappy
    time.sleep(5)
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = [ex.submit(_warm, d) for d in WARMUP_DOMAINS[:100]]
        for f in futs:
            try:
                f.result()
            except Exception:
                pass
    log.info("WARMUP domains done: %d" % len(WARMUP_DOMAINS[:100]))


# ---------------------------------------------------------------------------
# UDP server
# ---------------------------------------------------------------------------
def handle_one(sock, data, addr):
    try:
        resp = handle_query(data, addr)
        if resp:
            sock.sendto(resp, addr)
    except OSError as ex:
        # WinError 10054: client sent ICMP unreachable after we answered - benign
        if getattr(ex, "winerror", None) != 10054:
            log.info("handler error: %s" % ex)
    except Exception as ex:
        # never leave the client hanging: answer SERVFAIL so the browser
        # fails fast instead of retrying every second
        log.info("handler error: %s" % ex)
        try:
            q = parse_query(data)
            sock.sendto(servfail_response(q), addr)
        except Exception:
            pass


def serve(sock):
    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            executor.submit(handle_one, sock, data, addr)
        except KeyboardInterrupt:
            break
        except OSError as ex:
            if getattr(ex, "winerror", None) != 10054:
                log.info("handler error: %s" % ex)
        except Exception as ex:
            log.info("handler error: %s" % ex)


def main():
    global UPSTREAMS
    port = LISTEN_PORT
    if "--port" in sys.argv:
        try:
            port = int(sys.argv[sys.argv.index("--port") + 1])
        except Exception:
            pass

    # collect upstreams from current system DNS (installer can also pass them)
    if "--upstream" in sys.argv:
        idx = sys.argv.index("--upstream")
        UPSTREAMS = [x for x in sys.argv[idx + 1].split(",") if x]
    if not UPSTREAMS:
        # default public resolvers
        UPSTREAMS = ["223.5.5.5", "119.29.29.29", "192.168.1.1"]

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lan_mode = "--lan" in sys.argv
    v4_addr = "0.0.0.0" if lan_mode else LISTEN_ADDR
    s.bind((v4_addr, port))
    # also listen on IPv6 loopback ::1 (or all :: in LAN mode) so IPv6-configured
    # clients hit us too
    s6 = None
    try:
        s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s6.bind(("::" if lan_mode else "::1", port))
        log.info("ipv6 listener on %s:%d%s" % ("::" if lan_mode else "::1", port,
                                               " (LAN shared)" if lan_mode else ""))
    except Exception as ex:
        log.info("ipv6 listener failed: %s" % ex)
    log.info("cdn-accelerator started on %s:%d, upstream=%s, cf-pool=%d%s" % (
        v4_addr, port, UPSTREAMS, len(CF_POOL), " [LAN SHARED]" if lan_mode else ""))

    threading.Thread(target=refresh_worker, daemon=True).start()
    threading.Thread(target=health_worker, daemon=True).start()
    threading.Thread(target=fetch_live_pool, daemon=True).start()

    t4 = threading.Thread(target=serve, args=(s,), daemon=True)
    t4.start()
    if s6:
        t6 = threading.Thread(target=serve, args=(s6,), daemon=True)
        t6.start()
        t6.join()
    t4.join()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # pythonw has no console: an uncaught exception used to vanish without
        # a trace, leaving system DNS pointed at a dead 127.0.0.1 (pages load
        # from cache, everything new fails - "bilibili opens but images don't").
        # Always write the crash to the log so the watchdog/next session can see it.
        import traceback
        log.error("FATAL crash: %s", traceback.format_exc())
        raise
