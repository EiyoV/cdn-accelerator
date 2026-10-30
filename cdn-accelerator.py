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
import socket
import struct
import threading
import logging
import ipaddress
from concurrent.futures import ThreadPoolExecutor

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
LISTEN_ADDR = "127.0.0.1"
LISTEN_PORT = 53
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cdn-accelerator.log")
LOG_MAX_BYTES = 1024 * 1024          # 1 MB, then rotate (truncate)
REFRESH_INTERVAL = 300               # seconds between full CF pool re-measure
HEALTH_INTERVAL = 30                 # seconds between health re-probes of live nodes
TCP_TIMEOUT = 2.0                    # seconds per TCP handshake probe
CACHE_TTL = REFRESH_INTERVAL         # answer cache validity
ANSWER_TTL = 60                      # TTL we hand to the client
MAX_CACHE = 2000                     # hard cap for domain cache entries
MAX_WORKERS = 32                     # concurrent query handlers per socket
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
    """Return list of A answers for qname from upstream(s)."""
    query = make_query(qname, qtype)
    for up in UPSTREAMS:
        for attempt in range(2):
            resp = forward_raw(query, up)
            if resp:
                answers = extract_a_records(resp)
                if answers:
                    return answers
    return []


PUBLIC_DNS = ["223.5.5.5", "119.29.29.29", "8.8.8.8"]


def resolve_multi_source(qname, qtype):
    """Query upstream + public DNS in parallel, merge unique A IPs.
    Gives CDN domains a wider candidate pool (a reachable edge may only be
    returned by one resolver, e.g. Akamai edges on some ISP routes)."""
    sources = [up for up in UPSTREAMS] + PUBLIC_DNS
    seen = []
    lock = threading.Lock()

    def _collect(server):
        query = make_query(qname, qtype)
        resp = forward_raw(query, server, timeout=2.0)
        if not resp:
            return
        for ip, _ in extract_a_records(resp):
            with lock:
                if ip not in seen:
                    seen.append(ip)

    with ThreadPoolExecutor(max_workers=len(sources)) as ex:
        futs = [ex.submit(_collect, srv) for srv in sources]
        for f in futs:
            try:
                f.result()
            except Exception:
                pass
    return [(ip, 60) for ip in seen]


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
def probe_conn(ip, host=None, port=443, timeout=TCP_TIMEOUT):
    """TCP connect + TLS handshake. Returns ms, or None on any failure."""
    st = time.time()
    s = None
    ss = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
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


def probe_http(ip, host, port=443, timeout=TCP_TIMEOUT):
    """TCP + TLS + real HTTP HEAD. A node is healthy only if it actually
    answers HTTP (2xx/3xx/4xx/5xx). Catches 'TLS handshake ok but page can't
    load' nodes (seen on Akamai/CF anycast on some ISP routes)."""
    st = time.time()
    s = None
    ss = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        ss = ctx.wrap_socket(s, server_hostname=host)
        ss.do_handshake()
        req = ("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: cdn-accelerator/1.0\r\n"
               "Connection: close\r\n\r\n") % host
        ss.sendall(req.encode("ascii"))
        data = b""
        while b"\r\n\r\n" not in data:
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
            if 200 <= code <= 599:
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


def probe_fastest(ips, workers=20, timeout=TCP_TIMEOUT, host=None):
    if not ips:
        return None
    if len(ips) == 1:
        return (ips[0], 0.0)
    with ThreadPoolExecutor(max_workers=min(workers, len(ips))) as ex:
        futures = {ex.submit(probe_http, ip, host, 443, timeout): ip for ip in ips}
        best = None
        best_ms = None
        for f in futures:
            ip = futures[f]
            ms = f.result()
            if ms is not None and (best_ms is None or ms < best_ms):
                best, best_ms = ip, ms
    return (best, best_ms)


# ---------------------------------------------------------------------------
# Domain routing state
# ---------------------------------------------------------------------------
# cache: qname -> {"ips": [..], "best": ip, "updated": ts, "cdn": bool}
_cache = {}
_cache_lock = threading.Lock()
# single-flight: qname -> threading.Event while a first lookup is in progress
_inflight = {}

# pool: sorted list of ("ip", ms) for Cloudflare anycast, refreshed by worker
_cf_sorted = [(ip, 0.0) for ip in CF_POOL]
_cf_sorted_lock = threading.Lock()


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
        best = cached["best"]
        if best:
            return build_response(q, 0, [make_a_answer(q["qname_bytes"], best)])
        resp = forward_upstream(data)
        return rewrite_id(resp, q["id"]) if resp else servfail_response(q)

    # single-flight: if another thread is already resolving this name, wait
    # for its result instead of probing again (Windows queries both ::1 and
    # 127.0.0.1 at the same time - we only want one probe per name).
    with _cache_lock:
        ev = _inflight.get(name)
    if ev is not None:
        ev.wait(timeout=6.0)
        with _cache_lock:
            cached2 = _cache.get(name)
        if cached2 and cached2.get("best"):
            return build_response(q, 0, [make_a_answer(q["qname_bytes"], cached2["best"])])
        resp = forward_upstream(data)
        return rewrite_id(resp, q["id"]) if resp else servfail_response(q)
    ev = threading.Event()
    with _cache_lock:
        _inflight[name] = ev

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

        # CDN if any resolved IP sits in a known CDN range (single-IP counts
        # too - DNS load balancing often returns one edge that may be dead)
        cdn = any(is_cdn_ip(ip) for ip in ips[:6])

        if cdn:
            # Wider candidate pool for CDN names: merge upstream + public DNS.
            # A reachable Akamai/CF edge may only be returned by one resolver.
            extra = resolve_multi_source(name, 1)
            pool = list(ips)
            for ip, _ in extra:
                if ":" not in ip and ip not in pool:
                    pool.append(ip)
            # Prefer the measured Cloudflare pool for CF domains
            cf_candidates = get_cf_fast(6)
            chosen, _ = probe_fastest(cf_candidates, timeout=TCP_TIMEOUT, host=name)
            if chosen is None:
                chosen, _ = probe_fastest(pool, timeout=TCP_TIMEOUT, host=name)
            if chosen is None:
                # all candidates dead: keep previous best if it still answers
                with _cache_lock:
                    old = _cache.get(name)
                if old and old.get("best"):
                    old_ms = probe_http(old["best"], name, 443, TCP_TIMEOUT)
                    if old_ms is not None:
                        chosen = old["best"]
            if chosen is None:
                log.warning("ALLDEAD %s (pool of %d, cf %d)" % (name, len(pool), len(cf_candidates)))
                return servfail_response(q)
            entry = {"ips": pool, "best": chosen, "updated": now, "cdn": True}
            with _cache_lock:
                _cache[name] = entry
            log.info("OPT  %s -> %s (cdn, pool of %d)" % (name, chosen, len(pool)))
            prune_cache()
            return build_response(q, 0, [make_a_answer(q["qname_bytes"], chosen)])

        # Non-CDN multi-IP: pick fastest among resolved IPs
        if len(ips) > 1:
            chosen, _ = probe_fastest(ips, timeout=TCP_TIMEOUT, host=name)
        else:
            chosen = ips[0]
        if chosen is None:
            with _cache_lock:
                old = _cache.get(name)
            if old and old.get("best"):
                old_ms = probe_http(old["best"], name, 443, TCP_TIMEOUT)
                if old_ms is not None:
                    chosen = old["best"]
        if chosen is None:
            log.warning("ALLDEAD %s (multi-ip)" % name)
            return servfail_response(q)
        entry = {"ips": ips, "best": chosen, "updated": now, "cdn": False}
        with _cache_lock:
            _cache[name] = entry
        log.info("OPT  %s -> %s (multi-ip)" % (name, chosen))
        prune_cache()
        return build_response(q, 0, [make_a_answer(q["qname_bytes"], chosen)])
    finally:
        with _cache_lock:
            _inflight.pop(name, None)
        ev.set()


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
        snapshot = [(k, v["ips"]) for k, v in _cache.items() if v["ips"]]
    for name, ips in snapshot:
        with _cache_lock:
            cur_best = _cache.get(name, {}).get("best")
        if cur_best and probe_http(cur_best, name, 443, TCP_TIMEOUT) is not None:
            continue
        chosen, _ = probe_fastest(ips, timeout=TCP_TIMEOUT, host=name)
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
    returning. If the live best node is dead, immediately re-pick from the
    remaining candidates (CF pool) or drop/refresh the cache entry."""
    while True:
        time.sleep(HEALTH_INTERVAL)
        try:
            # 1) current CF pool favourite
            with _cf_sorted_lock:
                if _cf_sorted:
                    cur = _cf_sorted[0][0]
                else:
                    cur = None
            if cur:
                ms = probe_http(cur, "cloudflare.com", 443, TCP_TIMEOUT)
                if ms is None:
                    log.info("HEALTH cf best %s dead -> re-pick" % cur)
                    refresh_cf_pool()

            # 2) cached domains (CDN + multi-IP)
            with _cache_lock:
                snapshot = [(k, dict(v)) for k, v in list(_cache.items())]
            for name, e in snapshot:
                best = e.get("best")
                if not best:
                    continue
                ms = probe_http(best, name, 443, TCP_TIMEOUT)
                if ms is not None:
                    continue
                log.info("HEALTH %s best %s dead -> re-pick" % (name, best))
                ips = e.get("ips") or []
                chosen, _ = probe_fastest(ips, timeout=TCP_TIMEOUT, host=name)
                with _cache_lock:
                    cur_e = _cache.get(name)
                    if cur_e is None:
                        continue
                    if chosen:
                        cur_e["best"] = chosen
                        cur_e["updated"] = time.time()
                        log.info("REPICK %s -> %s" % (name, chosen))
                    else:
                        del _cache[name]
                        log.info("DROPPED %s (all ips dead)" % name)
        except Exception as ex:
            log.info("health error: %s" % ex)


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
        log.info("handler error: %s" % ex)


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
    s.bind((LISTEN_ADDR, port))
    # also listen on IPv6 loopback ::1 so IPv6-configured clients hit us too
    s6 = None
    try:
        s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s6.bind(("::1", port))
        log.info("ipv6 listener on ::1:%d" % port)
    except Exception as ex:
        log.info("ipv6 listener failed: %s" % ex)
    log.info("cdn-accelerator started on %s:%d, upstream=%s, cf-pool=%d" % (
        LISTEN_ADDR, port, UPSTREAMS, len(CF_POOL)))

    threading.Thread(target=refresh_worker, daemon=True).start()
    threading.Thread(target=health_worker, daemon=True).start()

    t4 = threading.Thread(target=serve, args=(s,), daemon=True)
    t4.start()
    if s6:
        t6 = threading.Thread(target=serve, args=(s6,), daemon=True)
        t6.start()
        t6.join()
    t4.join()


if __name__ == "__main__":
    main()
