import socket, struct, time

# Replay experiment v2: fixed domains -> fixed response styles
# style-a.test -> full non-compressed name answer (current implementation)
# style-b.test -> compressed pointer answer (upstream style)
# style-c.test -> plain forward to upstream
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 53))
s.settimeout(40)
print("replay server up", flush=True)

def parse_q(data):
    if len(data) < 12: return None
    qid = struct.unpack(">H", data[0:2])[0]
    off = 12
    raw = b""
    labels = []
    while off < len(data):
        ln = data[off]
        if ln == 0:
            off += 1; break
        if ln & 0xC0: return None
        raw += data[off: off + 1 + ln]
        labels.append(data[off + 1: off + 1 + ln])
        off += 1 + ln
    qtype, qclass = struct.unpack(">HH", data[off:off + 4])
    return qid, raw, b".".join(labels).decode("ascii", "ignore").lower(), qtype, qclass

def full_name_resp(qid, raw_qb, qtype, qclass, ip):
    hdr = struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0)
    q = raw_qb + struct.pack(">HH", qtype, qclass)
    ans = raw_qb + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return hdr + q + ans

def ptr_name_resp(qid, raw_qb, qtype, qclass, ip):
    hdr = struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0)
    q = raw_qb + struct.pack(">HH", qtype, qclass)
    ans = struct.pack(">H", 0xC00C) + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return hdr + q + ans

def forward_resp(data):
    s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s2.settimeout(4)
    try:
        s2.sendto(data, ("192.168.1.1", 53))
        resp, _ = s2.recvfrom(4096)
        qid = struct.unpack(">H", data[0:2])[0]
        return struct.pack(">H", qid) + resp[2:]
    except Exception as e:
        return None
    finally:
        s2.close()

while True:
    try:
        data, addr = s.recvfrom(4096)
    except socket.timeout:
        print("timeout", flush=True); break
    except Exception as e:
        print("err", e, flush=True); break
    p = parse_q(data)
    if not p: continue
    qid, raw_qb, qname, qtype, qclass = p
    if qname == "style-a.test":
        resp = full_name_resp(qid, raw_qb, qtype, qclass, "1.1.1.1")
        print("STYLE1 full-name -> %s" % qname, flush=True)
    elif qname == "style-b.test":
        resp = ptr_name_resp(qid, raw_qb, qtype, qclass, "1.1.1.1")
        print("STYLE2 ptr -> %s" % qname, flush=True)
    elif qname == "style-c.test":
        resp = forward_resp(data)
        print("STYLE3 forward -> %s (%s)" % (qname, len(resp) if resp else 0), flush=True)
    else:
        resp = None
        print("UNKNOWN %s" % qname, flush=True)
    if resp:
        s.sendto(resp, addr)
