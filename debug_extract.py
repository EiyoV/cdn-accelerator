import socket, struct

def make_query(qname, qtype=1, qid=0x1234):
    qb = b""
    for label in qname.split("."):
        if label:
            qb += bytes([len(label)]) + label.encode("ascii")
    qb += b"\x00"
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qb + struct.pack(">HH", qtype, 1)

def extract_a_records(resp):
    if len(resp) < 12:
        return []
    try:
        ancount = struct.unpack(">H", resp[6:8])[0]
        off = 12
        while off < len(resp):
            ln = resp[off]
            if ln == 0:
                off += 1
                break
            if ln & 0xC0:
                off += 2
                break
            off += 1 + ln
        off += 4
        out = []
        for _ in range(ancount):
            if off + 10 > len(resp):
                print("early break off=%d" % off)
                break
            if resp[off] & 0xC0:
                off += 2
            else:
                while off < len(resp) and resp[off] != 0:
                    off += 1 + resp[off]
                off += 1
            if off + 10 > len(resp):
                print("early break2 off=%d" % off)
                break
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", resp[off: off + 10])
            off += 10
            if off + rdlen > len(resp):
                print("early break3 off=%d rdlen=%d" % (off, rdlen))
                break
            rdata = resp[off: off + rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:
                out.append((socket.inet_ntoa(rdata), ttl))
        return out
    except Exception as e:
        print("extract exception:", e)
        return []

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
q = make_query("pokebonk.com")
s.sendto(q, ("192.168.1.1", 53))
resp, _ = s.recvfrom(4096)
print("resp len=%d hex=%s" % (len(resp), resp.hex()))
print("extracted:", extract_a_records(resp))
