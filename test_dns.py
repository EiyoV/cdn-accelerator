import socket, struct, sys

def make_query(qname, qid=0xABCD):
    qb = b""
    for label in qname.split("."):
        if label:
            qb += bytes([len(label)]) + label.encode("ascii")
    qb += b"\x00"
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return header + qb + struct.pack(">HH", 1, 1)

def probe(server, qname, port=53):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    q = make_query(qname)
    s.sendto(q, (server, port))
    try:
        data, _ = s.recvfrom(4096)
        return data
    except Exception as e:
        return b"TIMEOUT: " + str(e).encode()

def parse(data):
    if len(data) < 12:
        return "short:" + data[:20].hex()
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    return "id=0x%04x flags=0x%04x qd=%d an=%d ns=%d ar=%d" % (qid, flags, qd, an, ns, ar)

for name in ["pokebonk.com", "www.baidu.com"]:
    print("==", name)
    d = probe("127.0.0.1", name)
    print("local :", d[:60].hex() if len(d) > 40 else d)
    print("       ", parse(d) if len(d) >= 12 else d)
    d2 = probe("192.168.1.1", name)
    print("upstr :", d2[:60].hex() if len(d2) > 40 else d2)
    print("       ", parse(d2) if len(d2) >= 12 else d2)
