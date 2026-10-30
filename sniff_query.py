import socket, struct, threading, time

# Listen on 0.0.0.0:53 to catch ANY local DNS query packet
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 53))
s.settimeout(8)
print("listener up on 0.0.0.0:53", flush=True)
seen = []
try:
    while True:
        try:
            data, addr = s.recvfrom(4096)
        except socket.timeout:
            break
        qname = b""
        if len(data) > 12:
            off = 12
            labels = []
            while off < len(data):
                ln = data[off]
                if ln == 0: break
                if ln & 0xC0: labels.append(b"<ptr>"); break
                labels.append(data[off+1:off+1+ln])
                off += 1 + ln
            qname = b".".join(labels).decode("ascii", "ignore")
        qtype = struct.unpack(">H", data[4:6])[0] if len(data) >= 6 else 0
        print("PKT from %s:%d -> qname=%s qtype=%d len=%d" % (addr[0], addr[1], qname, qtype, len(data)), flush=True)
except Exception as e:
    print("err", e, flush=True)
