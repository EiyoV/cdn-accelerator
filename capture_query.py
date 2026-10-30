import socket, struct, time

# Temporarily capture the raw DNS query Windows sends to 127.0.0.1:53
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 53))
s.settimeout(15)
print("listening for one query...", flush=True)
try:
    data, addr = s.recvfrom(4096)
    print("got %d bytes from %s" % (len(data), addr))
    print("hex:", data.hex())
    if len(data) >= 12:
        qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
        print("id=0x%04x flags=0x%04x qd=%d an=%d ns=%d ar=%d" % (qid, flags, qd, an, ns, ar))
except socket.timeout:
    print("timeout, no query received")
