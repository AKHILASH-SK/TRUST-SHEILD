"""
A tiny DNS server for the lab (UDP and TCP, on localhost): it plays an attacker who rotates addresses.

    flux.bank-verify.test    a different set of addresses on EVERY question, TTL 30 s, spread over many networks  (fast-flux)
    steady.shop.test         the same two addresses every time, TTL 3600 s                                       (normal)
    cdn.bigsite.test         many addresses but a long TTL and the same set each time                            (a CDN-like site)

Run:  python -m lab.fastflux_dns          (listens on 127.0.0.1:5353)
"""
import random
import socketserver
import threading

from dnslib import A, QTYPE, RR, DNSRecord, RCODE

HOST, PORT = "127.0.0.1", 5353

# documentation / test ranges from many unrelated /16 blocks (never real hosts)
_POOL = [f"{a}.{b}.{random.randint(1, 250)}.{random.randint(1, 250)}"
         for a, b in ((198, 18), (198, 19), (203, 0), (192, 0), (100, 64), (100, 65), (192, 88), (198, 51), (45, 33), (185, 220),
                      (91, 121), (77, 88), (5, 188), (62, 210), (37, 139))]


def answers_for(name: str):
    """(list of addresses, ttl) for a question, or None for 'no such name'."""
    name = name.rstrip(".").lower()
    if name == "flux.bank-verify.test":
        return random.sample(_POOL, 5), 30
    if name == "steady.shop.test":
        return ["203.0.113.10", "203.0.113.11"], 3600
    if name == "cdn.bigsite.test":
        return [f"198.51.100.{i}" for i in range(1, 9)], 3600
    return None


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0] if isinstance(self.request, tuple) else self.request.recv(4096)[2:]
        reply = self.respond(data)
        if isinstance(self.request, tuple):
            self.request[1].sendto(reply, self.client_address)
        else:
            self.request.sendall(len(reply).to_bytes(2, "big") + reply)

    @staticmethod
    def respond(data: bytes) -> bytes:
        request = DNSRecord.parse(data)
        reply = request.reply()
        qname = str(request.q.qname)
        found = answers_for(qname)
        if found is None:
            reply.header.rcode = RCODE.NXDOMAIN
        elif request.q.qtype == QTYPE.A:
            ips, ttl = found
            for ip in ips:
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=ttl))
        return reply.pack()


def start(host: str = HOST, port: int = PORT):
    """Start UDP and TCP servers in background threads; returns a stop() function."""
    class UDP(socketserver.ThreadingUDPServer):
        allow_reuse_address = True

    udp = UDP((host, port), _Handler)
    threading.Thread(target=udp.serve_forever, daemon=True, name="lab-dns-udp").start()

    def stop():
        udp.shutdown()
        udp.server_close()
    return stop


if __name__ == "__main__":
    stop = start()
    print(f"[lab-dns] answering on udp {HOST}:{PORT}  (flux.bank-verify.test rotates, steady.shop.test is stable)", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        stop()
