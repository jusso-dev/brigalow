"""Loopback-only signed notification receiver. Generated secrets; no request logging."""
import base64
import hashlib
import hmac
import http.server
import json
import pathlib
import ssl
import sys
import time

root = pathlib.Path(sys.argv[3])
secret = (root / "secret").read_bytes().rstrip(b"\n")
seen = set()

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 8192:
            self.send_error(413)
            return
        body = self.rfile.read(size)
        expected = hmac.new(secret, b"brigalow.notification.v1\n" + body, hashlib.sha256).digest()
        supplied = base64.b64decode(self.headers.get("x-brigalow-signature", ""), validate=True)
        if not hmac.compare_digest(supplied, expected):
            self.send_error(403)
            return
        event = json.loads(body)
        if abs(time.time() - event["at"]) > 60 or event["event_id"] in seen:
            self.send_error(409)
            return
        seen.add(event["event_id"])
        with (root / "events.jsonl").open("a") as out:
            out.write(json.dumps(event) + "\n")
        status = int((root / "status").read_text())
        self.send_response(status)
        if status == 302:
            self.send_header("Location", "/redirected")
        self.end_headers()

server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print(server.server_port, flush=True)
server.serve_forever()
