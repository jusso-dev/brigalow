"""Reference local fixture rebuild gate. No artifact uploads or network fetches.

This fixture demonstrates the protocol, not a general build sandbox. Replace the
builder only after independently pinning source and isolating untrusted builds.
"""
import base64
import hashlib
import hmac
import http.server
import json
import pathlib
import ssl
import sys
import time


def build_fixture():
    # Reconstruct deterministic output from fixed source inputs, never request metadata.
    source = {"name": "Brigalow gate fixture", "version": 1, "values": list(range(16))}
    return (json.dumps(source, sort_keys=True, separators=(",", ":")) + "\n").encode()


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def evaluate(self, request):
        return self.path == "/rebuild" and request["digest"] == list(hashlib.sha256(build_fixture()).digest())

    def respond(self, reply):
        body = json.dumps(reply, separators=(",", ":")).encode()
        tag = hmac.new(self.server.secret, b"brigalow.gate.response.v1\n" + body, hashlib.sha256).digest()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Brigalow-Signature", base64.b64encode(tag).decode())
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 65536:
                raise ValueError()
            body = self.rfile.read(size)
            supplied = base64.b64decode(self.headers.get("x-brigalow-signature", ""), validate=True)
            expected = hmac.new(self.server.secret, b"brigalow.gate.request.v1\n" + body, hashlib.sha256).digest()
            if not hmac.compare_digest(supplied, expected):
                raise ValueError()
            request = json.loads(body)
            if request["version"] != 1 or request["digest_alg"] != "sha256" or abs(time.time() - request["at"]) > 60:
                raise ValueError()
            # Bind response to this exact invocation; the client never accepts replayed replies.
            self.respond({"nonce": request["nonce"], "request": request["request"],
                          "digest": request["digest"], "pass": self.evaluate(request)})
        except (ValueError, KeyError, TypeError):
            self.send_error(403)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass


def serve(handler, cert, key, secret_file):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.secret = pathlib.Path(secret_file).read_bytes().rstrip(b"\n")
    if len(server.secret) < 32:
        raise ValueError("generated secret must contain at least 32 bytes")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(server.server_port, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    if sys.argv[1:] == ["--fixture"]:
        sys.stdout.buffer.write(build_fixture())
    else:
        serve(Handler, *sys.argv[1:])
