"""Ephemeral CSC v2.0.0.2 subset. No real CA, no outbound connections."""
import base64
import http.server
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import time

os.umask(0o077)
directory = Path(sys.argv[1])
fixtures = Path(os.environ["BRIGALOW_TEST_SECRETS"])
def openssl(*args, data=None):
    result = subprocess.run(["openssl", *args], cwd=directory, input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True)
    return result.stdout
openssl("req", "-new", "-newkey", "rsa:3072", "-nodes", "-keyout", "key.pem",
        "-out", "key.csr", "-subj", "/CN=Ephemeral CSC mock")
(directory / "leaf.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\n")
openssl("x509", "-req", "-in", "key.csr", "-CA", str(fixtures / "ca.crt"),
        "-CAkey", str(fixtures / "ca.key"), "-set_serial", "1234", "-days", "1",
        "-extfile", "leaf.ext", "-out", "leaf.pem")
openssl("x509", "-in", "leaf.pem", "-outform", "DER", "-out", "leaf.der")
openssl("pkey", "-in", "key.pem", "-pubout", "-out", "public.pem")
(directory / "token").write_text(secrets.token_urlsafe(32))
(directory / "mode").write_text("pass")
(directory / "events").touch()
cert = base64.b64encode((directory / "leaf.der").read_bytes()).decode()
authorisations = {}
SHA256 = "2.16.840.1.101.3.4.2.1"
RSA = "1.2.840.113549.1.1.1"

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass
    def reply(self, value, status=200):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        if self.headers.get("Authorization") != "Bearer " + (directory / "token").read_text():
            return self.reply({}, 401)
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size < 8192:
            return self.reply({}, 400)
        body = json.loads(self.rfile.read(size))
        method = self.path.removeprefix("/csc/v2/")
        mode = (directory / "mode").read_text()
        # Never persist bearer, SAD, or request bodies. Only public observations.
        with (directory / "events").open("a") as stream:
            stream.write(json.dumps({"method": method, "fields": sorted(body),
                                    "size": size, "hashes": body.get("hashes", [])}) + "\n")
        if mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "/redirect-target")
            self.end_headers()
            return
        if mode == "oversize":
            return self.reply({"padding": "x" * 1048577})
        if method == "credentials/list":
            return self.reply({"credentialIDs": ["mock-key"]})
        if body.get("credentialID") != "mock-key":
            return self.reply({}, 404)
        if method == "credentials/info":
            return self.reply({"key": {"status": "enabled", "len": 3072, "algo": [RSA]},
                               "cert": {"status": "valid", "certificates": [cert]},
                               "auth": {"mode": "explicit", "objects": []},
                               "SCAL": "2", "multisign": 1})
        hashes = body.get("hashes", [])
        if len(hashes) != 1 or len(base64.b64decode(hashes[0], validate=True)) != 32 or body.get("hashAlgorithmOID") != SHA256:
            return self.reply({}, 400)
        if method == "credentials/authorize":
            assert set(body) == {"credentialID", "numSignatures", "hashes", "hashAlgorithmOID", "authData"}
            assert body["numSignatures"] == 1 and body["authData"] == []
            if mode == "denied":
                return self.reply({"error": "access_denied"}, 403)
            sad = secrets.token_urlsafe(32)
            authorisations[sad] = (hashes, time.monotonic() + (0 if mode == "expired-remote" else 5))
            return self.reply({"SAD": sad, "expiresIn": 0 if mode == "expired" else 5})
        if method == "signatures/signHash":
            assert set(body) == {"credentialID", "SAD", "hashes", "hashAlgorithmOID", "signAlgo", "operationMode"}
            assert body["signAlgo"] == RSA and body["operationMode"] == "S"
            entry = authorisations.pop(body.get("SAD"), None)
            if not entry or entry[0] != hashes or time.monotonic() >= entry[1]:
                return self.reply({}, 403)
            digest = base64.b64decode(hashes[0], validate=True)
            if mode == "wrong-signature":
                digest = bytes(32)
            signature = openssl("pkeyutl", "-sign", "-inkey", "key.pem", "-pkeyopt", "digest:sha256", data=digest)
            signatures = [base64.b64encode(signature).decode()] * (2 if mode == "multiple" else 1)
            return self.reply({"signatures": signatures})
        self.reply({}, 404)

server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(os.environ["BRIGALOW_TEST_TLS_CERT_FILE"], os.environ["BRIGALOW_TEST_TLS_KEY_FILE"])
server.socket = context.wrap_socket(server.socket, server_side=True)
print(server.server_port, flush=True)
server.serve_forever()
