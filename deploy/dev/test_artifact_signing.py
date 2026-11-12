"""Ephemeral Azure Artifact Signing data-plane and IMDS mock. Loopback only, no outbound calls.

Generates every key and certificate at start-up with OpenSSL: a TLS CA, a mock issuing root and
intermediate, a second (wrong) root, and two RSA-3072 leaf keys that model daily rotation. Leaves
are valid for 72 hours and carry code signing plus a profile EKU under 1.3.6.1.4.1.311.97.

Prints "<sign_port> <imds_port>" once both listeners are ready. Control files in the working
directory select behaviour: `mode`, `day`, `imds_mode`, `revoke`. Only public observations are
written to `events` (never tokens).
"""
import base64
import datetime
import http.server
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid

os.umask(0o077)
directory = Path(sys.argv[1]).resolve()
ACCOUNT = "brigalowtest"
PROFILES = {"test-profile", "release-profile", "untrusted-profile"}
PROFILE_EKU = "1.3.6.1.4.1.311.97.4242.1.1"
OTHER_EKU = "1.3.6.1.4.1.311.97.4242.9.9"
API_VERSION = "2022-06-15-preview"
RESOURCE = "https://codesigning.azure.net"


def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], cwd=directory, input=data, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout


def write(name, text):
    (directory / name).write_text(text)


def ca(name, issuer=None):
    """EC P-256 CA certificate; `issuer` makes an intermediate."""
    openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", f"/CN=Mock {name}")
    write(f"{name}.ext", "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
          "subjectKeyIdentifier=hash\n" + ("authorityKeyIdentifier=keyid:always\n" if issuer else ""))
    signer = ["-CA", f"{issuer}.pem", "-CAkey", f"{issuer}.key"] if issuer else ["-key", f"{name}.key"]
    openssl("x509", "-req", "-in", f"{name}.csr", *signer, "-set_serial", str(secrets.randbits(63)),
            "-days", "2", "-extfile", f"{name}.ext", "-out", f"{name}.pem")
    openssl("x509", "-in", f"{name}.pem", "-outform", "DER", "-out", f"{name}.der")


def leaf(name, key, issuer, eku, start, end):
    """Leaf from `issuer` with an explicit validity window (openssl ca works on OpenSSL 3.0)."""
    store = directory / f"ca-{name}"
    store.mkdir()
    (store / "index.txt").touch()
    (store / "serial").write_text(secrets.token_hex(8) + "\n")
    write(f"{name}.cnf", f"[ca]\ndefault_ca=d\n[d]\ndir={store}\ndatabase=$dir/index.txt\n"
          "new_certs_dir=$dir\nserial=$dir/serial\ndefault_md=sha256\npolicy=p\n"
          "unique_subject=no\ncopy_extensions=none\n[p]\ncommonName=supplied\n")
    write(f"{name}.ext", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
          f"extendedKeyUsage={eku}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
    openssl("req", "-new", "-key", key, "-out", f"{name}.csr", "-subj", f"/CN=Mock Artifact Signing {name}")
    stamp = lambda t: t.strftime("%Y%m%d%H%M%SZ")
    openssl("ca", "-batch", "-notext", "-config", f"{name}.cnf", "-cert", f"{issuer}.pem",
            "-keyfile", f"{issuer}.key", "-in", f"{name}.csr", "-out", f"{name}.pem",
            "-extfile", f"{name}.ext", "-startdate", stamp(start), "-enddate", stamp(end))
    openssl("x509", "-in", f"{name}.pem", "-outform", "DER", "-out", f"{name}.der")


# TLS for the HTTPS data-plane mock only.
openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", "tls-ca.key", "-out", "tls-ca.pem", "-days", "1", "-subj", "/CN=Mock TLS CA",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign",
        "-addext", "subjectKeyIdentifier=hash")
openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", "tls.key", "-out", "tls.csr", "-subj", "/CN=127.0.0.1")
write("tls.ext", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
      "extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\nsubjectKeyIdentifier=hash\n"
      "authorityKeyIdentifier=keyid:always\n")
openssl("x509", "-req", "-in", "tls.csr", "-CA", "tls-ca.pem", "-CAkey", "tls-ca.key",
        "-set_serial", "1", "-days", "1", "-extfile", "tls.ext", "-out", "tls.pem")

ca("root")
ca("intermediate", "root")
ca("wrong-root")
ca("wrong-intermediate", "wrong-root")
for day in ("day0", "day1"):
    openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", f"{day}.key")
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
current = (now - datetime.timedelta(hours=1), now + datetime.timedelta(hours=71))
eku = f"codeSigning,{PROFILE_EKU}"
leaf("day0", "day0.key", "intermediate", eku, *current)
leaf("day1", "day1.key", "intermediate", eku, *current)
leaf("wrong-anchor", "day0.key", "wrong-intermediate", eku, *current)
leaf("other-profile", "day0.key", "intermediate", f"codeSigning,{OTHER_EKU}", *current)
leaf("no-codesigning", "day0.key", "intermediate", PROFILE_EKU, *current)
leaf("expired", "day0.key", "intermediate", eku,
     now - datetime.timedelta(hours=80), now - datetime.timedelta(hours=8))
openssl("pkey", "-in", "day0.key", "-pubout", "-out", "day0-public.pem")
write("mode", "pass")
write("day", "day0")
write("imds_mode", "pass")
(directory / "events").touch()

lock = threading.Lock()
tokens = set()
operations = {}


def event(**fields):
    with lock, (directory / "events").open("a") as stream:
        stream.write(json.dumps(fields) + "\n")


def control(name):
    return (directory / name).read_text().strip()


def bundle(name, encoding):
    """`signingCertificate`: base64 of a base64 PKCS#7 bundle, as observed by Jsign."""
    certs = [f"{name}.pem", "wrong-intermediate.pem" if name == "wrong-anchor" else "intermediate.pem"]
    if encoding == "pem":
        text = "".join((directory / c).read_text() for c in certs)
    elif encoding == "der-concat":
        der = b"".join(openssl("x509", "-in", c, "-outform", "DER") for c in certs)
        text = base64.encodebytes(der).decode()
    else:
        args = [a for c in certs for a in ("-certfile", c)]
        text = base64.encodebytes(openssl("crl2pkcs7", "-nocrl", *args, "-outform", "DER")).decode()
    return base64.b64encode(text.encode()).decode()


class Imds(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, value, status=200):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        query = dict(urllib.parse.parse_qsl(url.query))
        mode = control("imds_mode")
        event(server="imds", method="GET", path=url.path, metadata=self.headers.get("Metadata"),
              authorization=self.headers.get("Authorization") is not None,
              client_id=query.get("client_id"))
        if (url.path != "/metadata/identity/oauth2/token" or self.headers.get("Metadata") != "true"
                or query.get("api-version") != "2018-02-01" or query.get("resource") != RESOURCE):
            return self.reply({"error": "invalid_request"}, 400)
        if mode == "error":
            return self.reply({"error": "unavailable"}, 500)
        if mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "/redirected")
            self.end_headers()
            return
        token = secrets.token_urlsafe(48)
        with lock:
            tokens.add(token)
        lifetime = 120 if mode == "short" else 3600
        self.reply({"access_token": token, "expires_on": str(int(time.time()) + lifetime),
                    "resource": RESOURCE, "token_type": "Bearer"})


class Sign(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, value, status=200):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def redirect(self):
        self.send_response(307)
        self.send_header("Location", "/redirected")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def authorised(self):
        # Models server-side token expiry: every token issued so far stops working.
        if (directory / "revoke").exists():
            with lock:
                tokens.clear()
            (directory / "revoke").unlink()
        header = self.headers.get("Authorization", "")
        with lock:
            return header.startswith("Bearer ") and header[7:] in tokens

    def route(self):
        url = urllib.parse.urlsplit(self.path)
        query = dict(urllib.parse.parse_qsl(url.query))
        parts = url.path.split("/")
        profile = parts[4] if len(parts) > 5 and parts[4] in PROFILES else "unknown"
        prefix = f"/codesigningaccounts/{ACCOUNT}/certificateprofiles/{profile}/sign"
        return url.path, query.get("api-version"), prefix

    def do_POST(self):
        path, version, prefix = self.route()
        size = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(size)) if 0 < size < 8192 else {}
        mode = control("mode")
        event(server="sign", method="POST", path=path, fields=sorted(body), size=size,
              digest=body.get("digest"), algorithm=body.get("signatureAlgorithm"))
        if path != prefix or version != API_VERSION:
            return self.reply({}, 404)
        if mode == "unauthorized" or not self.authorised():
            return self.reply({"errorDetail": {"code": "Unauthorized"}}, 401)
        if mode == "forbidden":
            return self.reply({"errorDetail": {"code": "Forbidden"}}, 403)
        if mode == "redirect":
            return self.redirect()
        if mode == "drop":
            self.close_connection = True
            return
        digest = base64.b64decode(body.get("digest", ""), validate=True)
        if set(body) != {"signatureAlgorithm", "digest"} or body["signatureAlgorithm"] != "RS256" or len(digest) != 32:
            return self.reply({}, 400)
        operation = str(uuid.uuid4())
        with lock:
            operations[operation] = {"digest": digest, "polls": 0, "mode": mode, "day": control("day")}
        self.reply({"operationId": operation, "status": "InProgress"}, 202)

    def do_GET(self):
        path, version, prefix = self.route()
        event(server="sign", method="GET", path=path)
        operation = path.removeprefix(prefix + "/")
        with lock:
            state = operations.get(operation)
        if not path.startswith(prefix + "/") or version != API_VERSION or state is None:
            return self.reply({}, 404)
        if not self.authorised():
            return self.reply({}, 401)
        mode = state["mode"]
        state["polls"] += 1
        if mode == "poll-redirect":
            return self.redirect()
        if mode == "poll-drop":
            self.close_connection = True
            return
        if mode == "timeout" or state["polls"] < 2:
            return self.reply({"operationId": operation, "status": "InProgress"})
        if mode == "failed":
            return self.reply({"operationId": operation, "status": "Failed"})
        if mode == "wrong-operation":
            return self.reply({"operationId": str(uuid.uuid4()), "status": "Succeeded"})
        name = {"wrong-anchor": "wrong-anchor", "other-profile": "other-profile",
                "no-codesigning": "no-codesigning", "expired": "expired"}.get(mode, state["day"])
        key = "day1.key" if name == "day1" else "day0.key"
        digest = state["digest"]
        if mode == "wrong-digest":
            digest = bytes(32)
        signature = openssl("pkeyutl", "-sign", "-inkey", key, "-pkeyopt", "digest:sha256", data=digest)
        if mode == "corrupt-signature":
            signature = signature[:-1] + bytes([signature[-1] ^ 1])
        certificate = bundle(name, mode if mode in ("pem", "der-concat") else "pkcs7")
        if mode == "malformed":
            certificate = base64.b64encode(b"not a certificate bundle").decode()
        self.reply({"operationId": operation, "status": "Succeeded",
                    "signature": base64.b64encode(signature).decode(), "signingCertificate": certificate})


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True


sign = Server(("127.0.0.1", 0), Sign)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(directory / "tls.pem", directory / "tls.key")
sign.socket = context.wrap_socket(sign.socket, server_side=True)
imds = Server(("127.0.0.1", 0), Imds)
threading.Thread(target=imds.serve_forever, daemon=True).start()
print(sign.server_port, imds.server_port, flush=True)
sign.serve_forever()
