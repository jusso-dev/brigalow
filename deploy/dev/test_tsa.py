"""Disposable, HTTPS RFC 3161 service. Never use outside the acceptance harness."""
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import ssl
import subprocess
import tempfile
root=Path(tempfile.mkdtemp(prefix="tsa-"))
(root/"serial").write_text("01")
(root/"tsa.cnf").write_text(f"""[tsa]
default_tsa=tsa_config
[tsa_config]
serial={root}/serial
crypto_device=builtin
signer_cert=/run/secrets/tsa_cert
certs=/run/secrets/tsa_ca
signer_key=/run/secrets/tsa_key
signer_digest=sha256
default_policy=1.2.3.4.1
digests=sha256
accuracy=secs:1
ordering=yes
tsa_name=yes
ess_cert_id_chain=no
ess_cert_id_alg=sha256
""")
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_POST(self):
        size=int(self.headers.get("Content-Length","0"))
        if size<1 or size>4096 or self.path=="/down":
            self.send_error(503); return
        query=self.rfile.read(size)
        (root/"query").write_bytes(query)
        result=subprocess.run(["openssl","ts","-reply","-config",str(root/"tsa.cnf"),"-queryfile",str(root/"query"),"-out",str(root/"response")],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if result.returncode:
            self.send_error(400);return
        response=(root/"response").read_bytes()
        if self.path=="/bad-signature": response=response[:-1]+bytes([response[-1]^1])
        self.send_response(200)
        self.send_header("Content-Type","application/timestamp-reply")
        self.send_header("Content-Length",str(len(response)))
        self.end_headers();self.wfile.write(response)
server=HTTPServer(("0.0.0.0",8443),Handler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/run/secrets/server_cert","/run/secrets/server_key")
server.socket=context.wrap_socket(server.socket,server_side=True)
server.serve_forever()
