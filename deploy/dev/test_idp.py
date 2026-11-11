"""Local acceptance-test IdP only. No accounts, production endpoints or persistent keys."""
import base64, hashlib, json, secrets, ssl, time, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, urlencode
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
key = rsa.generate_private_key(public_exponent=65537,key_size=3072)
bad_key = rsa.generate_private_key(public_exponent=65537,key_size=3072)
codes = {}
lock = threading.Lock()
def b64(value): return base64.urlsafe_b64encode(value).rstrip(b"=").decode()
def integer(value): return b64(value.to_bytes((value.bit_length()+7)//8,"big"))
def token(claims, bad=False, alg="RS256"):
    header={"alg":alg,"kid":"test","typ":"JWT"}
    message=b64(json.dumps(header).encode())+"."+b64(json.dumps(claims).encode())
    signature=(bad_key if bad else key).sign(message.encode(),padding.PKCS1v15(),hashes.SHA256()) if alg!="none" else b""
    return message+"."+b64(signature)
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def reply(self,status,value,headers=None):
        body=json.dumps(value).encode();self.send_response(status)
        self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(body)))
        for name,value in (headers or {}).items():self.send_header(name,value)
        self.end_headers();self.wfile.write(body)
    def issuer(self):return "https://"+self.headers["Host"]
    def do_GET(self):
        url=urlparse(self.path)
        if url.path=="/jwks":
            public=key.public_key().public_numbers()
            return self.reply(200,{"keys":[{"kty":"RSA","kid":"test","alg":"RS256","use":"sig","n":integer(public.n),"e":integer(public.e)}]})
        if url.path=="/authorize":
            q={k:v[0] for k,v in parse_qs(url.query).items()}
            required=("state","nonce","client_id","redirect_uri","code_challenge")
            if any(k not in q for k in required) or q.get("code_challenge_method")!="S256" or q.get("response_type")!="code":return self.reply(400,{})
            # Only the test application's fixed HTTPS origin can receive codes.
            if not q["redirect_uri"].startswith("https://brigalow.test/auth/"):return self.reply(400,{})
            code=secrets.token_urlsafe(32)
            with lock:
                codes[code]={**q,"expires":time.time()+60}
            return self.reply(302,{}, {"Location":q["redirect_uri"]+"?"+urlencode({"state":q["state"],"code":code})})
        return self.reply(404,{})
    def do_POST(self):
        size=int(self.headers.get("Content-Length",0))
        if size>65536:return self.reply(413,{})
        data=self.rfile.read(size)
        if self.path=="/mint":
            request=json.loads(data); claims={"iss":self.issuer(),"sub":"test-workload","iat":int(time.time()),"nbf":int(time.time())-1,"exp":int(time.time())+300,**request["claims"]}
            return self.reply(200,{"token":token(claims,request.get("bad",False),request.get("alg","RS256"))})
        if self.path=="/token":
            q={k:v[0] for k,v in parse_qs(data.decode()).items()}
            with lock: pending=codes.pop(q.get("code"),None)
            if not pending or pending["expires"]<=time.time():return self.reply(400,{})
            challenge=b64(hashlib.sha256(q.get("code_verifier","").encode()).digest())
            if q.get("grant_type")!="authorization_code" or challenge!=pending["code_challenge"] or q.get("client_id")!=pending["client_id"] or q.get("redirect_uri")!=pending["redirect_uri"]:return self.reply(400,{})
            claims={"iss":self.issuer(),"sub":"test-human","aud":pending["client_id"],"iat":int(time.time()),"exp":int(time.time())+300,"nonce":pending["nonce"],"groups":["admins"]}
            # Auth-code tests request deliberately invalid ID tokens using distinct client IDs.
            if pending["client_id"]=="wrong-audience":claims["aud"]="unrelated"
            if pending["client_id"]=="expired":claims["exp"]=int(time.time())-1
            if pending["client_id"]=="wrong-nonce":claims["nonce"]="unrelated"
            return self.reply(200,{"id_token":token(claims),"access_token":secrets.token_urlsafe(32),"token_type":"Bearer"})
        return self.reply(404,{})
server=ThreadingHTTPServer(("0.0.0.0",8443),Handler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/run/secrets/server_cert","/run/secrets/server_key")
server.socket=context.wrap_socket(server.socket,server_side=True)
server.serve_forever()
