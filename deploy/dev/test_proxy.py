"""Loopback-only TLS proxy for CLI acceptance tests; never logs credentials or bodies."""
from http.server import HTTPServer,BaseHTTPRequestHandler
import http.client
import ssl
import sys
backend=int(sys.argv[1])
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def proxy(self):
        size=int(self.headers.get("Content-Length","0"))
        if size>65536:self.send_error(413);return
        connection=http.client.HTTPConnection("127.0.0.1",backend,timeout=20)
        try:
            headers={k:v for k,v in self.headers.items() if k.lower() not in ("host","connection")}
            connection.request(self.command,self.path,self.rfile.read(size),headers)
            response=connection.getresponse();body=response.read(1048577)
            self.send_response(response.status)
            self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(body)))
            self.end_headers();self.wfile.write(body)
        finally: connection.close()
    do_GET=proxy
    do_POST=proxy
server=HTTPServer(("127.0.0.1",0),Handler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[2],sys.argv[3])
server.socket=context.wrap_socket(server.socket,server_side=True)
print(server.server_port,flush=True)
server.serve_forever()
