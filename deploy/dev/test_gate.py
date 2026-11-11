"""Fault injection around the reference gate; loopback tests only."""
import importlib.util
import pathlib
import sys
import time

path = pathlib.Path(__file__).resolve().parents[2] / "examples/gates/hash_validation.py"
spec = importlib.util.spec_from_file_location("reference_gate", path)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

class Faults(gate.Handler):
    def evaluate(self, request):
        if self.path == "/timeout":
            time.sleep(2)
        if self.path == "/fail":
            return False
        if self.path == "/rebuild":
            return super().evaluate(request)
        return True

    def respond(self, reply):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/pass")
            self.end_headers()
        elif self.path == "/bad-hmac":
            body = gate.json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Brigalow-Signature", gate.base64.b64encode(bytes(32)).decode())
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/replay":
            reply["nonce"] = "00000000-0000-0000-0000-000000000000"
            super().respond(reply)
        elif self.path == "/wrong-digest":
            reply["digest"] = [0] * 32
            super().respond(reply)
        elif self.path == "/oversize":
            reply["padding"] = "x" * 10000
            super().respond(reply)
        else:
            super().respond(reply)

if __name__ == "__main__":
    gate.serve(Faults, *sys.argv[1:])
