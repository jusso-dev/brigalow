#!/usr/bin/env python3
"""Verify manifest signature and every payload digest. Pin the public key independently."""
import argparse
import hashlib
import json
import pathlib
import subprocess
p=argparse.ArgumentParser()
p.add_argument("directory",type=pathlib.Path)
p.add_argument("--public-key",required=True,type=pathlib.Path)
a=p.parse_args()
result=subprocess.run(["openssl","dgst","-sha256","-verify",str(a.public_key),"-signature",str(a.directory/"manifest.sig"),str(a.directory/"manifest.json")],capture_output=True)
assert result.returncode==0,"release manifest signature invalid"
manifest=json.loads((a.directory/"manifest.json").read_text())
assert manifest["version"]==1 and manifest["trust"]=="lab"
assert manifest["files"] and len(manifest["files"])<=20
for name, digest in manifest["files"].items():
    assert pathlib.Path(name).name==name and name not in [".",".."],"invalid artifact path"
    assert hashlib.sha256((a.directory/name).read_bytes()).hexdigest()==digest,"artifact digest mismatch"
print("Lab release signature and payload digests verified; identity depends on independently trusting the public key")
