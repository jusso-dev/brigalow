"""Copy the one test executable Cargo reports building.

Usage: cargo test ... --no-run --message-format=json-render-diagnostics \
           | python3 copy_test_binary.py <test-name> <destination>

Cargo's own JSON names the executable, so this works whatever directory layout
the toolchain uses (`target/debug/deps/` before Rust 1.100,
`target/debug/build/<package>/<hash>/out/` from 1.100).
"""

import json
import shutil
import sys

name, destination = sys.argv[1], sys.argv[2]
found = []
for line in sys.stdin:
    if not line.startswith("{"):
        continue
    message = json.loads(line)
    if (
        message.get("reason") == "compiler-artifact"
        and message.get("executable")
        and message.get("profile", {}).get("test")
        and message.get("target", {}).get("name") == name
    ):
        found.append(message["executable"])
if len(found) != 1:
    sys.exit(f"expected exactly one test executable named {name!r}, found {found}")
shutil.copy2(found[0], destination)
