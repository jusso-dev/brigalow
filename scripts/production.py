#!/usr/bin/env python3
"""Validate operator inputs before invoking the production Compose reference."""
import argparse
import os
from pathlib import Path
import re
import stat
import subprocess


def validate(env):
    if not re.fullmatch(r"[^\s]+@sha256:[a-f0-9]{64}", env.get("BRIGALOW_IMAGE", "")):
        raise ValueError("BRIGALOW_IMAGE must use an immutable sha256 digest")
    for name, uid, required in [("BRIGALOW_CONFIG_DIR", 10001, ("config.toml", "identity.json")),
                                ("BRIGALOW_TLS_DIR", 101, ("tls.crt", "tls.key"))]:
        path = Path(env.get(name, ""))
        if not path.is_absolute():
            raise ValueError("private configuration directories must be absolute")
        info = path.lstat()
        if info.st_uid != uid:
            raise ValueError("private directory owner must match its container UID")
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("private configuration directories must be regular directories with mode 0700")
        if not all((path / file).is_file() for file in required):
            raise ValueError("required production configuration files are missing")
        for file in path.iterdir():
            info = file.lstat()
            if info.st_uid != uid:
                raise ValueError("private file owner must match its container UID")
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
                raise ValueError("production configuration must contain only regular 0600 files")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("compose_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        validate(os.environ)
    except (ValueError, OSError) as error:
        # Filesystem diagnostics can contain private paths; never echo them.
        parser.exit(2, (str(error) if isinstance(error, ValueError) else "cannot inspect private configuration") + "\n")
    root = Path(__file__).resolve().parents[1]
    return subprocess.run(["docker", "--context", args.context, "compose", "-f",
                           str(root / "deploy/production/compose.yml"),
                           *(args.compose_args or ["config", "--quiet"])]).returncode


if __name__ == "__main__":
    raise SystemExit(main())
