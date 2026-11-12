#!/usr/bin/env python3
"""Boot-time materialisation for the Azure reference VM.

Reads runtime secrets and non-secret configuration from Key Vault over its private endpoint with
the VM's user-assigned managed identity, writes them into private tmpfs directories (0700 directories, 0600 files, owned by the
container UIDs 10001 and 101), then starts the reviewed Compose reference through
scripts/production.py, which re-checks every guard. Owner/migration credentials are never read.

Values are never printed. Errors are reported as fixed messages only.
"""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request

IMDS = "http://169.254.169.254/metadata/identity/oauth2/token"
VAULT_RESOURCE = "https://vault.azure.net"
VAULT_API = "7.4"
ROOT = Path("/opt/brigalow")
RUN = Path("/run/brigalow")
SERVER_UID, PROXY_UID = 10001, 101
SECRETS = {
    "image": "brigalow-image",
    "config": "brigalow-config-toml",
    "identity": "brigalow-identity-json",
    "anchor": "brigalow-artifact-signing-root",
    "db_password": "brigalow-db-runtime-password",
    "login_key": "brigalow-login-state-key",
    "tls_crt": "brigalow-tls-crt",
    "tls_key": "brigalow-tls-key",
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise urllib.error.URLError("redirect refused")


# No environment proxy and no redirects for every call below.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def fail(message):
    print("brigalow-boot: " + message, file=sys.stderr)
    raise SystemExit(1)


def get_json(url, headers, limit=1 << 20):
    request = urllib.request.Request(url, headers=headers)
    with OPENER.open(request, timeout=10) as response:
        if response.status != 200:
            raise ValueError("unexpected status")
        body = response.read(limit + 1)
    if len(body) > limit:
        raise ValueError("response too large")
    return json.loads(body)


def token(client_id):
    query = urllib.parse.urlencode({"api-version": "2018-02-01", "resource": VAULT_RESOURCE,
                                    "client_id": client_id})
    value = get_json(IMDS + "?" + query, {"Metadata": "true"}, 65536)["access_token"]
    if not isinstance(value, str) or not value:
        raise ValueError("no token")
    return value


def read_secrets(vault, client_id):
    if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]", vault):
        raise ValueError("invalid vault name")
    bearer = token(client_id)
    values = {}
    for key, name in SECRETS.items():
        url = f"https://{vault}.vault.azure.net/secrets/{name}?api-version={VAULT_API}"
        value = get_json(url, {"Authorization": "Bearer " + bearer})["value"]
        if not isinstance(value, str):
            raise ValueError("invalid secret")
        values[key] = value
    return values


def private_dir(path, uid):
    if path.is_symlink():
        raise ValueError("symlinked directory")
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(mode=0o700, parents=False)
    os.chmod(path, 0o700)
    os.chown(path, uid, uid)


def private_file(directory, name, data, uid):
    path = directory / name
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data if isinstance(data, bytes) else data.encode())
    os.chmod(path, 0o600)
    os.chown(path, uid, uid)


def materialise(values, run=RUN, server_uid=SERVER_UID, proxy_uid=PROXY_UID,
                ca_bundle=Path("/etc/ssl/certs/ca-certificates.crt")):
    """Write the two private directories. Returns them as (config_dir, tls_dir)."""
    image = values["image"].strip()
    if not re.fullmatch(r"[^\s]+@sha256:[a-f0-9]{64}", image):
        raise ValueError("image must be pinned by sha256 digest")
    key = base64.b64decode(values["login_key"].strip(), validate=True)
    if len(key) != 32:
        raise ValueError("login state key must be base64 of 32 bytes")
    run.mkdir(mode=0o755, exist_ok=True)
    config, tls = run / "config", run / "tls"
    private_dir(config, server_uid)
    private_dir(tls, proxy_uid)
    private_file(config, "config.toml", values["config"], server_uid)
    private_file(config, "identity.json", values["identity"], server_uid)
    private_file(config, "db-password", values["db_password"].strip() + "\n", server_uid)
    private_file(config, "login-key", values["login_key"].strip() + "\n", server_uid)
    private_file(config, "db-ca.pem", ca_bundle.read_bytes(), server_uid)
    anchor = values["anchor"].strip()
    if anchor != "-":
        private_file(config, "artifact-signing-root.der", base64.b64decode(anchor, validate=True), server_uid)
    private_file(tls, "tls.crt", values["tls_crt"], proxy_uid)
    private_file(tls, "tls.key", values["tls_key"], proxy_uid)
    return image, config, tls


def main():
    # The directories are rewritten on every start, so recreate the containers: a container left
    # running from an earlier start would keep a bind mount to the removed directory.
    command = sys.argv[1:] or ["up", "-d", "--force-recreate"]
    config, tls, image_file = RUN / "config", RUN / "tls", RUN / "image"
    if command == ["down"] and image_file.is_file():
        # Stopping needs no secrets: reuse the directories written at start.
        image = image_file.read_text().strip()
    else:
        settings = json.loads((ROOT / "boot.json").read_text())
        try:
            values = read_secrets(settings["vault"], settings["client_id"])
            image, config, tls = materialise(values)
            image_file.write_text(image + "\n")
        except Exception:
            fail("cannot materialise configuration from Key Vault (details withheld)")
    env = {k: v for k, v in os.environ.items() if not k.startswith("BRIGALOW_")}
    env.update({"BRIGALOW_IMAGE": image, "BRIGALOW_CONFIG_DIR": str(config),
                "BRIGALOW_TLS_DIR": str(tls), "BRIGALOW_LISTEN_IP": "0.0.0.0",
                "BRIGALOW_HTTPS_PORT": "443"})
    raise SystemExit(subprocess.run([sys.executable, str(ROOT / "scripts/production.py"),
                                     "--context", "default", *command], env=env).returncode)


if __name__ == "__main__":
    main()
