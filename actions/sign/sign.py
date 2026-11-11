"""GitHub OIDC wrapper. Secrets remain in memory/environment, never argv or output."""
import json
import os
import ssl
import subprocess
import urllib.parse
import urllib.request
import uuid

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("redirect refused")


def sign(env):
    org = str(uuid.UUID(env["BRIGALOW_INPUT_ORG"]))
    parts = urllib.parse.urlsplit(env["ACTIONS_ID_TOKEN_REQUEST_URL"])
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ValueError("invalid OIDC endpoint")
    query = [(k, v) for k, v in urllib.parse.parse_qsl(parts.query) if k != "audience"]
    query.append(("audience", "brigalow:" + org))
    url = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                         urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
    with client.open(request, timeout=10) as response:
        data = response.read(65537)
    if len(data) > 65536:
        raise ValueError("OIDC response too large")
    token = json.loads(data)["value"]
    if not isinstance(token, str) or not token or len(token) > 32768:
        raise ValueError("invalid OIDC token")
    args = [env["BRIGALOW_BINARY"], "sign"]
    for name in ["server", "org", "project", "policy", "output", "format"]:
        args.extend(["--" + name, env["BRIGALOW_INPUT_" + name.upper()]])
    if env.get("BRIGALOW_INPUT_CA_FILE"):
        args.extend(["--ca-file", env["BRIGALOW_INPUT_CA_FILE"]])
    args.append(env["BRIGALOW_INPUT_FILE"])
    child = dict(env, BRIGALOW_TOKEN=token)
    # The CLI needs the verified ID token only, not GitHub's token-minting credential.
    child.pop("ACTIONS_ID_TOKEN_REQUEST_TOKEN", None)
    child.pop("ACTIONS_ID_TOKEN_REQUEST_URL", None)
    subprocess.run(args, env=child, check=True)


if __name__ == "__main__":
    try:
        sign(os.environ)
    except Exception:
        raise SystemExit("Brigalow OIDC signing failed; inspect request status before retrying") from None
