"""Real TLS/image acceptance: generated IdP, isolated DB and test-only SoftHSM."""
import json
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def exercise(base, org, env, root, directory, context, restart, protected):
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                        urllib.request.HTTPSHandler(context=context))

    def request(path, expected=200, session=None, data=None, form=None, headers=None, method=None):
        # Stay below the production ingress budget; never retry a mutation.
        time.sleep(0.12)
        fields = {"Origin": "https://brigalow.test", **(headers or {})}
        if session:
            fields.update({"Cookie": session[0], "X-CSRF-Token": session[1]})
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            fields["Content-Type"] = "application/json"
        if form is not None:
            body = urllib.parse.urlencode(form).encode()
            fields["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            response = client.open(urllib.request.Request(base+path, data=body, headers=fields, method=method), timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            assert response.code == expected, f"production flow expected HTTP {expected}, received {response.code}"
            return response.headers, response.read(65537)

    def begin(provider):
        headers, _ = request(f"/auth/{org}/{provider}/login", expected=303)
        binding = headers["Set-Cookie"]
        for attribute in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"]:
            assert attribute in binding, "login cookie missing protection"
        binding = binding.split(";", 1)[0]
        protected.append(binding.split("=", 1)[1])
        authorize = urllib.parse.urlsplit(headers["Location"])
        assert authorize.scheme == "https" and authorize.netloc == "idp:8443" and authorize.path == "/authorize"
        # Reach the generated IdP via its loopback port, retaining its configured issuer.
        url = env["BRIGALOW_TEST_IDP_URL"] + authorize.path + "?" + authorize.query
        try:
            client.open(urllib.request.Request(url, headers={"Host": "idp:8443"}), timeout=10)
            raise AssertionError("IdP did not return authorization redirect")
        except urllib.error.HTTPError as response:
            with response:
                assert response.code == 302
                callback = urllib.parse.urlsplit(response.headers["Location"])
        assert callback.scheme == "https" and callback.netloc == "brigalow.test"
        assert callback.path == f"/auth/{org}/{provider}/callback"
        form = dict(urllib.parse.parse_qsl(callback.query, strict_parsing=True))
        assert set(form) == {"state", "code"}
        protected.extend(form.values())
        _, page = request(callback.path+"?"+callback.query)
        assert b"<form" in page and b"/complete" in page
        return binding, form

    def complete(provider, pending):
        binding, form = pending
        path = f"/auth/{org}/{provider}/complete"
        request(path, expected=401, form=form)  # Missing browser binding cannot consume state.
        headers, _ = request(path, expected=303, form=form, headers={"Cookie": binding})
        cookie = next(v for v in headers.get_all("Set-Cookie") if v.startswith("__Host-brigalow="))
        for attribute in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"]:
            assert attribute in cookie, "session cookie missing protection"
        cookie = cookie.split(";", 1)[0]
        protected.append(cookie.split("=", 1)[1])
        request(path, expected=401, form=form, headers={"Cookie": binding})  # Single use.
        _, page = request(f"/orgs/{org}", headers={"Cookie": cookie})
        assert b"LAB MODE" not in page
        csrf = re.search(rb'name="csrf" value="([^"]+)"', page)
        assert csrf, "authenticated page missing CSRF token"
        protected.append(csrf[1].decode())
        return cookie, csrf[1].decode()

    # The application process actually restarts between authorize and token exchange.
    pending = begin("test")
    restart()
    admin = complete("test", pending)
    # Established sessions and CSRF state must also survive a separate process restart.
    restart()
    request(f"/orgs/{org}", session=admin)
    custodian = complete("custodian", begin("custodian"))
    prefix = f"/v1/orgs/{org}"
    project_input = {"name": "Production image acceptance", "request_id": str(uuid.uuid4())}
    request(prefix+"/projects", expected=403, data=project_input, headers={"Cookie": admin[0]})
    _, body = request(prefix+"/projects", expected=201, session=admin, data=project_input)
    project = json.loads(body)["id"]
    request(prefix+"/projects", expected=409, session=admin, data=project_input)
    request(f"/v1/orgs/{uuid.uuid4()}/projects/{project}", expected=404, session=admin)
    project_path = prefix+f"/projects/{project}"
    key_input = {"algorithm": "p256", "purpose": "test", "offline": False}
    request(project_path+"/keys", expected=403, session=admin, data=key_input)
    _, body = request(project_path+"/keys", expected=201, session=custodian, data=key_input)
    key = json.loads(body)
    key_path = prefix+"/keys/"+key["key"]["id"]
    request(key_path+"/activate", session=custodian, data={})
    _, body = request(project_path+"/policies", expected=201, session=admin,
                      data={"name": "image-smoke", "key": key["key"]["id"], "purpose": "test",
                            "claims": {}, "algorithms": ["p256"], "timestamp": "disabled"})
    policy = json.loads(body)["id"]
    _, body = request(prefix+"/tokens", expected=201, session=admin,
                      data={"project": project, "policy": policy, "expires_at": int(time.time())+300})
    credential = json.loads(body)
    protected.append(credential["token"])
    work = Path(directory)/"image-flow"
    work.mkdir(mode=0o700)
    artifact, signature, public_key = [work/name for name in ["artifact.bin", "artifact.sig", "public.der"]]
    artifact.write_bytes(b"Brigalow disposable production-image signing acceptance\n")
    public_key.write_bytes(bytes(key["public_key"]))
    target = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], cwd=root))["target_directory"]
    command = [str(Path(target)/"debug/brig"), "sign", "--server", base, "--org", org,
               "--project", project, "--policy", "image-smoke", "--format", "raw", "--wait", "15",
               "--ca-file", env["BRIGALOW_TEST_DB_CA_FILE"], "--output", str(signature), str(artifact)]
    child = {k:v for k,v in env.items() if not k.startswith("BRIGALOW_")}
    child["BRIGALOW_TOKEN"] = credential["token"]
    result = subprocess.run(command, cwd=root, env=child, capture_output=True, timeout=30)
    assert credential["token"].encode() not in result.stdout+result.stderr, "CLI disclosed credential"
    assert result.returncode == 0 and signature.is_file(), "production-image CLI signing failed; diagnostics withheld"
    verified = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public_key), "-keyform", "DER",
                               "-signature", str(signature), str(artifact)], capture_output=True)
    assert verified.returncode == 0, "production-image signature failed independent verification"
    artifact.write_bytes(b"modified artifact\n")
    rejected = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public_key), "-keyform", "DER",
                               "-signature", str(signature), str(artifact)], capture_output=True)
    assert rejected.returncode != 0, "signature verification accepted modified artifact"
    request(key_path+"/disable", session=custodian, data={})
    signature.unlink()
    result = subprocess.run(command, cwd=root, env=child, capture_output=True, timeout=30)
    assert result.returncode != 0 and not signature.exists(), "disabled key produced output"
    rejected_id = re.search(rb"Submitting request ([0-9a-f-]{36})", result.stderr)
    assert rejected_id, "disabled-key test did not reach request submission"
    _, body = request(prefix+"/requests/"+rejected_id[1].decode(), session=admin)
    rejected_request = json.loads(body)
    assert rejected_request["state"] == "rejected" and rejected_request["failure"] == "key_binding"
    assert rejected_request["output"] is None, "disabled-key request persisted a signature"
    request(prefix+"/tokens/"+credential["id"], expected=204, session=admin, method="DELETE")
    request(project_path+"/policies/image-smoke", expected=401, headers={"Authorization": "Bearer "+credential["token"]})
    request(f"/orgs/{org}/logout", expected=204, session=admin, form={"csrf": admin[1]})
    request(f"/orgs/{org}", expected=401, session=admin)
    print("AT-OPS-05: real TLS/image OIDC login, pending/session restart survival, CSRF, roles, tenant isolation, CLI signing/OpenSSL verification, key disable and token/session revocation passed")
