"""AT-OPS-04/05: disposable production-mode image/bootstrap/TLS checks. No deployment."""
import concurrent.futures
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import time
import urllib.error
import urllib.request
import uuid

PROXY = "nginxinc/nginx-unprivileged:stable-bookworm@sha256:cd33960e98e93d4d63385790ff7f8f5bf2ca95184c581b7f42ae8aea1139fbfc"


def bootstrap(env, root, restricted=False):
    binary = Path(json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], cwd=root))["target_directory"])/"debug/brigalow-admin"
    child = {k: v for k, v in env.items() if not k.startswith("BRIGALOW_")}
    child.update(BRIGALOW_MODE="production", BRIGALOW_BACKEND="disabled",
                 BRIGALOW_DB_HOST="127.0.0.1", BRIGALOW_DB_PORT=env["BRIGALOW_TEST_DB_PORT"],
                 BRIGALOW_DB_USER="brigalow_runtime" if restricted else "postgres",
                 BRIGALOW_DB_CA_FILE=env["BRIGALOW_TEST_DB_CA_FILE"],
                 BRIGALOW_DB_PASSWORD_FILE=env["BRIGALOW_TEST_APP_PASSWORD_FILE" if restricted else "BRIGALOW_TEST_ADMIN_PASSWORD_FILE"])
    def command(*args, success=True):
        result = subprocess.run([str(binary), *args], cwd=root, env=child, capture_output=True)
        assert (result.returncode == 0) == success, "operator CLI result unexpected; diagnostics withheld"
        password = Path(child["BRIGALOW_DB_PASSWORD_FILE"]).read_bytes()
        assert password not in result.stdout + result.stderr, "operator credential disclosed"
    command("migrate", success=not restricted)
    if not restricted:
        command("migrate")
        org = str(uuid.uuid4())
        command("org-create", "--org", org, "--name", "Bootstrap acceptance fixture")
        command("org-create", "--org", org, "--name", "Bootstrap acceptance fixture")
        command("org-create", "--org", org, "--name", "conflicting name", success=False)
    print("AT-OPS-04: operator CLI restricted-role refusal" if restricted else "AT-OPS-04: fresh database migration and idempotent organisation bootstrap")


def qualify(compose, env, root, directory):
    docker, project = compose[:3], compose[5]
    runtime, test_image = project+"-production:local", project+"-production-test:local"
    config_volume, tls_volume = project+"-prod-config", project+"-prod-tls"
    server, proxy = project+"-prod-server", project+"-prod-proxy"
    keeper = project+"-prod-config-keeper"
    source = Path(directory)/"production-image"
    app, tls = source/"app", source/"tls"
    app.mkdir(parents=True); tls.mkdir()
    protected = [secrets.token_hex(24), secrets.token_hex(24), secrets.token_hex(24)]
    (app/"hsm_pin").write_text(protected[0]); (app/"hsm_so_pin").write_text(protected[1])
    (app/"db_password").write_bytes((Path(directory)/"app_password").read_bytes())
    (app/"ca.crt").write_bytes((Path(directory)/"ca.crt").read_bytes())
    (tls/"tls.crt").write_bytes((Path(directory)/"server.crt").read_bytes())
    (tls/"tls.key").write_bytes((Path(directory)/"server.key").read_bytes())
    (app/"softhsm.conf").write_text("directories.tokendir = /tokens\nobjectstore.backend = file\nlog.level = ERROR\n")
    (app/"config.toml").write_text('''mode = "production"
backend = "pkcs11"
db_host = "postgres"
db_user = "brigalow_runtime"
db_password_file = "/run/brigalow/db_password"
db_ca_file = "/run/brigalow/ca.crt"
hsm_module = "/usr/lib/softhsm/libsofthsm2.so"
hsm_token = "production-test"
hsm_pin_file = "/run/brigalow/hsm_pin"
''')
    (app/"identity.json").write_text(json.dumps(dict(public_url="https://brigalow.test", ca_file="/run/brigalow/ca.crt", authorities=[dict(org_id=str(uuid.uuid4()),name="test",issuer="https://idp:8443",jwks_url="https://idp:8443/jwks",human=dict(client_id="valid",authorization_url="https://idp:8443/authorize",token_url="https://idp:8443/token",group_roles={"admins":"org_admin"}))])))
    for path in [*app.iterdir(), *tls.iterdir()]: path.chmod(0o600)
    def call(*args, **kwargs):
        return subprocess.run(docker+list(args), cwd=root, env=env, check=True, **kwargs)
    restricted = ["--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=1g", "--cpus=2"]
    try:
        validation_env = dict(env, BRIGALOW_IMAGE="brigalow@sha256:"+"1"*64, BRIGALOW_CONFIG_DIR=str(app), BRIGALOW_TLS_DIR=str(tls))
        subprocess.run(docker+["compose", "-f", "deploy/production/compose.yml", "config", "--quiet"], cwd=root, env=validation_env, check=True)
        call("build", "--target", "production", "-t", runtime, ".")
        call("build", "--target", "test-runtime", "-t", test_image, ".")
        call("pull", PROXY)
        info = json.loads(call("image", "inspect", runtime, capture_output=True, text=True).stdout)[0]
        assert info["Config"]["User"] == "10001:10001"
        assert "BRIGALOW_MODE=production" in info["Config"]["Env"]
        call("run", "--rm", "--network=none", *restricted, runtime, "sh", "-ec", "test ! -e /usr/lib/softhsm/libsofthsm2.so; test ! -e /usr/bin/cargo; brigalow-admin --help >/dev/null")
        for volume in [config_volume, tls_volume]:
            call("volume", "create", "--opt", "type=tmpfs", "--opt", "device=tmpfs", "--opt", "o=size=4194304", volume, stdout=subprocess.DEVNULL)
        # Keep tmpfs volumes mounted until consumers exit; stopping the last mount erases them.
        call("run", "-d", "--name", keeper, "--network=none", "--user=0:0", "--read-only", "--cap-drop=ALL", "--cap-add=CHOWN", "--cap-add=DAC_OVERRIDE", "--security-opt=no-new-privileges",
             "-v", f"{source}:/input:ro", "-v", f"{config_volume}:/app", "-v", f"{tls_volume}:/tls", runtime,
             "sh", "-ec", "cp /input/app/* /app/; cp /input/tls/* /tls/; chmod 0700 /app /tls; chmod 0600 /app/* /tls/*; chown -R 10001:10001 /app; chown -R 101:101 /tls; touch /app/ready; exec sleep infinity", stdout=subprocess.DEVNULL)
        for _ in range(100):
            ready = subprocess.run(docker+["exec", keeper, "test", "-f", "/app/ready"], capture_output=True)
            if ready.returncode == 0: break
            time.sleep(0.1)
        else: raise AssertionError("private test configuration was not initialised")
        for overrides in [["-e","BRIGALOW_BACKEND=disabled"],["-e","BRIGALOW_BACKEND=pkcs11","-e","BRIGALOW_HSM_MODULE=/missing-provider.so","-e","BRIGALOW_IDENTITY_FILE=/run/brigalow/identity.json"]]:
            refused = subprocess.run(docker+["run","--rm","--network=none",*restricted,"-v",f"{config_volume}:/run/brigalow:ro","-e","BRIGALOW_CONFIG=/run/brigalow/config.toml",*overrides,runtime],capture_output=True)
            assert refused.returncode != 0, "production container accepted unavailable signing backend"
        call("run", "-d", "--name", server, "--network", project+"_tool-tests", "--network-alias", "server", *restricted,
             "--tmpfs", "/tokens:rw,noexec,nosuid,size=16m,uid=10001,gid=10001,mode=0700", "-v", f"{config_volume}:/run/brigalow:ro",
             "-e", "BRIGALOW_CONFIG=/run/brigalow/config.toml", "-e", "BRIGALOW_IDENTITY_FILE=/run/brigalow/identity.json", "-e", "SOFTHSM2_CONF=/run/brigalow/softhsm.conf",
             test_image, "sh", "-ec", 'softhsm2-util --init-token --free --label production-test --pin "$(cat /run/brigalow/hsm_pin)" --so-pin "$(cat /run/brigalow/hsm_so_pin)" >/dev/null; exec /usr/local/bin/brigalow-server', stdout=subprocess.DEVNULL)
        call("create", "--name", proxy, "--network", project+"_default", *restricted, "--user=101:101",
             "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m,uid=101,gid=101,mode=0700", "-v", f"{tls_volume}:/run/tls:ro",
             "-v", f"{root}/deploy/production/nginx.conf:/etc/nginx/nginx.conf:ro", "-p", "127.0.0.1::8443", "--entrypoint", "nginx", PROXY, "-g", "daemon off;", stdout=subprocess.DEVNULL)
        call("network", "connect", project+"_tool-tests", proxy)
        call("start", proxy, stdout=subprocess.DEVNULL)
        address = call("port", proxy, "8443", capture_output=True, text=True).stdout.strip()
        context = ssl.create_default_context(cafile=str(Path(directory)/"ca.crt"))
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        deadline = time.monotonic()+40
        while True:
            try:
                with client.open("https://"+address+"/healthz", timeout=5) as response:
                    body = json.loads(response.read())
                    assert body == {"status":"ok","mode":"production","signing_available":True}
                    assert response.headers["Strict-Transport-Security"] == "max-age=31536000"
                    assert response.headers["X-Content-Type-Options"] == "nosniff"
                break
            except (urllib.error.URLError, ConnectionError):
                if time.monotonic() > deadline: raise AssertionError("production readiness failed; diagnostics withheld") from None
                time.sleep(0.2)
        def request(path, data=None):
            req=urllib.request.Request("https://"+address+path,data=data,headers={"Authorization":"Bearer "+protected[2]})
            try:
                with client.open(req,timeout=5) as response: return response.status
            except urllib.error.HTTPError as error: return error.code
        assert request("/oversized", b"x"*65537)==413
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
            statuses=list(pool.map(lambda _:request("/livez?code="+protected[2]),range(100)))
        assert 429 in statuses and 200 in statuses, "ingress budget not enforced"
        for container in [server,proxy]:
            info=json.loads(call("inspect",container,capture_output=True,text=True).stdout)[0]
            assert info["HostConfig"]["ReadonlyRootfs"] and info["HostConfig"]["CapDrop"]==["ALL"]
            logs=call("logs",container,capture_output=True).stdout+call("logs",container,capture_output=True).stderr
            for secret in protected+[str((app/"db_password").read_text())]:
                assert secret.encode() not in logs, "production fixture credential disclosure"
        print("AT-OPS-05: non-root/read-only production-mode HSM container, TLS, body/rate limits and credential redaction passed")
    except Exception:
        # Only static status and redacted fixture diagnostics; never inspect container env.
        for name in [proxy, server]:
            result = subprocess.run(docker+["logs", name], capture_output=True, text=True)
            diagnostic = result.stdout + result.stderr
            for value in protected + [(app/"db_password").read_text()]:
                diagnostic = diagnostic.replace(value, "[REDACTED]")
            print(diagnostic[-2000:])
        raise
    finally:
        for name in [proxy,server,keeper]: subprocess.run(docker+["rm","-f",name],capture_output=True)
        for volume in [config_volume,tls_volume]: subprocess.run(docker+["volume","rm",volume],capture_output=True)
        for image in [test_image,runtime]: subprocess.run(docker+["image","rm",image],capture_output=True)
