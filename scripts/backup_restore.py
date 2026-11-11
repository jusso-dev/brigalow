"""AT-OPS-03: dump/wipe/restore a uniquely named disposable DB, never the source DB."""
import json
import pathlib
import secrets
import subprocess

def drill(compose, env, root, directory, brig):
    scratch = "brigalow_restore_" + secrets.token_hex(6)
    def command(args, data=None):
        result = subprocess.run(compose + args, cwd=root, env=env, input=data, capture_output=True)
        if result.returncode:
            raise AssertionError("backup drill command failed; diagnostics withheld")
        return result.stdout
    def sql(query, db="brigalow"):
        return command(["exec", "-T", "postgres", "psql", "-U", "postgres", "-d", db, "-At", "-v", "ON_ERROR_STOP=1", "-c", query]).decode().strip()
    public = json.loads(command(["exec", "-T", "softhsm", "cat", "/tmp/recovery-key.json"]))
    pending = sql("SELECT org_id::text||','||project_id::text FROM brigalow.sign_requests WHERE state='awaiting_approval' LIMIT 1")
    assert pending, "backup drill needs a real pending approval from API acceptance"
    org, project = pending.split(",")
    record = dict(public, project=project, backend="recovery-hsm", state="active", offline=False,
                  trust="lab", anchor=None, chain=[], revision=0)
    record_json = json.dumps(record).replace("'", "''")
    sql(f"INSERT INTO brigalow.signing_keys(org_id,id,project_id,record) VALUES('{org}','{public['key']['id']}','{project}','{record_json}'::jsonb)")
    states = "SELECT org_id::text||':'||id::text||':'||state FROM brigalow.sign_requests ORDER BY org_id,id"
    expected = sql(states)
    dump = command(["exec", "-T", "postgres", "pg_dump", "-U", "postgres", "-Fc", "brigalow"])
    created = False
    try:
        command(["exec", "-T", "postgres", "createdb", "-U", "postgres", scratch]); created = True
        command(["exec", "-T", "postgres", "pg_restore", "-U", "postgres", "-d", scratch, "--exit-on-error"], dump)
        # Wipe only the scratch copy, then perform the recovery from the dump again.
        command(["exec", "-T", "postgres", "dropdb", "-U", "postgres", scratch]); created = False
        command(["exec", "-T", "postgres", "createdb", "-U", "postgres", scratch]); created = True
        command(["exec", "-T", "postgres", "pg_restore", "-U", "postgres", "-d", scratch, "--exit-on-error"], dump)
        assert sql(states, scratch) == expected, "restore changed request states"
        restored = json.loads(sql(f"SELECT record FROM brigalow.signing_keys WHERE org_id='{org}' AND id='{public['key']['id']}'", scratch))
        assert restored == record
        command(["exec", "-T", "softhsm", "sh", "-c", "cat > /tmp/restored-key.json"], json.dumps(restored).encode())
        command(["exec", "-T", "softhsm", "python3", "/hsm_recover.py"])
        orgs = sql("SELECT DISTINCT org_id FROM brigalow.audit_entries ORDER BY org_id", scratch).splitlines()
        assert orgs
        for organisation in orgs:
            entries = sql(f"SELECT entry FROM brigalow.audit_entries WHERE org_id='{organisation}' ORDER BY seq", scratch)
            path = pathlib.Path(directory) / "restored-audit.jsonl"
            path.write_text(entries + "\n")
            result = subprocess.run([brig, "audit", "verify", str(path)], capture_output=True)
            assert result.returncode == 0, "restored audit chain failed verification"
        checkpoints = "SELECT org_id::text||':'||seq::text||':'||record::text FROM brigalow.audit_checkpoints ORDER BY org_id,seq"
        assert sql(checkpoints, scratch) == sql(checkpoints), "restore changed signed checkpoints"
        print("AT-OPS-03: scratch DB wiped/restored; all audit chains and request states verified; restored HSM reference signs and OpenSSL verifies")
    finally:
        if created:
            command(["exec", "-T", "postgres", "dropdb", "-U", "postgres", scratch])
