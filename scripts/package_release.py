#!/usr/bin/env python3
"""Build a local release bundle and CycloneDX SBOM; signing is a later control-plane step.

`--trust lab` (default) keeps the version 1 lab manifest. `--trust operator` writes the strict
version 2 operator manifest as frozen canonical bytes and requires a clean git checkout so the
recorded source commit describes the packaged source.
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import tarfile

from verify_release import ARCHIVE, SBOM, Rejected, canonical, operator_schema

FILES = ["brig", "brigalow-server", "brigalow-ca", "brigalow-audit", "brigalow-admin", "libbrigalow_pkcs11.so"]


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def operator_manifest(source_commit, archive_digest, sbom_digest):
    """The version 2 operator manifest. Its canonical encoding is exactly what gets signed."""
    manifest = dict(version=2, trust="operator", provenance="self-hosted", source_commit=source_commit,
                    digest_algorithm="sha256", artifacts=[
                        dict(role="archive", name=ARCHIVE, sha256=archive_digest),
                        dict(role="sbom", name=SBOM, sha256=sbom_digest)])
    operator_schema(manifest)
    return canonical(manifest)


def write_new(path, data):
    with open(path, "xb") as handle:
        handle.write(data)


def clean_commit(source):
    """Full HEAD commit of a checkout with no staged, unstaged or untracked changes."""
    status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=source,
                            capture_output=True, text=True)
    if status.returncode:
        raise Rejected("operator packaging requires a git checkout")
    if status.stdout.strip():
        raise Rejected("operator packaging requires a clean checkout; commit or remove local changes")
    return subprocess.check_output(["git", "rev-parse", "--verify", "HEAD^{commit}"], cwd=source, text=True).strip()


def package(binaries, output, trust="lab", source=None):
    source = pathlib.Path(source or pathlib.Path(__file__).resolve().parents[1])
    revision = clean_commit(source) if trust == "operator" else None
    output.mkdir(parents=True, exist_ok=False)
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1"], cwd=source))
    components = []
    for item in metadata["packages"]:
        component = dict(type="library", name=item["name"], version=item["version"],
                         purl=f"pkg:cargo/{item['name']}@{item['version']}")
        if item.get("license"):
            component["licenses"] = [{"expression": item["license"]}]
        components.append(component)
    sbom = dict(bomFormat="CycloneDX", specVersion="1.6", version=1, components=components)
    write_new(output/SBOM, (json.dumps(sbom, sort_keys=True, indent=2)+"\n").encode())
    for file in FILES:
        assert (binaries/file).is_file(), f"missing Linux release artifact: {file}"
    with tarfile.open(output/ARCHIVE, "x:gz") as archive:
        for file in FILES:
            archive.add(binaries/file, arcname=file)
        archive.add(source/"LICENSE", arcname="LICENSE")
    if trust == "operator":
        if clean_commit(source) != revision:
            raise Rejected("source checkout changed during packaging")
        write_new(output/"manifest.json", operator_manifest(revision, sha256(output/ARCHIVE), sha256(output/SBOM)))
        return revision
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    manifest = dict(version=1, revision=revision, trust="lab", note="Ephemeral local lab signature; no public trust or publisher identity claim",
                    files={name: hashlib.sha256((output/name).read_bytes()).hexdigest() for name in [ARCHIVE, SBOM]})
    (output/"manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2)+"\n")
    return revision


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--trust", choices=["lab", "operator"], default="lab")
    parser.add_argument("--source", type=pathlib.Path, help="git checkout to package (default: this repository)")
    args = parser.parse_args()
    try:
        package(args.binaries, args.output, args.trust, args.source)
    except Rejected as error:
        raise SystemExit(f"release packaging failed: {error}") from None
