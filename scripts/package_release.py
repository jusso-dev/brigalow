#!/usr/bin/env python3
"""Build a local release bundle and CycloneDX SBOM; signing is a later control-plane step."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import tarfile

p = argparse.ArgumentParser()
p.add_argument("--binaries", required=True, type=pathlib.Path)
p.add_argument("--output", required=True, type=pathlib.Path)
a = p.parse_args()
root = pathlib.Path(__file__).resolve().parents[1]
a.output.mkdir(parents=True, exist_ok=False)
metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1"], cwd=root))
components = []
for package in metadata["packages"]:
    item = dict(type="library", name=package["name"], version=package["version"],
                purl=f"pkg:cargo/{package['name']}@{package['version']}")
    if package.get("license"):
        item["licenses"] = [{"expression": package["license"]}]
    components.append(item)
sbom = dict(bomFormat="CycloneDX", specVersion="1.6", version=1, components=components)
(a.output/"sbom.cdx.json").write_text(json.dumps(sbom, sort_keys=True, indent=2)+"\n")
files = ["brig", "brigalow-server", "brigalow-ca", "brigalow-audit", "brigalow-admin", "libbrigalow_pkcs11.so"]
for file in files:
    assert (a.binaries/file).is_file(), f"missing Linux release artifact: {file}"
with tarfile.open(a.output/"brigalow-linux.tar.gz", "w:gz") as archive:
    for file in files:
        archive.add(a.binaries/file, arcname=file)
    archive.add(root/"LICENSE", arcname="LICENSE")
revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
manifest = dict(version=1, revision=revision, trust="lab", note="Ephemeral local lab signature; no public trust or publisher identity claim",
                files={name:hashlib.sha256((a.output/name).read_bytes()).hexdigest() for name in ["brigalow-linux.tar.gz","sbom.cdx.json"]})
(a.output/"manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2)+"\n")
