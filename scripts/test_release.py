"""Test bundle/SBOM and manifest verification using generated fixture executables/keys."""
import json
import pathlib
import subprocess
import tarfile
import tempfile
with tempfile.TemporaryDirectory(prefix="brigalow-release-test-") as directory:
    d=pathlib.Path(directory);binaries=d/"bin";binaries.mkdir()
    names=["brig","brigalow-server","brigalow-ca","brigalow-audit","libbrigalow_pkcs11.so"]
    for name in names: (binaries/name).write_bytes(b"generated packaging fixture")
    subprocess.run(["python3","scripts/package_release.py","--binaries",str(binaries),"--output",str(d/"dist")],check=True)
    with tarfile.open(d/"dist/brigalow-linux.tar.gz") as archive:
        assert set(archive.getnames())==set(names+["LICENSE"])
    sbom=json.loads((d/"dist/sbom.cdx.json").read_text())
    assert sbom["bomFormat"]=="CycloneDX" and any(c["name"]=="brigalow-core" for c in sbom["components"])
    def openssl(*args):
        result=subprocess.run(["openssl",*args],capture_output=True)
        assert result.returncode==0,"generated release fixture signing failed"
    openssl("genpkey","-algorithm","EC","-pkeyopt","ec_paramgen_curve:P-256","-out",str(d/"key"))
    openssl("pkey","-in",str(d/"key"),"-pubout","-out",str(d/"public"))
    openssl("dgst","-sha256","-sign",str(d/"key"),"-out",str(d/"dist/manifest.sig"),str(d/"dist/manifest.json"))
    verify=["python3","scripts/verify_release.py",str(d/"dist"),"--public-key",str(d/"public")]
    subprocess.run(verify,check=True)
    (d/"dist/brigalow-linux.tar.gz").write_bytes(b"tampered payload")
    assert subprocess.run(verify,capture_output=True).returncode!=0
print("Release packaging/SBOM and payload tamper rejection passed")
