"""Exercise installers with inert archives; no network, real install or native UI."""
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASE = ("opaqued", "opaque", "opaque-mcp", "opaque-approve-helper", "opaque-web")
ADDED = ("opaque-approver", "opaque-evidence")


class InstallDeliveryTests(unittest.TestCase):
    def install(self, binaries=BASE + ADDED, *, app=False, mismatch=False,
                signature=False, certificate=True, signature_valid=True):
        temporary = tempfile.TemporaryDirectory(prefix="opaque-install-fixture-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        commands = root / "commands"
        commands.mkdir()
        # GNU tar invokes gzip through PATH; BSD tar handles gzip internally.
        for command in ("tar", "gzip", "mktemp", "install", "mkdir", "rm", "awk", "sed", "head"):
            located = shutil.which(command)
            self.assertIsNotNone(located, command)
            (commands / command).symlink_to(located)
        checksum = "sha256sum" if shutil.which("sha256sum") else "shasum"
        (commands / checksum).symlink_to(shutil.which(checksum))
        archive = root / "fixture.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for name in binaries:
                content = b"#!/bin/sh\nexit 0\n"
                info = tarfile.TarInfo(name)
                info.size = len(content)
                info.mode = 0o755
                output.addfile(info, io.BytesIO(content))
            if app:
                info = tarfile.TarInfo("Opaque Reviewer.app/")
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                output.addfile(info)
        digest = "0" * 64 if mismatch else hashlib.sha256(archive.read_bytes()).hexdigest()
        (root / "fixture.sha256").write_text(digest + "  fixture.tar.gz\n")
        (root / "fixture.sig").write_text("synthetic-signature")
        if certificate:
            (root / "fixture.pem").write_text("synthetic-certificate")

        def script(name, body):
            path = commands / name
            path.write_text(f"#!{sys.executable}\n" + body)
            path.chmod(0o755)

        script("uname", "import sys\nprint('Darwin' if sys.argv[1] == '-s' else 'arm64')\n")
        script("curl", """import os, pathlib, shutil, sys
args = sys.argv[1:]
url = args[-1]
root = pathlib.Path(os.environ['FIXTURE_ROOT'])
suffix = next((s for s in ('.sha256', '.sig', '.pem') if url.endswith(s)), '.tar.gz')
source = root / ('fixture' + suffix)
if not source.is_file():
    sys.exit(22)
shutil.copyfile(source, args[args.index('-o') + 1])
""")
        if signature:
            script("cosign", """import os, pathlib, sys
args = sys.argv[1:]
assert args[0] == 'verify-blob'
assert pathlib.Path(args[args.index('--certificate') + 1]).read_text() == 'synthetic-certificate'
assert pathlib.Path(args[args.index('--signature') + 1]).read_text() == 'synthetic-signature'
assert args[args.index('--certificate-oidc-issuer') + 1] == 'https://token.actions.githubusercontent.com'
assert args[args.index('--certificate-identity') + 1] == 'https://github.com/kcirtapfromspace/opaque/.github/workflows/release.yml@refs/tags/v0.99.0'
pathlib.Path(os.environ['FIXTURE_ROOT'], 'verified').touch()
sys.exit(0 if os.environ['SIGNATURE_VALID'] == '1' else 1)
""")
        destination = root / "installed"
        env = {
            "PATH": str(commands), "OPAQUE_VERSION": "0.99.0",
            "OPAQUE_INSTALL": str(destination), "FIXTURE_ROOT": str(root),
            "SIGNATURE_VALID": "1" if signature_valid else "0",
            "TMPDIR": str(root), "LC_ALL": "C",
        }
        result = subprocess.run(["/bin/sh", str(ROOT / "install.sh")], env=env,
                                text=True, capture_output=True, timeout=15)
        return root, destination, result

    def test_new_archive_installs_both_clis_and_leaves_app_registration_explicit(self):
        _, destination, result = self.install(app=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({p.name for p in destination.iterdir()}, set(BASE + ADDED))
        self.assertIn("CLI tools only", result.stdout)
        self.assertIn("opaque-approver opaque-evidence", result.stdout)
        self.assertFalse((destination / "Opaque Reviewer.app").exists())

    def test_older_archive_reports_only_installed_tools(self):
        _, destination, result = self.install(BASE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({p.name for p in destination.iterdir()}, set(BASE))
        self.assertIn("binary opaque-evidence not found", result.stderr)
        installed = next(line for line in result.stdout.splitlines() if line.startswith("Installed binaries:"))
        self.assertNotIn("opaque-evidence", installed)
        self.assertNotIn("opaque-approver", installed)

    def test_checksum_mismatch_prevents_installation(self):
        _, destination, result = self.install(mismatch=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertFalse(destination.exists())

    def test_detached_signature_receives_certificate_and_rejection_prevents_install(self):
        root, destination, result = self.install(signature=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((root / "verified").exists())
        self.assertTrue((destination / "opaque-evidence").is_file())
        _, destination, result = self.install(signature=True, signature_valid=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cosign signature verification failed", result.stderr)
        self.assertFalse(destination.exists())
        root, destination, result = self.install(signature=True, certificate=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature certificate unavailable", result.stderr)
        self.assertFalse((root / "verified").exists())
        self.assertFalse(destination.exists())

    def test_empty_archive_cannot_report_success(self):
        _, _, result = self.install(())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archive contained no supported binaries", result.stderr)


if __name__ == "__main__":
    unittest.main()
