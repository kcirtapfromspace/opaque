"""Local source, custody and artifact evidence regressions; no Docker or registry."""
import copy
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import build_staging_artifact as artifact


class CommittedSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        self.git("config", "user.name", "Artifact test")
        self.git("config", "user.email", "artifact@example.invalid")
        self.git("remote", "add", "origin", artifact.SOURCE_URL + ".git")
        (self.repo / "source.rs").write_text("committed source\n")
        self.git("add", "source.rs")
        self.git("commit", "-qm", "fixture source")
        self.revision = self.git("rev-parse", "HEAD").decode().strip()

    def tearDown(self):
        self.temporary.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args])

    def test_dirty_default_refuses_but_explicit_commit_excludes_edits_and_untracked_data(self):
        self.assertEqual(artifact.select_revision(self.repo, None), self.revision)
        (self.repo / "source.rs").write_text("uncommitted change\n")
        (self.repo / "credentials.env").write_text("must never enter context\n")
        with self.assertRaisesRegex(artifact.ArtifactError, "clean worktree"):
            artifact.select_revision(self.repo, None)
        revision = artifact.select_revision(self.repo, self.revision)
        output = self.root / "output"
        output.mkdir()
        context, recipe_hash = artifact.prepare(self.repo, revision, output)
        self.assertEqual((context / "source/source.rs").read_text(), "committed source\n")
        self.assertFalse((context / "source/credentials.env").exists())
        self.assertFalse((context / "source/.git").exists())
        self.assertEqual(len(recipe_hash), 64)

    def test_moving_refs_and_missing_commits_are_rejected(self):
        for revision in ["HEAD", "main", self.revision[:7], "A" * 40, "a" * 40]:
            with self.subTest(revision=revision), self.assertRaises(artifact.ArtifactError):
                artifact.select_revision(self.repo, revision)

    def test_public_or_foreign_origin_cannot_claim_private_source_label(self):
        self.git("remote", "set-url", "origin", "https://github.com/kcirtapfromspace/opaque.git")
        with self.assertRaisesRegex(artifact.ArtifactError, "source contract"):
            artifact.select_revision(self.repo, self.revision)

    def test_submodule_source_is_not_silently_omitted(self):
        self.git("update-index", "--add", "--cacheinfo", "160000," + self.revision + ",dependency")
        self.git("commit", "-qm", "add unbundled submodule")
        revision = self.git("rev-parse", "HEAD").decode().strip()
        with self.assertRaisesRegex(artifact.ArtifactError, "Submodules"):
            artifact.select_revision(self.repo, revision)

    def test_prepare_only_does_not_invoke_docker_or_claim_registry_digest(self):
        output = self.root / "prepared"
        with patch.object(artifact, "ROOT", self.repo), patch("sys.stdout", new_callable=io.StringIO) as stdout:
            self.assertEqual(artifact.main(["--output-dir", str(output), "--prepare-only"]), 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["status"], "prepared")
        self.assertEqual(report["source_revision"], self.revision)
        self.assertIsNone(report["registry_digest"])
        self.assertFalse(report["published"])
        self.assertFalse(report["ready_for_live_dispatch"])
        self.assertNotIn("local_image_id", report)
        self.assertTrue((output / "evidence.json").is_file())

    def test_existing_evidence_directory_is_never_overwritten(self):
        marker = self.root / "retained.json"
        marker.write_text("retained")
        with self.assertRaisesRegex(artifact.ArtifactError, "already exists"):
            artifact.output_directory(self.root)
        self.assertEqual(marker.read_text(), "retained")

    def test_source_cleanup_failure_is_separate_from_verified_artifact_result(self):
        output = self.root / "built"
        actual_command = artifact.command

        def fake_build(args, **kwargs):
            if args[:3] == ["docker", "buildx", "build"]:
                Path(args[args.index("--iidfile") + 1]).write_text("sha256:" + "d" * 64)
                return b""
            return actual_command(args, **kwargs)

        with patch.object(artifact, "ROOT", self.repo), \
             patch.object(artifact, "command", side_effect=fake_build), \
             patch.object(artifact, "inspect_image"), \
             patch.object(artifact, "smoke_image", return_value="opaque 0.2.0+" + self.revision[:7]), \
             patch.object(artifact.shutil, "rmtree", side_effect=OSError("private path detail")), \
             patch("sys.stdout", new_callable=io.StringIO) as stdout:
            self.assertEqual(artifact.main(["--output-dir", str(output)]), 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["status"], "validated_local")
        self.assertEqual(report["source_cleanup"], "incomplete")
        self.assertIn("cleanup_error", report)
        self.assertNotIn("error", report)
        self.assertNotIn("private path detail", stdout.getvalue())


class ArtifactBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.revision = "190cb16d9c9082f56beb11f4dcee5ace5ba85e34"
        self.image_id = "sha256:" + "d" * 64
        self.metadata = {"Id": self.image_id, "Os": "linux", "Architecture": "amd64",
                         "Config": {"User": "65532:65532", "Entrypoint": ["/usr/local/bin/opaque"],
                                    "Labels": {"org.opencontainers.image.revision": self.revision,
                                               "org.opencontainers.image.source": artifact.SOURCE_URL}}}

    def test_build_is_local_amd64_and_never_mounts_credentials_or_host_source(self):
        command = artifact.build_command(Path("/private/context"), self.revision, "opaque-staging-artifact:test", Path("/private/out"))
        self.assertIn("--load", command)
        self.assertEqual(command[command.index("--platform") + 1], "linux/amd64")
        self.assertEqual(command[-1], "/private/context")
        for option in ["--push", "--secret", "--ssh", "--output", "--volume", "--mount"]:
            self.assertNotIn(option, command)

    def test_metadata_requires_exact_image_platform_source_revision_and_execution_identity(self):
        with patch.object(artifact, "command", return_value=json.dumps([self.metadata]).encode()):
            artifact.inspect_image(self.image_id, self.revision)
        invalid = []
        for key, value in [("Id", "sha256:" + "e" * 64), ("Os", "windows"), ("Architecture", "arm64")]:
            item = copy.deepcopy(self.metadata)
            item[key] = value
            invalid.append(item)
        for key, value in [("User", "root"), ("Entrypoint", ["/bin/sh"]), ("Labels", [])]:
            item = copy.deepcopy(self.metadata)
            item["Config"][key] = value
            invalid.append(item)
        for label in ["org.opencontainers.image.revision", "org.opencontainers.image.source"]:
            item = copy.deepcopy(self.metadata)
            item["Config"]["Labels"][label] = "wrong"
            invalid.append(item)
        for item in invalid:
            with self.subTest(item=item), patch.object(artifact, "command", return_value=json.dumps([item]).encode()):
                with self.assertRaises(artifact.ArtifactError):
                    artifact.inspect_image(self.image_id, self.revision)

    def test_smoke_uses_image_id_no_network_bounded_resources_and_known_version_only(self):
        with patch.object(artifact, "command", return_value=b"opaque 0.2.0+190cb16\n") as run:
            self.assertEqual(artifact.smoke_image(self.image_id, self.revision), "opaque 0.2.0+190cb16")
        command = run.call_args_list[0].args[0]
        self.assertEqual(command[-2:], [self.image_id, "--version"])
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertEqual(command[command.index("--user") + 1], "65532:65532")
        for option in ["--read-only", "--cap-drop", "--security-opt", "--pids-limit", "--memory", "--cpus"]:
            self.assertIn(option, command)
        self.assertEqual(run.call_args_list[1].args[0][:3], ["docker", "rm", "--force"])

    def test_bad_version_or_arbitrary_stdout_is_not_retained_in_error(self):
        for output in [b"opaque 0.2.0+unknown\n", b"opaque 0.2.0+abcdef0\n", b"opaque 0.2.0+190cb16\nsecret", b"secret"]:
            with patch.object(artifact, "command", return_value=output):
                with self.assertRaises(artifact.ArtifactError) as failure:
                    artifact.smoke_image(self.image_id, self.revision)
                self.assertNotIn("secret", str(failure.exception))

    def test_timed_out_smoke_removes_only_its_own_container(self):
        with patch.object(artifact, "command", side_effect=[artifact.ArtifactError("timed out"), b""]) as run:
            with self.assertRaises(artifact.ArtifactError):
                artifact.smoke_image(self.image_id, self.revision)
        start = run.call_args_list[0].args[0]
        cleanup = run.call_args_list[1].args[0]
        self.assertEqual(cleanup, ["docker", "rm", "--force", start[start.index("--name") + 1]])

    def test_archive_cannot_follow_links_or_escape_context(self):
        for name, entry_type in [("../escaped", tarfile.REGTYPE), ("source/link", tarfile.SYMTYPE)]:
            with tempfile.TemporaryDirectory() as directory:
                archive = Path(directory) / "source.tar"
                with tarfile.open(archive, "w") as output:
                    item = tarfile.TarInfo(name)
                    item.type = entry_type
                    item.linkname = "/outside"
                    output.addfile(item)
                with self.assertRaises(artifact.ArtifactError):
                    artifact.extract_source(archive, Path(directory))

    def test_subprocess_failure_does_not_echo_raw_diagnostics(self):
        failure = subprocess.CompletedProcess([], 1, b"sensitive output", b"sensitive error")
        with patch.object(artifact.subprocess, "run", return_value=failure):
            with self.assertRaises(artifact.ArtifactError) as raised:
                artifact.command(["docker", "image", "inspect", self.image_id])
        self.assertNotIn("sensitive", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
