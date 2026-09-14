"""Protocol guards and owned-process cleanup; real model acceptance is separate."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import assets
import service
sys.path.pop(0)


class AssetTests(unittest.TestCase):
    def test_same_size_wrong_model_bytes_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.gguf"
            path.write_bytes(b"GGUFgood")
            with patch.object(assets, "MODEL_SIZE", 8), patch.object(assets, "MODEL_SHA256", hashlib.sha256(b"GGUFgood").hexdigest()):
                assets.verify_model(path)
                path.write_bytes(b"GGUFevil")
                with self.assertRaises(ValueError):
                    assets.verify_model(path)

    def test_model_symlink_is_not_an_attested_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_bytes(b"GGUF")
            alias = Path(directory) / "alias"
            alias.symlink_to(target)
            with self.assertRaises(ValueError):
                assets.digest(alias)

    def test_failed_download_is_bounded_and_never_publishes_an_asset(self):
        for data in (b"short", b"longer-than-the-pinned-size"):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as directory:
                with patch.object(assets, "MODEL_SIZE", 8), \
                     patch.object(assets.urllib.request, "build_opener") as opener:
                    opener.return_value.open.return_value = io.BytesIO(data)
                    with self.assertRaises(ValueError):
                        assets.obtain_model(None, Path(directory))
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_public_download_requires_both_length_and_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            content = b"GGUFtest"
            with patch.object(assets, "MODEL_SIZE", len(content)), \
                 patch.object(assets, "MODEL_SHA256", hashlib.sha256(content).hexdigest()), \
                 patch.object(assets.urllib.request, "build_opener") as opener:
                opener.return_value.open.return_value = io.BytesIO(content)
                path = assets.obtain_model(None, Path(directory))
            self.assertEqual(path.read_bytes(), content)
            self.assertEqual(len(list(Path(directory).iterdir())), 1)


class ServiceTests(unittest.TestCase):
    def test_generation_counter_requires_one_exact_integer_sample(self):
        self.assertEqual(service.generation_count("# HELP unrelated\nllamacpp:tokens_predicted_total 288\n"), 288)
        for metrics in ("", "llamacpp:tokens_predicted_total 1.5", "llamacpp:tokens_predicted_total -1",
                        'llamacpp:tokens_predicted_total{other="x"} 1',
                        "llamacpp:tokens_predicted_total 1\nllamacpp:tokens_predicted_total 1",
                        "llamacpp:tokens_predicted_total NaN"):
            with self.subTest(metrics=metrics), self.assertRaises(ValueError):
                service.generation_count(metrics)

    def test_metadata_identity_mutations_cannot_bind_a_different_model(self):
        props = {"build_info": "b1-" + assets.LLAMA_COMMIT[:9], "chat_template": "controlled template",
                 "model_path": str(service.MODEL), "total_slots": 1,
                 "default_generation_settings": {"n_ctx": 1024}}
        models = {"data": [{"id": service.ALIAS}]}
        with patch.object(service, "TEMPLATE_SHA256", hashlib.sha256(props["chat_template"].encode()).hexdigest()):
            profile = service.profile_from_metadata("http://127.0.0.1:1234/", props, models, "service-fixture")
            self.assertEqual(profile["model_artifact_sha256"], assets.MODEL_SHA256)
            self.assertNotIn("credential_ref", profile)
            self.assertNotIn("source_snapshot_sha256", profile)
            for key, value in (("build_info", "b1-different"), ("chat_template", "different"),
                               ("model_path", "/different.gguf"), ("total_slots", 2),
                               ("total_slots", True), ("total_slots", 1.0),
                               ("default_generation_settings", {"n_ctx": 4096})):
                changed = copy.deepcopy(props)
                changed[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    service.profile_from_metadata("http://127.0.0.1:1234/", changed, models, "fixture")
            for inventory in ({"data": []}, {"data": [{"id": "foreign"}]}, {"data": models["data"] * 2}, None):
                with self.subTest(inventory=inventory), self.assertRaises(ValueError):
                    service.profile_from_metadata("http://127.0.0.1:1234/", props, inventory, "fixture")

    def test_owned_child_is_signalled_reaped_and_group_absence_is_observed(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True)
        try:
            self.assertEqual(service.stop_owned(child), "stopped_and_reaped")
            self.assertIsNotNone(child.returncode)
            with self.assertRaises(ProcessLookupError):
                service.os.killpg(child.pid, 0)
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)

    def test_invalid_model_is_rejected_before_any_docker_command(self):
        spec = importlib.util.spec_from_file_location("model_contained_runner", HERE.parent / "contained-ssh/run.py")
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid = root / "wrong.gguf"
            invalid.write_bytes(b"not the pinned model")
            output = root / "output"
            previous_umask = os.umask(0o077)
            try:
                with patch.object(runner.sys, "argv", ["run.py", "--real-model", "--model-file", str(invalid), "--output", str(output)]), \
                     patch.object(runner, "command") as command:
                    with self.assertRaises(ValueError):
                        runner.main()
            finally:
                os.umask(previous_umask)
            command.assert_not_called()
            report = json.loads((output / "run.json").read_text())
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["cleanup"], "not_started")


if __name__ == "__main__":
    unittest.main()
