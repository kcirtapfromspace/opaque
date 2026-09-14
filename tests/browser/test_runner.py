"""TAP evidence must preserve every existing browser check and reject skips."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("browser_runner", Path(__file__).with_name("run.py"))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class BrowserResultTests(unittest.TestCase):
    def test_exact_pass_inventory_not_just_zero_exit_or_zero_failures(self):
        rows = [f"ok {index} - {name}" for index, name in enumerate(sorted(RUNNER.EXPECTED), 1)]
        summary = "# tests 4\n# pass 4\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n"
        output = ("\n".join(rows) + "\n" + summary).encode()
        self.assertEqual(RUNNER.passing_tests(output), sorted(RUNNER.EXPECTED))
        for bad in (output.replace(b"# pass 4", b"# pass 3"), output.replace(b"# skipped 0", b"# skipped 1"),
                    output.replace(rows[0].encode(), b"ok 1 - invented test"), output + rows[0].encode() + b"\n"):
            with self.assertRaises(ValueError):
                RUNNER.passing_tests(bad)


if __name__ == "__main__":
    unittest.main()
