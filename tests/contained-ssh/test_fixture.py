"""Fixture readiness contracts; these mocks are not live service evidence."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import MagicMock, call, patch
from urllib.error import HTTPError

SPEC = importlib.util.spec_from_file_location("contained_fixture", Path(__file__).with_name("fixture.py"))
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class ReadinessTests(unittest.TestCase):
    def test_active_control_and_ssh_cannot_qualify_an_unbound_health_listener(self):
        for health_ready in (False, True):
            with self.subTest(health_ready=health_ready):
                ssh, health = MagicMock(), MagicMock()
                ssh.__enter__.return_value.recv.return_value = b"SSH-2.0-fixture\r\n"
                connections = [ssh, health if health_ready else ConnectionRefusedError()]
                with patch.object(FIXTURE.ssl, "create_default_context"), \
                     patch.object(FIXTURE, "urlopen", side_effect=HTTPError("https://fixture.invalid", 403, "denied", {}, None)), \
                     patch.object(FIXTURE.socket, "create_connection", side_effect=connections) as connect:
                    if health_ready:
                        self.assertTrue(FIXTURE.host_ready())
                    else:
                        with self.assertRaises(ConnectionRefusedError):
                            FIXTURE.host_ready()
                self.assertEqual(connect.call_args_list, [
                    call(("127.0.0.1", 2222), timeout=1),
                    call(("127.0.0.1", 8080), timeout=1),
                ])
                ssh.__exit__.assert_called_once()
                if health_ready:
                    health.__exit__.assert_called_once()
                    health.__enter__.return_value.send.assert_not_called()
                    health.__enter__.return_value.sendall.assert_not_called()
                    health.__enter__.return_value.recv.assert_not_called()


if __name__ == "__main__":
    unittest.main()
