import sys
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
SERVER_DIR = ROOT / "server"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))


class ServerConfigValidationTests(unittest.TestCase):
    def test_invalid_windows_path_characters_are_rejected(self):
        import services

        with self.assertRaisesRegex(ValueError, "invalid Windows path characters"):
            services._validate_config_path(r"C:\safe\bad?name", "scan_dirs")

    def test_config_sanitize_dedupes_and_normalizes_extensions(self):
        import services

        sanitized, changed = services._sanitize_agent_config_payload(
            {
                "config_version": 4,
                "scan_dirs": [r"C:\test", r"C:\test\\"],
                "watch_dirs": [r"%USERPROFILE%\Downloads"],
                "exclude_paths": [r"C:\Windows"],
                "include_extensions": ["txt", ".PDF", ".txt"],
            },
            4,
        )

        self.assertTrue(changed)
        self.assertEqual(sanitized["scan_dirs"], [r"C:\test"])
        self.assertEqual(sanitized["include_extensions"], [".txt", ".pdf", ".doc", ".ppt"])

    def test_config_endpoint_reports_validation_error(self):
        import api

        from fastapi import FastAPI

        fastapi_app = FastAPI()
        fastapi_app.include_router(api.router)
        client = TestClient(fastapi_app)

        with mock.patch.dict("os.environ", {"SAFEGUARD_ADMIN_TOKEN": "admin-token"}), \
            mock.patch.object(api, "update_global_config", side_effect=ValueError("scan_dirs contains invalid Windows path characters: C:\\bad?name")):
            response = client.put(
                "/api/v1/admin/configs",
                headers={"Authorization": "Bearer admin-token"},
                json={"scan_dirs": [r"C:\bad?name"]},
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("invalid Windows path characters", response.json()["detail"])


class AgentConfigValidationTests(unittest.TestCase):
    def test_invalid_config_path_is_ignored_by_agent(self):
        from agent_core.config import expand_config_paths

        self.assertEqual(expand_config_paths(r"C:\safe\bad?name"), [])

    def test_exclude_path_requires_boundary_match(self):
        from agent_core.config import should_exclude_path

        self.assertTrue(should_exclude_path(r"C:\safe\dir\file.txt", [r"C:\safe\dir"]))
        self.assertFalse(should_exclude_path(r"C:\safe\dir2\file.txt", [r"C:\safe\dir"]))


if __name__ == "__main__":
    unittest.main()
