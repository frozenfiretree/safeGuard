import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SERVER_DIR = ROOT / "server"
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))


class ApiAuthTests(unittest.TestCase):
    ADMIN_HEADERS = {"Authorization": "Bearer test-admin-token"}

    def _client(self):
        try:
            from fastapi import FastAPI
            from fastapi.testclient import TestClient
        except ModuleNotFoundError as exc:
            self.skipTest(f"FastAPI test dependency is not installed: {exc}")

        import api

        app = FastAPI()
        app.include_router(api.router)
        app.include_router(api.assets_alias_router)
        app.include_router(api.rules_alias_router)
        return TestClient(app), api

    def test_rules_list_requires_admin_token(self):
        client, api = self._client()
        with mock.patch.dict(os.environ, {"SAFEGUARD_ADMIN_TOKEN": "test-admin-token"}), \
            mock.patch.object(api, "list_detection_rules", return_value=[]):
            response = client.get("/api/v1/rules")
        self.assertEqual(response.status_code, 401)

    def test_rules_list_allows_admin_token(self):
        client, api = self._client()
        with mock.patch.dict(os.environ, {"SAFEGUARD_ADMIN_TOKEN": "test-admin-token"}), \
            mock.patch.object(api, "list_detection_rules", return_value=[]):
            response = client.get("/api/v1/rules", headers=self.ADMIN_HEADERS)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"items": []})

    def test_sensitive_file_download_requires_admin_token(self):
        client, api = self._client()
        with mock.patch.dict(os.environ, {"SAFEGUARD_ADMIN_TOKEN": "test-admin-token"}), \
            mock.patch.object(api, "get_version_artifact_info") as artifact_info:
            response = client.get("/api/v1/sensitive-files/t1/versions/v1/download")
        self.assertEqual(response.status_code, 401)
        artifact_info.assert_not_called()

    def test_sensitive_file_download_allows_admin_token(self):
        client, api = self._client()
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "sample.txt"
            artifact.write_text("classified sample", encoding="utf-8")
            with mock.patch.dict(os.environ, {"SAFEGUARD_ADMIN_TOKEN": "test-admin-token"}), \
                mock.patch.object(api, "get_version_artifact_info", return_value={"path": artifact, "filename": "sample.txt"}):
                response = client.get(
                    "/api/v1/sensitive-files/t1/versions/v1/download",
                    headers=self.ADMIN_HEADERS,
                )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"classified sample")

    def test_upload_status_rejects_missing_agent_token_before_session_lookup(self):
        client, api = self._client()
        with mock.patch.object(api, "get_upload_session_agent_id") as session_agent:
            response = client.get("/api/v1/uploads/session-1")
        self.assertEqual(response.status_code, 401)
        session_agent.assert_not_called()

    def test_upload_status_rejects_invalid_agent_token(self):
        client, api = self._client()
        with mock.patch.object(api, "get_upload_session_agent_id", return_value="agent-1"), \
            mock.patch.object(api, "authenticate_agent", side_effect=ValueError("invalid token")):
            response = client.get("/api/v1/uploads/session-1", headers={"Authorization": "Bearer wrong-token"})
        self.assertEqual(response.status_code, 401)

    def test_upgrade_download_requires_auth(self):
        client, _api = self._client()
        response = client.get("/api/v1/upgrades/2.0/download")
        self.assertEqual(response.status_code, 401)

    def test_upgrade_download_allows_agent_auth(self):
        client, api = self._client()
        with tempfile.TemporaryDirectory() as tmp:
            package_dir = Path(tmp) / "2.0"
            package_dir.mkdir(parents=True)
            package = package_dir / "SafeGuardAgent.exe"
            package.write_bytes(b"agent package")
            headers = {"Authorization": "Bearer agent-token", "X-Agent-ID": "agent-1"}
            with mock.patch.object(api, "UPGRADE_STORE_DIR", Path(tmp)), \
                mock.patch.object(api, "authenticate_agent", return_value=object()):
                response = client.get("/api/v1/upgrades/2.0/download", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"agent package")


class AbortError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class FakeGrpcContext:
    def __init__(self, metadata):
        self._metadata = [SimpleNamespace(key=key, value=value) for key, value in metadata]

    def invocation_metadata(self):
        return self._metadata

    def abort(self, code, message):
        raise AbortError(code, message)


class GrpcUploadAuthTests(unittest.TestCase):
    def test_upload_session_auth_rejects_missing_token(self):
        import grpc
        import grpc_upload_server

        context = FakeGrpcContext([])
        with self.assertRaises(AbortError) as raised:
            grpc_upload_server._require_upload_session_auth(context, "session-1")
        self.assertEqual(raised.exception.code, grpc.StatusCode.UNAUTHENTICATED)

    def test_upload_session_auth_rejects_agent_mismatch(self):
        import grpc
        import grpc_upload_server

        context = FakeGrpcContext([
            ("authorization", "Bearer agent-token"),
            ("x-agent-id", "agent-2"),
        ])
        with mock.patch.object(grpc_upload_server, "get_upload_session_agent_id", return_value="agent-1"):
            with self.assertRaises(AbortError) as raised:
                grpc_upload_server._require_upload_session_auth(context, "session-1")
        self.assertEqual(raised.exception.code, grpc.StatusCode.UNAUTHENTICATED)

    def test_upload_session_auth_accepts_session_owner_token(self):
        import grpc_upload_server

        context = FakeGrpcContext([
            ("authorization", "Bearer agent-token"),
            ("x-agent-id", "agent-1"),
        ])
        with mock.patch.object(grpc_upload_server, "get_upload_session_agent_id", return_value="agent-1"), \
            mock.patch.object(grpc_upload_server, "authenticate_agent", return_value=object()) as auth:
            grpc_upload_server._require_upload_session_auth(context, "session-1")
        auth.assert_called_once_with("agent-1", "agent-token")


if __name__ == "__main__":
    unittest.main()
