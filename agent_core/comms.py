import hashlib
import json
import math
import time
from pathlib import Path
from typing import Dict, List, Optional

import grpc
import requests

from .config import (
    AGENT_CONFIG_URL_TEMPLATE,
    AGENT_VERSION,
    ARTIFACT_URL_TEMPLATE,
    EVENT_BATCH_URL,
    GRPC_UPLOAD_TARGET,
    HEARTBEAT_URL_TEMPLATE,
    REGISTER_URL,
    SCAN_COMPLETE_URL_TEMPLATE,
    UPGRADE_DOWNLOAD_URL_TEMPLATE,
    UPGRADE_REPORT_URL_TEMPLATE,
    UPLOAD_CHUNK_URL_TEMPLATE,
    UPLOAD_COMPLETE_URL_TEMPLATE,
    UPLOAD_INIT_URL,
    UPLOAD_STATUS_URL_TEMPLATE,
    build_agent_identity,
)
from .grpc_proto import safeguard_upload_pb2, safeguard_upload_pb2_grpc
from .store import AgentStore


class ServerClient:
    def __init__(self, store: AgentStore, logger, request_timeout: int = 20):
        self.store = store
        self.logger = logger
        self.request_timeout = request_timeout
        self.session = requests.Session()
        self.grpc_target = GRPC_UPLOAD_TARGET

    def register(self) -> Dict:
        cached_agent_id = self.store.get_state("agent_id")
        identity = build_agent_identity(cached_agent_id)
        response = self.session.post(REGISTER_URL, json=identity, timeout=self.request_timeout)
        response.raise_for_status()
        data = response.json()
        agent_id = str(data.get("agent_id") or cached_agent_id or identity["agent_id"])
        token = str(data.get("token") or "")
        token_expires = float(data.get("token_expires") or 0)
        config_version = str(data.get("config_version") or "")

        self.store.set_state("agent_id", agent_id)
        if token:
            self.store.set_state("token", token)
            self.store.set_state("token_expires", str(token_expires))
        if config_version:
            self.store.set_state("config_version", config_version)
        self.store.set_state("last_register_at", str(time.time()))
        self.store.set_json_state(
            "last_register_result",
            {
                "status": "ok",
                "agent_id": agent_id,
                "config_version": config_version,
                "token_expires": token_expires,
            },
        )
        self.logger.info("register success: agent_id=%s", agent_id)
        return data

    def heartbeat(self, state: str, config_version: str, pending_count: int) -> Dict:
        agent_id = self._require_agent_id()
        payload = {
            "timestamp": time.time(),
            "agent_version": AGENT_VERSION,
            "config_version": int(config_version or 0),
            "scan_status": state,
            "pending_task_count": int(pending_count),
        }
        data = self._request_json(
            "POST",
            HEARTBEAT_URL_TEMPLATE.format(agent_id=agent_id),
            json_payload=payload,
            with_auth=True,
        )
        self.store.set_state("last_heartbeat_at", str(time.time()))
        self.store.set_json_state("last_heartbeat_payload", payload)
        self.store.set_json_state("last_heartbeat_result", data)
        self._apply_piggyback(data)
        return data

    def fetch_config(self) -> Dict:
        agent_id = self._require_agent_id()
        current_version = self.store.get_state("config_version")
        cached_config = self.store.get_json_state("config_json", None)
        params = None
        if current_version and cached_config:
            params = {"config_version": int(current_version or 0)}
        response = self.session.get(
            AGENT_CONFIG_URL_TEMPLATE.format(agent_id=agent_id),
            params=params,
            headers=self._auth_headers(),
            timeout=self.request_timeout,
        )
        if response.status_code == 304:
            return {"status": "not_modified"}
        response.raise_for_status()
        data = response.json()
        self.store.set_state("config_version", str(data.get("config_version") or current_version or ""))
        self.store.set_json_state("config_json", data)
        return {"status": "ok", **data}

    def submit_events_batch(self, events: List[Dict]) -> Dict:
        if not events:
            return {"accepted": 0, "duplicates": 0}
        payload = {"events": [self._event_payload(item) for item in events]}
        return self._request_json("POST", EVENT_BATCH_URL, json_payload=payload, with_auth=True)

    def submit_file(self, payload: Dict, chunk_size_bytes: int) -> Dict:
        agent_id = self._require_agent_id()
        file_path = Path(payload["path"])
        if not file_path.exists():
            raise FileNotFoundError(file_path)

        total_chunks = max(1, int(math.ceil(int(payload["size"]) / max(1, int(chunk_size_bytes)))))
        token = self.store.get_state("token")
        if not token:
            raise RuntimeError("agent token missing")
        with grpc.insecure_channel(self.grpc_target) as channel:
            stub = safeguard_upload_pb2_grpc.UploadServiceStub(channel)
            init_resp = stub.InitUpload(
                safeguard_upload_pb2.InitUploadRequest(
                    agent_id=agent_id,
                    agent_token=token,
                    file_hash=payload["sha256"],
                    file_size=int(payload["size"]),
                    total_chunks=total_chunks,
                    file_name=file_path.name,
                    file_type=payload["extension"],
                    file_path=payload["path"],
                    priority=str(payload.get("priority") or "MEDIUM"),
                ),
                timeout=max(self.request_timeout, 120),
            )
            status = str(init_resp.status or "")
            if status == "dedup":
                return {"status": "ok", "reused": True, "result": {"file_hash": payload["sha256"]}}
            if status not in {"created", "existing"}:
                raise RuntimeError(f"unexpected upload init status: {status}")

            session_id = str(init_resp.session_id or "")
            if not session_id:
                raise RuntimeError("missing session_id in gRPC init response")

            uploaded_chunks = set(int(x) for x in (init_resp.uploaded_chunks or []))
            if status == "existing":
                status_resp = stub.GetUploadStatus(
                    safeguard_upload_pb2.UploadStatusRequest(session_id=session_id),
                    timeout=max(self.request_timeout, 60),
                )
                uploaded_chunks = set(int(x) for x in (status_resp.uploaded_chunks or []))

            def chunk_iter():
                with open(file_path, "rb") as handle:
                    for index in range(total_chunks):
                        chunk = handle.read(chunk_size_bytes)
                        if index in uploaded_chunks:
                            continue
                        yield safeguard_upload_pb2.UploadChunkRequest(
                            session_id=session_id,
                            index=index,
                            content=chunk,
                            chunk_sha256=hashlib.sha256(chunk).hexdigest(),
                        )

            stub.UploadChunks(chunk_iter(), timeout=max(self.request_timeout, 300))
            complete_resp = stub.CompleteUpload(
                safeguard_upload_pb2.CompleteUploadRequest(
                    session_id=session_id,
                    priority=str(payload.get("priority") or "MEDIUM"),
                ),
                timeout=max(self.request_timeout, 300),
            )
        return {
            "status": "ok",
            "reused": False,
            "result": {
                "status": complete_resp.status,
                "session_id": complete_resp.session_id,
                "file_hash": complete_resp.file_hash,
                "task_id": complete_resp.task_id,
            },
        }

    def submit_scan_complete(self, stats: Dict) -> Dict:
        agent_id = self._require_agent_id()
        return self._request_json(
            "POST",
            SCAN_COMPLETE_URL_TEMPLATE.format(agent_id=agent_id),
            json_payload={
                "total_files": int(stats.get("total_files") or 0),
                "scanned": int(stats.get("scanned") or 0),
                "uploaded": int(stats.get("uploaded") or 0),
                "skipped": int(stats.get("skipped") or 0),
                "errors": int(stats.get("errors") or 0),
                "duration_sec": float(stats.get("duration_sec") or 0.0),
            },
            timeout=max(self.request_timeout, 120),
            with_auth=True,
        )

    def report_upgrade_result(self, payload: Dict) -> Dict:
        agent_id = self._require_agent_id()
        return self._request_json(
            "POST",
            UPGRADE_REPORT_URL_TEMPLATE.format(agent_id=agent_id),
            json_payload=payload,
            timeout=max(self.request_timeout, 120),
            with_auth=True,
        )

    def download_upgrade(self, version: str, dst: Path) -> Path:
        response = self.session.get(
            UPGRADE_DOWNLOAD_URL_TEMPLATE.format(version=version),
            timeout=max(self.request_timeout, 300),
        )
        response.raise_for_status()
        dst.parent.mkdir(parents=True, exist_ok=True)
        with open(dst, "wb") as handle:
            handle.write(response.content)
        return dst

    def download_artifact(self, artifact_id: str, dst: Path) -> Path:
        response = self.session.get(
            ARTIFACT_URL_TEMPLATE.format(artifact_id=artifact_id),
            timeout=max(self.request_timeout, 120),
        )
        response.raise_for_status()
        dst.parent.mkdir(parents=True, exist_ok=True)
        with open(dst, "wb") as handle:
            handle.write(response.content)
        return dst

    def backoff_sleep(self, attempt: int):
        delay = min(300, 5 * (2 ** max(0, attempt - 1)))
        self.logger.warning("network unavailable, retry in %ss", delay)
        time.sleep(delay)

    def _request_json(
        self,
        method: str,
        url: str,
        *,
        json_payload: Optional[Dict] = None,
        timeout: Optional[int] = None,
        with_auth: bool = False,
    ) -> Dict:
        response = self.session.request(
            method,
            url,
            json=json_payload,
            headers=self._auth_headers() if with_auth else None,
            timeout=timeout or self.request_timeout,
        )
        response.raise_for_status()
        if not response.content:
            return {}
        return response.json()

    def _event_payload(self, item: Dict) -> Dict:
        agent_id = self._require_agent_id()
        return {
            "event_id": item["event_id"],
            "event_type": item["event_type"],
            "file_path": item.get("file_path"),
            "old_path": item.get("old_path"),
            "new_path": item.get("new_path"),
            "old_hash": item.get("old_hash"),
            "new_hash": item.get("new_hash"),
            "file_size": item.get("file_size"),
            "timestamp": float(item.get("timestamp") or time.time()),
            "agent_id": agent_id,
            "usb_context": item.get("usb_context") or {},
            "event_details": item.get("event_details") or {},
        }

    def _apply_piggyback(self, data: Dict):
        token = data.get("token_refreshed")
        if token:
            self.store.set_state("token", str(token))
        if "config_changed" in data:
            self.store.set_json_state("last_piggyback", data)

    def _auth_headers(self) -> Dict[str, str]:
        token = self.store.get_state("token")
        if not token:
            raise RuntimeError("agent token missing")
        return {"Authorization": f"Bearer {token}"}

    def _require_agent_id(self) -> str:
        agent_id = self.store.get_state("agent_id")
        if not agent_id:
            raise RuntimeError("agent_id missing")
        return agent_id
