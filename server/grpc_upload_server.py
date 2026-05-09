from concurrent import futures
from typing import Optional
import time

import grpc

from config_app import GRPC_UPLOAD_HOST, GRPC_UPLOAD_PORT, setup_app_logger
from grpc_proto import safeguard_upload_pb2, safeguard_upload_pb2_grpc
from services import authenticate_agent, complete_upload_session, get_upload_status, init_upload_session, upload_chunk
from tasks import submit_discovery_task


logger = setup_app_logger("grpc_upload")
GRPC_MAX_MESSAGE_BYTES = 64 * 1024 * 1024
GRPC_SERVER_STATUS = "stopped"
GRPC_SERVER_STARTED_AT: Optional[float] = None
GRPC_SERVER_ERROR: Optional[str] = None


def _grpc_error(code: grpc.StatusCode, message: str):
    error = grpc.RpcError()
    raise grpc.RpcError(f"{code.name}: {message}")


class UploadServiceServicer(safeguard_upload_pb2_grpc.UploadServiceServicer):
    def InitUpload(self, request, context):
        try:
            authenticate_agent(request.agent_id, request.agent_token)
            result = init_upload_session(
                {
                    "file_hash": request.file_hash,
                    "file_size": int(request.file_size),
                    "total_chunks": int(request.total_chunks),
                    "file_name": request.file_name,
                    "file_type": request.file_type,
                    "agent_id": request.agent_id,
                    "file_path": request.file_path,
                }
            )
            return safeguard_upload_pb2.InitUploadResponse(
                status=result.get("status", ""),
                session_id=result.get("session_id", ""),
                file_id=result.get("file_id", ""),
                uploaded_chunks=[int(x) for x in (result.get("uploaded_chunks") or [])],
            )
        except Exception as exc:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))

    def UploadChunks(self, request_iterator, context):
        session_id: Optional[str] = None
        uploaded_chunks = []
        try:
            for request in request_iterator:
                session_id = request.session_id or session_id
                result = upload_chunk(
                    session_id=session_id or "",
                    index=int(request.index),
                    body=request.content,
                    chunk_sha256=(request.chunk_sha256 or None),
                )
                uploaded_chunks = [int(x) for x in (result.get("uploaded_chunks") or [])]
            return safeguard_upload_pb2.UploadChunksResponse(
                status="ok",
                session_id=session_id or "",
                uploaded_chunks=uploaded_chunks,
            )
        except Exception as exc:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))

    def GetUploadStatus(self, request, context):
        try:
            result = get_upload_status(request.session_id)
            return safeguard_upload_pb2.UploadStatusResponse(
                session_id=result.get("session_id", ""),
                status=result.get("status", ""),
                uploaded_chunks=[int(x) for x in (result.get("uploaded_chunks") or [])],
                total_chunks=int(result.get("total_chunks") or 0),
            )
        except Exception as exc:
            context.abort(grpc.StatusCode.NOT_FOUND, str(exc))

    def CompleteUpload(self, request, context):
        try:
            result = complete_upload_session(request.session_id, request.priority or "MEDIUM")
            task_id = submit_discovery_task(result["file_hash"], priority=result.get("priority", request.priority or "MEDIUM"))
            return safeguard_upload_pb2.CompleteUploadResponse(
                status=result.get("status", ""),
                session_id=result.get("session_id", ""),
                file_hash=result.get("file_hash", ""),
                task_id=task_id or "",
            )
        except Exception as exc:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))


def build_grpc_server() -> grpc.Server:
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=8),
        options=[
            ("grpc.max_receive_message_length", GRPC_MAX_MESSAGE_BYTES),
            ("grpc.max_send_message_length", GRPC_MAX_MESSAGE_BYTES),
        ],
    )
    safeguard_upload_pb2_grpc.add_UploadServiceServicer_to_server(UploadServiceServicer(), server)
    server.add_insecure_port(f"{GRPC_UPLOAD_HOST}:{GRPC_UPLOAD_PORT}")
    return server


def start_grpc_server() -> grpc.Server:
    global GRPC_SERVER_ERROR
    global GRPC_SERVER_STARTED_AT
    global GRPC_SERVER_STATUS
    server = build_grpc_server()
    try:
        server.start()
        GRPC_SERVER_STATUS = "serving"
        GRPC_SERVER_STARTED_AT = time.time()
        GRPC_SERVER_ERROR = None
        logger.info("grpc upload server started at %s:%s", GRPC_UPLOAD_HOST, GRPC_UPLOAD_PORT)
        return server
    except Exception as exc:
        GRPC_SERVER_STATUS = "error"
        GRPC_SERVER_ERROR = str(exc)
        logger.exception("grpc upload server failed to start: %s", exc)
        raise


def _health_target() -> str:
    host = GRPC_UPLOAD_HOST
    if host in {"0.0.0.0", "::", ""}:
        host = "127.0.0.1"
    return f"{host}:{GRPC_UPLOAD_PORT}"


def get_grpc_server_state() -> dict:
    return {
        "service": "grpc_upload",
        "host": GRPC_UPLOAD_HOST,
        "port": GRPC_UPLOAD_PORT,
        "target": _health_target(),
        "status": GRPC_SERVER_STATUS,
        "started_at": GRPC_SERVER_STARTED_AT,
        "error": GRPC_SERVER_ERROR,
    }


def mark_grpc_server_stopped() -> None:
    global GRPC_SERVER_STATUS
    GRPC_SERVER_STATUS = "stopped"


def check_grpc_health(timeout_seconds: float = 2.0) -> dict:
    started = time.time()
    state = get_grpc_server_state()
    try:
        channel = grpc.insecure_channel(state["target"])
        grpc.channel_ready_future(channel).result(timeout=timeout_seconds)
        channel.close()
        latency_ms = int((time.time() - started) * 1000)
        return {
            **state,
            "status": "ok",
            "serving": True,
            "latency_ms": latency_ms,
            "error": None,
        }
    except Exception as exc:
        latency_ms = int((time.time() - started) * 1000)
        return {
            **state,
            "status": "error",
            "serving": False,
            "latency_ms": latency_ms,
            "error": state.get("error") or str(exc),
        }
