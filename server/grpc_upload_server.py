from concurrent import futures
from typing import Optional

import grpc

from config_app import GRPC_UPLOAD_HOST, GRPC_UPLOAD_PORT, setup_app_logger
from grpc_proto import safeguard_upload_pb2, safeguard_upload_pb2_grpc
from services import authenticate_agent, complete_upload_session, get_upload_status, init_upload_session, upload_chunk
from tasks import submit_discovery_task


logger = setup_app_logger("grpc_upload")
GRPC_MAX_MESSAGE_BYTES = 64 * 1024 * 1024


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
    server = build_grpc_server()
    server.start()
    logger.info("grpc upload server started at %s:%s", GRPC_UPLOAD_HOST, GRPC_UPLOAD_PORT)
    return server
