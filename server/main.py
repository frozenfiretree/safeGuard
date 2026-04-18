import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from api import router as v1_router, rules_alias_router
from config_app import APP_VERSION, setup_app_logger, validate_production_settings
from grpc_upload_server import start_grpc_server
from storage import init_db


logger = setup_app_logger()
validate_production_settings()
init_db()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    app.state.grpc_server = start_grpc_server()
    logger.info("server v2 startup complete")
    yield
    # Shutdown
    grpc_server = getattr(app.state, "grpc_server", None)
    if grpc_server:
        grpc_server.stop(grace=5)


app = FastAPI(title="SafeGuard Server V2", version=APP_VERSION, lifespan=lifespan)
BASE_DIR = Path(__file__).resolve().parent
WEBUI_DIR = BASE_DIR / "webui"
WEBUI_ASSETS_DIR = WEBUI_DIR / "assets"
WEBUI_INDEX = WEBUI_DIR / "index.html"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    started = time.time()
    response = await call_next(request)
    elapsed = int((time.time() - started) * 1000)
    logger.info("http_request_v2 method=%s path=%s status=%s duration_ms=%s", request.method, request.url.path, response.status_code, elapsed)
    return response


app.include_router(v1_router)
app.include_router(rules_alias_router)

if WEBUI_ASSETS_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(WEBUI_ASSETS_DIR)), name="assets")

STATIC_DIR = WEBUI_DIR / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def serve_webui_index():
    if WEBUI_INDEX.exists():
        return FileResponse(str(WEBUI_INDEX))
    return {"status": "ok", "version": APP_VERSION}


