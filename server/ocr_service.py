import logging
import os
import threading
import time
import zipfile
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from config_app import (
    OCR_MODEL_CHECK_TIMEOUT_SECONDS,
    OCR_MODEL_HOME,
    OCR_MODELS_ZIP,
    OCR_WARMUP_ENABLED,
    OCR_WARMUP_TIMEOUT_SECONDS,
)


logger = logging.getLogger("ocr_service")
OCR_MODEL = None
OCR_INIT_ERROR: Optional[Exception] = None
OCR_RUNTIME_DEVICE = "unloaded"
OCR_STATE = {
    "initialized": False,
    "initializing": False,
    "warmup_completed": False,
    "warmup_in_progress": False,
    "last_warmup_at": None,
    "last_success_at": None,
    "last_error": None,
    "runtime_device": OCR_RUNTIME_DEVICE,
}
OCR_INIT_LOCK = threading.RLock()

REQUIRED_MODEL_DIRS = [
    "PP-OCRv5_server_det",
    "PP-OCRv5_server_rec",
    "PP-LCNet_x1_0_textline_ori",
    "PP-LCNet_x1_0_doc_ori",
    "UVDoc",
]


def _env_truthy(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _ocr_use_gpu() -> bool:
    return _env_truthy("SAFEGUARD_OCR_USE_GPU", "true")


def _ocr_gpu_id() -> str:
    return os.environ.get("SAFEGUARD_OCR_GPU_ID", "0").strip() or "0"


def _paddle_cuda_status() -> dict:
    try:
        import paddle

        compiled = bool(paddle.device.is_compiled_with_cuda())
        try:
            count = int(paddle.device.cuda.device_count()) if compiled else 0
        except Exception:
            count = 0
        return {
            "paddle_version": getattr(paddle, "__version__", "unknown"),
            "cuda_compiled": compiled,
            "cuda_device_count": count,
            "available": compiled and count > 0,
            "error": None,
        }
    except Exception as e:
        return {
            "paddle_version": None,
            "cuda_compiled": False,
            "cuda_device_count": 0,
            "available": False,
            "error": str(e),
        }


def _base_dir() -> Path:
    return Path(__file__).resolve().parent


def _model_home() -> Path:
    return Path(OCR_MODEL_HOME).expanduser()


def _models_zip_path() -> Path:
    return Path(OCR_MODELS_ZIP).expanduser()


def check_model_integrity() -> dict:
    started = time.time()
    model_home = _model_home()
    missing_items = []
    if not model_home.exists():
        missing_items.append(str(model_home))
    elif not model_home.is_dir():
        missing_items.append(f"{model_home} is not a directory")
    else:
        for dirname in REQUIRED_MODEL_DIRS:
            path = model_home / dirname
            if not path.exists() or not path.is_dir():
                missing_items.append(str(path))
    elapsed_ms = int((time.time() - started) * 1000)
    timed_out = elapsed_ms > OCR_MODEL_CHECK_TIMEOUT_SECONDS * 1000
    return {
        "models_ok": not missing_items and not timed_out,
        "model_home": str(model_home),
        "required_items": REQUIRED_MODEL_DIRS,
        "missing_items": missing_items,
        "checked_at": time.time(),
        "latency_ms": elapsed_ms,
        "timeout_seconds": OCR_MODEL_CHECK_TIMEOUT_SECONDS,
        "timed_out": timed_out,
    }


def ensure_model_home() -> Path:
    model_home = _model_home()
    zip_path = _models_zip_path()
    if model_home.exists():
        os.environ["PADDLE_PDX_MODEL_HOME"] = str(model_home)
        return model_home
    if zip_path.exists():
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(zip_path.parent)
    if not model_home.exists():
        raise RuntimeError(f"OCR model directory not found: {model_home}")
    os.environ["PADDLE_PDX_MODEL_HOME"] = str(model_home)
    return model_home


def _local_ocr_model_kwargs(model_home: Path) -> dict:
    return {
        "text_detection_model_name": "PP-OCRv5_server_det",
        "text_detection_model_dir": str(model_home / "PP-OCRv5_server_det"),
        "text_recognition_model_name": "PP-OCRv5_server_rec",
        "text_recognition_model_dir": str(model_home / "PP-OCRv5_server_rec"),
        "textline_orientation_model_name": "PP-LCNet_x1_0_textline_ori",
        "textline_orientation_model_dir": str(model_home / "PP-LCNet_x1_0_textline_ori"),
        "doc_orientation_classify_model_name": "PP-LCNet_x1_0_doc_ori",
        "doc_orientation_classify_model_dir": str(model_home / "PP-LCNet_x1_0_doc_ori"),
        "doc_unwarping_model_name": "UVDoc",
        "doc_unwarping_model_dir": str(model_home / "UVDoc"),
    }


def get_ocr_model():
    global OCR_MODEL
    global OCR_INIT_ERROR
    global OCR_RUNTIME_DEVICE
    with OCR_INIT_LOCK:
        if OCR_MODEL is not None:
            return OCR_MODEL
        if OCR_INIT_ERROR is not None:
            raise OCR_INIT_ERROR

        os.environ["MKLDNN_ENABLED"] = "0"
        os.environ["FLAGS_use_mkldnn"] = "0"
        os.environ["FLAGS_use_onednn"] = "0"
        os.environ["FLAGS_enable_pir_api"] = "0"
        os.environ["FLAGS_use_cinn"] = "0"
        use_gpu = _ocr_use_gpu()
        gpu_id = _ocr_gpu_id()
        if use_gpu:
            cuda_status = _paddle_cuda_status()
            if not cuda_status["available"]:
                logger.warning("Paddle CUDA device is unavailable; OCR service falls back to CPU: %s", cuda_status)
                use_gpu = False

        if use_gpu:
            os.environ.setdefault("CUDA_VISIBLE_DEVICES", gpu_id)
            os.environ["FLAGS_use_gpu"] = "1"
        else:
            os.environ["FLAGS_use_gpu"] = "0"
        os.environ["PADDLE_SKIP_LOAD_EXTENSION"] = "1"
        os.environ["PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK"] = "True"
        os.environ["PADDLE_PDX_MODEL_SOURCE"] = "LOCAL"
        os.environ["GLOG_minloglevel"] = "2"
        os.environ["FLAGS_minloglevel"] = "3"

        try:
            OCR_STATE["initializing"] = True
            OCR_STATE["last_error"] = None
            model_home = ensure_model_home()
            integrity = check_model_integrity()
            if not integrity["models_ok"]:
                raise RuntimeError(f"OCR model integrity check failed: missing={integrity['missing_items']}")
            from paddleocr import PaddleOCR

            local_models = _local_ocr_model_kwargs(model_home)
            base_constructors = [
                {
                    **local_models,
                    "use_doc_orientation_classify": False,
                    "use_doc_unwarping": False,
                    "use_textline_orientation": False,
                    "lang": "ch",
                    "enable_mkldnn": False,
                },
                {
                    "use_doc_orientation_classify": False,
                    "use_doc_unwarping": False,
                    "use_textline_orientation": False,
                    "lang": "ch",
                    "enable_mkldnn": False,
                },
                {"lang": "ch", "enable_mkldnn": False},
            ]
            constructors = []
            for kwargs in base_constructors:
                if use_gpu:
                    constructors.append({**kwargs, "device": f"gpu:{gpu_id}"})
                    constructors.append({**kwargs, "use_gpu": True, "gpu_id": int(gpu_id) if gpu_id.isdigit() else 0})
                constructors.append({**kwargs, "device": "cpu"})
                constructors.append({**kwargs, "use_gpu": False})
                constructors.append(dict(kwargs))
            last_error: Optional[Exception] = None
            for kwargs in constructors:
                try:
                    OCR_MODEL = PaddleOCR(**kwargs)
                    OCR_INIT_ERROR = None
                    OCR_RUNTIME_DEVICE = "gpu" if str(kwargs.get("device") or "").startswith("gpu") or kwargs.get("use_gpu") is True else "cpu"
                    OCR_STATE["initialized"] = True
                    OCR_STATE["initializing"] = False
                    OCR_STATE["last_success_at"] = time.time()
                    OCR_STATE["last_error"] = None
                    OCR_STATE["runtime_device"] = OCR_RUNTIME_DEVICE
                    logger.info("ocr_initialized args=%s gpu_enabled=%s runtime_device=%s model_home=%s", sorted(kwargs.keys()), use_gpu, OCR_RUNTIME_DEVICE, model_home)
                    return OCR_MODEL
                except TypeError as e:
                    last_error = e
                    continue
                except Exception as e:
                    last_error = e
                    if "device" in kwargs or "use_gpu" in kwargs:
                        logger.warning("PaddleOCR initialization failed; trying next constructor: %s", e)
                        os.environ["FLAGS_use_gpu"] = "0"
                        os.environ["CUDA_VISIBLE_DEVICES"] = ""
                        continue
                    raise
            raise last_error or RuntimeError("PaddleOCR initialization failed")
        except Exception as e:
            OCR_INIT_ERROR = e
            OCR_STATE["initialized"] = False
            OCR_STATE["initializing"] = False
            OCR_STATE["last_error"] = str(e)
            logger.exception("ocr_initialization_failed error=%s", e)
            raise


def warmup_ocr_model() -> dict:
    if OCR_MODEL is not None:
        OCR_STATE["warmup_completed"] = True
        OCR_STATE["last_warmup_at"] = OCR_STATE["last_warmup_at"] or time.time()
        return build_status()
    if not OCR_INIT_LOCK.acquire(blocking=False):
        data = build_status()
        data["status"] = "warming"
        data["message"] = "warmup already in progress"
        return data
    try:
        OCR_STATE["warmup_in_progress"] = True
        OCR_STATE["last_error"] = None
        started = time.time()
        get_ocr_model()
        OCR_STATE["warmup_completed"] = True
        OCR_STATE["last_warmup_at"] = time.time()
        data = build_status()
        data["warmup_latency_ms"] = int((time.time() - started) * 1000)
        logger.info("ocr_warmup_completed latency_ms=%s", data["warmup_latency_ms"])
        return data
    except Exception as exc:
        OCR_STATE["warmup_completed"] = False
        OCR_STATE["last_error"] = str(exc)
        logger.exception("ocr_warmup_failed error=%s", exc)
        data = build_status()
        data["status"] = "error"
        data["error"] = str(exc)
        return data
    finally:
        OCR_STATE["warmup_in_progress"] = False
        OCR_INIT_LOCK.release()


def build_status() -> dict:
    integrity = check_model_integrity()
    init_error = str(OCR_INIT_ERROR) if OCR_INIT_ERROR else OCR_STATE.get("last_error")
    ready = bool(integrity["models_ok"] and OCR_INIT_ERROR is None)
    return {
        "status": "ok" if ready else "error",
        "service": "ocr",
        "service_alive": True,
        "ready": ready,
        "models_ok": bool(integrity["models_ok"]),
        "missing_items": integrity["missing_items"],
        "model_integrity": integrity,
        "model_loaded": OCR_MODEL is not None,
        "ocr_initialized": OCR_MODEL is not None,
        "initializing": bool(OCR_STATE.get("initializing")),
        "warmup_completed": bool(OCR_STATE.get("warmup_completed")),
        "warmup_in_progress": bool(OCR_STATE.get("warmup_in_progress")),
        "warmup_enabled": OCR_WARMUP_ENABLED,
        "warmup_timeout_seconds": OCR_WARMUP_TIMEOUT_SECONDS,
        "last_warmup_at": OCR_STATE.get("last_warmup_at"),
        "last_success_at": OCR_STATE.get("last_success_at"),
        "model_home": integrity["model_home"],
        "gpu_requested": _ocr_use_gpu(),
        "gpu_enabled": OCR_RUNTIME_DEVICE == "gpu" if OCR_MODEL is not None else _ocr_use_gpu(),
        "runtime_device": OCR_RUNTIME_DEVICE,
        "gpu_id": _ocr_gpu_id() if _ocr_use_gpu() else None,
        "cuda_visible_devices": os.environ.get("CUDA_VISIBLE_DEVICES"),
        "paddle_cuda": _paddle_cuda_status(),
        "init_error": init_error,
        "error": init_error,
    }


def _image_bytes_to_cv2(img_bytes: bytes):
    import cv2
    import numpy as np

    nparr = np.frombuffer(img_bytes, np.uint8)
    return cv2.imdecode(nparr, cv2.IMREAD_COLOR)


def _normalize_box(box):
    import numpy as np

    if box is None:
        return None
    if isinstance(box, np.ndarray):
        box = box.tolist()
    if not isinstance(box, (list, tuple)) or not box:
        return None
    if len(box) == 4 and not isinstance(box[0], (list, tuple)):
        x1, y1, x2, y2 = box
        return [[float(x1), float(y1)], [float(x2), float(y1)], [float(x2), float(y2)], [float(x1), float(y2)]]
    if len(box) >= 4 and isinstance(box[0], (list, tuple, np.ndarray)):
        points = []
        for item in box[:4]:
            if isinstance(item, np.ndarray):
                item = item.tolist()
            if len(item) >= 2:
                points.append([float(item[0]), float(item[1])])
        if len(points) == 4:
            return points
    return None


def run_ocr(img_bytes: bytes, location: str) -> List[dict]:
    import cv2

    model = get_ocr_model()
    img = _image_bytes_to_cv2(img_bytes)
    if img is None:
        return []
    height, width = img.shape[:2]
    if width < 40 or height < 40:
        return []
    if width < 500 or height < 500:
        img = cv2.resize(img, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)

    results = []
    for result in model.predict(img) or []:
        if isinstance(result, list):
            for line in result:
                if not isinstance(line, list) or len(line) < 2:
                    continue
                bbox = _normalize_box(line[0])
                rec_info = line[1]
                text = str(rec_info[0]).strip() if isinstance(rec_info, (list, tuple)) and rec_info else ""
                if text and bbox:
                    results.append({"text": text, "bbox": bbox, "location": location})
        elif isinstance(result, dict):
            rec_texts = result.get("rec_texts") or []
            boxes = result.get("rec_boxes")
            if boxes is None or len(boxes) == 0:
                boxes = result.get("dt_polys")
            if boxes is None:
                boxes = []
            for text, box in zip(rec_texts, boxes):
                bbox = _normalize_box(box)
                text = str(text).strip()
                if text and bbox:
                    results.append({"text": text, "bbox": bbox, "location": location})
    return results


app = FastAPI(title="SafeGuard OCR Service", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return build_status()


@app.get("/status")
def status():
    return build_status()


@app.post("/warmup")
def warmup():
    return warmup_ocr_model()


@app.on_event("startup")
def startup_warmup():
    if not OCR_WARMUP_ENABLED:
        return
    logger.info("ocr_startup_warmup_enabled")
    warmup_ocr_model()


@app.post("/ocr/image")
async def ocr_image(file: UploadFile = File(...), location: str = Form(default="image")):
    try:
        content = await file.read()
        items = run_ocr(content, location)
        return {"status": "ok", "items": items}
    except Exception as e:
        logger.exception("ocr image failed: %s", e)
        raise HTTPException(status_code=503, detail=str(e))
