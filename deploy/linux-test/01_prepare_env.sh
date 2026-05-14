#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DEPLOY_DIR="${SAFEGUARD_DEPLOY_DIR:-/opt/safeguard}"
VENV_DIR="${SAFEGUARD_VENV:-/opt/safeguard-venv}"
SERVICE_USER="${SAFEGUARD_SERVICE_USER:-safeguard}"
SERVICE_GROUP="${SAFEGUARD_SERVICE_GROUP:-$SERVICE_USER}"
MODEL_HOME="${SAFEGUARD_OCR_MODEL_HOME:-$DEPLOY_DIR/server/artifacts/models/paddlex_models}"
MODEL_ZIP_ENV="${SAFEGUARD_OCR_MODELS_ZIP:-}"
MODEL_URL="${SAFEGUARD_OCR_MODELS_URL:-}"
PYTHON_BIN="${SAFEGUARD_PYTHON_BIN:-python3}"
INSTALL_PADDLE="${SAFEGUARD_INSTALL_PADDLE:-true}"
OCR_USE_GPU="${SAFEGUARD_OCR_USE_GPU:-false}"

REQUIRED_MODEL_DIRS=(
  "PP-OCRv5_server_det"
  "PP-OCRv5_server_rec"
  "PP-LCNet_x1_0_textline_ori"
  "PP-LCNet_x1_0_doc_ori"
  "UVDoc"
)

log() {
  printf '[prepare-env] %s\n' "$*"
}

die() {
  printf '[prepare-env] ERROR: %s\n' "$*" >&2
  exit 1
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "please run as root, for example: sudo bash $0"
  fi
}

detect_os() {
  if [[ ! -r /etc/os-release ]]; then
    die "/etc/os-release not found; unsupported Linux distribution"
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_LIKE="${ID_LIKE:-}"
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

install_apt_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y \
    ca-certificates curl wget unzip rsync git nginx \
    python3 python3-venv python3-dev python3-pip \
    build-essential pkg-config \
    libreoffice libreoffice-writer libreoffice-impress \
    fonts-noto-cjk fonts-liberation \
    libgl1 libglib2.0-0
}

install_dnf_packages() {
  local pm="dnf"
  have_cmd dnf || pm="yum"
  "$pm" install -y \
    ca-certificates curl wget unzip rsync git nginx \
    python3 python3-devel python3-pip \
    gcc gcc-c++ make pkgconfig \
    libreoffice libreoffice-writer libreoffice-impress \
    google-noto-sans-cjk-fonts liberation-fonts \
    mesa-libGL glib2
}

install_system_packages() {
  log "installing system packages"
  if have_cmd apt-get; then
    install_apt_packages
  elif have_cmd dnf || have_cmd yum; then
    install_dnf_packages
  else
    die "unsupported package manager; expected apt-get, dnf, or yum"
  fi
}

ensure_user() {
  if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    log "creating group $SERVICE_GROUP"
    groupadd --system "$SERVICE_GROUP"
  fi
  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    log "creating user $SERVICE_USER"
    useradd --system --create-home --home-dir "/opt/${SERVICE_USER}-home" --gid "$SERVICE_GROUP" --shell /usr/sbin/nologin "$SERVICE_USER"
  fi
}

find_requirements() {
  local candidates=(
    "$DEPLOY_DIR/requirements.txt"
    "$SCRIPT_DIR/requirements.txt"
    "$SCRIPT_DIR/../../requirements.txt"
  )
  for item in "${candidates[@]}"; do
    if [[ -f "$item" ]]; then
      readlink -f "$item"
      return 0
    fi
  done
  return 1
}

create_venv() {
  log "creating/updating Python virtual environment: $VENV_DIR"
  mkdir -p "$(dirname "$VENV_DIR")"
  "$PYTHON_BIN" -m venv "$VENV_DIR"
  "$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel

  local req
  if req="$(find_requirements)"; then
    log "installing Python dependencies from $req"
    "$VENV_DIR/bin/python" -m pip install -r "$req"
  else
    log "requirements.txt not found yet; installing baseline packages"
    "$VENV_DIR/bin/python" -m pip install \
      fastapi "uvicorn[standard]" python-multipart pydantic requests httpx openai \
      python-docx pdfplumber openpyxl python-pptx PyMuPDF Pillow paddleocr \
      opencv-python numpy matplotlib reportlab SQLAlchemy celery redis minio \
      psycopg2-binary grpcio grpcio-tools psutil
  fi

  if [[ "$INSTALL_PADDLE" == "true" || "$INSTALL_PADDLE" == "1" ]]; then
    if [[ "$OCR_USE_GPU" == "true" || "$OCR_USE_GPU" == "1" ]]; then
      log "SAFEGUARD_OCR_USE_GPU=$OCR_USE_GPU; not auto-installing GPU paddle because CUDA wheel selection is environment-specific"
    else
      log "installing CPU paddlepaddle for test OCR"
      "$VENV_DIR/bin/python" -m pip install --upgrade paddlepaddle
    fi
  fi
}

copy_or_extract_zip() {
  local zip_path="$1"
  local dest_parent
  dest_parent="$(dirname "$MODEL_HOME")"
  mkdir -p "$dest_parent"
  log "extracting OCR models from $zip_path into $dest_parent"
  unzip -oq "$zip_path" -d "$dest_parent"

  if [[ -d "$dest_parent/models/paddlex_models" && ! -d "$MODEL_HOME" ]]; then
    mkdir -p "$(dirname "$MODEL_HOME")"
    mv "$dest_parent/models/paddlex_models" "$MODEL_HOME"
  fi
  if [[ -d "$dest_parent/paddlex_models" && "$dest_parent/paddlex_models" != "$MODEL_HOME" && ! -d "$MODEL_HOME" ]]; then
    mkdir -p "$(dirname "$MODEL_HOME")"
    mv "$dest_parent/paddlex_models" "$MODEL_HOME"
  fi
}

prepare_models() {
  log "preparing OCR models at $MODEL_HOME"
  mkdir -p "$(dirname "$MODEL_HOME")"

  if [[ -d "$MODEL_HOME" ]]; then
    log "model directory already exists"
    return 0
  fi

  if [[ -d "$SCRIPT_DIR/paddlex_models" ]]; then
    log "copying OCR models from $SCRIPT_DIR/paddlex_models"
    mkdir -p "$(dirname "$MODEL_HOME")"
    rsync -a "$SCRIPT_DIR/paddlex_models/" "$MODEL_HOME/"
    return 0
  fi

  local zip_path=""
  if [[ -n "$MODEL_ZIP_ENV" && -f "$MODEL_ZIP_ENV" ]]; then
    zip_path="$MODEL_ZIP_ENV"
  elif [[ -f "$SCRIPT_DIR/models.zip" ]]; then
    zip_path="$SCRIPT_DIR/models.zip"
  elif [[ -f "$DEPLOY_DIR/server/artifacts/models.zip" ]]; then
    zip_path="$DEPLOY_DIR/server/artifacts/models.zip"
  fi

  if [[ -z "$zip_path" && -n "$MODEL_URL" ]]; then
    zip_path="/tmp/safeguard-models.zip"
    log "downloading OCR models from SAFEGUARD_OCR_MODELS_URL"
    curl -fL --retry 3 --connect-timeout 15 "$MODEL_URL" -o "$zip_path"
  fi

  if [[ -n "$zip_path" ]]; then
    copy_or_extract_zip "$zip_path"
    return 0
  fi

  die "OCR models not found. Put models.zip or paddlex_models/ next to this script, or set SAFEGUARD_OCR_MODELS_URL / SAFEGUARD_OCR_MODELS_ZIP"
}

check_models() {
  local missing=()
  for dirname in "${REQUIRED_MODEL_DIRS[@]}"; do
    if [[ ! -d "$MODEL_HOME/$dirname" ]]; then
      missing+=("$MODEL_HOME/$dirname")
    fi
  done
  if (( ${#missing[@]} > 0 )); then
    printf '%s\n' "${missing[@]}" >&2
    die "OCR model integrity check failed"
  fi
  log "OCR model integrity check passed"
}

verify_runtime() {
  log "verifying runtime"
  have_cmd soffice || die "soffice is not in PATH after installing LibreOffice"
  soffice --version || die "failed to execute soffice"
  "$VENV_DIR/bin/python" - <<'PY'
import importlib
mods = [
    "fastapi", "uvicorn", "sqlalchemy", "httpx", "paddleocr",
    "paddle", "fitz", "docx", "pptx", "openpyxl", "PIL",
]
missing = []
for name in mods:
    try:
        importlib.import_module(name)
    except Exception as exc:
        missing.append(f"{name}: {exc}")
if missing:
    raise SystemExit("missing python modules:\n" + "\n".join(missing))
print("python dependency check passed")
PY
}

fix_permissions() {
  mkdir -p "$DEPLOY_DIR/server/artifacts/models" "$DEPLOY_DIR/server/data" "$DEPLOY_DIR/server/logs" || true
  chown -R "$SERVICE_USER:$SERVICE_GROUP" "$VENV_DIR" "$DEPLOY_DIR" 2>/dev/null || true
}

main() {
  need_root
  detect_os
  log "detected OS: ${OS_ID} ${OS_LIKE}"
  install_system_packages
  ensure_user
  create_venv
  prepare_models
  check_models
  verify_runtime
  fix_permissions
  log "environment is ready"
  log "venv: $VENV_DIR"
  log "model_home: $MODEL_HOME"
}

main "$@"
