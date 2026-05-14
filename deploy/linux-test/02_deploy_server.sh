#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DEPLOY_DIR="${SAFEGUARD_DEPLOY_DIR:-/opt/safeguard}"
VENV_DIR="${SAFEGUARD_VENV:-/opt/safeguard-venv}"
SERVICE_USER="${SAFEGUARD_SERVICE_USER:-safeguard}"
SERVICE_GROUP="${SAFEGUARD_SERVICE_GROUP:-$SERVICE_USER}"
ENV_DIR="${SAFEGUARD_ENV_DIR:-/etc/safeguard}"
ENV_FILE="${SAFEGUARD_ENV_FILE:-$ENV_DIR/server.env}"
API_PORT="${SAFEGUARD_API_PORT:-8000}"
OCR_PORT="${SAFEGUARD_OCR_PORT:-8010}"
GRPC_PORT="${SAFEGUARD_GRPC_UPLOAD_PORT:-50051}"
NGINX_PORT="${SAFEGUARD_NGINX_PORT:-80}"
REPO_URL="${SAFEGUARD_REPO_URL:-}"
REPO_REF="${SAFEGUARD_REPO_REF:-main}"
ARCHIVE_PATH="${SAFEGUARD_SOURCE_ARCHIVE:-}"
ADMIN_TOKEN="${SAFEGUARD_ADMIN_TOKEN:-dev-admin-token}"
ADMIN_USER="${SAFEGUARD_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${SAFEGUARD_ADMIN_PASSWORD:-dev-admin-password}"
LLM_PROVIDER="${SAFEGUARD_LLM_PROVIDER:-qwen}"
LLM_API_KEY="${SAFEGUARD_LLM_API_KEY:-}"
OCR_USE_GPU="${SAFEGUARD_OCR_USE_GPU:-false}"
MODEL_HOME="${SAFEGUARD_OCR_MODEL_HOME:-$DEPLOY_DIR/server/artifacts/models/paddlex_models}"
MODEL_ZIP="${SAFEGUARD_OCR_MODELS_ZIP:-$DEPLOY_DIR/server/artifacts/models.zip}"
ENABLE_WORKER="${SAFEGUARD_ENABLE_WORKER:-true}"
ENABLE_BEAT="${SAFEGUARD_ENABLE_BEAT:-true}"
REQUIRE_PRODUCTION_DEPS="${SAFEGUARD_REQUIRE_PRODUCTION_DEPS:-false}"

log() {
  printf '[deploy-server] %s\n' "$*"
}

die() {
  printf '[deploy-server] ERROR: %s\n' "$*" >&2
  exit 1
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "please run as root, for example: sudo bash $0"
  fi
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

ensure_user() {
  if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    groupadd --system "$SERVICE_GROUP"
  fi
  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --create-home --home-dir "/opt/${SERVICE_USER}-home" --gid "$SERVICE_GROUP" --shell /usr/sbin/nologin "$SERVICE_USER"
  fi
}

find_archive() {
  if [[ -n "$ARCHIVE_PATH" && -f "$ARCHIVE_PATH" ]]; then
    readlink -f "$ARCHIVE_PATH"
    return 0
  fi
  local item
  for item in "$SCRIPT_DIR"/safeGuard*.zip "$SCRIPT_DIR"/safeguard*.zip "$SCRIPT_DIR"/server*.zip "$SCRIPT_DIR"/source.zip; do
    if [[ -f "$item" ]]; then
      readlink -f "$item"
      return 0
    fi
  done
  return 1
}

copy_from_current_tree() {
  local candidate
  candidate="$(readlink -f "$SCRIPT_DIR/../..")"
  if [[ -f "$candidate/requirements.txt" && -d "$candidate/server" ]]; then
    log "using current repository tree: $candidate"
    rsync -a --delete \
      --exclude ".git" \
      --exclude "__pycache__" \
      --exclude ".pytest_cache" \
      --exclude "server/data" \
      --exclude "server/logs" \
      "$candidate/" "$STAGING_DIR/"
    return 0
  fi
  return 1
}

prepare_source() {
  STAGING_DIR="$(mktemp -d /tmp/safeguard-source.XXXXXX)"
  TMP_DIR="$(mktemp -d /tmp/safeguard-unpack.XXXXXX)"

  local archive=""
  if archive="$(find_archive)"; then
    log "deploying from archive: $archive"
    unzip -oq "$archive" -d "$TMP_DIR"
    local root=""
    if [[ -f "$TMP_DIR/requirements.txt" && -d "$TMP_DIR/server" ]]; then
      root="$TMP_DIR"
    else
      root="$(find "$TMP_DIR" -mindepth 1 -maxdepth 2 -type f -name requirements.txt -printf '%h\n' | head -n 1 || true)"
    fi
    [[ -n "$root" && -d "$root/server" ]] || die "archive does not contain a SafeGuard source tree"
    rsync -a --delete --exclude ".git" --exclude "__pycache__" --exclude "server/data" --exclude "server/logs" "$root/" "$STAGING_DIR/"
    return 0
  fi

  if [[ -n "$REPO_URL" ]]; then
    have_cmd git || die "git is required for repository deployment"
    log "cloning $REPO_URL ref=$REPO_REF"
    git clone --depth 1 --branch "$REPO_REF" "$REPO_URL" "$STAGING_DIR"
    return 0
  fi

  if copy_from_current_tree; then
    return 0
  fi

  die "no source found. Put a source zip next to this script, set SAFEGUARD_SOURCE_ARCHIVE, or set SAFEGUARD_REPO_URL"
}

backup_existing() {
  if [[ -d "$DEPLOY_DIR" && -f "$DEPLOY_DIR/requirements.txt" ]]; then
    BACKUP_DIR="${DEPLOY_DIR}.backup.$(date +%Y%m%d%H%M%S)"
    log "backing up existing deployment to $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    rsync -a "$DEPLOY_DIR/" "$BACKUP_DIR/"
  fi
}

deploy_code() {
  log "deploying code to $DEPLOY_DIR"
  mkdir -p "$DEPLOY_DIR"

  local keep_dir
  keep_dir="$(mktemp -d /tmp/safeguard-keep.XXXXXX)"
  if [[ -d "$DEPLOY_DIR/server/data" ]]; then
    mkdir -p "$keep_dir/server"
    rsync -a "$DEPLOY_DIR/server/data/" "$keep_dir/server/data/"
  fi
  if [[ -d "$DEPLOY_DIR/server/artifacts/models" ]]; then
    mkdir -p "$keep_dir/server/artifacts"
    rsync -a "$DEPLOY_DIR/server/artifacts/models/" "$keep_dir/server/artifacts/models/"
  fi
  if [[ -f "$DEPLOY_DIR/server/artifacts/models.zip" ]]; then
    mkdir -p "$keep_dir/server/artifacts"
    cp -f "$DEPLOY_DIR/server/artifacts/models.zip" "$keep_dir/server/artifacts/models.zip"
  fi

  rsync -a --delete \
    --exclude "server/data" \
    --exclude "server/logs" \
    --exclude "server/artifacts/models" \
    --exclude "server/artifacts/models.zip" \
    "$STAGING_DIR/" "$DEPLOY_DIR/"

  if [[ -d "$keep_dir/server/data" ]]; then
    mkdir -p "$DEPLOY_DIR/server/data"
    rsync -a "$keep_dir/server/data/" "$DEPLOY_DIR/server/data/"
  fi
  if [[ -d "$keep_dir/server/artifacts/models" ]]; then
    mkdir -p "$DEPLOY_DIR/server/artifacts/models"
    rsync -a "$keep_dir/server/artifacts/models/" "$DEPLOY_DIR/server/artifacts/models/"
  fi
  if [[ -f "$keep_dir/server/artifacts/models.zip" ]]; then
    mkdir -p "$DEPLOY_DIR/server/artifacts"
    cp -f "$keep_dir/server/artifacts/models.zip" "$DEPLOY_DIR/server/artifacts/models.zip"
  fi
  rm -rf "$keep_dir"
}

ensure_models_available() {
  if [[ -d "$MODEL_HOME" ]]; then
    return 0
  fi
  if [[ -d "$SCRIPT_DIR/paddlex_models" ]]; then
    log "copying OCR models from $SCRIPT_DIR/paddlex_models"
    mkdir -p "$(dirname "$MODEL_HOME")"
    rsync -a "$SCRIPT_DIR/paddlex_models/" "$MODEL_HOME/"
  elif [[ -f "$SCRIPT_DIR/models.zip" ]]; then
    log "copying models.zip into deployment"
    mkdir -p "$(dirname "$MODEL_ZIP")"
    cp -f "$SCRIPT_DIR/models.zip" "$MODEL_ZIP"
    unzip -oq "$MODEL_ZIP" -d "$(dirname "$MODEL_HOME")"
  else
    log "OCR model directory is not present yet. Run 01_prepare_env.sh with models.zip/paddlex_models or SAFEGUARD_OCR_MODELS_URL before starting OCR."
  fi
}

write_env_file() {
  log "writing $ENV_FILE"
  mkdir -p "$ENV_DIR"
  umask 077
  cat > "$ENV_FILE" <<EOF
SAFEGUARD_DATABASE_URL=sqlite:///$DEPLOY_DIR/server/data/server_v2.db
SAFEGUARD_CELERY_BROKER_URL=memory://
SAFEGUARD_CELERY_RESULT_BACKEND=cache+memory://
SAFEGUARD_REDIS_URL=
SAFEGUARD_MINIO_ENDPOINT=
SAFEGUARD_MINIO_ACCESS_KEY=
SAFEGUARD_MINIO_SECRET_KEY=
SAFEGUARD_MINIO_SECURE=false
SAFEGUARD_MINIO_BUCKET=safeguard
SAFEGUARD_REQUIRE_PRODUCTION_DEPS=$REQUIRE_PRODUCTION_DEPS

SAFEGUARD_OCR_SERVICE_URL=http://127.0.0.1:$OCR_PORT
SAFEGUARD_OCR_SERVICE_TIMEOUT_SECONDS=120
SAFEGUARD_OCR_USE_GPU=$OCR_USE_GPU
SAFEGUARD_OCR_GPU_ID=0
SAFEGUARD_OCR_MODEL_HOME=$MODEL_HOME
SAFEGUARD_OCR_MODELS_ZIP=$MODEL_ZIP
SAFEGUARD_OCR_WARMUP_ENABLED=false

SAFEGUARD_GRPC_UPLOAD_HOST=0.0.0.0
SAFEGUARD_GRPC_UPLOAD_PORT=$GRPC_PORT

SAFEGUARD_ADMIN_TOKEN=$ADMIN_TOKEN
SAFEGUARD_ADMIN_USER=$ADMIN_USER
SAFEGUARD_ADMIN_PASSWORD=$ADMIN_PASSWORD

SAFEGUARD_LLM_PROVIDER=$LLM_PROVIDER
SAFEGUARD_LLM_API_KEY=$LLM_API_KEY
SAFEGUARD_LLM_ENABLED=true
SAFEGUARD_LLM_TIMEOUT_SECONDS=60
EOF
  chmod 600 "$ENV_FILE"
}

write_systemd_units() {
  log "writing systemd units"
  local python_path="$VENV_DIR/bin"
  cat > /etc/systemd/system/safeguard-api.service <<EOF
[Unit]
Description=SafeGuard API Service
After=network.target

[Service]
Type=simple
WorkingDirectory=$DEPLOY_DIR/server
EnvironmentFile=$ENV_FILE
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$python_path"
ExecStart=$python_path/uvicorn main:app --host 0.0.0.0 --port $API_PORT --workers 1
Restart=always
RestartSec=5
User=$SERVICE_USER
Group=$SERVICE_GROUP

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/safeguard-ocr.service <<EOF
[Unit]
Description=SafeGuard OCR Service
After=network.target

[Service]
Type=simple
WorkingDirectory=$DEPLOY_DIR/server
EnvironmentFile=$ENV_FILE
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$python_path"
ExecStart=$python_path/uvicorn ocr_service:app --host 127.0.0.1 --port $OCR_PORT --workers 1
Restart=always
RestartSec=5
User=$SERVICE_USER
Group=$SERVICE_GROUP

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/safeguard-worker.service <<EOF
[Unit]
Description=SafeGuard Celery Worker
After=network.target safeguard-api.service

[Service]
Type=simple
WorkingDirectory=$DEPLOY_DIR/server
EnvironmentFile=$ENV_FILE
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$python_path"
ExecStart=$python_path/celery -A tasks.celery_app worker --loglevel=INFO --concurrency=2
Restart=always
RestartSec=5
User=$SERVICE_USER
Group=$SERVICE_GROUP

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/safeguard-beat.service <<EOF
[Unit]
Description=SafeGuard Celery Beat
After=network.target safeguard-api.service

[Service]
Type=simple
WorkingDirectory=$DEPLOY_DIR/server
EnvironmentFile=$ENV_FILE
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$python_path"
ExecStart=$python_path/celery -A tasks.celery_app beat --loglevel=INFO
Restart=always
RestartSec=5
User=$SERVICE_USER
Group=$SERVICE_GROUP

[Install]
WantedBy=multi-user.target
EOF
}

write_nginx_config() {
  if ! have_cmd nginx; then
    log "nginx not found; skipping nginx config"
    return 0
  fi
  log "writing nginx config"
  mkdir -p /etc/nginx/conf.d
  cat > /etc/nginx/conf.d/safeguard.conf <<EOF
server {
    listen $NGINX_PORT;
    server_name _;

    client_max_body_size 200m;

    location / {
        proxy_pass http://127.0.0.1:$API_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
}

fix_permissions() {
  log "setting permissions"
  mkdir -p "$DEPLOY_DIR/server/data" "$DEPLOY_DIR/server/logs" "$DEPLOY_DIR/server/artifacts/models"
  chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DEPLOY_DIR"
}

enable_and_start() {
  log "reloading systemd"
  systemctl daemon-reload

  local services=(safeguard-ocr safeguard-api)
  if [[ "$ENABLE_WORKER" == "true" || "$ENABLE_WORKER" == "1" ]]; then
    services+=(safeguard-worker)
  fi
  if [[ "$ENABLE_BEAT" == "true" || "$ENABLE_BEAT" == "1" ]]; then
    services+=(safeguard-beat)
  fi

  log "enabling and starting: ${services[*]}"
  systemctl enable --now "${services[@]}"

  if have_cmd nginx; then
    nginx -t
    systemctl enable --now nginx
    systemctl reload nginx || systemctl restart nginx
  fi
}

health_check() {
  log "health check"
  sleep 3
  curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" "http://127.0.0.1:$API_PORT/api/v1/admin/ocr/health" >/tmp/safeguard-ocr-health.json || true
  curl -fsS "http://127.0.0.1:$OCR_PORT/status" >/tmp/safeguard-ocr-status.json || true
  log "API URL: http://$(hostname -I 2>/dev/null | awk '{print $1}'):$NGINX_PORT/"
  log "Local API: http://127.0.0.1:$API_PORT/"
  log "Admin token: $ADMIN_TOKEN"
  log "Logs:"
  log "  sudo journalctl -u safeguard-api -f"
  log "  sudo journalctl -u safeguard-ocr -f"
}

cleanup_tmp() {
  rm -rf "${STAGING_DIR:-}" "${TMP_DIR:-}"
}

main() {
  trap cleanup_tmp EXIT
  need_root
  ensure_user
  [[ -x "$VENV_DIR/bin/python" ]] || die "Python venv not found at $VENV_DIR. Run 01_prepare_env.sh first."
  prepare_source
  backup_existing
  deploy_code
  ensure_models_available
  write_env_file
  write_systemd_units
  write_nginx_config
  fix_permissions
  enable_and_start
  health_check
  log "deployment completed"
}

main "$@"
