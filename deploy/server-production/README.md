# Server Production Deployment

This directory contains production-ready templates for the v2 server stack.

## Files

- `.env.example`
  Copy to `/etc/safeguard/server.env` and replace credentials.
- `docker-compose.infrastructure.yml`
  Starts PostgreSQL, Redis, and MinIO.
- `systemd/safeguard-api.service`
  FastAPI API process.
- `systemd/safeguard-worker.service`
  Celery worker process.
- `systemd/safeguard-beat.service`
  Celery beat scheduler.
- `systemd/safeguard-ocr.service`
  OCR sidecar service.
- `nginx/safeguard.conf`
  Reverse-proxy template.

## Suggested deployment layout

- App code: `/opt/safeguard`
- Python env: `/opt/conda/envs/scanocr`
- Environment file: `/etc/safeguard/server.env`
- Service user: `safeguard`

## Startup order

1. Start PostgreSQL, Redis, MinIO:
   `docker compose -f docker-compose.infrastructure.yml up -d`
2. Install env file:
   `sudo install -D -m 600 .env.example /etc/safeguard/server.env`
3. Install systemd units:
   copy `systemd/*.service` into `/etc/systemd/system/`
4. Reload and enable:
   `sudo systemctl daemon-reload`
   `sudo systemctl enable --now safeguard-ocr safeguard-api safeguard-worker safeguard-beat`
5. Install nginx config and reload:
   copy `nginx/safeguard.conf` into `/etc/nginx/conf.d/`
   `sudo nginx -t && sudo systemctl reload nginx`

## Notes

- `SAFEGUARD_OCR_SERVICE_URL` must point to the OCR sidecar.
- Admin endpoints require either `SAFEGUARD_ADMIN_TOKEN` or `SAFEGUARD_ADMIN_USER/SAFEGUARD_ADMIN_PASSWORD`.
- Production should use PostgreSQL/Redis/MinIO instead of sqlite/memory/local-file fallback.
