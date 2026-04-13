from celery import Celery

from config_app import (
    CELERY_BROKER_URL,
    CELERY_RESULT_BACKEND,
    NON_SENSITIVE_CLEANUP_INTERVAL_SECONDS,
    OFFLINE_SWEEP_INTERVAL_SECONDS,
    UPLOAD_CLEANUP_INTERVAL_SECONDS,
)
from services import (
    cleanup_expired_upload_sessions,
    cleanup_non_sensitive_records,
    mark_offline_agents,
    record_task_failure,
    refresh_watch_dirs,
    run_discovery_pipeline,
)
from storage import redis_cache


celery_app = Celery("safeguard_server_v2", broker=CELERY_BROKER_URL, backend=CELERY_RESULT_BACKEND)
celery_app.conf.task_default_queue = "default"
celery_app.conf.task_always_eager = CELERY_BROKER_URL == "memory://"
celery_app.conf.task_acks_late = True
celery_app.conf.worker_prefetch_multiplier = 1
celery_app.conf.task_default_priority = 5
celery_app.conf.task_queue_max_priority = 10
celery_app.conf.task_routes = {
    "tasks.discovery_task": {"queue": "discovery"},
}
celery_app.conf.beat_schedule = {
    "refresh-watch-dirs": {
        "task": "tasks.refresh_watch_dirs_task",
        "schedule": 300.0,
    },
    "cleanup-expired-uploads": {
        "task": "tasks.cleanup_expired_uploads_task",
        "schedule": float(UPLOAD_CLEANUP_INTERVAL_SECONDS),
    },
    "mark-offline-agents": {
        "task": "tasks.mark_offline_agents_task",
        "schedule": float(OFFLINE_SWEEP_INTERVAL_SECONDS),
    },
    "cleanup-non-sensitive-files": {
        "task": "tasks.cleanup_non_sensitive_task",
        "schedule": float(NON_SENSITIVE_CLEANUP_INTERVAL_SECONDS),
    },
}


@celery_app.task(name="tasks.discovery_task", bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def discovery_task(self, file_hash: str):
    try:
        return run_discovery_pipeline(file_hash)
    except Exception as e:
        record_task_failure("tasks.discovery_task", {"file_hash": file_hash}, str(e))
        raise
    finally:
        redis_cache.delete(f"discovery:queued:{file_hash}")


@celery_app.task(name="tasks.refresh_watch_dirs_task")
def refresh_watch_dirs_task():
    return refresh_watch_dirs()


@celery_app.task(name="tasks.cleanup_expired_uploads_task")
def cleanup_expired_uploads_task():
    return cleanup_expired_upload_sessions()


@celery_app.task(name="tasks.mark_offline_agents_task")
def mark_offline_agents_task():
    return mark_offline_agents()


@celery_app.task(name="tasks.cleanup_non_sensitive_task")
def cleanup_non_sensitive_task():
    return cleanup_non_sensitive_records()


PRIORITY_MAP = {
    "CRITICAL": 9,
    "HIGH": 7,
    "MEDIUM": 5,
    "LOW": 3,
}


def submit_discovery_task(file_hash: str, priority: str = "MEDIUM"):
    task_id = f"discovery:{file_hash}"
    lock_key = f"discovery:queued:{file_hash}"
    if not redis_cache.setnx(lock_key, task_id, 3600):
        return task_id
    task = discovery_task.apply_async(
        args=[file_hash],
        task_id=task_id,
        priority=PRIORITY_MAP.get(str(priority or "MEDIUM").upper(), 5),
    )
    return getattr(task, "id", None) or task_id
