"""Celery transport configuration; durable job payloads remain in the database."""

import os

from celery import Celery

EXECUTE_TASK = "signalwatch.execute_job"
SCHEDULE_TASK = "signalwatch.enqueue_scheduled"
QUEUE_NAME = "signalwatch"
BROKER_TIMEOUT = 5

app = Celery("signalwatch", broker=os.environ.get("CELERY_BROKER_URL", "").strip() or None,
             include=["signalwatch.tasks"])
app.conf.update(
    accept_content=["json"],
    task_serializer="json",
    result_serializer="json",
    enable_utc=True,
    timezone="UTC",
    task_ignore_result=True,
    task_store_errors_even_if_ignored=False,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_acks_on_failure_or_timeout=True,
    task_default_queue=QUEUE_NAME,
    task_routes={EXECUTE_TASK: {"queue": QUEUE_NAME}, SCHEDULE_TASK: {"queue": QUEUE_NAME}},
    worker_pool="prefork",
    worker_concurrency=1,
    worker_prefetch_multiplier=1,
    # Recycle only after a task returns, preserving active collection and its
    # durable checkpoint while releasing retained allocator/cache memory.
    worker_max_tasks_per_child=100,
    worker_max_memory_per_child=768 * 1024,  # Celery uses KiB, not bytes.
    worker_enable_remote_control=False,
    worker_cancel_long_running_tasks_on_connection_loss=True,
    broker_connection_timeout=BROKER_TIMEOUT,
    broker_connection_retry=True,
    broker_connection_retry_on_startup=True,
    broker_connection_max_retries=3,
    broker_transport_options={
        "socket_connect_timeout": BROKER_TIMEOUT,
        "socket_timeout": BROKER_TIMEOUT,
        "retry_on_timeout": False,
        # Long imports may exceed Redis' default one-hour visibility window.
        # A redelivery cannot execute concurrently: jobs hold a database/file lock.
        "visibility_timeout": 24 * 60 * 60,
    },
    task_publish_retry=False,
    beat_schedule={"collect-due-sources": {"task": SCHEDULE_TASK, "schedule": 60.0,
                                         "options": {"expires": 60}}},
)
