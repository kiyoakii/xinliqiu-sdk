# -*- coding: utf-8 -*-
"""Background task tracking for long-running device operations.

Long operations (recording a fixed window, syncing a range) exceed typical
agent tool timeouts, so they return a task id immediately and are polled.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Task:
    task_id: str
    name: str
    state: str = "running"  # running | succeeded | failed
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    result: dict[str, Any] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "name": self.name,
            "state": self.state,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "result": self.result,
            "error": self.error,
        }


class TaskRegistry:
    def __init__(self) -> None:
        self._tasks: dict[str, Task] = {}
        self._lock = threading.Lock()

    def submit(self, name: str, fn: Callable[[], dict[str, Any]]) -> Task:
        task = Task(task_id=uuid.uuid4().hex[:12], name=name)
        with self._lock:
            self._tasks[task.task_id] = task

        def runner() -> None:
            try:
                result = fn()
                task.result = result
                # A structured result that reports ok=False is a finished
                # operation with a non-success outcome, not a success.
                if isinstance(result, dict) and result.get("ok") is False:
                    task.state = "failed"
                    task.error = str(result.get("state") or "operation reported ok=false")
                else:
                    task.state = "succeeded"
            except BaseException as exc:  # noqa: BLE001 - surfaced to callers
                task.error = f"{type(exc).__name__}: {exc}"
                task.state = "failed"
                if not isinstance(exc, Exception):
                    task.finished_at = time.time()
                    raise
            finally:
                if task.finished_at is None:
                    task.finished_at = time.time()

        threading.Thread(target=runner, name=f"xinliqiu-{task.task_id}", daemon=True).start()
        return task

    def get(self, task_id: str) -> Task | None:
        with self._lock:
            return self._tasks.get(task_id)

    def prune(self, max_age: float = 3600.0) -> int:
        """Forget finished tasks older than ``max_age`` seconds.

        A running task is never pruned, however long it has run: its
        ``finished_at`` is still ``None``, and dropping it would lose the only
        handle to an operation that is still using the device.
        """
        cutoff = time.time() - max_age
        with self._lock:
            dead = [
                k for k, t in self._tasks.items()
                if t.state != "running"
                and t.finished_at is not None
                and t.finished_at < cutoff
            ]
            for key in dead:
                del self._tasks[key]
            return len(dead)

    def running(self) -> list[Task]:
        """Tasks that have not finished yet."""
        with self._lock:
            return [t for t in self._tasks.values() if t.state == "running"]
