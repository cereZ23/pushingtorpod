"""Thread pools that carry the caller's contextvars into worker threads.

Python's :class:`~concurrent.futures.ThreadPoolExecutor` does **not** copy the
submitting thread's :mod:`contextvars` context to its workers. The scan pipeline
sets a tenant scope (``set_current_tenant`` / ``tenant_scope`` — a contextvar)
in the task thread, so any DB query that runs inside a plain thread pool loses
that scope and trips the tenant-isolation guard (and, under enforce, raises).

``ContextThreadPoolExecutor`` snapshots the active context at submit time and
runs each task inside it, so the tenant scope propagates. It is a drop-in
replacement (``.submit`` and ``.map`` both route through ``submit``).
"""

from __future__ import annotations

import contextvars
from concurrent.futures import ThreadPoolExecutor


class ContextThreadPoolExecutor(ThreadPoolExecutor):
    """ThreadPoolExecutor that runs each submitted callable in a copy of the
    submitting thread's contextvars context (propagating the tenant scope)."""

    def submit(self, fn, *args, **kwargs):
        ctx = contextvars.copy_context()
        return super().submit(ctx.run, fn, *args, **kwargs)
