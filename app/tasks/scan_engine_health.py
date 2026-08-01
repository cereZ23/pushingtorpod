"""Scan-engine health: a nuclei detection canary.

Runs nuclei against a fixed target whose vulnerability is known (Google Firing
Range → reflected XSS) and asserts the expected template fires. The result is
cached so a superuser endpoint can show engine health (ok / degraded / failing)
without re-running nuclei on every request.

Self-contained: if the fuzzing-templates set isn't installed it fetches it into a
cache dir, so the canary works before the DAST image change lands.
"""

from __future__ import annotations

import io
import json
import logging
import os
import tarfile
import urllib.request

from app.celery_app import celery
from app.config import settings
from app.core.cache import cache_set_sync
from app.services.scanning.nuclei_canary import evaluate_canary
from app.utils.secure_executor import SecureToolExecutor

logger = logging.getLogger(__name__)

CACHE_KEY = "scan_engine:nuclei_canary"
CACHE_TTL = 60 * 60 * 26  # a day + slack, so a missed daily run still shows the last result


def _ensure_fuzzing_templates() -> str | None:
    """Return a path to the fuzzing-templates, downloading them if absent. None on failure."""
    path = settings.fuzzing_templates_path
    if os.path.isdir(path) and os.listdir(path):
        return path
    try:
        os.makedirs(path, exist_ok=True)
        with urllib.request.urlopen(settings.fuzzing_templates_url, timeout=60) as resp:
            data = resp.read()
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            # strip the top-level "<repo>-main/" dir
            members = tar.getmembers()
            top = members[0].name.split("/")[0] + "/" if members else ""
            for m in members:
                if top and m.name.startswith(top):
                    m.name = m.name[len(top) :]
                if m.name:
                    tar.extract(m, path)  # nosec - trusted PD repo tarball
        return path if os.listdir(path) else None
    except Exception as exc:  # pragma: no cover - network/io
        logger.error("Failed to fetch fuzzing-templates: %s", exc)
        return None


@celery.task(name="app.tasks.scan_engine_health.run_nuclei_efficacy_canary")
def run_nuclei_efficacy_canary() -> dict:
    """Run the nuclei detection canary and cache the result. Returns the result dict."""
    from datetime import datetime, timezone

    result: dict = {"ran_at": datetime.now(timezone.utc).isoformat(), "target": settings.nuclei_canary_target}

    ft = _ensure_fuzzing_templates()
    if not ft:
        result.update({"status": "unavailable", "reason": "fuzzing-templates not installed/reachable"})
        cache_set_sync(CACHE_KEY, result, CACHE_TTL)
        return result

    found_ids: list[str] = []
    try:
        with SecureToolExecutor(0) as executor:  # system-scoped (no tenant)
            target_file = executor.create_input_file("canary.txt", settings.nuclei_canary_target)
            args = [
                "-list",
                target_file,
                "-dast",
                "-t",
                ft,
                "-fa",
                settings.nuclei_canary_aggression,
                "-jsonl",
                "-silent",
                "-rl",
                "30",
                "-c",
                "10",
            ]
            _, stdout, _ = executor.execute("nuclei", args, timeout=settings.nuclei_canary_timeout)
        for line in (stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                found_ids.append(str(json.loads(line).get("template-id", "")))
            except (ValueError, TypeError):
                continue
    except Exception as exc:
        result.update({"status": "error", "reason": str(exc)[:200]})
        cache_set_sync(CACHE_KEY, result, CACHE_TTL)
        logger.error("nuclei canary run failed: %s", exc)
        return result

    result.update(evaluate_canary(found_ids, settings.nuclei_canary_expected))
    cache_set_sync(CACHE_KEY, result, CACHE_TTL)
    logger.info("nuclei canary: %s (matched %s)", result.get("status"), result.get("matched"))
    return result
