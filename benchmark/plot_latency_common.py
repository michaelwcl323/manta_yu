"""Shared helpers for latency plots (time-axis alignment with benchmark logs)."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from re import search

from benchmark.logs import parse_primary_log_markers


def _to_posix_utc(string: str) -> float:
    return datetime.timestamp(datetime.fromisoformat(string.replace("Z", "+00:00")))


def parse_client_start_ts(run_dir: Path) -> float | None:
    """Earliest client ``Start sending transactions`` wall time under ``run_dir/logs``."""
    logs_dir = run_dir / "logs"
    if not logs_dir.is_dir():
        return None

    starts: list[float] = []
    for path in sorted(logs_dir.glob("client-*.log")):
        try:
            with path.open("r", errors="replace") as f:
                for line in f:
                    if "Start sending" not in line:
                        continue
                    match = search(r"\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z) ", line)
                    if match is not None:
                        starts.append(_to_posix_utc(match.group(1)))
                    break
        except OSError:
            continue
    return min(starts) if starts else None


def resolve_primary_start_ts(run_dir: Path, fallback_min_proposal_ts: float) -> float:
    """
    Unix timestamp for plot t=0.

    Prefer ``run_metadata.benchmark_start_unix`` (synchronized release right before
    duration). Fall back to client Start, then primary-0 boot, then min proposal.
    """
    metadata_path = run_dir / "run_metadata.json"
    if metadata_path.exists():
        try:
            metadata = json.loads(metadata_path.read_text())
            release = metadata.get("benchmark_start_unix")
            if release is not None:
                return float(release)
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            pass

    client_start = parse_client_start_ts(run_dir)
    if client_start is not None:
        return float(client_start)

    log = run_dir / "logs" / "primary-0.log"
    if log.exists():
        markers = parse_primary_log_markers(log)
        boot = markers.get("boot_ts")
        if boot is not None:
            return float(boot)
    return float(fallback_min_proposal_ts)
