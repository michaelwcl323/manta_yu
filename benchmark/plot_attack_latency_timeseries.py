from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

import numpy as np
import matplotlib

if not hasattr(np, "Inf"):
    np.Inf = np.inf

matplotlib.use("Agg")
import matplotlib.pyplot as plt


DEFAULT_ORDER = ["k2-c4", "k2-c7", "k3-c7", "k4-c7"]
TIME_AXIS_PROPOSAL = "proposal"
TIME_AXIS_COMMIT = "commit"


def load_run_metadata(run_dir: Path) -> dict:
    metadata_file = run_dir / "run_metadata.json"
    if not metadata_file.exists():
        return {}
    return json.loads(metadata_file.read_text())


def execution_time_axis_t0(metadata: dict) -> float | None:
    """Wall-clock T0 shared with Summary *Execution time* and ``latency.csv`` ``relative_time_s``."""
    v = metadata.get("execution_time_start_unix")
    if v is not None:
        return float(v)
    legacy = metadata.get("execution_origin_unix")
    return float(legacy) if legacy is not None else None


def config_label(node_params: dict) -> str:
    return f"k{int(node_params.get('kappa', 0))}-c{int(node_params.get('coverage', 0))}"


def get_attack_window(
    metadata: dict,
    attack_start_override: float | None,
    attack_duration_override: float | None,
) -> dict[str, float | None | bool]:
    node_params = metadata.get("node_params", {})
    attack_enabled = bool(node_params.get("attack_enabled", False))
    attack_start_secs = (
        attack_start_override
        if attack_start_override is not None
        else node_params.get("attack_start_secs")
    )
    attack_duration_secs = (
        attack_duration_override
        if attack_duration_override is not None
        else node_params.get("attack_duration_secs")
    )

    if (
        attack_start_secs is None
        or (not attack_enabled and attack_start_override is None)
    ):
        return {
            "offset_s": None,
            "start": None,
            "duration": None,
            "use_execution_time_axis": False,
        }

    start_secs = float(attack_start_secs)
    use_axis = execution_time_axis_t0(metadata) is not None
    return {
        "offset_s": start_secs,
        # Same wall clock as Summary Execution time T0: attack at x = attack_start_secs when T0
        # is last primary boot (matches node ``attack_start_secs`` after boot).
        "start": start_secs if use_axis else 0.0,
        "duration": float(attack_duration_secs or 0.0),
        "use_execution_time_axis": use_axis,
    }


def load_consensus_latency_rows(
    run_dir: Path,
    time_axis: str,
    attack_window: dict[str, float | None | bool],
    metadata: dict,
) -> list[dict[str, float]]:
    latency_file = run_dir / "latency.csv"
    if not latency_file.exists():
        return []

    raw_rows: list[dict[str, float]] = []
    with latency_file.open(newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("metric") != "consensus_latency":
                continue
            proposal_ts = row.get("proposal_ts")
            commit_ts = row.get("commit_ts")
            latency_ms = row.get("latency_ms")
            if not proposal_ts or not latency_ms:
                continue
            proposal_value = float(proposal_ts)
            latency_value = float(latency_ms)
            commit_value = float(commit_ts) if commit_ts else proposal_value + latency_value / 1000.0
            rel_raw = row.get("relative_time_s")
            rel_val: float | None
            try:
                rel_val = float(rel_raw) if rel_raw not in (None, "") else None
            except (TypeError, ValueError):
                rel_val = None
            raw_rows.append(
                {
                    "proposal_ts": proposal_value,
                    "commit_ts": commit_value,
                    "latency_ms": latency_value,
                    "relative_time_s": rel_val,
                }
            )

    if not raw_rows:
        return []

    event_key = "proposal_ts" if time_axis == TIME_AXIS_PROPOSAL else "commit_ts"
    first_proposal_ts = min(row["proposal_ts"] for row in raw_rows)
    t0_exec = execution_time_axis_t0(metadata)
    if t0_exec is not None:
        out: list[dict[str, float]] = []
        for row in raw_rows:
            # ``latency.csv`` records ``relative_time_s = commit_ts - T0`` (same T0 as
            # ``run_metadata.execution_time_start_unix``). Use that column on the commit axis so
            # the plot matches the CSV exactly; proposal axis stays ``proposal_ts - T0``.
            if time_axis == TIME_AXIS_COMMIT:
                rel = row.get("relative_time_s")
                if rel is not None:
                    aligned_time_s = float(rel)
                else:
                    aligned_time_s = row["commit_ts"] - t0_exec
            else:
                aligned_time_s = row["proposal_ts"] - t0_exec
            out.append({"aligned_time_s": aligned_time_s, "latency_ms": row["latency_ms"]})
        return out
    attack_offset_s = float(attack_window.get("offset_s") or 0.0)
    return [
        {
            "aligned_time_s": row[event_key] - first_proposal_ts - attack_offset_s,
            "latency_ms": row["latency_ms"],
        }
        for row in raw_rows
    ]


def rolling_quantile_series(
    rows: list[dict[str, float]],
    window_size_s: float,
    step_size_s: float,
    min_samples: int,
) -> list[dict[str, float]]:
    if not rows:
        return []

    ordered = sorted(rows, key=lambda row: row["aligned_time_s"])
    xs = np.array([row["aligned_time_s"] for row in ordered], dtype=float)
    ys = np.array([row["latency_ms"] for row in ordered], dtype=float)

    half_window = window_size_s / 2.0
    start = np.floor(xs.min())
    end = np.ceil(xs.max())
    centers = np.arange(start, end + step_size_s * 0.5, step_size_s)

    series: list[dict[str, float]] = []
    left = 0
    right = 0
    for center in centers:
        window_start = center - half_window
        window_end = center + half_window
        while left < len(xs) and xs[left] < window_start:
            left += 1
        while right < len(xs) and xs[right] <= window_end:
            right += 1
        if right - left < min_samples:
            continue
        window_values = ys[left:right]
        series.append(
            {
                "x": float(center),
                "p50": float(np.percentile(window_values, 50)),
                "p95": float(np.percentile(window_values, 95)),
                "mean": float(np.mean(window_values)),
                "count": float(len(window_values)),
            }
        )
    return series


def aggregate_runs(
    run_dirs: list[Path],
    time_axis: str,
    window_size_s: float,
    step_size_s: float,
    min_samples: int,
    attack_start_override: float | None,
    attack_duration_override: float | None,
) -> tuple[dict[str, list[dict[str, float]]], dict[str, dict[str, float | None]]]:
    grouped_rows: dict[str, list[dict[str, float]]] = defaultdict(list)
    attack_windows: dict[str, dict[str, float | None]] = {}

    for run_dir in run_dirs:
        metadata = load_run_metadata(run_dir)
        node_params = metadata.get("node_params", {})
        label = config_label(node_params)
        attack_window = get_attack_window(
            metadata,
            attack_start_override,
            attack_duration_override,
        )
        rows = load_consensus_latency_rows(
            run_dir,
            time_axis,
            attack_window,
            metadata,
        )
        if not rows:
            continue
        grouped_rows[label].extend(rows)
        if attack_window["start"] is not None:
            attack_windows[label] = {
                "start": attack_window["start"],
                "duration": attack_window["duration"],
                "use_execution_time_axis": attack_window.get(
                    "use_execution_time_axis", False
                ),
            }

    aggregated: dict[str, list[dict[str, float]]] = {}
    for label, rows in grouped_rows.items():
        aggregated[label] = rolling_quantile_series(
            rows,
            window_size_s,
            step_size_s,
            min_samples,
        )

    return aggregated, attack_windows


def draw_latency_execution_line_plot(run_dir: Path, output_path: Path, title: str) -> bool:
    """Plot every ``consensus_latency`` row from ``latency.csv``: x = execution time from T0, y = latency_ms, connected in time order.

    ``x`` uses ``relative_time_s`` when present (same as export: ``commit_ts - execution_time_start_unix``).
    Points follow **latency.csv row order** (export sorts by ``commit_ts``), then connected in that order.
    """
    metadata = load_run_metadata(run_dir)
    t0 = execution_time_axis_t0(metadata)
    latency_path = run_dir / "latency.csv"
    if not latency_path.is_file():
        return False

    pairs: list[tuple[float, float]] = []
    with latency_path.open(newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("metric") != "consensus_latency":
                continue
            latency_ms = row.get("latency_ms")
            commit_ts = row.get("commit_ts")
            if not latency_ms:
                continue
            rel_raw = row.get("relative_time_s")
            try:
                y = float(latency_ms)
            except (TypeError, ValueError):
                continue
            x: float | None = None
            if rel_raw not in (None, ""):
                try:
                    x = float(rel_raw)
                except (TypeError, ValueError):
                    x = None
            if x is None and t0 is not None and commit_ts:
                try:
                    x = float(commit_ts) - float(t0)
                except (TypeError, ValueError):
                    continue
            elif x is None:
                continue
            pairs.append((x, y))

    if not pairs:
        return False

    xs = [p[0] for p in pairs]
    ys = [p[1] for p in pairs]

    fig, ax = plt.subplots(figsize=(11, 5.2), dpi=160)
    ax.plot(
        xs,
        ys,
        color="#1d4ed8",
        linewidth=0.35,
        linestyle="-",
        rasterized=True,
        label="consensus_latency (CSV row order)",
    )
    if len(xs) <= 25_000:
        ax.scatter(
            xs,
            ys,
            s=2,
            c="#1e3a8a",
            alpha=0.1,
            linewidths=0,
            rasterized=True,
            zorder=3,
        )

    node_params = metadata.get("node_params", {})
    if bool(node_params.get("attack_enabled")):
        try:
            a_start = float(node_params.get("attack_start_secs") or 0)
            a_dur = float(node_params.get("attack_duration_secs") or 0)
            ax.axvline(a_start, color="#475569", linestyle="--", linewidth=1.1, label="attack start")
            if a_dur > 0:
                ax.axvspan(a_start, a_start + a_dur, color="#94a3b8", alpha=0.12)
                ax.axvline(
                    a_start + a_dur,
                    color="#64748b",
                    linestyle=":",
                    linewidth=1.0,
                    label="attack end",
                )
        except (TypeError, ValueError):
            pass

    ax.set_title(title)
    ax.set_xlabel(
        "Execution time (s) from T0 — latency.csv relative_time_s (= commit_ts − T0)"
        if t0 is not None
        else "Execution time (s) — latency.csv relative_time_s"
    )
    ax.set_ylabel("Consensus latency (ms)")
    ax.grid(True, linestyle="--", linewidth=0.45, alpha=0.45)
    ax.legend(loc="upper right", fontsize=8)
    ax.margins(x=0.01, y=0.06)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, bbox_inches="tight")
    plt.close(fig)
    return True


def discover_run_dirs(input_dir: Path) -> list[Path]:
    return sorted(path.parent for path in input_dir.rglob("latency.csv"))


def ordered_labels(
    data: dict[str, list[dict[str, float]]],
    preferred: list[str],
) -> list[str]:
    existing = [label for label in preferred if label in data]
    remaining = sorted(label for label in data if label not in preferred)
    return existing + remaining


def draw(
    aggregated: dict[str, list[dict[str, float]]],
    attack_windows: dict[str, dict[str, float | None]],
    output_path: Path,
    title: str,
    label_order: list[str],
    time_axis: str,
) -> None:
    fig, ax = plt.subplots(figsize=(10, 5.8), dpi=180)

    colors = {
        "k2-c4": "#dc2626",
        "k2-c7": "#f59e0b",
        "k3-c7": "#2563eb",
        "k4-c7": "#16a34a",
    }

    ordered = ordered_labels(aggregated, label_order)
    for label in ordered:
        series = aggregated[label]
        if not series:
            continue
        color = colors.get(label)
        xs = [point["x"] for point in series]
        ys = [point["p95"] for point in series]
        ax.plot(
            xs,
            ys,
            linewidth=2.4,
            label=f"{label} rolling p95",
            color=color,
        )

    if attack_windows:
        first = next(iter(attack_windows.values()))
        attack_start = first.get("start")
        attack_duration = first.get("duration")
        if attack_start is not None:
            ax.axvline(
                float(attack_start),
                color="#475569",
                linestyle="--",
                linewidth=1.2,
                label="attack start",
            )
            if attack_duration and attack_duration > 0:
                attack_end = float(attack_start) + float(attack_duration)
                ax.axvspan(float(attack_start), attack_end, color="#94a3b8", alpha=0.15)
                ax.axvline(
                    attack_end,
                    color="#64748b",
                    linestyle=":",
                    linewidth=1.0,
                    label="attack end",
                )

    use_exec = False
    if attack_windows:
        use_exec = bool(
            next(iter(attack_windows.values())).get("use_execution_time_axis")
        )
    if use_exec:
        axis_label = (
            "Execution time (s) since run_metadata.execution_time_start_unix (proposal_ts − T0)"
            if time_axis == TIME_AXIS_PROPOSAL
            else "Execution time (s) = latency.csv relative_time_s (commit_ts − T0)"
        )
    else:
        axis_label = (
            "Seconds since earliest proposal minus attack_start_secs offset (proposal time)"
            if time_axis == TIME_AXIS_PROPOSAL
            else "Seconds since earliest proposal minus attack_start_secs offset (commit time)"
        )
    ax.set_title(title)
    ax.set_xlabel(axis_label)
    ax.set_ylabel("Consensus latency p95 (ms)")
    ax.grid(True, linestyle="--", linewidth=0.6, alpha=0.45)
    ax.legend()
    ax.margins(x=0.02, y=0.08)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, bbox_inches="tight")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plot rolling p95 consensus latency aligned to attack onset."
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        required=True,
        help="Directory containing run subdirectories with latency.csv and run_metadata.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output PNG path. Defaults to attack_latency_timeseries.png inside input-dir.",
    )
    parser.add_argument(
        "--window-size",
        type=float,
        default=5.0,
        help="Rolling window size in seconds.",
    )
    parser.add_argument(
        "--step-size",
        type=float,
        default=1.0,
        help="Spacing between rolling window centers in seconds.",
    )
    parser.add_argument(
        "--min-samples",
        type=int,
        default=25,
        help="Minimum samples required to emit a rolling point.",
    )
    parser.add_argument(
        "--title",
        default="Rolling p95 consensus latency around attack onset",
        help="Plot title.",
    )
    parser.add_argument(
        "--time-axis",
        choices=[TIME_AXIS_PROPOSAL, TIME_AXIS_COMMIT],
        default=TIME_AXIS_COMMIT,
        help=(
            "Align rolling samples by proposal or commit wall time. Default commit: matches "
            "latency.csv ``relative_time_s`` (= commit_ts − execution_time_start_unix) and "
            "Summary Execution time."
        ),
    )
    parser.add_argument(
        "--order",
        default=",".join(DEFAULT_ORDER),
        help="Comma-separated configuration label order, e.g. k2-c4,k2-c7,k3-c7,k4-c7",
    )
    parser.add_argument(
        "--attack-start-secs",
        type=float,
        default=None,
        help="Override attack start time in seconds when metadata is missing or incorrect.",
    )
    parser.add_argument(
        "--attack-duration-secs",
        type=float,
        default=None,
        help="Override attack duration in seconds when metadata is missing or incorrect.",
    )
    parser.add_argument(
        "--skip-raw-line-plot",
        action="store_true",
        help="Do not write latency_execution_line.png (per-sample line plot from latency.csv).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_dir = args.input_dir.resolve()
    output_path = (
        args.output.resolve()
        if args.output
        else input_dir / "attack_latency_timeseries.png"
    )
    run_dirs = discover_run_dirs(input_dir)
    if not run_dirs:
        raise SystemExit(f"No run directories with latency.csv found under {input_dir}")

    aggregated, attack_windows = aggregate_runs(
        run_dirs,
        args.time_axis,
        args.window_size,
        args.step_size,
        args.min_samples,
        args.attack_start_secs,
        args.attack_duration_secs,
    )
    if not aggregated:
        raise SystemExit("No consensus latency samples found.")

    draw(
        aggregated,
        attack_windows,
        output_path,
        args.title,
        [item.strip() for item in args.order.split(",") if item.strip()],
        args.time_axis,
    )
    print(output_path)

    if not args.skip_raw_line_plot:
        raw_title = f"{args.title} — per-sample consensus latency (CSV)"
        for run_dir in run_dirs:
            raw_out = run_dir / "latency_execution_line.png"
            if draw_latency_execution_line_plot(run_dir, raw_out, raw_title):
                print(raw_out)


if __name__ == "__main__":
    main()
