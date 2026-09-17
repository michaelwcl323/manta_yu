from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import matplotlib
import numpy as np
from benchmark.logs import parse_primary_log_markers

if not hasattr(np, "Inf"):
    np.Inf = np.inf

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from plot_latency_common import resolve_primary_start_ts
from plot_latency_y_axis import (
    apply_linear_latency_axis,
    apply_log_scale_latency_below_cut,
    latency_yaxis_label,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate one plot per run: x-axis is time since primary start "
            "(approximated by first proposal timestamp), y-axis is per-sample "
            "consensus latency."
        )
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        required=True,
        help="Directory containing one or more run subdirectories with latency.csv files.",
    )
    parser.add_argument(
        "--time-axis",
        choices=["proposal", "commit"],
        default="commit",
        help="Use proposal or commit timestamp as event time (default: commit).",
    )
    parser.add_argument(
        "--output-name",
        default="primary_start_vs_consensus_latency.png",
        help="Output PNG filename for each run directory.",
    )
    parser.add_argument(
        "--y-log-scale",
        action="store_true",
        help="Plot the latency y-axis on a log scale.",
    )
    parser.add_argument(
        "--y-log-cut-s",
        type=float,
        default=2.0,
        metavar="S",
        help="With --y-log-scale: latency breakpoint (s) below which axis is compressed. Default 2.",
    )
    parser.add_argument(
        "--y-log-below-cut-scale",
        type=float,
        default=0.35,
        metavar="ALPHA",
        help=(
            "With --y-log-scale: compress log10 region below --y-log-cut-s by this factor; "
            "1.0 = uniform log. Default 0.35."
        ),
    )
    parser.add_argument(
        "--no-shared-y-axis",
        action="store_true",
        help="Let each run's figure auto-scale y independently.",
    )
    parser.add_argument(
        "--y-min-s",
        type=float,
        default=None,
        help="Override y-axis minimum (seconds) when using shared axis.",
    )
    parser.add_argument(
        "--y-max-s",
        type=float,
        default=None,
        help="Override y-axis maximum (seconds) when using shared axis.",
    )
    return parser.parse_args()


def discover_run_dirs(input_dir: Path) -> list[Path]:
    if not input_dir.exists() or not input_dir.is_dir():
        raise SystemExit(f"Input directory does not exist: {input_dir}")
    run_dirs = sorted(path.parent for path in input_dir.rglob("latency.csv"))
    if not run_dirs:
        raise SystemExit(f"No latency.csv found under {input_dir}")
    return run_dirs


def load_samples(latency_file: Path) -> list[dict[str, float]]:
    with latency_file.open(newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            return []

        fields = set(reader.fieldnames)
        required = {"metric", "proposal_ts", "latency_ms"}
        if not required.issubset(fields):
            return []

        samples: list[dict[str, float]] = []
        for row in reader:
            if row.get("metric") != "consensus_latency":
                continue

            proposal_text = row.get("proposal_ts")
            commit_text = row.get("commit_ts")
            latency_text = row.get("latency_ms")
            if not proposal_text or not latency_text:
                continue

            proposal_ts = float(proposal_text)
            latency_s = float(latency_text) / 1000.0
            commit_ts = float(commit_text) if commit_text else proposal_ts + latency_s

            samples.append(
                {
                    "proposal_ts": proposal_ts,
                    "commit_ts": commit_ts,
                    "latency_s": latency_s,
                }
            )
    return samples


def to_series(
    samples: list[dict[str, float]],
    time_axis: str,
    run_dir: Path,
) -> list[tuple[float, float]]:
    if not samples:
        return []

    fallback = min(sample["proposal_ts"] for sample in samples)
    primary_start_ts = resolve_primary_start_ts(run_dir, fallback)
    event_key = "commit_ts" if time_axis == "commit" else "proposal_ts"

    series = [
        (sample[event_key] - primary_start_ts, sample["latency_s"])
        for sample in samples
    ]
    return sorted(series, key=lambda item: item[0])


def collect_all_latencies_s(run_dirs: list[Path], time_axis: str) -> list[float]:
    values: list[float] = []
    for run_dir in run_dirs:
        samples = load_samples(run_dir / "latency.csv")
        if not samples:
            continue
        series = to_series(samples, time_axis, run_dir)
        values.extend(y for _, y in series)
    return values


def shared_y_limits_from_values(
    values: list[float],
    y_log_scale: bool,
    margin: float = 0.08,
) -> tuple[float, float]:
    if not values:
        return (1e-3, 1.0)
    lo = float(min(values))
    hi = float(max(values))
    if y_log_scale:
        lo = max(lo * (1.0 - margin), 1e-9)
        hi = hi * (1.0 + margin)
    else:
        span = hi - lo
        pad = max(span * margin, 1e-9)
        lo = max(0.0, lo - pad)
        hi = hi + pad
    if hi <= lo:
        hi = lo + 1e-6
    return (lo, hi)


def load_attack_window(
    run_dir: Path,
    primary_start_ts: float | None,
) -> tuple[float | None, float | None]:
    metadata_file = run_dir / "run_metadata.json"
    if not metadata_file.exists():
        return None, None

    try:
        metadata = json.loads(metadata_file.read_text())
    except Exception:
        return None, None

    node_params = metadata.get("node_params", {})
    if not bool(node_params.get("attack_enabled", False)):
        return None, None

    derived_timing = metadata.get("derived_timing", {})
    artifacts = metadata.get("artifacts", {})
    primary0_log_candidates = []
    primary0_from_metadata = artifacts.get("primary0_log")
    if primary0_from_metadata:
        primary0_log_candidates.append(Path(primary0_from_metadata))
    primary0_log_candidates.append(run_dir / "logs" / "primary-0.log")

    markers = {}
    for candidate in primary0_log_candidates:
        markers = parse_primary_log_markers(candidate)
        if markers:
            break

    attack_start_ts = markers.get("attack_start_ts")
    attack_end_ts = markers.get("attack_end_ts")
    if attack_start_ts is not None and primary_start_ts is not None:
        attack_start = float(attack_start_ts - primary_start_ts)
    else:
        attack_start = derived_timing.get("attack_start_on_primary_start_axis_secs")
        if attack_start is None:
            attack_start = node_params.get("attack_start_secs")

    if attack_start is None:
        return None, None

    if attack_end_ts is not None and attack_start_ts is not None:
        attack_duration = float(max(0.0, attack_end_ts - attack_start_ts))
    else:
        attack_duration = derived_timing.get(
            "attack_duration_secs",
            node_params.get("attack_duration_secs"),
        )
    return float(attack_start), float(attack_duration or 0.0)


def plot_run(
    series: list[tuple[float, float]],
    output_file: Path,
    title: str,
    attack_start_s: float | None,
    attack_duration_s: float | None,
    y_log_scale: bool,
    y_log_cut_s: float,
    y_log_below_cut_scale: float,
    y_lim: tuple[float, float] | None,
) -> None:
    xs = [x for x, _ in series]
    ys = [y for _, y in series]

    fig, ax = plt.subplots(figsize=(10, 3.8), dpi=180)
    ax.scatter(xs, ys, s=6, color="#2563eb", alpha=0.55, label="consensus latency (each sample)")

    if attack_start_s is not None:
        ax.axvline(
            attack_start_s,
            color="#dc2626",
            linestyle="--",
            linewidth=1.4,
            label="attack start",
        )
        if attack_duration_s and attack_duration_s > 0:
            attack_end = attack_start_s + attack_duration_s
            ax.axvspan(attack_start_s, attack_end, color="#fca5a5", alpha=0.18, label="attack window")
            ax.axvline(
                attack_end,
                color="#ef4444",
                linestyle=":",
                linewidth=1.2,
                label="attack end",
            )

    ax.set_title(title)
    ax.set_xlabel("Time since primary start (s)")
    ax.set_ylabel(
        latency_yaxis_label(
            "Consensus latency (s)",
            y_log_scale=y_log_scale,
            below_cut_scale=y_log_below_cut_scale,
            cut_s=y_log_cut_s,
        )
    )
    if y_log_scale:
        apply_log_scale_latency_below_cut(
            ax,
            cut_s=y_log_cut_s,
            below_scale=y_log_below_cut_scale,
        )
    ax.margins(x=0.02)
    if y_lim is not None:
        ax.set_ylim(y_lim[0], y_lim[1])
    else:
        ax.margins(y=0.08)
    if not y_log_scale:
        apply_linear_latency_axis(ax)
    ax.grid(True, linestyle="--", linewidth=0.6, alpha=0.45)
    ax.legend()

    output_file.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_file, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    args = parse_args()
    input_dir = args.input_dir.resolve()
    run_dirs = discover_run_dirs(input_dir)

    shared_lim: tuple[float, float] | None = None
    if not args.no_shared_y_axis:
        all_y = collect_all_latencies_s(run_dirs, args.time_axis)
        if all_y:
            auto_lo, auto_hi = shared_y_limits_from_values(all_y, args.y_log_scale)
            shared_lim = (
                args.y_min_s if args.y_min_s is not None else auto_lo,
                args.y_max_s if args.y_max_s is not None else auto_hi,
            )

    generated = 0
    skipped = 0

    for run_dir in run_dirs:
        latency_file = run_dir / "latency.csv"
        samples = load_samples(latency_file)
        series = to_series(samples, args.time_axis, run_dir)
        if not series:
            skipped += 1
            continue

        primary_start_ts = min(sample["proposal_ts"] for sample in samples)
        attack_start_s, attack_duration_s = load_attack_window(run_dir, primary_start_ts)
        output_file = run_dir / args.output_name
        y_lim = None if args.no_shared_y_axis else shared_lim
        plot_run(
            series,
            output_file,
            title=f"Consensus latency vs primary uptime ({args.time_axis})\n{run_dir.name}",
            attack_start_s=attack_start_s,
            attack_duration_s=attack_duration_s,
            y_log_scale=args.y_log_scale,
            y_log_cut_s=args.y_log_cut_s,
            y_log_below_cut_scale=args.y_log_below_cut_scale,
            y_lim=y_lim,
        )
        print(output_file)
        generated += 1

    print(f"generated={generated} skipped={skipped}")


if __name__ == "__main__":
    main()
