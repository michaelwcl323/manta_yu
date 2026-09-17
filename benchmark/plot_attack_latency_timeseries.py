from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from re import search

import numpy as np
import matplotlib
from benchmark.logs import parse_primary_log_markers

if not hasattr(np, "Inf"):
    np.Inf = np.inf

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from plot_latency_common import resolve_primary_start_ts
from plot_latency_y_axis import apply_linear_latency_axis, apply_log_scale_latency_below_cut


DEFAULT_ORDER = ["k2-c4", "k2-c7", "k3-c7", "k4-c7"]
TIME_AXIS_PROPOSAL = "proposal"
TIME_AXIS_COMMIT = "commit"

# Figure typography (axes, ticks, title) and legend; cumulative-mean default y-axis top.
PLOT_FONT_SIZE = 24
PLOT_LEGEND_FONT_SIZE = 16
# Wide time-series aspect (inches); increase width to stretch the plot horizontally.
FIG_WIDTH_IN = 20.0
# Default figure height (inches); larger = taller plot area for the y-axis.
FIG_HEIGHT_DEFAULT_COMPOSITION = 4.75
FIG_HEIGHT_DEFAULT_FIXED_Y = 5
DEFAULT_Y_MAX_MEAN_S = 1.2


def load_run_metadata(run_dir: Path) -> dict:
    metadata_file = run_dir / "run_metadata.json"
    if not metadata_file.exists():
        return {}
    return json.loads(metadata_file.read_text())


def config_label(node_params: dict) -> str:
    return f"k{int(node_params.get('kappa', 0))}-c{int(node_params.get('coverage', 0))}"


def resolve_config_label(run_dir: Path, node_params: dict) -> str:
    """
    Prefer k{kappa}-c{coverage} from ``node_params``. If missing (truncated
    ``run_metadata.json``), parse ``...-k{κ}-ref{r}-...`` from the directory name
    so overlays match ``--order`` (e.g. k2-c4 for k2-ref4 runs).
    """
    k = node_params.get("kappa")
    c = node_params.get("coverage")
    if k is not None and c is not None:
        return f"k{int(k)}-c{int(c)}"
    m = search(r"-k(\d+)-ref(\d+)-", run_dir.name)
    if m:
        return f"k{int(m.group(1))}-c{int(m.group(2))}"
    return config_label(node_params)


def load_primary0_log_markers(run_dir: Path) -> dict:
    metadata = load_run_metadata(run_dir)
    artifacts = metadata.get("artifacts", {})
    candidates = []
    primary0_from_metadata = artifacts.get("primary0_log")
    if primary0_from_metadata:
        candidates.append(Path(primary0_from_metadata))
    candidates.append(run_dir / "logs" / "primary-0.log")

    for candidate in candidates:
        markers = parse_primary_log_markers(candidate)
        if markers:
            return markers
    return {}


def get_attack_window(
    run_dir: Path,
    metadata: dict,
    primary_start_ts: float | None,
    attack_start_override: float | None,
    attack_duration_override: float | None,
    attack_end_override: float | None,
    boot_to_proposal_offset_override: float | None,
) -> dict[str, float | None]:
    node_params = metadata.get("node_params", {})
    attack_enabled = bool(node_params.get("attack_enabled", False))
    configured_attack_start_secs = node_params.get("attack_start_secs")
    derived_timing = metadata.get("derived_timing", {})
    aligned_attack_start_secs = derived_timing.get("attack_start_on_primary_start_axis_secs")
    aligned_attack_end_secs = derived_timing.get("attack_end_on_primary_start_axis_secs")
    primary0_markers = load_primary0_log_markers(run_dir)
    attack_start_ts = primary0_markers.get("attack_start_ts")
    attack_end_ts = primary0_markers.get("attack_end_ts")
    attack_duration_secs = (
        attack_duration_override
        if attack_duration_override is not None
        else derived_timing.get("attack_duration_secs", node_params.get("attack_duration_secs"))
    )

    if not attack_enabled and attack_start_override is None:
        return {
            "start": None,
            "duration": None,
            "trusted": None,
            "configured_start": configured_attack_start_secs,
        }

    if attack_start_override is not None:
        start = float(attack_start_override)
        trusted = True
    elif attack_start_ts is not None and primary_start_ts is not None:
        start = float(attack_start_ts - primary_start_ts)
        trusted = True
    elif aligned_attack_start_secs is not None:
        start = float(aligned_attack_start_secs)
        trusted = True
    elif (
        boot_to_proposal_offset_override is not None
        and configured_attack_start_secs is not None
    ):
        start = float(configured_attack_start_secs) - float(boot_to_proposal_offset_override)
        trusted = True
    else:
        # We have only boot-based config attack_start_secs but no boot->proposal
        # offset. Plotting this on the proposal-aligned axis is misleading, so
        # do not draw an attack line unless caller explicitly overrides.
        start = None
        trusted = False

    duration = float(attack_duration_secs or 0.0)
    if attack_start_override is None and attack_start_ts is not None and attack_end_ts is not None:
        duration = float(max(0.0, attack_end_ts - attack_start_ts))
    elif (
        attack_start_override is None
        and attack_duration_override is None
        and aligned_attack_start_secs is not None
        and aligned_attack_end_secs is not None
    ):
        duration = float(max(0.0, aligned_attack_end_secs - aligned_attack_start_secs))

    if attack_end_override is not None and start is not None:
        duration = float(max(0.0, float(attack_end_override) - float(start)))

    return {
        "start": start,
        "duration": duration,
        "trusted": trusted,
        "configured_start": configured_attack_start_secs,
    }


def load_consensus_latency_rows(
    run_dir: Path,
    time_axis: str,
) -> tuple[list[dict[str, float]], float | None]:
    latency_file = run_dir / "latency.csv"
    if not latency_file.exists():
        return [], None

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
            latency_value_s = float(latency_ms) / 1000.0
            commit_value = float(commit_ts) if commit_ts else proposal_value + latency_value_s
            raw_rows.append(
                {
                    "proposal_ts": proposal_value,
                    "commit_ts": commit_value,
                    "latency_s": latency_value_s,
                }
            )

    if not raw_rows:
        return [], None

    event_key = "proposal_ts" if time_axis == TIME_AXIS_PROPOSAL else "commit_ts"
    fallback = min(row["proposal_ts"] for row in raw_rows)
    primary_start = resolve_primary_start_ts(run_dir, fallback)
    return [
        {
            "aligned_time_s": row[event_key] - primary_start,
            "latency_s": row["latency_s"],
        }
        for row in raw_rows
    ], primary_start


def rolling_quantile_series(
    rows: list[dict[str, float]],
    window_size_s: float,
    step_size_s: float,
    min_samples: int,
) -> list[dict[str, float]]:
    """Sliding time window (original behaviour): p95/p50 per window center."""
    if not rows:
        return []

    ordered = sorted(rows, key=lambda row: row["aligned_time_s"])
    xs = np.array([row["aligned_time_s"] for row in ordered], dtype=float)
    ys = np.array([row["latency_s"] for row in ordered], dtype=float)

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


def rolling_cumulative_mean_series(
    rows: list[dict[str, float]],
    step_size_s: float,
    min_samples: int,
) -> list[dict[str, float]]:
    """
    Expanding-window mean: at each time grid point ``center``, the mean of all samples
    with ``aligned_time_s <= center`` (cumulative average over time).
    """
    if not rows:
        return []

    ordered = sorted(rows, key=lambda row: row["aligned_time_s"])
    xs = np.array([row["aligned_time_s"] for row in ordered], dtype=float)
    ys = np.array([row["latency_s"] for row in ordered], dtype=float)
    prefix = np.cumsum(ys)
    start = float(np.floor(xs.min()))
    end = float(np.ceil(xs.max()))
    centers = np.arange(start, end + step_size_s * 0.5, step_size_s)

    series: list[dict[str, float]] = []
    for center in centers:
        r = int(np.searchsorted(xs, float(center), side="right"))
        if r < min_samples:
            continue
        m = float(prefix[r - 1] / r)
        series.append(
            {
                "x": float(center),
                "p50": m,
                "p95": m,
                "mean": m,
                "count": float(r),
            }
        )
    return series


def binned_cumulative_mean_series(
    rows: list[dict[str, float]],
    bin_width_s: float,
    min_samples: int,
) -> list[dict[str, float]]:
    """At each bin end, cumulative mean of all samples with time <= bin end."""
    if not rows or bin_width_s <= 0:
        return []

    ordered = sorted(rows, key=lambda row: row["aligned_time_s"])
    xs = np.array([row["aligned_time_s"] for row in ordered], dtype=float)
    ys = np.array([row["latency_s"] for row in ordered], dtype=float)
    prefix = np.cumsum(ys)
    t_min = float(xs.min())
    t_max = float(xs.max())
    t = float(np.floor(t_min / bin_width_s) * bin_width_s)
    series: list[dict[str, float]] = []
    while t < t_max + bin_width_s * 0.5:
        t_end = t + bin_width_s
        r = int(np.searchsorted(xs, t_end, side="right"))
        if r >= min_samples:
            m = float(prefix[r - 1] / r)
            center = t + bin_width_s / 2.0
            series.append(
                {
                    "x": float(center),
                    "p50": m,
                    "p95": m,
                    "mean": m,
                    "count": float(r),
                }
            )
        t += bin_width_s
    return series


def _build_aggregated_series(
    rows: list[dict[str, float]],
    *,
    rolling_stat: str,
    window_size_s: float,
    step_size_s: float,
    min_samples: int,
    bin_width_s: float | None,
) -> list[dict[str, float]]:
    if rolling_stat == "mean":
        if bin_width_s is not None and bin_width_s > 0:
            return binned_cumulative_mean_series(rows, bin_width_s, min_samples)
        return rolling_cumulative_mean_series(rows, step_size_s, min_samples)
    if bin_width_s is not None and bin_width_s > 0:
        return binned_quantile_series(rows, bin_width_s, min_samples)
    return rolling_quantile_series(rows, window_size_s, step_size_s, min_samples)


def binned_quantile_series(
    rows: list[dict[str, float]],
    bin_width_s: float,
    min_samples: int,
) -> list[dict[str, float]]:
    """Non-overlapping time bins of width ``bin_width_s``; x is bin center."""
    if not rows or bin_width_s <= 0:
        return []

    ordered = sorted(rows, key=lambda row: row["aligned_time_s"])
    xs = np.array([row["aligned_time_s"] for row in ordered], dtype=float)
    ys = np.array([row["latency_s"] for row in ordered], dtype=float)

    t_min = float(xs.min())
    t_max = float(xs.max())
    t = float(np.floor(t_min / bin_width_s) * bin_width_s)
    series: list[dict[str, float]] = []
    while t < t_max + bin_width_s * 0.5:
        mask = (xs >= t) & (xs < t + bin_width_s)
        window_values = ys[mask]
        if len(window_values) >= min_samples:
            center = t + bin_width_s / 2.0
            series.append(
                {
                    "x": float(center),
                    "p50": float(np.percentile(window_values, 50)),
                    "p95": float(np.percentile(window_values, 95)),
                    "mean": float(np.mean(window_values)),
                    "count": float(len(window_values)),
                }
            )
        t += bin_width_s
    return series


def shared_y_limits_from_values(
    values: list[float],
    y_log_scale: bool,
    margin: float = 0.08,
) -> tuple[float, float]:
    """Y limits from raw latency samples (seconds), with a small margin."""
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


def global_raw_latency_y_limits(
    run_dirs: list[Path],
    time_axis: str,
    y_log_scale: bool,
) -> tuple[float, float]:
    """Same y-range as scatter plots: min/max over all raw consensus_latency samples."""
    values: list[float] = []
    for run_dir in run_dirs:
        rows, _ = load_consensus_latency_rows(run_dir, time_axis)
        values.extend(row["latency_s"] for row in rows)
    return shared_y_limits_from_values(values, y_log_scale)


def aggregate_runs(
    run_dirs: list[Path],
    time_axis: str,
    window_size_s: float,
    step_size_s: float,
    min_samples: int,
    bin_width_s: float | None,
    rolling_stat: str,
    attack_start_override: float | None,
    attack_duration_override: float | None,
    attack_end_override: float | None,
    boot_to_proposal_offset_override: float | None,
) -> tuple[dict[str, list[dict[str, float]]], dict[str, dict[str, float | None]]]:
    grouped_rows: dict[str, list[dict[str, float]]] = defaultdict(list)
    attack_windows: dict[str, dict[str, float | None]] = {}
    unaligned_attack_markers = 0

    for run_dir in run_dirs:
        metadata = load_run_metadata(run_dir)
        node_params = metadata.get("node_params", {})
        label = resolve_config_label(run_dir, node_params)
        rows, primary_start_ts = load_consensus_latency_rows(
            run_dir,
            time_axis,
        )
        if not rows:
            continue
        attack_window = get_attack_window(
            run_dir,
            metadata,
            primary_start_ts,
            attack_start_override,
            attack_duration_override,
            attack_end_override,
            boot_to_proposal_offset_override,
        )
        grouped_rows[label].extend(rows)
        if attack_window["start"] is not None:
            attack_windows[label] = attack_window
        elif attack_window.get("trusted") is False:
            unaligned_attack_markers += 1

    if unaligned_attack_markers > 0:
        print(
            "[warn] Attack marker omitted for "
            f"{unaligned_attack_markers} run(s): missing primary-0 attack markers and "
            "derived timing. Re-process the run so logs are exported or pass "
            "--attack-start-secs to override."
        )

    aggregated: dict[str, list[dict[str, float]]] = {}
    for label, rows in grouped_rows.items():
        aggregated[label] = _build_aggregated_series(
            rows,
            rolling_stat=rolling_stat,
            window_size_s=window_size_s,
            step_size_s=step_size_s,
            min_samples=min_samples,
            bin_width_s=bin_width_s,
        )

    return aggregated, attack_windows


def aggregate_runs_disjoint(
    run_dirs: list[Path],
    time_axis: str,
    window_size_s: float,
    step_size_s: float,
    min_samples: int,
    bin_width_s: float | None,
    rolling_stat: str,
    attack_start_override: float | None,
    attack_duration_override: float | None,
    attack_end_override: float | None,
    boot_to_proposal_offset_override: float | None,
) -> tuple[dict[str, list[dict[str, float]]], dict[str, dict[str, float | None]]]:
    """One rolling series per run directory — always separate curves (same figure, one x/y)."""
    grouped_rows: dict[str, list[dict[str, float]]] = {}
    attack_windows: dict[str, dict[str, float | None]] = {}
    used_labels: set[str] = set()
    unaligned_attack_markers = 0

    for run_dir in run_dirs:
        metadata = load_run_metadata(run_dir)
        node_params = metadata.get("node_params", {})
        base = resolve_config_label(run_dir, node_params)
        label = base
        if label in used_labels:
            short = run_dir.name
            if len(short) > 40:
                short = short[:37] + "..."
            label = f"{base} ({short})"
            suffix = 2
            while label in used_labels:
                label = f"{base} ({short}) #{suffix}"
                suffix += 1
        used_labels.add(label)

        rows, primary_start_ts = load_consensus_latency_rows(run_dir, time_axis)
        if not rows:
            continue
        attack_window = get_attack_window(
            run_dir,
            metadata,
            primary_start_ts,
            attack_start_override,
            attack_duration_override,
            attack_end_override,
            boot_to_proposal_offset_override,
        )
        grouped_rows[label] = rows
        if attack_window["start"] is not None:
            attack_windows[label] = attack_window
        elif attack_window.get("trusted") is False:
            unaligned_attack_markers += 1

    if unaligned_attack_markers > 0:
        print(
            "[warn] Attack marker omitted for "
            f"{unaligned_attack_markers} run(s): missing primary-0 attack markers and "
            "derived timing. Re-process the run so logs are exported or pass "
            "--attack-start-secs to override."
        )

    aggregated: dict[str, list[dict[str, float]]] = {}
    for label, rows in grouped_rows.items():
        aggregated[label] = _build_aggregated_series(
            rows,
            rolling_stat=rolling_stat,
            window_size_s=window_size_s,
            step_size_s=step_size_s,
            min_samples=min_samples,
            bin_width_s=bin_width_s,
        )

    return aggregated, attack_windows


def discover_run_dirs(input_dir: Path) -> list[Path]:
    return sorted(path.parent for path in input_dir.rglob("latency.csv"))


def ordered_labels(
    data: dict[str, list[dict[str, float]]],
    preferred: list[str],
) -> list[str]:
    existing = [label for label in preferred if label in data]
    remaining = sorted(label for label in data if label not in preferred)
    return existing + remaining


def default_png_path(base: Path, rolling_stat: str) -> Path:
    """If rolling_stat is not p95, insert _mean / _p50 before the suffix."""
    if rolling_stat == "p95":
        return base
    return base.parent / f"{base.stem}_{rolling_stat}{base.suffix}"


def rolling_latency_ylabel(rolling_stat: str) -> str:
    return {
        "p95": "Rolling p95 latency (s)",
        "p50": "Rolling p50 latency (s)",
        "mean": "Cumulative mean latency (s)",
    }[rolling_stat]


def composition_y_limits_from_aggregated(
    aggregated: dict[str, list[dict[str, float]]],
    *,
    y_key: str,
    y_log_scale: bool,
    low_pct: float,
    high_pct: float,
    top_headroom: float,
    bottom_pad: float,
) -> tuple[float, float]:
    """
    Y-axis limits from rolling series values (p95 / mean / p50). Default percentiles
    0 / 100 use the true min/max of the plotted series.
    """
    ys: list[float] = []
    for series in aggregated.values():
        for pt in series:
            ys.append(float(pt[y_key]))
    if not ys:
        return (1e-3, 1.0)
    arr = np.asarray(ys, dtype=float)
    arr = arr[np.isfinite(arr) & (arr > 0)]
    if len(arr) == 0:
        return (1e-3, 1.0)
    if low_pct <= 0.0:
        lo = float(np.min(arr))
    else:
        lo = float(np.percentile(arr, low_pct))
    if high_pct >= 100.0:
        hi_bulk = float(np.max(arr))
    else:
        hi_bulk = float(np.percentile(arr, high_pct))
    hi_bulk = max(hi_bulk, lo * 1.0001)
    if y_log_scale:
        log_lo = np.log10(lo)
        log_hi = np.log10(hi_bulk)
        span = max(log_hi - log_lo, 1e-9)
        log_hi_axis = log_hi + top_headroom * span
        log_lo_axis = log_lo - bottom_pad * span
        return (float(10**log_lo_axis), float(10**log_hi_axis))
    span_lin = hi_bulk - lo
    pad_b = bottom_pad * span_lin
    pad_t = top_headroom * span_lin
    return (max(0.0, lo - pad_b), hi_bulk + pad_t)


def draw(
    aggregated: dict[str, list[dict[str, float]]],
    attack_windows: dict[str, dict[str, float | None]],
    output_path: Path,
    title: str,
    label_order: list[str],
    time_axis: str,
    y_log_scale: bool,
    y_log_cut_s: float,
    y_log_below_cut_scale: float,
    y_lim: tuple[float, float] | None,
    x_lim: tuple[float, float],
    *,
    y_composition: bool,
    composition_low_pct: float,
    composition_high_pct: float,
    composition_top_headroom: float,
    composition_bottom_pad: float,
    y_floor: float | None,
    y_ceiling: float | None,
    fig_height: float,
    attack_end_axis_s: float | None = None,
    rolling_stat: str = "p95",
) -> None:
    # Wide, short aspect (paper-style overlay); serif fonts; thin frame.
    paper_rc = {
        "font.family": "serif",
        "font.serif": ["DejaVu Serif", "Times New Roman", "Nimbus Roman", "serif"],
        "font.size": PLOT_FONT_SIZE,
        "axes.titlesize": PLOT_FONT_SIZE,
        "axes.labelsize": PLOT_FONT_SIZE,
        "xtick.labelsize": PLOT_FONT_SIZE,
        "ytick.labelsize": PLOT_FONT_SIZE,
        "axes.linewidth": 0.9,
        "xtick.direction": "in",
        "ytick.direction": "in",
        "legend.frameon": True,
        "legend.fancybox": False,
        "legend.edgecolor": "0.3",
        "legend.fontsize": PLOT_LEGEND_FONT_SIZE,
    }
    markers = ("D", "o", "v", "s", "^", "<", ">", "p", "P", "h")

    with plt.rc_context(paper_rc):
        fig, ax = plt.subplots(figsize=(FIG_WIDTH_IN, fig_height), dpi=180)

        colors = {
            "k2-c4": "#c2410c",
            "k2-c7": "#d97706",
            "k3-c7": "#0284c7",
            "k3-c10": "#7c3aed",
            "k4-c7": "#16a34a",
        }
        fallback_cycle = ["#0d9488", "#db2777", "#4f46e5", "#ca8a04", "#15803d"]

        ordered = ordered_labels(aggregated, label_order)
        for idx, label in enumerate(ordered):
            series = aggregated[label]
            if not series:
                continue
            color = colors.get(label)
            if color is None:
                color = fallback_cycle[idx % len(fallback_cycle)]
            xs = [point["x"] for point in series]
            ys = [point[rolling_stat] for point in series]
            n = len(xs)
            markevery = 1 if n <= 40 else max(2, n // 18)
            mk = markers[idx % len(markers)]
            ax.plot(
                xs,
                ys,
                linewidth=2.6,
                label=label,
                color=color,
                marker=mk,
                markersize=10.0,
                markeredgewidth=0.9,
                markeredgecolor=color,
                markevery=markevery,
                clip_on=True,
            )

        if attack_windows:
            starts = [
                float(item["start"])
                for item in attack_windows.values()
                if item.get("start") is not None
            ]
            durations = [
                float(item["duration"])
                for item in attack_windows.values()
                if item.get("duration") is not None
            ]
            attack_start = float(np.median(starts)) if starts else None
            attack_duration = float(np.median(durations)) if durations else 0.0
            if attack_start is not None:
                ax.axvline(
                    float(attack_start),
                    color="#dc2626",
                    linestyle="--",
                    linewidth=1.35,
                    zorder=0,
                    label="attack start",
                )
                if attack_end_axis_s is not None:
                    attack_end = float(attack_end_axis_s)
                elif attack_duration and attack_duration > 0:
                    attack_end = float(attack_start) + float(attack_duration)
                else:
                    attack_end = None
                if attack_end is not None and attack_end > float(attack_start):
                    ax.axvspan(
                        float(attack_start),
                        attack_end,
                        color="#fecaca",
                        alpha=0.22,
                        zorder=0,
                    )
                    ax.axvline(
                        attack_end,
                        color="#b91c1c",
                        linestyle=":",
                        linewidth=1.0,
                        zorder=0,
                        label="attack end",
                    )

        if title and title.strip():
            ax.set_title(title)
        ax.set_xlabel("Time (s)")
        ax.set_ylabel(rolling_latency_ylabel(rolling_stat))
        if y_log_scale:
            apply_log_scale_latency_below_cut(
                ax,
                cut_s=y_log_cut_s,
                below_scale=y_log_below_cut_scale,
            )
        ax.set_xlim(x_lim[0], x_lim[1])
        if y_composition and aggregated:
            lo, hi = composition_y_limits_from_aggregated(
                aggregated,
                y_key=rolling_stat,
                y_log_scale=y_log_scale,
                low_pct=composition_low_pct,
                high_pct=composition_high_pct,
                top_headroom=composition_top_headroom,
                bottom_pad=composition_bottom_pad,
            )
            if y_floor is not None:
                lo = max(lo, y_floor)
            if y_ceiling is not None:
                hi = min(hi, y_ceiling)
            if hi > lo:
                ax.set_ylim(lo, hi)
            else:
                ax.margins(y=0.08)
        elif y_lim is not None:
            ax.set_ylim(y_lim[0], y_lim[1])
        else:
            ax.margins(y=0.08)
        if not y_log_scale:
            apply_linear_latency_axis(ax)
        ax.grid(True, linestyle="--", linewidth=0.55, alpha=0.45)
        ax.legend(
            loc="best",
            fontsize=PLOT_LEGEND_FONT_SIZE,
            ncol=min(len(ordered), 4) if ordered else 1,
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(output_path, bbox_inches="tight")
        plt.close(fig)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Plot rolling consensus latency (p95, p50, or mean per time window) aligned to attack onset."
        )
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=None,
        help=(
            "Directory containing run subdirectories with latency.csv. "
            "Not used when --merge-four-runs is set."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=(
            "Output PNG path. Defaults to attack_latency_timeseries.png inside input-dir; "
            "with --rolling-stat mean or p50, adds _mean / _p50 before .png unless --output is set."
        ),
    )
    parser.add_argument(
        "--rolling-stat",
        choices=["p95", "p50", "mean"],
        default="p95",
        help=(
            "Statistic to plot: p95 / p50 use a sliding time window; "
            "mean uses cumulative (expanding) mean: at each x, average over all samples with time ≤ x."
        ),
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
        help="Minimum samples required inside a window to emit a point.",
    )
    parser.add_argument(
        "--bin-width-secs",
        type=float,
        default=None,
        metavar="SECONDS",
        help=(
            "If set, use non-overlapping bins of this width instead of the rolling window "
            "(optional alternative to --window-size / --step-size)."
        ),
    )
    parser.add_argument(
        "--no-shared-y-axis",
        action="store_true",
        help="Do not force a common y-axis range across curves (auto per view).",
    )
    parser.add_argument(
        "--y-min-s",
        type=float,
        default=None,
        metavar="S",
        help="Y-axis minimum (seconds). Default 0 unless --y-range-auto.",
    )
    parser.add_argument(
        "--y-max-s",
        type=float,
        default=None,
        metavar="S",
        help=(
            "Y-axis maximum (seconds). Default 10 for p95/p50; for mean, see --y-max-mean-s. "
            "Overrides --y-max-mean-s when set. Use --y-range-auto for data-driven limits."
        ),
    )
    parser.add_argument(
        "--y-max-mean-s",
        type=float,
        default=None,
        metavar="S",
        help=(
            f"Default y-axis max for cumulative-mean plots only (default {DEFAULT_Y_MAX_MEAN_S:g}). "
            "Ignored if --y-max-s is set."
        ),
    )
    parser.add_argument(
        "--y-range-auto",
        action="store_true",
        help=(
            "Ignore --y-min-s/--y-max-s and set y from data (composition or shared raw limits), "
            "e.g. for log-scale or exploratory plots."
        ),
    )
    parser.add_argument(
        "--title",
        default="",
        help="Plot title (default: none, paper-style figure).",
    )
    parser.add_argument(
        "--x-min-s",
        type=float,
        default=0.0,
        help="X-axis minimum (seconds since primary start). Default 0.",
    )
    parser.add_argument(
        "--x-max-s",
        type=float,
        default=123.0,
        help=(
            "X-axis maximum (seconds). Default 123 — a few seconds past 120 so the axis "
            "hints that data continues; use 120 for a hard stop."
        ),
    )
    parser.add_argument(
        "--time-axis",
        choices=[TIME_AXIS_PROPOSAL, TIME_AXIS_COMMIT],
        default=TIME_AXIS_PROPOSAL,
        help="Align points by proposal time or commit time. Defaults to proposal time.",
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
        "--attack-end-secs",
        type=float,
        default=None,
        metavar="S",
        help=(
            "Attack end time on the primary-start axis (seconds). When set, duration is "
            "max(0, end - start), overriding log-derived duration and --attack-duration-secs."
        ),
    )
    parser.add_argument(
        "--boot-to-proposal-offset-secs",
        type=float,
        default=None,
        help=(
            "Manual correction for legacy runs: subtract this offset from "
            "configured attack_start_secs to place attack marker on the "
            "primary-start axis."
        ),
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
        help=(
            "With --y-log-scale: latency breakpoint in seconds; below this, the axis "
            "is compressed (see --y-log-below-cut-scale). Default 2."
        ),
    )
    parser.add_argument(
        "--y-log-below-cut-scale",
        type=float,
        default=0.35,
        metavar="ALPHA",
        help=(
            "With --y-log-scale: in log10 space, scale (t - t_cut) for y <= cut by this "
            "factor; 1.0 = uniform log decades; default 0.35 compresses 0–cut s vertically."
        ),
    )
    parser.add_argument(
        "--merge-runs",
        nargs="+",
        type=Path,
        metavar="RUN_DIR",
        default=None,
        help=(
            "Overlay each run as one curve on a single figure (shared x/y axes). "
            "Requires at least 2 directories with latency.csv. "
            "Default output: attack_latency_timeseries_overlay.png beside the first run."
        ),
    )
    parser.add_argument(
        "--merge-four-runs",
        nargs=4,
        type=Path,
        metavar=("RUN_A", "RUN_B", "RUN_C", "RUN_D"),
        default=None,
        help=(
            "Same as --merge-runs with exactly four paths (legacy). "
            "Default output: attack_latency_timeseries_4overlay.png."
        ),
    )
    parser.add_argument(
        "--no-y-composition",
        action="store_true",
        help=(
            "Disable composition mode: use shared y from raw latencies (with --no-shared-y-axis, "
            "auto margins) instead of tight limits from rolling p95 percentiles plus top headroom."
        ),
    )
    parser.add_argument(
        "--y-composition-low-pct",
        type=float,
        default=0.5,
        metavar="PCT",
        help="Composition mode: lower percentile of rolling p95 for y-axis floor (default 0.5).",
    )
    parser.add_argument(
        "--y-composition-high-pct",
        type=float,
        default=99.5,
        metavar="PCT",
        help=(
            "Composition mode: upper percentile of rolling p95 (default 99.5; use 100 for min/max)."
        ),
    )
    parser.add_argument(
        "--y-composition-top-headroom",
        type=float,
        default=0.42,
        metavar="FRAC",
        help=(
            "Composition mode: extra fraction of log (or linear) span added above the data band "
            "(whitespace above curves; default 0.42)."
        ),
    )
    parser.add_argument(
        "--y-composition-bottom-pad",
        type=float,
        default=0.06,
        metavar="FRAC",
        help="Composition mode: extra fraction of span below the low percentile (default 0.06).",
    )
    parser.add_argument(
        "--fig-height",
        type=float,
        default=None,
        metavar="INCHES",
        help=(
            f"Figure height in inches (default {FIG_HEIGHT_DEFAULT_COMPOSITION} with composition, "
            f"{FIG_HEIGHT_DEFAULT_FIXED_Y} with fixed y-axis)."
        ),
    )
    return parser.parse_args()


def _resolve_default_y_min_max(args: argparse.Namespace) -> None:
    """Set y_min/y_max defaults: cumulative mean uses 0–(y-max-mean-s or DEFAULT_Y_MAX_MEAN_S); else 0–10."""
    if args.y_range_auto:
        return
    if args.y_min_s is None:
        args.y_min_s = 0.0
    if args.y_max_s is None:
        if args.rolling_stat == "mean":
            args.y_max_s = (
                float(args.y_max_mean_s)
                if args.y_max_mean_s is not None
                else DEFAULT_Y_MAX_MEAN_S
            )
        else:
            args.y_max_s = 10.0


def _effective_y_min_max(args: argparse.Namespace) -> tuple[float | None, float | None]:
    """When --y-range-auto, bounds are ignored so y can follow data (composition / shared)."""
    if args.y_range_auto:
        return None, None
    return args.y_min_s, args.y_max_s


def _resolve_y_lim(args, run_dirs: list[Path]) -> tuple[float, float] | None:
    y_min, y_max = _effective_y_min_max(args)
    if y_min is not None and y_max is not None:
        return (float(y_min), float(y_max))
    if args.no_shared_y_axis:
        return None
    if y_min is not None or y_max is not None:
        auto_lo, auto_hi = global_raw_latency_y_limits(run_dirs, args.time_axis, args.y_log_scale)
        return (
            y_min if y_min is not None else auto_lo,
            y_max if y_max is not None else auto_hi,
        )
    return global_raw_latency_y_limits(run_dirs, args.time_axis, args.y_log_scale)


def _resolved_y_lim_and_draw_kw(
    args: argparse.Namespace, y_lim: tuple[float, float] | None
) -> tuple[tuple[float, float] | None, dict]:
    y_min, y_max = _effective_y_min_max(args)
    # Fixed (min,max) both set: use exact y_lim, no composition (e.g. default linear 0–10 s).
    fixed_y = y_min is not None and y_max is not None
    y_composition = not args.no_y_composition and not fixed_y
    fig_height = (
        args.fig_height
        if args.fig_height is not None
        else (
            FIG_HEIGHT_DEFAULT_COMPOSITION
            if y_composition
            else FIG_HEIGHT_DEFAULT_FIXED_Y
        )
    )
    resolved_y_lim = None if y_composition else y_lim
    draw_kw = {
        "y_composition": y_composition,
        "composition_low_pct": args.y_composition_low_pct,
        "composition_high_pct": args.y_composition_high_pct,
        "composition_top_headroom": args.y_composition_top_headroom,
        "composition_bottom_pad": args.y_composition_bottom_pad,
        "y_floor": y_min if y_composition else None,
        "y_ceiling": y_max if y_composition else None,
        "fig_height": fig_height,
    }
    return resolved_y_lim, draw_kw


def main() -> None:
    args = parse_args()
    _resolve_default_y_min_max(args)
    if args.x_max_s <= args.x_min_s:
        raise SystemExit("--x-max-s must be greater than --x-min-s")
    if not args.y_range_auto and args.y_min_s is not None and args.y_max_s is not None:
        if args.y_min_s >= args.y_max_s:
            raise SystemExit("--y-max-s must be greater than --y-min-s")

    overlay_paths = args.merge_runs if args.merge_runs else args.merge_four_runs
    if args.merge_runs and args.merge_four_runs:
        raise SystemExit("Use either --merge-runs or --merge-four-runs, not both.")
    if overlay_paths:
        run_dirs = [p.resolve() for p in overlay_paths]
        if len(run_dirs) < 2:
            raise SystemExit("--merge-runs needs at least two run directories.")
        for rd in run_dirs:
            if not (rd / "latency.csv").exists():
                raise SystemExit(f"Missing latency.csv: {rd}")
        default_overlay_name = (
            "attack_latency_timeseries_4overlay.png"
            if args.merge_four_runs
            else "attack_latency_timeseries_overlay.png"
        )
        output_path = (
            args.output.resolve()
            if args.output
            else default_png_path(run_dirs[0].parent / default_overlay_name, args.rolling_stat)
        )
        aggregated, attack_windows = aggregate_runs_disjoint(
            run_dirs,
            args.time_axis,
            args.window_size,
            args.step_size,
            args.min_samples,
            args.bin_width_secs,
            args.rolling_stat,
            args.attack_start_secs,
            args.attack_duration_secs,
            args.attack_end_secs,
            args.boot_to_proposal_offset_secs,
        )
        if not aggregated:
            raise SystemExit("No consensus latency samples found in the merged runs.")
        y_lim = _resolve_y_lim(args, run_dirs)
        resolved_y_lim, draw_kw = _resolved_y_lim_and_draw_kw(args, y_lim)
        draw(
            aggregated,
            attack_windows,
            output_path,
            args.title,
            [item.strip() for item in args.order.split(",") if item.strip()],
            args.time_axis,
            args.y_log_scale,
            args.y_log_cut_s,
            args.y_log_below_cut_scale,
            resolved_y_lim,
            (args.x_min_s, args.x_max_s),
            attack_end_axis_s=args.attack_end_secs,
            rolling_stat=args.rolling_stat,
            **draw_kw,
        )
        print(output_path)
        return

    if args.input_dir is None:
        raise SystemExit("Either --input-dir, --merge-runs, or --merge-four-runs is required.")

    input_dir = args.input_dir.resolve()
    output_path = (
        args.output.resolve()
        if args.output
        else default_png_path(input_dir / "attack_latency_timeseries.png", args.rolling_stat)
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
        args.bin_width_secs,
        args.rolling_stat,
        args.attack_start_secs,
        args.attack_duration_secs,
        args.attack_end_secs,
        args.boot_to_proposal_offset_secs,
    )
    if not aggregated:
        raise SystemExit("No consensus latency samples found.")

    y_lim = _resolve_y_lim(args, run_dirs)
    resolved_y_lim, draw_kw = _resolved_y_lim_and_draw_kw(args, y_lim)

    draw(
        aggregated,
        attack_windows,
        output_path,
        args.title,
        [item.strip() for item in args.order.split(",") if item.strip()],
        args.time_axis,
        args.y_log_scale,
        args.y_log_cut_s,
        args.y_log_below_cut_scale,
        resolved_y_lim,
        (args.x_min_s, args.x_max_s),
        attack_end_axis_s=args.attack_end_secs,
        rolling_stat=args.rolling_stat,
        **draw_kw,
    )
    print(output_path)


if __name__ == "__main__":
    main()
