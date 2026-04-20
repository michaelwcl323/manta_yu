#!/usr/bin/env python3
"""
Plot mean TPS vs mean latency: one line per top-level folder under the result root,
points ordered by input rate (means over runs at the same input rate).

By default, runs with input rate 140000 (r140000) are omitted for most series; pass
--all-input-rates to keep them everywhere. Series listed in
_INCLUDE_EXCLUDED_RATES_BY_SERIES still get selected rates (e.g. manta_complete uses 140000).
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path
from statistics import mean

import numpy as np
import matplotlib

if not hasattr(np, "Inf"):
    np.Inf = np.inf

matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Okabe–Ito (colorblind-friendly), extended with distinct hues
# 默认不绘制 r140000（与实验对比范围一致时可在命令行关闭）
_DEFAULT_EXCLUDE_INPUT_RATES: frozenset[int] = frozenset({140_000})

# 全局排除某些 input rate 时，这些子目录仍保留列出的 rate（例如仍要画 manta_complete 的 r140000）
_INCLUDE_EXCLUDED_RATES_BY_SERIES: dict[str, frozenset[int]] = {
    "manta_complete": frozenset({140_000}),
}

_SERIES_COLORS = [
    "#0072B2",
    "#E69F00",
    "#009E73",
    "#D55E00",
    "#CC79A7",
    "#F0E442",
    "#56B4E9",
    "#000000",
]


def parse_summary(text: str) -> dict[str, int]:
    def num(label: str) -> int:
        m = re.search(rf"{re.escape(label)}\s*([\d,]+)\s*(?:tx/s|ms|B/s)", text)
        if not m:
            raise ValueError(f"missing field: {label}")
        return int(m.group(1).replace(",", ""))

    return {
        "input_rate": num("Input rate:"),
        "consensus_tps": num("Consensus TPS:"),
        "consensus_latency": num("Consensus latency:"),
        "end_to_end_tps": num("End-to-end TPS:"),
        "end_to_end_latency": num("End-to-end latency:"),
    }


def load_summaries_under(
    folder: Path,
    *,
    exclude_input_rates: frozenset[int],
    include_input_rates: frozenset[int] = frozenset(),
) -> list[dict[str, int]]:
    rows: list[dict[str, int]] = []
    for summary_path in sorted(folder.rglob("summary.txt")):
        if "plots" in summary_path.parts:
            continue
        try:
            row = parse_summary(summary_path.read_text(encoding="utf-8", errors="replace"))
        except ValueError:
            continue
        rate = row["input_rate"]
        if rate in exclude_input_rates and rate not in include_input_rates:
            continue
        rows.append(row)
    return rows


def aggregate_by_input_rate(
    rows: list[dict[str, int]], tps_key: str, lat_key: str
) -> tuple[list[float], list[float], list[int]]:
    """Returns (mean_tps, mean_lat, input_rates) sorted by input_rate."""
    by_rate: dict[int, list[tuple[int, int]]] = defaultdict(list)
    for r in rows:
        by_rate[r["input_rate"]].append((r[tps_key], r[lat_key]))

    mean_tps: list[float] = []
    mean_lat: list[float] = []
    rates: list[int] = []

    for rate in sorted(by_rate):
        vals = by_rate[rate]
        tpss = [v[0] for v in vals]
        lats = [v[1] for v in vals]
        mean_tps.append(mean(tpss))
        mean_lat.append(mean(lats))
        rates.append(rate)

    return mean_tps, mean_lat, rates


def discover_series_dirs(result_root: Path) -> list[Path]:
    """One series per immediate child directory (excluding logs, plots, hidden)."""
    series: list[Path] = []
    for p in sorted(result_root.iterdir()):
        if not p.is_dir():
            continue
        name = p.name
        if name.startswith(".") or name in ("logs", "plots"):
            continue
        series.append(p)
    return series


def plot_series(
    result_root: Path,
    output_path: Path,
    *,
    metric: str,
    title: str,
    exclude_input_rates: frozenset[int],
) -> None:
    tps_key = "consensus_tps" if metric == "consensus" else "end_to_end_tps"
    lat_key = "consensus_latency" if metric == "consensus" else "end_to_end_latency"

    fig, ax = plt.subplots(figsize=(9, 5.5), dpi=160)

    for idx, series_dir in enumerate(discover_series_dirs(result_root)):
        include_rates = _INCLUDE_EXCLUDED_RATES_BY_SERIES.get(series_dir.name, frozenset())
        rows = load_summaries_under(
            series_dir,
            exclude_input_rates=exclude_input_rates,
            include_input_rates=include_rates,
        )
        if not rows:
            continue
        mx, my, _rates = aggregate_by_input_rate(rows, tps_key, lat_key)
        if not mx:
            continue
        label = series_dir.name
        color = _SERIES_COLORS[idx % len(_SERIES_COLORS)]
        ax.plot(
            mx,
            my,
            "-o",
            color=color,
            linewidth=1.6,
            markersize=5,
            markerfacecolor=color,
            markeredgecolor="0.2",
            markeredgewidth=0.4,
            alpha=0.95,
            label=label,
            zorder=2 + idx * 0.01,
        )

    ax.set_xlabel("Throughput (tx/s)")
    ax.set_ylabel("Latency (ms)")
    if title:
        ax.set_title(title)
    ax.grid(True, linestyle="--", linewidth=0.55, alpha=0.55)
    ax.legend(loc="best", framealpha=0.95)
    fig.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Mean TPS vs mean latency: one line per folder, ordered by input rate."
    )
    p.add_argument(
        "--input-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "manta_result",
        help="Root directory containing one subdirectory per series (e.g. manta_no_solid_round).",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output PNG path (default: <input-dir>/mean_tps_latency_by_folder.png).",
    )
    p.add_argument(
        "--metric",
        choices=("consensus", "end_to_end"),
        default="consensus",
        help="Which TPS/latency pair to plot.",
    )
    p.add_argument(
        "--title",
        default="",
        help="Figure title (default: none).",
    )
    p.add_argument(
        "--all-input-rates",
        action="store_true",
        help="不排除任何 input rate（所有系列都含 r140000）。默认全局排除 r140000，但 manta_complete 仍会单独保留 140000。",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    root = args.input_dir.resolve()
    out = args.output.resolve() if args.output else root / "mean_tps_latency_by_folder.png"
    exclude = frozenset() if args.all_input_rates else _DEFAULT_EXCLUDE_INPUT_RATES
    plot_series(
        root,
        out,
        metric=args.metric,
        title=args.title,
        exclude_input_rates=exclude,
    )
    print(out)


if __name__ == "__main__":
    main()
