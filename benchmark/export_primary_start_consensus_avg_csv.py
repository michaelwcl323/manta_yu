from __future__ import annotations

import argparse
import csv
import math
from collections import defaultdict
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Export CSV where x-axis is time since primary start "
            "(approximated by first consensus proposal timestamp) and "
            "y-axis is average consensus latency."
        )
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="A latency.csv file or a directory containing latency.csv files.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=(
            "Output CSV path. Defaults to "
            "primary_start_vs_consensus_avg.csv under input directory "
            "or next to input file."
        ),
    )
    parser.add_argument(
        "--bin-size",
        type=float,
        default=1.0,
        help="Bucket size for x-axis in seconds. Default: 1.0",
    )
    parser.add_argument(
        "--time-axis",
        choices=["proposal", "commit"],
        default="proposal",
        help="Use proposal or commit timestamp as the event time for x-axis.",
    )
    return parser.parse_args()


def discover_latency_files(input_path: Path) -> list[Path]:
    if input_path.is_file():
        if input_path.name != "latency.csv":
            raise SystemExit(f"Input file must be latency.csv: {input_path}")
        return [input_path]

    if not input_path.is_dir():
        raise SystemExit(f"Input path does not exist: {input_path}")

    files = sorted(input_path.rglob("latency.csv"))
    if not files:
        raise SystemExit(f"No latency.csv found under {input_path}")
    return files


def load_consensus_rows(latency_file: Path, time_axis: str) -> list[tuple[float, float]]:
    with latency_file.open(newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            return []

        fieldnames = set(reader.fieldnames)
        if "proposal_ts" not in fieldnames or "latency_ms" not in fieldnames:
            raise SystemExit(
                f"{latency_file} does not contain proposal_ts/latency_ms columns. "
                "Please regenerate latency.csv with timestamp fields."
            )

        rows: list[tuple[float, float]] = []
        for row in reader:
            if row.get("metric") != "consensus_latency":
                continue

            proposal_text = row.get("proposal_ts")
            commit_text = row.get("commit_ts")
            latency_text = row.get("latency_ms")
            if not proposal_text or not latency_text:
                continue

            proposal_ts = float(proposal_text)
            latency_ms = float(latency_text)

            if time_axis == "proposal":
                event_ts = proposal_ts
            else:
                event_ts = float(commit_text) if commit_text else proposal_ts + latency_ms / 1000.0

            rows.append((event_ts, latency_ms))
        return rows


def normalize_to_primary_start(rows: list[tuple[float, float]]) -> list[tuple[float, float]]:
    if not rows:
        return []

    primary_start_ts = min(event_ts for event_ts, _ in rows)
    return [(event_ts - primary_start_ts, latency_ms) for event_ts, latency_ms in rows]


def aggregate_by_bucket(
    normalized_rows: list[tuple[float, float]],
    bin_size: float,
) -> list[dict[str, float]]:
    if not normalized_rows:
        return []

    grouped: dict[float, list[float]] = defaultdict(list)
    for uptime_s, latency_ms in normalized_rows:
        bucket_index = math.floor(uptime_s / bin_size)
        bucket_start = bucket_index * bin_size
        grouped[bucket_start].append(latency_ms)

    output_rows: list[dict[str, float]] = []
    cumulative_sum = 0.0
    cumulative_count = 0
    for bucket_start in sorted(grouped.keys()):
        values = grouped[bucket_start]
        bucket_count = len(values)
        bucket_avg = sum(values) / bucket_count
        cumulative_sum += sum(values)
        cumulative_count += bucket_count
        cumulative_avg = cumulative_sum / cumulative_count
        output_rows.append(
            {
                "primary_uptime_s": round(bucket_start, 6),
                "avg_consensus_latency_ms": round(bucket_avg, 3),
                "sample_count": bucket_count,
                "cumulative_avg_consensus_latency_ms": round(cumulative_avg, 3),
            }
        )
    return output_rows


def write_output(rows: list[dict[str, float]], output_file: Path) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "primary_uptime_s",
                "avg_consensus_latency_ms",
                "sample_count",
                "cumulative_avg_consensus_latency_ms",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def default_output_path(input_path: Path) -> Path:
    if input_path.is_file():
        return input_path.parent / "primary_start_vs_consensus_avg.csv"
    return input_path / "primary_start_vs_consensus_avg.csv"


def main() -> None:
    args = parse_args()
    if args.bin_size <= 0:
        raise SystemExit("--bin-size must be > 0")

    input_path = args.input.resolve()
    latency_files = discover_latency_files(input_path)

    all_normalized_rows: list[tuple[float, float]] = []
    for latency_file in latency_files:
        rows = load_consensus_rows(latency_file, args.time_axis)
        normalized = normalize_to_primary_start(rows)
        all_normalized_rows.extend(normalized)

    if not all_normalized_rows:
        raise SystemExit("No consensus_latency samples found.")

    aggregated = aggregate_by_bucket(all_normalized_rows, args.bin_size)
    output_file = args.output.resolve() if args.output else default_output_path(input_path)
    write_output(aggregated, output_file)
    print(output_file)


if __name__ == "__main__":
    main()
