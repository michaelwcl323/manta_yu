#!/usr/bin/env python3
import argparse
import csv
from collections import defaultdict
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Compute average CPU and bandwidth utilization over time."
    )
    parser.add_argument("--csv", required=True, help="Path to resource_usage.csv")
    parser.add_argument(
        "--link-capacity-mbps",
        type=float,
        default=1000.0,
        help="Per-node link capacity in Mbps (default: 1000)",
    )
    parser.add_argument(
        "--window-seconds",
        type=float,
        default=0.0,
        help="Only keep samples in [0, window_seconds] from first sample (<=0 means all)",
    )
    args = parser.parse_args()

    csv_path = Path(args.csv).resolve()
    out_dir = csv_path.parent
    out_csv = out_dir / "resource_usage_avg_over_time.csv"
    out_txt = out_dir / "resource_usage_avg_over_time.txt"

    by_t = defaultdict(list)
    with csv_path.open("r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cpu = row["cpu_usage_pct"].strip()
            rx = row["rx_mbps"].strip()
            tx = row["tx_mbps"].strip()
            if not cpu or not rx or not tx:
                continue
            t = float(row["timestamp_unix"])
            by_t[t].append((float(cpu), float(rx), float(tx)))

    if not by_t:
        raise SystemExit("No valid rows with cpu/rx/tx found.")

    link = max(args.link_capacity_mbps, 1e-9)
    times = sorted(by_t.keys())
    t0 = times[0]
    rows = []
    for t in times:
        if args.window_seconds > 0 and (t - t0) > args.window_seconds:
            continue
        samples = by_t[t]
        n = len(samples)
        avg_cpu = sum(x[0] for x in samples) / n
        avg_rx = sum(x[1] for x in samples) / n
        avg_tx = sum(x[2] for x in samples) / n
        avg_bw_pct = ((avg_rx + avg_tx) / (2.0 * link)) * 100.0
        rows.append(
            {
                "time_s": t - t0,
                "timestamp_unix": t,
                "nodes_counted": n,
                "avg_cpu_usage_pct": avg_cpu,
                "avg_rx_mbps": avg_rx,
                "avg_tx_mbps": avg_tx,
                "avg_bandwidth_used_pct": avg_bw_pct,
            }
        )

    with out_csv.open("w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "time_s",
                "timestamp_unix",
                "nodes_counted",
                "avg_cpu_usage_pct",
                "avg_rx_mbps",
                "avg_tx_mbps",
                "avg_bandwidth_used_pct",
            ],
        )
        w.writeheader()
        for r in rows:
            w.writerow(
                {
                    "time_s": f"{r['time_s']:.3f}",
                    "timestamp_unix": f"{r['timestamp_unix']:.3f}",
                    "nodes_counted": r["nodes_counted"],
                    "avg_cpu_usage_pct": f"{r['avg_cpu_usage_pct']:.3f}",
                    "avg_rx_mbps": f"{r['avg_rx_mbps']:.3f}",
                    "avg_tx_mbps": f"{r['avg_tx_mbps']:.3f}",
                    "avg_bandwidth_used_pct": f"{r['avg_bandwidth_used_pct']:.3f}",
                }
            )

    overall_cpu = sum(r["avg_cpu_usage_pct"] for r in rows) / len(rows)
    overall_bw = sum(r["avg_bandwidth_used_pct"] for r in rows) / len(rows)
    peak_cpu = max(r["avg_cpu_usage_pct"] for r in rows)
    peak_bw = max(r["avg_bandwidth_used_pct"] for r in rows)

    with out_txt.open("w") as f:
        f.write("Average resource usage over time (all nodes)\n")
        f.write(f"Input CSV: {csv_path}\n")
        f.write(f"Link capacity per node: {link:.3f} Mbps\n")
        if args.window_seconds > 0:
            f.write(f"Window seconds: {args.window_seconds:.3f}\n")
        f.write("Bandwidth percent formula: (avg_rx_mbps + avg_tx_mbps) / (2 * link_capacity_mbps) * 100\n\n")
        f.write(f"Time points: {len(rows)}\n")
        f.write(f"Overall avg CPU usage: {overall_cpu:.3f}%\n")
        f.write(f"Overall avg bandwidth used: {overall_bw:.3f}%\n")
        f.write(f"Peak avg CPU usage: {peak_cpu:.3f}%\n")
        f.write(f"Peak avg bandwidth used: {peak_bw:.3f}%\n")
        f.write(f"\nDetailed time series: {out_csv}\n")

    print(out_csv)
    print(out_txt)


if __name__ == "__main__":
    main()
