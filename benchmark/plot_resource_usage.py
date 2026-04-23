#!/usr/bin/env python3
import argparse
import csv
from collections import defaultdict
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def parse_csv(path: Path):
    by_host = defaultdict(list)
    with path.open("r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            host = row["host"]
            t = float(row["timestamp_unix"])
            cpu = row["cpu_usage_pct"].strip()
            rx = row["rx_mbps"].strip()
            tx = row["tx_mbps"].strip()
            if not cpu or not rx or not tx:
                continue
            by_host[host].append((t, float(cpu), float(rx), float(tx)))
    return by_host


def pick_font(size=16):
    try:
        return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", size=size)
    except Exception:
        return ImageFont.load_default()


def palette():
    return [
        (31, 119, 180), (255, 127, 14), (44, 160, 44), (214, 39, 40),
        (148, 103, 189), (140, 86, 75), (227, 119, 194), (127, 127, 127),
        (188, 189, 34), (23, 190, 207), (66, 133, 244), (219, 68, 55),
    ]


def draw_line_chart(out_path: Path, title: str, x_label: str, y_label: str, series, y_min=0.0):
    width, height = 1600, 900
    ml, mr, mt, mb = 110, 40, 80, 120
    pw, ph = width - ml - mr, height - mt - mb

    all_x = []
    all_y = []
    for _name, points, _color in series:
        all_x.extend([p[0] for p in points])
        all_y.extend([p[1] for p in points])
    if not all_x or not all_y:
        raise ValueError("No points to draw")

    xmin, xmax = min(all_x), max(all_x)
    ymin, ymax = min(all_y), max(all_y)
    ymin = min(ymin, y_min)
    if xmax <= xmin:
        xmax = xmin + 1.0
    if ymax <= ymin:
        ymax = ymin + 1.0

    img = Image.new("RGB", (width, height), (255, 255, 255))
    d = ImageDraw.Draw(img)
    f_title = pick_font(34)
    f_axis = pick_font(22)
    f_tick = pick_font(18)
    f_leg = pick_font(16)

    d.rectangle([ml, mt, ml + pw, mt + ph], outline=(40, 40, 40), width=2)
    for i in range(1, 10):
        y = mt + int(ph * i / 10)
        d.line([(ml, y), (ml + pw, y)], fill=(230, 230, 230), width=1)
    for i in range(1, 10):
        x = ml + int(pw * i / 10)
        d.line([(x, mt), (x, mt + ph)], fill=(235, 235, 235), width=1)

    for i in range(0, 11):
        xv = xmin + (xmax - xmin) * i / 10.0
        x = ml + int(pw * i / 10)
        d.text((x - 20, mt + ph + 10), f"{xv:.0f}", fill=(30, 30, 30), font=f_tick)
    for i in range(0, 11):
        yv = ymin + (ymax - ymin) * (10 - i) / 10.0
        y = mt + int(ph * i / 10)
        d.text((10, y - 10), f"{yv:.1f}", fill=(30, 30, 30), font=f_tick)

    def sx(x):
        return ml + int((x - xmin) / (xmax - xmin) * pw)

    def sy(y):
        return mt + int((1.0 - (y - ymin) / (ymax - ymin)) * ph)

    for name, points, color in series:
        if len(points) < 2:
            continue
        xy = [(sx(x), sy(y)) for x, y in points]
        d.line(xy, fill=color, width=2)

    d.text((ml, 20), title, fill=(0, 0, 0), font=f_title)
    d.text((ml + pw // 2 - 80, height - 45), x_label, fill=(0, 0, 0), font=f_axis)
    d.text((20, mt - 40), y_label, fill=(0, 0, 0), font=f_axis)

    lx, ly = ml + 10, mt + 10
    for i, (name, _points, color) in enumerate(series[:16]):
        yy = ly + i * 24
        d.line([(lx, yy + 10), (lx + 25, yy + 10)], fill=color, width=3)
        d.text((lx + 32, yy), name, fill=(20, 20, 20), font=f_leg)

    img.save(out_path)


def main():
    parser = argparse.ArgumentParser(description="Plot CPU and bandwidth over time.")
    parser.add_argument("--csv", required=True, help="Path to resource_usage.csv")
    args = parser.parse_args()

    csv_path = Path(args.csv).resolve()
    out_dir = csv_path.parent
    by_host = parse_csv(csv_path)
    if not by_host:
        raise SystemExit("No valid rows found in CSV.")

    t0 = min(points[0][0] for points in by_host.values() if points)
    colors = palette()

    cpu_series = []
    for i, (host, points) in enumerate(sorted(by_host.items())):
        cpu_series.append((host, [(p[0] - t0, p[1]) for p in points], colors[i % len(colors)]))
    cpu_png = out_dir / "cpu_usage_over_time.png"
    draw_line_chart(
        cpu_png,
        "CPU Usage vs Time",
        "Time (s)",
        "CPU Usage (%)",
        cpu_series,
        y_min=0.0,
    )

    totals = defaultdict(lambda: [0.0, 0.0])
    for points in by_host.values():
        for t, _cpu, rx, tx in points:
            tn = round(t - t0, 3)
            totals[tn][0] += rx
            totals[tn][1] += tx

    xs = sorted(totals.keys())
    rxs = [totals[x][0] for x in xs]
    txs = [totals[x][1] for x in xs]

    bw_series = [
        ("Total RX (Mbps)", list(zip(xs, rxs)), (31, 119, 180)),
        ("Total TX (Mbps)", list(zip(xs, txs)), (214, 39, 40)),
    ]
    bw_png = out_dir / "bandwidth_over_time.png"
    draw_line_chart(
        bw_png,
        "Bandwidth vs Time (All Hosts Aggregated)",
        "Time (s)",
        "Bandwidth (Mbps)",
        bw_series,
        y_min=0.0,
    )

    print(cpu_png)
    print(bw_png)


if __name__ == "__main__":
    main()
