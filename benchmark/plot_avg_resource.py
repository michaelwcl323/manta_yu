#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def pick_font(size=16):
    try:
        return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", size=size)
    except Exception:
        return ImageFont.load_default()


def draw_chart(out_path: Path, title: str, y_label: str, points, color):
    width, height = 1400, 800
    ml, mr, mt, mb = 100, 40, 70, 90
    pw, ph = width - ml - mr, height - mt - mb

    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    xmin, xmax = min(xs), max(xs)
    ymin, ymax = min(0.0, min(ys)), max(ys)
    if xmax <= xmin:
        xmax = xmin + 1.0
    if ymax <= ymin:
        ymax = ymin + 1.0

    def sx(x):
        return ml + int((x - xmin) / (xmax - xmin) * pw)

    def sy(y):
        return mt + int((1.0 - (y - ymin) / (ymax - ymin)) * ph)

    img = Image.new("RGB", (width, height), (255, 255, 255))
    d = ImageDraw.Draw(img)
    f_title = pick_font(30)
    f_axis = pick_font(20)
    f_tick = pick_font(16)

    d.rectangle([ml, mt, ml + pw, mt + ph], outline=(30, 30, 30), width=2)
    for i in range(1, 10):
        y = mt + int(ph * i / 10)
        d.line([(ml, y), (ml + pw, y)], fill=(230, 230, 230), width=1)
    for i in range(1, 10):
        x = ml + int(pw * i / 10)
        d.line([(x, mt), (x, mt + ph)], fill=(235, 235, 235), width=1)

    for i in range(11):
        xv = xmin + (xmax - xmin) * i / 10
        x = ml + int(pw * i / 10)
        d.text((x - 18, mt + ph + 8), f"{xv:.0f}", fill=(20, 20, 20), font=f_tick)
    for i in range(11):
        yv = ymin + (ymax - ymin) * (10 - i) / 10
        y = mt + int(ph * i / 10)
        d.text((8, y - 8), f"{yv:.1f}", fill=(20, 20, 20), font=f_tick)

    line_xy = [(sx(x), sy(y)) for x, y in points]
    if len(line_xy) >= 2:
        d.line(line_xy, fill=color, width=3)

    d.text((ml, 20), title, fill=(0, 0, 0), font=f_title)
    d.text((ml + pw // 2 - 45, height - 40), "Time (s)", fill=(0, 0, 0), font=f_axis)
    d.text((20, mt - 36), y_label, fill=(0, 0, 0), font=f_axis)
    img.save(out_path)


def main():
    parser = argparse.ArgumentParser(description="Plot average CPU and bandwidth-used% over time.")
    parser.add_argument("--csv", required=True, help="Path to resource_usage_avg_over_time.csv")
    args = parser.parse_args()

    csv_path = Path(args.csv).resolve()
    out_dir = csv_path.parent

    ts, cpu, bw = [], [], []
    with csv_path.open("r", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            ts.append(float(row["time_s"]))
            cpu.append(float(row["avg_cpu_usage_pct"]))
            bw.append(float(row["avg_bandwidth_used_pct"]))

    if not ts:
        raise SystemExit("No rows in avg-over-time CSV.")

    cpu_png = out_dir / "avg_cpu_usage_over_time.png"
    bw_png = out_dir / "avg_bandwidth_used_percent_over_time.png"

    draw_chart(
        cpu_png,
        "Average CPU Usage Over Time (All Nodes)",
        "CPU Usage (%)",
        list(zip(ts, cpu)),
        (31, 119, 180),
    )
    draw_chart(
        bw_png,
        "Average Bandwidth Used Over Time (All Nodes)",
        "Bandwidth Used (%)",
        list(zip(ts, bw)),
        (214, 39, 40),
    )

    print(cpu_png)
    print(bw_png)


if __name__ == "__main__":
    main()
