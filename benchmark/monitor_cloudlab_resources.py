#!/usr/bin/env python3
"""
Monitor CPU and bandwidth usage on CloudLab nodes and save results next to summary.txt.

By default, output directory is the latest run directory:
  benchmark/manta_result/.latest_run -> benchmark/manta_result/<...run...>
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fabric import Connection
from paramiko import RSAKey
from paramiko.ssh_exception import PasswordRequiredException, SSHException


SAMPLE_CMD = "sed -n '1p' /proc/stat; cat /proc/net/dev"
DEFAULT_EXCLUDE_IFACE = r"^(lo|docker.*|veth.*|br-.*|virbr.*|tun.*|tap.*)$"


@dataclass
class HostConfig:
    hostname: str
    username: str
    port: int


@dataclass
class CpuNetSnapshot:
    cpu_total: int
    cpu_idle: int
    rx_bytes: int
    tx_bytes: int


class MonitorError(Exception):
    pass


def load_settings(settings_path: Path) -> Dict:
    if not settings_path.exists():
        raise MonitorError(f"Settings file not found: {settings_path}")
    with settings_path.open("r") as f:
        data = json.load(f)
    for key in ("ssh_key_path", "servers"):
        if key not in data:
            raise MonitorError(f"Missing '{key}' in settings file")
    return data


def resolve_output_dir(benchmark_dir: Path, explicit_output_dir: Optional[str]) -> Path:
    if explicit_output_dir:
        out = Path(explicit_output_dir).expanduser()
        return out if out.is_absolute() else (benchmark_dir / out).resolve()

    latest_run_file = benchmark_dir / "manta_result" / ".latest_run"
    if latest_run_file.exists():
        run_dir = latest_run_file.read_text().strip()
        if run_dir:
            run_path = Path(run_dir)
            return run_path if run_path.is_absolute() else (benchmark_dir / run_path).resolve()
    return (benchmark_dir / "manta_result").resolve()


def load_private_key(settings: Dict) -> RSAKey:
    key_path = Path(settings["ssh_key_path"]).expanduser()
    if not key_path.exists():
        raise MonitorError(f"SSH key not found: {key_path}")

    try:
        return RSAKey.from_private_key_file(str(key_path))
    except PasswordRequiredException:
        password = os.environ.get("SSH_KEY_PASSWORD") or settings.get("ssh_key_password")
        if not password:
            raise MonitorError(
                "SSH key is password-protected. Set SSH_KEY_PASSWORD or ssh_key_password in settings."
            )
        return RSAKey.from_private_key_file(str(key_path), password=password)
    except (IOError, SSHException) as e:
        raise MonitorError(f"Failed loading SSH key: {e}")


def hosts_from_settings(settings: Dict) -> List[HostConfig]:
    hosts: List[HostConfig] = []
    for s in settings["servers"]:
        hosts.append(
            HostConfig(
                hostname=s["hostname"],
                username=s.get("username", "root"),
                port=int(s.get("port", 22)),
            )
        )
    if not hosts:
        raise MonitorError("No hosts found in settings")
    return hosts


def parse_cpu_line(line: str) -> Tuple[int, int]:
    parts = line.split()
    if len(parts) < 5 or parts[0] != "cpu":
        raise ValueError(f"Invalid cpu line: {line}")
    values = [int(v) for v in parts[1:]]
    cpu_total = sum(values[:8]) if len(values) >= 8 else sum(values)
    idle = values[3]
    iowait = values[4] if len(values) > 4 else 0
    cpu_idle = idle + iowait
    return cpu_total, cpu_idle


def parse_net_dev(raw: str, iface_exclude: re.Pattern) -> Tuple[int, int]:
    rx_total = 0
    tx_total = 0
    lines = raw.splitlines()
    for line in lines:
        if ":" not in line:
            continue
        iface, rest = line.split(":", 1)
        iface = iface.strip()
        if iface_exclude.match(iface):
            continue
        fields = rest.split()
        if len(fields) < 16:
            continue
        rx_total += int(fields[0])
        tx_total += int(fields[8])
    return rx_total, tx_total


def collect_snapshot(conn: Connection, iface_exclude: re.Pattern) -> CpuNetSnapshot:
    result = conn.run(SAMPLE_CMD, hide=True, warn=True)
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or "remote command failed")

    lines = result.stdout.splitlines()
    if not lines:
        raise RuntimeError("empty remote output")
    cpu_total, cpu_idle = parse_cpu_line(lines[0].strip())
    rx_bytes, tx_bytes = parse_net_dev(result.stdout, iface_exclude)
    return CpuNetSnapshot(cpu_total=cpu_total, cpu_idle=cpu_idle, rx_bytes=rx_bytes, tx_bytes=tx_bytes)


def summarize_rows(rows: List[Dict]) -> Dict[str, Dict[str, float]]:
    by_host: Dict[str, List[Dict]] = {}
    for row in rows:
        if row["cpu_usage_pct"] == "":
            continue
        by_host.setdefault(row["host"], []).append(row)

    summary: Dict[str, Dict[str, float]] = {}
    for host, hs in by_host.items():
        cpu = [float(x["cpu_usage_pct"]) for x in hs]
        rx = [float(x["rx_mbps"]) for x in hs]
        tx = [float(x["tx_mbps"]) for x in hs]
        summary[host] = {
            "samples": float(len(hs)),
            "cpu_avg_pct": sum(cpu) / len(cpu),
            "cpu_max_pct": max(cpu),
            "rx_avg_mbps": sum(rx) / len(rx),
            "rx_max_mbps": max(rx),
            "tx_avg_mbps": sum(tx) / len(tx),
            "tx_max_mbps": max(tx),
        }
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Record remote CPU/bandwidth usage and save beside summary.txt"
    )
    parser.add_argument(
        "--settings",
        default="cloudlab_settings.json",
        help="Path to cloudlab settings JSON (default: benchmark/cloudlab_settings.json)",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory. Default: latest run directory from manta_result/.latest_run",
    )
    parser.add_argument("--interval", type=float, default=1.0, help="Sampling interval seconds")
    parser.add_argument(
        "--duration",
        type=float,
        default=0,
        help="Total monitoring duration seconds (<=0 means run until Ctrl+C)",
    )
    parser.add_argument(
        "--exclude-iface-regex",
        default=DEFAULT_EXCLUDE_IFACE,
        help="Regex for interfaces to exclude",
    )
    args = parser.parse_args()

    stop_flag = {"stop": False}

    def _handle_sigint(_signum, _frame):
        stop_flag["stop"] = True

    signal.signal(signal.SIGINT, _handle_sigint)
    signal.signal(signal.SIGTERM, _handle_sigint)

    benchmark_dir = Path(__file__).resolve().parent
    settings_path = Path(args.settings)
    if not settings_path.is_absolute():
        settings_path = (benchmark_dir / settings_path).resolve()

    try:
        settings = load_settings(settings_path)
        pkey = load_private_key(settings)
        hosts = hosts_from_settings(settings)
        output_dir = resolve_output_dir(benchmark_dir, args.output_dir)
    except MonitorError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "resource_usage.csv"
    summary_path = output_dir / "resource_usage_summary.txt"

    iface_exclude = re.compile(args.exclude_iface_regex)
    connections: Dict[str, Connection] = {}
    prev: Dict[str, Tuple[float, CpuNetSnapshot]] = {}
    rows: List[Dict] = []

    print(f"Output directory: {output_dir}")
    print(f"CSV file: {csv_path}")
    print(f"Summary file: {summary_path}")
    print(f"Hosts: {len(hosts)}")

    try:
        for host in hosts:
            key = f"{host.username}@{host.hostname}:{host.port}"
            conn = Connection(
                host.hostname,
                user=host.username,
                port=host.port,
                connect_kwargs={"pkey": pkey},
                connect_timeout=20,
            )
            conn.open()
            connections[key] = conn

        fieldnames = [
            "timestamp_unix",
            "timestamp_iso",
            "host",
            "cpu_usage_pct",
            "rx_mbps",
            "tx_mbps",
        ]

        start = time.time()
        with csv_path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            while not stop_flag["stop"]:
                now = time.time()
                if args.duration > 0 and (now - start) >= args.duration:
                    break

                iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
                futures = {}
                with ThreadPoolExecutor(max_workers=len(connections)) as ex:
                    for host_key, conn in connections.items():
                        futures[ex.submit(collect_snapshot, conn, iface_exclude)] = host_key

                    for fut in as_completed(futures):
                        host_key = futures[fut]
                        row = {
                            "timestamp_unix": f"{now:.3f}",
                            "timestamp_iso": iso,
                            "host": host_key,
                            "cpu_usage_pct": "",
                            "rx_mbps": "",
                            "tx_mbps": "",
                        }
                        try:
                            snap = fut.result()
                            if host_key in prev:
                                prev_t, prev_snap = prev[host_key]
                                dt = max(now - prev_t, 1e-6)
                                cpu_delta_total = snap.cpu_total - prev_snap.cpu_total
                                cpu_delta_idle = snap.cpu_idle - prev_snap.cpu_idle
                                cpu_pct = (
                                    0.0
                                    if cpu_delta_total <= 0
                                    else 100.0 * (1.0 - cpu_delta_idle / cpu_delta_total)
                                )
                                rx_mbps = (snap.rx_bytes - prev_snap.rx_bytes) * 8.0 / dt / 1_000_000.0
                                tx_mbps = (snap.tx_bytes - prev_snap.tx_bytes) * 8.0 / dt / 1_000_000.0

                                row["cpu_usage_pct"] = f"{max(cpu_pct, 0.0):.2f}"
                                row["rx_mbps"] = f"{max(rx_mbps, 0.0):.3f}"
                                row["tx_mbps"] = f"{max(tx_mbps, 0.0):.3f}"
                        except Exception as e:
                            print(f"[WARN] {host_key} sample failed: {e}")
                        finally:
                            if "snap" in locals():
                                prev[host_key] = (now, snap)
                                del snap
                            writer.writerow(row)
                            rows.append(row)

                f.flush()
                sleep_left = args.interval - (time.time() - now)
                if sleep_left > 0:
                    time.sleep(sleep_left)

    except KeyboardInterrupt:
        pass
    finally:
        for conn in connections.values():
            try:
                conn.close()
            except Exception:
                pass

    summary = summarize_rows(rows)
    with summary_path.open("w") as f:
        f.write("Resource usage summary (per host)\n")
        f.write(f"Generated at: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n")
        f.write(f"Total rows: {len(rows)}\n\n")
        if not summary:
            f.write("No valid samples collected.\n")
        else:
            for host in sorted(summary):
                s = summary[host]
                f.write(f"{host}\n")
                f.write(f"  samples      : {int(s['samples'])}\n")
                f.write(f"  cpu avg/max  : {s['cpu_avg_pct']:.2f}% / {s['cpu_max_pct']:.2f}%\n")
                f.write(f"  rx avg/max   : {s['rx_avg_mbps']:.3f} / {s['rx_max_mbps']:.3f} Mbps\n")
                f.write(f"  tx avg/max   : {s['tx_avg_mbps']:.3f} / {s['tx_max_mbps']:.3f} Mbps\n\n")

    print("Monitoring complete.")
    print(f"Saved: {csv_path}")
    print(f"Saved: {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

