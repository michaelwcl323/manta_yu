#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path


CONFIGS = [
    {"kappa": 2, "reference": 4, "coverage": 4},
    {"kappa": 2, "reference": 7, "coverage": 7},
    {"kappa": 3, "reference": 7, "coverage": 7},
    {"kappa": 3, "reference": 10, "coverage": 10},
]

ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run fab cloudlab-remote sequentially for predefined parameter sets."
        )
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=1,
        help="How many times to repeat the full 4-config sequence (default: 1).",
    )
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Continue with next config even if one command fails.",
    )
    return parser.parse_args()


def run_one(config: dict[str, int], step: int, total: int, workdir: Path) -> int:
    cmd = [
        "fab",
        "cloudlab-remote",
        f"--kappa={config['kappa']}",
        f"--reference={config['reference']}",
        f"--coverage={config['coverage']}",
    ]
    print()
    print(f"[{step}/{total}] {datetime.utcnow().isoformat(timespec='seconds')}Z")
    print("Running:", " ".join(cmd))
    print("-" * 72)
    process = subprocess.Popen(
        cmd,
        cwd=str(workdir),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert process.stdout is not None

    saw_internal_error = False
    for line in process.stdout:
        print(line, end="")
        plain = ANSI_ESCAPE_RE.sub("", line)
        if "ERROR:" in plain:
            saw_internal_error = True

    process.wait()
    rc = process.returncode
    if rc == 0 and saw_internal_error:
        rc = 1

    print("-" * 72)
    print(f"Exit code: {rc}")
    return rc


def main() -> int:
    args = parse_args()
    if args.rounds <= 0:
        print("Error: --rounds must be > 0")
        return 2

    workdir = Path(__file__).resolve().parent
    total = args.rounds * len(CONFIGS)
    step = 0
    failed = 0

    for round_idx in range(1, args.rounds + 1):
        print()
        print(f"========== Round {round_idx}/{args.rounds} ==========")
        for config in CONFIGS:
            step += 1
            rc = run_one(config, step, total, workdir)
            if rc != 0:
                failed += 1
                if not args.continue_on_error:
                    print("Stopping due to failure (use --continue-on-error to keep going).")
                    return rc

    print()
    if failed == 0:
        print("All fab cloudlab-remote runs completed successfully.")
        return 0
    print(f"Completed with failures: {failed}/{total} commands failed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
