#!/usr/bin/env python3
"""Collect process-scoped native counters with pinned, nonmultiplexed events."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess

from probe_oracle_test import oracle


def counters(text: str) -> dict[str, dict[str, float]]:
    result = {}
    for row in text.splitlines():
        fields = row.split(",")
        if len(fields) < 5:
            continue
        event = fields[2].split(":")[0]
        if event not in ("cycles", "instructions", "branches", "branch-misses"):
            continue
        value = float(fields[0])
        running = float(fields[4].strip().rstrip("%"))
        if not math.isfinite(value) or not math.isfinite(running) or not 99 <= running <= 100 or value < 0 or event in result:
            raise ValueError(f"invalid or multiplexed counter: {row}")
        result[event] = {"value": value, "running_pct": running}
    if len(result) != 4 or result["cycles"]["value"] <= 0:
        raise ValueError("missing hardware counters")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cpu", type=int, default=min(os.sched_getaffinity(0)))
    parser.add_argument("--iterations", type=int, default=100000000)
    args = parser.parse_args()
    if args.iterations <= 0 or args.cpu not in os.sched_getaffinity(0):
        parser.error("positive iterations and an admitted CPU are required")
    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "cpu": args.cpu, "probes": {}}
    for probe in ("socket_step", "h2_frame_header", "ws_mask", "pool_select"):
        command = ["perf", "stat", "-x", ",", "--no-big-num", "-e",
                   "{cycles:u,instructions:u,branches:u,branch-misses:u}", "--", "taskset", "-c", str(args.cpu),
                   str(binary), "--probe", probe, "--iterations", str(args.iterations)]
        run = subprocess.run(command, text=True, capture_output=True, timeout=120, check=False)
        (output / f"{probe}.stdout").write_text(run.stdout)
        (output / f"{probe}.csv").write_text(run.stderr)
        (output / f"{probe}.command.json").write_text(json.dumps(command))
        if run.returncode != 0:
            raise RuntimeError(f"hardware collection failed: {output / (probe + '.csv')}")
        match = re.fullmatch(rf"probe={probe} iterations={args.iterations} checksum=(\d+)\n", run.stdout)
        if match is None or int(match[1]) != oracle(probe, args.iterations, 1):
            raise ValueError("independent native checksum mismatch")
        measured = counters(run.stderr)
        branch_misses_per_op = measured["branch-misses"]["value"] / args.iterations
        if branch_misses_per_op > 0.005:
            raise ValueError(f"branch prediction gate failed: {probe}")
        measured["ipc"] = measured["instructions"]["value"] / measured["cycles"]["value"]
        measured["branch_misses_per_op"] = branch_misses_per_op
        report["probes"][probe] = measured
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"{probe}: IPC={measured['ipc']}, branch-misses/op={branch_misses_per_op}", flush=True)


if __name__ == "__main__":
    main()
