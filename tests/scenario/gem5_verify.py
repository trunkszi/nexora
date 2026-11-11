#!/usr/bin/env python3
"""Three-point O3 audit over the minimal native nexora guest."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess

from probe_oracle_test import oracle

COUNTS = (512, 2560, 4608)
ALIASES = {
    "cycles": ("numCycles",),
    "idle": ("idleCycles",),
    "instructions": ("commitStats0.numInsts", "commit.instsCommitted::total", "committedInsts"),
    "ops": ("commitStats0.numOps", "commit.opsCommitted::total", "committedOps"),
    "renamed": ("rename.renamedInsts", "rename.RenamedInsts"),
    "rename_idle": ("rename.idleCycles", "rename.IdleCycles", "rename.status::Idle"),
    "squash": ("rename.squashCycles", "rename.SquashCycles", "rename.status::Squashing"),
    "branch_misses": ("commit.branchMispredicts", "branchPred.condIncorrect"),
    "memory_violations": ("iew.memOrderViolationEvents",),
}


def roi_stats(text: str) -> dict[str, float]:
    epochs = re.findall(r"Begin Simulation Statistics.*?End Simulation Statistics", text, re.DOTALL)
    if len(epochs) != 2:
        raise ValueError("expected measured ROI and final exit epochs")
    return parse_stats(epochs[0])


def parse_stats(text: str) -> dict[str, float]:
    if text.count("Begin Simulation Statistics") != 1 or text.count("End Simulation Statistics") != 1:
        raise ValueError("expected one complete statistics epoch")
    raw = {}
    for line in text.splitlines():
        words = line.split()
        if len(words) < 2 or not words[0].startswith("system.cpu."):
            continue
        key = words[0][len("system.cpu.") :]
        if key in raw:
            raise ValueError(f"duplicate CPU counter: {key}")
        raw[key] = words[1]
    result = {}
    for name, aliases in ALIASES.items():
        value = next((raw[alias] for alias in aliases if alias in raw), None)
        # gem5 suppresses zero-valued prereq and nozero statistics after an ROI reset.
        if value is None and name in ("idle", "rename_idle", "squash"):
            value = "0"
        if value is None:
            raise ValueError(f"missing required O3 counter: {name}")
        numeric = float(value)
        if not math.isfinite(numeric) or numeric < 0:
            raise ValueError(f"invalid O3 counter: {name}")
        result[name] = numeric
    return result


def difference(high: dict[str, float], low: dict[str, float]) -> dict[str, float]:
    result = {name: high[name] - low[name] for name in ALIASES}
    if any(value < 0 for value in result.values()):
        raise ValueError("non-monotonic O3 counter")
    if result["cycles"] <= 0 or result["ops"] <= 0:
        raise ValueError("empty measured interval")
    return result


def metrics(samples: list[dict[str, float]], width: int) -> dict[str, float | str]:
    first = difference(samples[1], samples[0])
    second = difference(samples[2], samples[1])
    slopes = (first["cycles"] / 2048, second["cycles"] / 2048)
    drift = abs(slopes[1] - slopes[0]) / slopes[0]
    if drift > 0.05:
        raise ValueError(f"non-stationary cycles/op: drift={drift}")
    if width <= 0 or second["idle"] >= second["cycles"]:
        raise ValueError("invalid active rename-slot interval")
    slots = width * (second["cycles"] - second["idle"])
    retiring = 100 * second["ops"] / slots
    bad_speculation = 100 * (max(0.0, second["renamed"] - second["ops"]) + width * second["squash"]) / slots
    frontend = 100 * width * second["rename_idle"] / slots
    total = retiring + bad_speculation + frontend
    if total > 105:
        raise ValueError(f"inconsistent rename-slot attribution: {total}")
    branch_misses = second["branch_misses"] / 2048
    raw_memory_violations = [int(sample["memory_violations"]) for sample in samples]
    delta_memory_violations = second["memory_violations"]
    if (
        branch_misses > 0.005
        or any(v != 0 for v in raw_memory_violations)
        or first["memory_violations"] != 0
        or delta_memory_violations != 0
    ):
        raise ValueError("branch prediction or memory ordering gate failed")
    return {
        "cycles_per_op": slopes[1],
        "linearity_drift": drift,
        "ipc": second["instructions"] / second["cycles"],
        "branch_misses_per_op": branch_misses,
        "raw_memory_violations": raw_memory_violations,
        "delta_memory_violations": delta_memory_violations,
        "memory_order_violations": delta_memory_violations,
        "retiring_pct": retiring,
        "bad_speculation_pct": bad_speculation,
        "frontend_bound_pct": frontend,
        "backend_bound_pct": max(0.0, 100 - total),
        "attribution": "o3-rename-slot",
    }


def resolve_tool(env_names: tuple[str, ...], fallback: Path, relatives: tuple[Path, ...]) -> Path:
    for name in env_names:
        value = os.environ.get(name)
        if value:
            return Path(value)
    for candidate in relatives:
        if candidate.exists():
            return candidate.resolve()
    return fallback


def main() -> None:
    repo = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gem5", type=Path, default=None)
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--profile", default="o3-w8-rob448")
    args = parser.parse_args()
    if args.gem5 is None:
        args.gem5 = resolve_tool(
            ("NEXORA_GEM5", "GEM5"),
            Path("/opt/gem5/build/ALL/gem5.opt"),
            (repo / "third_party" / "gem5" / "build" / "ALL" / "gem5.opt", Path("/opt/gem5/build/ALL/gem5.opt")),
        )
    if args.config is None:
        args.config = resolve_tool(
            ("NEXORA_GEM5_CONFIG", "GEM5_CONFIG"),
            Path("/root/uarch/scripts/gem5/o3_sim.py"),
            (
                repo / "scripts" / "gem5" / "o3_sim.py",
                repo.parent.parent / "uarch" / "scripts" / "gem5" / "o3_sim.py",
                Path("/root/uarch/scripts/gem5/o3_sim.py"),
            ),
        )
    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    if output == Path("/tmp") or Path("/tmp") in output.parents or Path("/var/tmp") in output.parents:
        parser.error("audit output must be inside the persistent build tree")
    output.mkdir(parents=True, exist_ok=True)
    settings = json.loads(subprocess.check_output(
        ["python3", str(args.config), "--dump-profile-json", args.profile], text=True
    ))
    width = int(settings["slot_width"])
    report = {
        "binary": str(binary),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "config_sha256": hashlib.sha256(args.config.read_bytes()).hexdigest(),
        "profile": settings,
        "probes": {},
    }
    for probe in ("socket_step", "h2_frame_header", "ws_mask", "pool_select"):
        samples = []
        for count in COUNTS:
            run = output / f"{probe}-{count:010d}"
            run.mkdir(exist_ok=True)
            command = [str(args.gem5), f"--outdir={run}", str(args.config), "--cpu", args.profile,
                       "--binary", str(binary), "--probe", probe, "--iterations", f"{count:010d}"]
            result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    env={**os.environ, "GLIBC_TUNABLES": "glibc.pthread.rseq=0"}, timeout=120, check=False)
            (run / "console.log").write_text(result.stdout)
            (run / "command.json").write_text(json.dumps(command))
            if result.returncode != 0:
                raise RuntimeError(f"simulation failed: {run}")
            checksums = re.findall(rf"^probe={probe} iterations=0*{count} checksum=(\d+)$", result.stdout, re.MULTILINE)
            if len(checksums) != 1 or int(checksums[0]) != oracle(probe, count, 1):
                raise ValueError(f"independent host oracle mismatch: {run}")
            samples.append(roi_stats((run / "stats.txt").read_text()))
        report["probes"][probe] = {"raw_samples": samples, "metrics": metrics(samples, width)}
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"{probe}: {report['probes'][probe]['metrics']}", flush=True)
    print("PASS: four probe checksums, three-point linearity, rename slots, branch and ordering gates")


if __name__ == "__main__":
    main()
