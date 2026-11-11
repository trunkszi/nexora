"""Bounded local execution, CMake cache inspection and target discovery."""

import json
import os
import shutil
import subprocess
from pathlib import Path

from .config import PROJECT_ROOT
from .toolchains import get_toolchain_root

CPP_EXTENSIONS = {".h", ".hpp", ".hh", ".cc", ".cpp", ".cxx"}


def get_physical_cores():
    allowed = os.sched_getaffinity(0) if hasattr(os, "sched_getaffinity") else range(os.cpu_count() or 1)
    pairs = set()
    for cpu in allowed:
        topology = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
        try:
            pairs.add(((topology / "physical_package_id").read_text(), (topology / "core_id").read_text()))
        except OSError:
            return max(1, len(allowed))
    return max(1, len(pairs))


def get_available_memory_gb():
    try:
        lines = Path("/proc/meminfo").read_text().splitlines()
        available = next(int(line.split()[1]) * 1024 for line in lines if line.startswith("MemAvailable:"))
        for base in [Path("/sys/fs/cgroup")]:
            try:
                limit = (base / "memory.max").read_text().strip()
                if limit != "max":
                    available = min(
                        available, max(0, int(limit) - int((base / "memory.current").read_text()))
                    )
            except (OSError, ValueError):
                pass
        return available / (1024**3)
    except (OSError, StopIteration, ValueError):
        return 1.0


def get_concurrency_budget():
    # Reflection compilation can consume substantial memory per translation unit.
    return max(1, min(get_physical_cores(), int(get_available_memory_gb() / 2), 2))


def prepare_build_environment(build_dir):
    temporary = Path(build_dir) / ".tmp"
    temporary.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["TMPDIR"] = str(temporary)
    env["TMP"] = str(temporary)
    env["TEMP"] = str(temporary)
    env.setdefault("CCACHE_DIR", str(Path.home() / ".cache/ccache"))
    env.setdefault("VCPKG_DEFAULT_BINARY_CACHE", str(Path.home() / ".cache/vcpkg/archives"))
    env.setdefault("VCPKG_FORCE_SYSTEM_BINARIES", "1")
    env.setdefault("VCPKG_MAX_CONCURRENCY", "4")
    return env


def read_cmake_cache_value(cache_path, key):
    if not Path(cache_path).exists():
        return None
    for line in Path(cache_path).read_text().splitlines():
        if line.startswith(key + ":") and "=" in line:
            return line.split("=", 1)[1]
    return None


def should_reconfigure(build_dir):
    build_dir = Path(build_dir)
    cache = build_dir / "CMakeCache.txt"
    if not cache.exists() or not (build_dir / "build.ninja").exists():
        return True
    # Generated trees ship their own CMakeLists.txt and would force a reconfigure loop.
    skipped = {"build", ".venv", ".git"}
    inputs = [PROJECT_ROOT / "CMakePresets.json"]
    inputs += [
        path
        for path in PROJECT_ROOT.glob("**/CMakeLists.txt")
        if not skipped.intersection(path.relative_to(PROJECT_ROOT).parts)
    ]
    inputs += list((PROJECT_ROOT / "cmake").glob("*.cmake"))
    return any(p.exists() and p.stat().st_mtime_ns > cache.stat().st_mtime_ns for p in inputs)


def find_clang_tool(name):
    env_key = f"NEXORA_{name.upper().replace('-', '_')}_BIN"
    override = os.environ.get(env_key)
    if override:
        override_path = Path(override)
        if override_path.is_file() and os.access(override_path, os.X_OK):
            return str(override_path)
        found = shutil.which(override)
        if found:
            return found
    local = get_toolchain_root() / "clang-glibc/bin" / name
    if local.is_file() and os.access(local, os.X_OK):
        return str(local)
    for version in (23, 22, 21, 20):
        candidate = shutil.which(f"{name}-{version}")
        if candidate:
            return candidate
    direct = shutil.which(name)
    if direct:
        return direct
    return None


def capture(command, cwd=PROJECT_ROOT):
    result = subprocess.run(list(map(str, command)), cwd=cwd, text=True, capture_output=True, check=True)
    return result.stdout


def list_ninja_targets(build_dir):
    text = capture(["ninja", "-C", build_dir, "-t", "targets", "all"])
    targets = {}
    for line in text.splitlines():
        name, _, kind = line.rpartition(": ")
        if "EXECUTABLE_LINKER" in kind:
            targets[Path(name).name] = "executable"
        elif (
            kind == "phony"
            and "/" not in name
            and not name.startswith("cmake_object_order_")
            and name not in {"all", "test", "clean", "help", "edit_cache", "rebuild_cache"}
        ):
            targets.setdefault(name, "target")
    return sorted(targets.items())


def list_ctest_targets(build_dir, filter_pattern=None, label=None):
    command = ["ctest", "--test-dir", build_dir, "--show-only=json-v1"]
    if filter_pattern:
        command += ["-R", filter_pattern]
    if label:
        command += ["-L", label]
    return json.loads(capture(command))["tests"]


def cpp_files(paths):
    result = set()
    for path in paths:
        path = Path(path).resolve()
        if not path.is_relative_to(PROJECT_ROOT):
            raise ValueError(f"Path is outside this checkout: {path}")
        if not path.exists():
            raise ValueError(f"Path does not exist: {path}")
        for file in path.rglob("*") if path.is_dir() else [path]:
            if file.is_file() and file.suffix in CPP_EXTENSIONS:
                if not file.resolve().is_relative_to(PROJECT_ROOT):
                    raise ValueError(f"Source symlink leaves this checkout: {file}")
                result.add(file)
    return sorted(result)


def configured_build_directory(value: Path) -> Path:
    """Resolve an existing build tree belonging to this checkout."""
    directory = Path(value).resolve()
    cache = directory / "CMakeCache.txt"
    source = read_cmake_cache_value(cache, "CMAKE_HOME_DIRECTORY")
    if source is None or Path(source).resolve() != PROJECT_ROOT.resolve():
        raise ValueError(f"Build directory is not configured for this checkout: {directory}")
    if directory.is_relative_to(Path("/tmp")) or directory.is_relative_to(Path("/var/tmp")):
        raise ValueError("Build directories must use a stable non-temporary location")
    return directory
