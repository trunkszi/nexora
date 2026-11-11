"""Discover benchmark targets from Ninja and execute their built binaries."""

import os
from pathlib import Path

import typer

from .cmd_build import build_targets, ensure_configured
from .config import PROJECT_ROOT, get_build_directory
from .preset import resolve_preset
from .utils import configured_build_directory, list_ninja_targets, prepare_build_environment


def benchmark_targets(directory):
    return [name for name, kind in list_ninja_targets(directory) if kind == "executable" and "bench" in name]


def find_binary(directory, target):
    for root in [
        directory / "benches",
        directory / "src",
        directory / "tools",
        directory,
        PROJECT_ROOT / "output" / directory.name,
    ]:
        if not root.exists():
            continue
        for path in root.rglob(target):
            if path.is_file() and os.access(path, os.X_OK):
                return path.resolve()
    raise ValueError(f"Executable {target!r} not found under {directory}; build it first")


def bench_cmd(
    ctx: typer.Context,
    bench_args: list[str] | None = typer.Argument(None, help="Arguments forwarded to benchmark executables"),
    target: str | None = typer.Option(
        None, "-t", "--target", help="Select a named build, test, or benchmark target"
    ),
    all_targets: bool = typer.Option(False, "--all", help="Select all enabled targets"),
    debug: bool = typer.Option(False, "-d", "--debug", help="Use the debug preset"),
    dev: bool = typer.Option(
        False, "-dev", "--dev", "--development", help="Use a development build with sanitizers"
    ),
    compiler: str = typer.Option(
        "clang",
        "-c",
        "--compiler",
        help="Compiler toolchain (clang, gcc, musl-clang, musl-gcc, clang-glibc, gcc-glibc, clang-musl, gcc-musl)",
    ),
    sanitizer: str = typer.Option(
        "asan-ubsan", "-s", "--sanitizer", help="Sanitizer for --dev builds (asan-ubsan)"
    ),
    preset: str | None = typer.Option(
        None,
        "--preset",
        help="Explicit CMake preset override (e.g. clang-glibc-release, gcc-glibc-release, clang-musl-release, gcc-musl-release)",
    ),
    build_dir: Path | None = typer.Option(None, "--build-dir", help="Use an existing configured build directory"),
    no_build: bool = typer.Option(
        False, "--no-build", help="Use already configured binaries without building"
    ),
    list_targets: bool = typer.Option(False, "--list", help="List available targets without building"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show verbose command output"),
):
    """Build and run named benchmarks; use --all to run the complete suite."""
    name = resolve_preset(debug, dev, compiler, sanitizer, preset=preset)
    directory = configured_build_directory(build_dir) if build_dir is not None else get_build_directory(name)
    if no_build:
        if not (directory / "build.ninja").exists():
            raise ValueError("No configured benchmark build; run without --no-build first")
    else:
        if build_dir is None:
            directory = ensure_configured(name, ctx.obj, components={"bench": True})
    available = benchmark_targets(directory)
    if list_targets:
        ctx.obj.table("Benchmarks", ["Target"], [[name] for name in available])
        return
    if all_targets and target:
        raise ValueError("Choose --all or --target, not both")
    if not target and not all_targets:
        raise ValueError("Choose a benchmark with --target or --all; use --list to discover names")
    selected = available if all_targets else [target]
    if not selected or any(name not in available for name in selected):
        raise ValueError(f"Unknown benchmark; available: {', '.join(available)}")
    if not no_build:
        build_targets(directory, ctx.obj, selected, verbose=verbose)
    for name in selected:
        ctx.obj.run_command(
            [find_binary(directory, name), *(bench_args or [])], env=prepare_build_environment(directory)
        )
