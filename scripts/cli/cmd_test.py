"""Run CTest with explicit target, regex and label selection."""

import re

import typer

from .cmd_build import build_targets, ensure_configured
from .config import get_build_directory
from .preset import resolve_preset
from .utils import (
    get_concurrency_budget,
    list_ctest_targets,
    list_ninja_targets,
    prepare_build_environment,
    read_cmake_cache_value,
)


def test_cmd(
    ctx: typer.Context,
    target: str | None = typer.Option(
        None, "-t", "--target", help="Select a named build, test, or benchmark target"
    ),
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
    filter_pattern: str | None = typer.Option(
        None, "--filter", "-R", help="Run CTest cases matching this regular expression"
    ),
    label: str | None = typer.Option(None, "--label", "-L", help="Run CTest cases matching this label"),
    parallel: int | None = typer.Option(
        None, "-j", "--parallel", min=1, help="Maximum parallel build and test jobs"
    ),
    no_build: bool = typer.Option(
        False, "--no-build", help="Use already configured binaries without building"
    ),
    output_junit: str | None = typer.Option(
        None, "--output-junit", help="Write CTest results to a JUnit XML file"
    ),
    list_tests: bool = typer.Option(
        False, "--list", help="List matching CTest cases without building or running"
    ),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show verbose command output"),
):
    """Configure and build tests, then execute the selected CTest cases."""
    if target and filter_pattern:
        raise ValueError("Choose --target or --filter, not both")
    if parallel is not None:
        parallel = min(parallel, 4)
    name = resolve_preset(debug, dev, compiler, sanitizer, preset=preset)
    directory = get_build_directory(name)
    if no_build:
        if not (directory / "CTestTestfile.cmake").exists() or read_cmake_cache_value(
            directory / "CMakeCache.txt", "NEXORA_BUILD_TESTS"
        ) not in {"ON", "TRUE", "1", "YES"}:
            raise ValueError("No configured tests; run without --no-build first")
    else:
        directory = ensure_configured(name, ctx.obj, components={"tests": True})
    cases = list_ctest_targets(directory)
    if target and target not in {case["name"] for case in cases}:
        raise ValueError(f"Unknown CTest target: {target}")
    if list_tests:
        cases = list_ctest_targets(directory, f"^{re.escape(target)}$" if target else filter_pattern, label)
        ctx.obj.table("CTest cases", ["Name"], [[case["name"]] for case in cases])
        return
    if not no_build:
        selected = None
        if target:
            available = dict(list_ninja_targets(directory))
            case = next(case for case in cases if case["name"] == target)
            command = case.get("command", [])
            executable = (directory / command[0]).resolve() if command else None
            # Script-driven CTest cases own their builds, including intentional compile failures.
            if executable and executable.is_relative_to(directory.resolve()):
                if target in available:
                    selected = [target]
                elif executable.name in available:
                    selected = [executable.name]
        build_targets(directory, ctx.obj, selected, parallel, verbose)
    command = [
        "ctest",
        "--test-dir",
        str(directory),
        "--output-on-failure",
        "--no-tests=error",
        "--parallel",
        str(parallel or get_concurrency_budget()),
    ]
    if target or filter_pattern:
        command += ["-R", f"^{re.escape(target)}$" if target else filter_pattern]
    if label:
        command += ["-L", label]
    if output_junit:
        command += ["--output-junit", output_junit]
    if verbose or getattr(ctx.obj, "verbose", False):
        command.append("--verbose")
    ctx.obj.run_command(command, env=prepare_build_environment(directory))
