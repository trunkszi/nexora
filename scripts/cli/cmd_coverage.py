"""Instrument, test, merge and report Clang source-based coverage."""

import functools
import http.server
import socketserver
from pathlib import Path

import typer

from .cmd_build import build_targets, ensure_configured
from .config import PROJECT_ROOT
from .utils import find_clang_tool, list_ctest_targets, prepare_build_environment


def coverage_cmd(
    ctx: typer.Context,
    report_format: str = typer.Option(
        "html", "--format", "--report-format", help="Coverage report format (html, lcov, text)"
    ),
    output: str | None = typer.Option(None, "--output", help="Coverage output file or directory"),
    open_server: bool = typer.Option(False, "--open", help="Serve the HTML report locally until interrupted"),
    port: int = typer.Option(8080, "--port", min=1, max=65535, help="Local HTTP port for the HTML report"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show verbose command output"),
):
    """Generate html, lcov or text coverage in an isolated instrumented build tree."""
    if report_format not in {"html", "lcov", "text"}:
        raise ValueError("Coverage format must be html, lcov, or text")
    if open_server and report_format != "html":
        raise ValueError("--open requires an HTML report")
    profdata, cov = find_clang_tool("llvm-profdata"), find_clang_tool("llvm-cov")
    if not profdata or not cov:
        raise ValueError("llvm-profdata and llvm-cov are required for coverage")
    directory = PROJECT_ROOT / "build" / "clang-glibc-coverage"
    ensure_configured(
        "clang-glibc-release",
        ctx.obj,
        build_dir=directory,
        components={"tests": True, "bench": False},
        extra={"CMAKE_CXX_FLAGS": "-fprofile-instr-generate -fcoverage-mapping"},
    )
    build_targets(directory, ctx.obj, verbose=verbose)
    profiles = directory / "profiles"
    profiles.mkdir(exist_ok=True)
    for old in profiles.glob("*.profraw"):
        old.unlink()
    env = prepare_build_environment(directory)
    env["LLVM_PROFILE_FILE"] = str(profiles / "%m-%p.profraw")
    ctx.obj.run_command(
        ["ctest", "--test-dir", directory, "--output-on-failure", "--no-tests=error"], env=env
    )
    raw = sorted(profiles.glob("*.profraw"))
    if not raw:
        raise ValueError("Tests generated no LLVM raw profiles")
    merged = directory / "coverage.profdata"
    ctx.obj.run_command([profdata, "merge", "-sparse", *raw, "-o", merged])
    binaries = set()
    for test in list_ctest_targets(directory):
        if not test.get("command"):
            continue
        binary = Path(test["command"][0])
        if binary.is_file() and binary.resolve().is_relative_to(directory):
            with binary.open("rb") as stream:
                if stream.read(4) == b"\x7fELF":
                    binaries.add(binary)
    if not binaries:
        raise ValueError("No instrumented test executables were discovered")
    objects = sorted(binaries)
    common = [
        str(objects[0]),
        f"-instr-profile={merged}",
        "-ignore-filename-regex=(/build/|/toolchain/|/usr/)",
    ]
    for binary in objects[1:]:
        common += ["-object", str(binary)]
    destination = Path(output).resolve() if output else PROJECT_ROOT / "output" / "coverage"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if report_format == "html":
        ctx.obj.run_command([cov, "show", *common, "-format=html", f"-output-dir={destination}"])
    elif report_format == "lcov":
        result = ctx.obj.run_command([cov, "export", *common, "-format=lcov"])
        if output is None:
            destination = destination.with_suffix(".lcov")
        destination.write_text(result.stdout)
    else:
        result = ctx.obj.run_command([cov, "report", *common])
        if output is None:
            destination = destination.with_suffix(".txt")
        destination.write_text(result.stdout)
    ctx.obj.info("Coverage report complete", path=str(destination), format=report_format)
    if open_server:
        ctx.obj.info(f"Serving report at http://127.0.0.1:{port}; interrupt to stop")
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(destination))
        with socketserver.TCPServer(("127.0.0.1", port), handler) as server:
            server.serve_forever()
