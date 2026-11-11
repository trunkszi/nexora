"""Bounded parallel clang-tidy checks against the selected compile database."""

import asyncio
import json
import re
import shlex
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import typer

from .cmd_build import ensure_configured
from .config import PROJECT_ROOT
from .preset import resolve_preset
from .utils import CPP_EXTENSIONS, cpp_files, find_clang_tool, get_concurrency_budget

DIAGNOSTIC_CHECK_RE = re.compile(r"(?:warning|error):\s+.*\[([^\],\s]+)(?:,[^\]]*)?\]\s*$")
LOCATION_DIAG_RE = re.compile(
    r"^([^:\n]+):(\d+):(\d+):\s+(warning|error):\s+(.*)\[([^\],\s]+)(?:,[^\]]*)?\]\s*$"
)
NOTE_LOCATION_RE = re.compile(r"^([^:\n]+):(\d+):(\d+):\s+note:\s+(.*)$")
LOCATION_PREFIX_RE = re.compile(r"^[^:\n]+:\d+:\d+:\s+(?:warning|error|note):\s+")
_DIRECT_REFLECTION_MARKERS = (
    "^^",
    "[[=",
    "[:",
    "std::meta",
    "define_static_",
    "template for",
    "blocks support disabled",
    "'meta' file not found",
)
_REFLECTION_SEED_MARKERS = (
    *_DIRECT_REFLECTION_MARKERS,
    "uarch::",
)
_DRIVER_ERROR_MARKERS = (
    "unknown argument:",
    "unsupported option",
    "no such file or directory",
    "unable to find compilation database",
    "Error while trying to load a compilation database",
    "unable to handle compilation",
    "no input files",
)
_REFLECTION_PROBE = "consteval bool Probe() { return ^^int == ^^int; }\nstatic_assert(Probe());\n"


@dataclass
class _DiagnosticBlock:
    file: str
    line: int
    message: str
    header: str
    lines: list[str] = field(default_factory=list)
    notes: set[str] = field(default_factory=set)

    def body(self) -> str:
        return "\n".join(LOCATION_PREFIX_RE.sub("", line) for line in self.lines)


def _verify_tidy_config(tool: str) -> None:
    result = subprocess.run(
        [tool, "--verify-config"],
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"clang-tidy configuration check failed:\n{result.stdout}{result.stderr}")


def supports_reflection(tool: str) -> bool:
    """True when clang-tidy accepts a consteval function that uses the reflection operator."""
    probe_root = PROJECT_ROOT / "build" / "tidy-probes"
    probe_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tidy-probe-", dir=probe_root) as temporary:
        probe = Path(temporary) / "probe.cc"
        probe.write_text(_REFLECTION_PROBE)
        for flag in ("-freflection", "-freflection-latest"):
            result = subprocess.run(
                [tool, str(probe), "--", "-std=c++26", flag],
                cwd=temporary,
                text=True,
                capture_output=True,
                check=False,
            )
            if result.returncode == 0:
                return True
        return False


def _unique_lines(lines: list[str]) -> list[str]:
    return list(dict.fromkeys(lines))


def _parse_clang_diagnostic_blocks(output: str) -> tuple[list[_DiagnosticBlock], list[str]]:
    blocks: list[_DiagnosticBlock] = []
    unlocated: list[str] = []
    current: _DiagnosticBlock | None = None
    for line in output.splitlines():
        location = LOCATION_DIAG_RE.match(line)
        if location:
            if current is not None:
                blocks.append(current)
            check_name = location.group(6)
            if check_name.startswith("clang-diagnostic-"):
                current = _DiagnosticBlock(
                    file=location.group(1),
                    line=int(location.group(2)),
                    message=location.group(5),
                    header=line,
                    lines=[line],
                )
            else:
                current = None
            continue
        check = DIAGNOSTIC_CHECK_RE.search(line)
        if check:
            if current is not None:
                blocks.append(current)
                current = None
            if check.group(1).startswith("clang-diagnostic-"):
                unlocated.append(line)
            continue
        if current is not None:
            current.lines.append(line)
            note = NOTE_LOCATION_RE.match(line)
            if note:
                current.notes.add(note.group(1))
    if current is not None:
        blocks.append(current)
    return blocks, unlocated


def _classify_clang_diagnostics(output: str) -> tuple[bool, list[str]]:
    if any(marker in output for marker in _DRIVER_ERROR_MARKERS):
        return False, [line for line in output.splitlines() if line.strip()]
    blocks, unlocated = _parse_clang_diagnostic_blocks(output)
    if unlocated:
        return False, unlocated
    by_file: dict[str, list[_DiagnosticBlock]] = {}
    direct_lines: dict[str, list[int]] = {}
    for block in blocks:
        by_file.setdefault(block.file, []).append(block)
        if any(marker in block.body() for marker in _DIRECT_REFLECTION_MARKERS):
            direct_lines.setdefault(block.file, []).append(block.line)
    if not direct_lines:
        return False, [block.header for block in blocks]
    reflection_files: set[str] = set()
    for file_path, file_blocks in by_file.items():
        first_body = file_blocks[0].body()
        if any(marker in first_body for marker in _REFLECTION_SEED_MARKERS):
            reflection_files.add(file_path)
    changed = True
    while changed:
        changed = False
        for file_path, file_blocks in by_file.items():
            if file_path not in reflection_files and (file_blocks[0].notes & reflection_files):
                reflection_files.add(file_path)
                changed = True
    unsuppressed: list[str] = []
    for block in blocks:
        if block.file not in reflection_files:
            unsuppressed.append(block.header)
            continue
        if "undeclared identifier" in block.message:
            anchors = direct_lines.get(block.file, [])
            if not any(0 <= block.line - anchor <= 30 for anchor in anchors):
                unsuppressed.append(block.header)
    return bool(blocks and not unsuppressed), unsuppressed


def _actionable_fatal_lines(output: str) -> list[str]:
    """Fatal diagnostics other than the P2996 standard-library header miss."""
    lines = []
    for line in output.splitlines():
        if "fatal error:" not in line or "'meta' file not found" in line:
            continue
        lines.append(line)
    return lines


def run_tidy(
    returncode: int | None, output: str, *, fallback: bool, compiler_verified: bool = False
) -> tuple[bool, str]:
    """Classify one clang-tidy result.

    Fallback mode drops a positive status when every clang frontend diagnostic
    is explained by P2996 reflection or its cascade in the same file/note chain.
    Named clang-tidy checks, driver errors, tool crashes, and other fatal errors still fail.
    A successful project-compiler syntax check can verify otherwise unclassified
    frontend cascades only when the output contains a direct reflection diagnostic.
    """
    if not fallback:
        failed = returncode not in (0, None) or "fatal error:" in output
        return failed, output
    filtered = _unique_lines(_extract_non_clang_diagnostics(output))
    fatals = _unique_lines(_actionable_fatal_lines(output))
    reflection_blocks, raw_unsuppressed = _classify_clang_diagnostics(output)
    unsuppressed = _unique_lines(raw_unsuppressed)
    has_reflection = reflection_blocks or (
        "'meta' file not found" in output and not fatals and not unsuppressed
    )
    if (
        compiler_verified
        and any(marker in output for marker in _DIRECT_REFLECTION_MARKERS)
        and not any(marker in output for marker in _DRIVER_ERROR_MARKERS)
    ):
        unsuppressed = []
        has_reflection = True
    negative = returncode is not None and returncode < 0
    positive = returncode is not None and returncode > 0
    if negative or filtered or fatals or unsuppressed or (positive and not has_reflection):
        shown = _unique_lines([*filtered, *fatals, *unsuppressed])
        return True, "\n".join(shown) if shown else output
    return False, ""


def _extract_non_clang_diagnostics(output: str) -> list[str]:
    findings: list[str] = []
    for line in output.splitlines():
        match = DIAGNOSTIC_CHECK_RE.search(line)
        if match:
            check_name = match.group(1)
            if not check_name.startswith("clang-diagnostic-"):
                findings.append(line)
    return findings


def _syntax_only_arguments(arguments: list[str]) -> list[str]:
    result = []
    skip = False
    for argument in arguments:
        if skip:
            skip = False
            continue
        if argument in {"-o", "-MF", "-MT", "-MQ"}:
            skip = True
        elif argument not in {"-c", "-MD", "-MMD"}:
            result.append(argument)
    if result and Path(result[0]).name == "ccache":
        result.pop(0)
    return [*result, "-fsyntax-only"]


async def _check_all(commands, jobs, out, *, p2996_capable: bool = True, native_commands=None):
    limit = asyncio.Semaphore(jobs)

    async def check(command):
        async with limit:
            process = await asyncio.create_subprocess_exec(
                *command, cwd=PROJECT_ROOT, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            combined = stdout.decode(errors="replace") + stderr.decode(errors="replace")
            if p2996_capable:
                failed, display = run_tidy(process.returncode, combined, fallback=False)
            else:
                failed, display = run_tidy(process.returncode, combined, fallback=True)
                native = (native_commands or {}).get(command[1])
                if (
                    native
                    and not _extract_non_clang_diagnostics(combined)
                    and any(marker in combined for marker in _DIRECT_REFLECTION_MARKERS)
                    and not any(marker in combined for marker in _DRIVER_ERROR_MARKERS)
                    and not _actionable_fatal_lines(combined)
                ):
                    arguments, directory = native
                    compiler = await asyncio.create_subprocess_exec(
                        *arguments,
                        cwd=directory,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    native_stdout, native_stderr = await compiler.communicate()
                    out.emit(
                        "command",
                        shlex.join(arguments),
                        exit_code=compiler.returncode,
                        stdout=native_stdout.decode(errors="replace"),
                        stderr=native_stderr.decode(errors="replace"),
                    )
                    if compiler.returncode == 0 and "warning:" not in native_stderr.decode(errors="replace"):
                        failed, display = run_tidy(
                            process.returncode, combined, fallback=True, compiler_verified=True
                        )
                    else:
                        failed = True
                        display += (
                            "\n"
                            + native_stdout.decode(errors="replace")
                            + native_stderr.decode(errors="replace")
                        )
            out.emit(
                "command",
                shlex.join(command),
                exit_code=1 if failed else 0,
                stdout=display if not p2996_capable else stdout.decode(errors="replace"),
                stderr="" if not p2996_capable else stderr.decode(errors="replace"),
            )
            if out.fmt == "text" and display:
                out.console.print(display, markup=False)
            return 1 if failed else 0

    codes = await asyncio.gather(*(check(command) for command in commands))
    if any(codes):
        raise RuntimeError("clang-tidy checks failed")


def tidy_cmd(
    ctx: typer.Context,
    paths: list[str] | None = typer.Argument(None, help="Source files or directories to process"),
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
    jobs: int | None = typer.Option(
        None, "-j", "--jobs", min=1, help="Maximum parallel build or analysis jobs"
    ),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show verbose command output"),
):
    """Run clang-tidy in parallel; reflection flags are adapted in a temporary database."""
    tool = find_clang_tool("clang-tidy")
    if not tool:
        raise ValueError("clang-tidy is unavailable; install a reflection-capable version or add it to PATH")
    _verify_tidy_config(tool)
    p2996_capable = supports_reflection(tool)
    name = resolve_preset(debug, dev, compiler, sanitizer, preset=preset)
    directory = Path(ensure_configured(name, ctx.obj)).resolve()
    project_root = PROJECT_ROOT.resolve()
    database = json.loads((directory / "compile_commands.json").read_text())
    selected = set(cpp_files(paths)) if paths else None
    def _is_negative_tu(path: Path) -> bool:
        return "compile_fail" in path.parts or path.stem.endswith("_compile_fail")

    explicit_negative = any(_is_negative_tu(Path(path).resolve()) for path in (paths or []))
    files = set()
    native_commands = {}
    stripped_flags = {"-freflection-latest"} if p2996_capable else {"-freflection-latest", "-freflection"}
    for entry in database:
        source = (Path(entry["directory"]) / entry["file"]).resolve()
        if _is_negative_tu(source) and not explicit_negative:
            continue
        if selected is None:
            if (
                not source.is_relative_to(project_root)
                or source.is_relative_to(directory)
                or "_deps" in source.parts
                or source.suffix not in CPP_EXTENSIONS
            ):
                continue
            files.add(source)
        elif source in selected:
            files.add(source)
        arguments = entry.get("arguments") or shlex.split(entry.pop("command"))
        native_commands[str(source)] = (_syntax_only_arguments(arguments), entry["directory"])
        entry["arguments"] = [arg for arg in arguments if arg not in stripped_flags]
    if not files:
        raise ValueError("No requested translation units appear in compile_commands.json")
    extra_args = (
        ["--extra-arg=-freflection", "--warnings-as-errors=*"]
        if p2996_capable
        else ["--extra-arg=-D__is_consteval_only(...)=false"]
    )
    with tempfile.TemporaryDirectory(prefix="tidy-", dir=directory) as temporary:
        (Path(temporary) / "compile_commands.json").write_text(json.dumps(database))
        commands = [[tool, str(file), "-p", temporary, *extra_args] for file in sorted(files)]
        asyncio.run(
            _check_all(
                commands,
                jobs or get_concurrency_budget(),
                ctx.obj,
                p2996_capable=p2996_capable,
                native_commands=native_commands,
            )
        )
