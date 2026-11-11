"""Check or apply clang-format without touching generated build trees."""

import typer

from .config import PROJECT_ROOT
from .utils import CPP_EXTENSIONS, capture, cpp_files, find_clang_tool


def format_cmd(
    ctx: typer.Context,
    paths: list[str] | None = typer.Argument(None, help="Source files or directories to process"),
    check: bool = typer.Option(False, "--check", help="Check formatting without changing files"),
    incremental: bool = typer.Option(
        False, "--incremental", help="Process only changed or untracked C++ files"
    ),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show verbose command output"),
):
    """Format C++ under include, src, tests and benches; --check never writes."""
    tool = find_clang_tool("clang-format")
    if not tool:
        raise ValueError("clang-format is unavailable")
    selected = paths or [
        str(PROJECT_ROOT / n) for n in ["include", "src", "tests", "benches"] if (PROJECT_ROOT / n).is_dir()
    ]
    files = cpp_files(selected)
    if incremental:
        names = capture(["git", "diff", "--name-only", "-z", "HEAD"]).split("\0")
        names += capture(["git", "ls-files", "--others", "--exclude-standard", "-z"]).split("\0")
        changed = {
            (PROJECT_ROOT / n).resolve() for n in names if n and (PROJECT_ROOT / n).suffix in CPP_EXTENSIONS
        }
        files = [p for p in files if p in changed]
    for i in range(0, len(files), 64):
        ctx.obj.run_command([tool, *(["--dry-run", "--Werror"] if check else ["-i"]), *files[i : i + 64]])
    ctx.obj.info(f"{'Checked' if check else 'Formatted'} {len(files)} C++ files")
