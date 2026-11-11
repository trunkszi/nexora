"""Check the four local compiler SDKs and required build/LLVM tools."""

import shutil

import typer

from .config import COMPILER_ALIASES, PROJECT_ROOT
from .toolchains import COMPILERS, check_toolchain
from .utils import find_clang_tool


def setup_cmd(
    ctx: typer.Context,
    compiler: str | None = typer.Option(
        None,
        "-c",
        "--compiler",
        help="Compiler toolchain (clang, gcc, musl-clang, musl-gcc, clang-glibc, gcc-glibc, clang-musl, gcc-musl)",
    ),
):
    """Validate C++26 reflection and installed tools; no downloads or system changes."""
    if compiler is not None and compiler not in COMPILER_ALIASES:
        raise ValueError(f"Unknown compiler: {compiler}")
    directory = PROJECT_ROOT / "build" / "setup"
    directory.mkdir(parents=True, exist_ok=True)
    for tool in ["cmake", "ninja"]:
        if not shutil.which(tool):
            raise ValueError(f"Required build tool is unavailable: {tool}")
    for name in [COMPILER_ALIASES[compiler]] if compiler else COMPILERS:
        check_toolchain(name, ctx.obj, directory)
    for name in [
        "llvm-objdump",
        "llvm-mca",
        "llvm-readobj",
        "llvm-nm",
        "llvm-size",
        "llvm-profdata",
        "llvm-cov",
    ]:
        tool = find_clang_tool(name)
        if not tool:
            raise ValueError(f"Required LLVM tool is unavailable: {name}")
        ctx.obj.run_command([tool, "--version"])
    if not find_clang_tool("clang-tidy"):
        ctx.obj.warning("clang-tidy is not installed; the tidy command requires it")
    ctx.obj.info("Local toolchain checks passed")
