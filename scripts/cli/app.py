"""Typer command registration; execution and reporting share one output object."""

import typer

from . import __version__
from .output import Output, OutputFormat

app = typer.Typer(no_args_is_help=False, context_settings={"help_option_names": ["-h", "--help"]})
output = Output()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    fmt: OutputFormat = typer.Option(OutputFormat.text, "--format", "-f", help="Output format (text, json)"),
    version: bool = typer.Option(False, "--version", "-V", help="Print the CLI version"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show verbose command output"),
):
    """Configure, build, test and audit nexora with the local C++26 toolchains."""
    global output
    output = Output(fmt)
    ctx.obj = output
    output.verbose = verbose
    if version:
        output.info(f"nexora-cli {__version__}")
        raise typer.Exit()


def register():
    from .cmd_bench import bench_cmd
    from .cmd_build import build_cmd
    from .cmd_coverage import coverage_cmd
    from .cmd_format import format_cmd
    from .cmd_setup import setup_cmd
    from .cmd_test import test_cmd
    from .cmd_tidy import tidy_cmd
    from .cmd_verify import verify_cmd

    for name, command in [
        ("build", build_cmd),
        ("test", test_cmd),
        ("bench", bench_cmd),
        ("verify", verify_cmd),
        ("coverage", coverage_cmd),
        ("format", format_cmd),
        ("tidy", tidy_cmd),
        ("setup", setup_cmd),
    ]:
        app.command(name)(command)
