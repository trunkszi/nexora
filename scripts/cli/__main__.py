"""Default-command injection and process-level error reporting."""

import os
import subprocess
import sys
import warnings

from typer._click.exceptions import ClickException

from .config import PROJECT_ROOT

KNOWN_COMMANDS = {"build", "test", "bench", "verify", "coverage", "format", "tidy", "setup"}


def _with_default_command(argv):
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in {"--help", "-h", "--version", "-V"}:
            return argv
        if arg in {"--format", "-f"}:
            i += 2
        elif arg.startswith(("--format=", "-f=")) or arg in {"--verbose", "-v"}:
            i += 1
        else:
            break
    if i < len(argv) and argv[i] in KNOWN_COMMANDS:
        return argv
    return [*argv[:i], "build", *argv[i:]]


def run():
    from . import app
    from .output import CommandFailure, Output, OutputFormat

    os.chdir(PROJECT_ROOT)
    args = _with_default_command(sys.argv[1:])
    # Parsing failures must still produce JSON when machine output was requested.
    if any(a == "--format=json" or a == "-f=json" for a in args) or any(
        a in {"--format", "-f"} and i + 1 < len(args) and args[i + 1] == "json" for i, a in enumerate(args)
    ):
        app.output = Output(OutputFormat.json)
    warnings.showwarning = lambda message, *a, **k: app.output.warning(str(message))
    code = 0
    try:
        app.register()
        result = app.app(args=args, prog_name="nexora", standalone_mode=False)
        code = result if isinstance(result, int) else 0
    except CommandFailure as error:
        app.output.emit("error", str(error))
        code = error.code
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError, ClickException) as error:
        app.output.emit("error", str(error))
        code = getattr(error, "exit_code", 1)
    except KeyboardInterrupt:
        app.output.emit("error", "Interrupted")
        code = 130
    return app.output.finish(code)


if __name__ == "__main__":
    raise SystemExit(run())
