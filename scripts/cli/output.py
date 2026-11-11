"""Rich text events and one machine-readable JSON result per invocation."""

import json
import shlex
import time
from enum import Enum

from invoke import Context
from rich.console import Console
from rich.table import Table


class OutputFormat(str, Enum):
    text = "text"
    json = "json"


class CommandFailure(RuntimeError):
    def __init__(self, command, code):
        super().__init__(f"Command failed ({code}): {shlex.join(map(str, command))}")
        self.code = code


class Output:
    def __init__(self, fmt=OutputFormat.text):
        self.fmt, self.events, self.started = fmt, [], time.monotonic()
        self.console = Console()

    def emit(self, level, message, **data):
        self.events.append({"level": level, "message": message, "data": data})
        if self.fmt == OutputFormat.text:
            self.console.print(f"{level.upper()}: {message}", markup=False)

    def info(self, message, **data):
        self.emit("info", message, **data)

    def warning(self, message, **data):
        self.emit("warning", message, **data)

    def table(self, title, columns, rows):
        self.emit("table", title, columns=columns, rows=rows)
        if self.fmt == OutputFormat.text:
            table = Table(*columns, title=title)
            for row in rows:
                table.add_row(*map(str, row))
            self.console.print(table)

    def run_command(self, command, *, cwd=None, env=None):
        from .config import PROJECT_ROOT

        command = list(map(str, command))
        self.info(shlex.join(command))
        context = Context()
        with context.cd(str(cwd or PROJECT_ROOT)):
            result = context.run(
                shlex.join(command),
                warn=True,
                hide=self.fmt == OutputFormat.json,
                env=env or {},
                in_stream=False,
                pty=False,
            )
        self.emit(
            "command",
            shlex.join(command),
            exit_code=result.exited,
            stdout=result.stdout,
            stderr=result.stderr,
        )
        if result.exited:
            raise CommandFailure(command, result.exited)
        return result

    def finish(self, exit_code=0):
        if self.fmt == OutputFormat.json:
            print(
                json.dumps(
                    {
                        "success": exit_code == 0,
                        "exit_code": exit_code,
                        "elapsed_seconds": round(time.monotonic() - self.started, 3),
                        "events": self.events,
                    }
                )
            )
        return exit_code
