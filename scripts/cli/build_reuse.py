"""Reject duplicate compiler work in the generated target graph."""

from __future__ import annotations

import json
import shlex
from pathlib import Path


def duplicate_compilations(database: Path) -> list[str]:
    """Compare real compiler inputs, retaining macro/option/include ordering."""
    seen: dict[tuple[str, tuple[str, ...]], str] = {}
    duplicates = []
    for entry in json.loads(database.read_text()):
        directory = Path(entry["directory"])

        def absolute(value: str, base: Path = directory) -> str:
            return str((base / value).resolve())

        source = absolute(entry["file"])
        arguments = entry.get("arguments") or shlex.split(entry["command"])
        inputs = []
        output = entry.get("output", "")
        index = 0
        while index < len(arguments):
            argument = arguments[index]
            index += 1
            if argument in ("-o", "-c", "-MF", "-MT", "-MQ"):
                if argument == "-o":
                    output = arguments[index]
                index += 1
                continue
            if argument in ("-I", "-isystem", "-iquote", "-idirafter", "-include", "-imacros", "--sysroot"):
                inputs.extend((argument, absolute(arguments[index])))
                index += 1
            elif argument.startswith("-I"):
                inputs.extend(("-I", absolute(argument[2:])))
            else:
                inputs.append(argument)
        key = (source, tuple(inputs))
        output = absolute(output) if output else shlex.join(arguments)
        if key in seen and seen[key] != output:
            duplicates.append(f"{source}\n  {seen[key]}\n  {output}")
        else:
            seen[key] = output
    return duplicates


def verify_build_reuse(build_dir: Path) -> None:
    """Audit once per generated database/checker revision, keeping no-ops cheap."""
    database = build_dir / "compile_commands.json"
    if not database.exists():
        return
    signature = []
    for path in (database, Path(__file__)):
        stat = path.stat()
        signature.extend((stat.st_mtime_ns, stat.st_size))
    receipt = build_dir / ".compilation-reuse-verified"
    expected = json.dumps(signature)
    if receipt.exists() and receipt.read_text() == expected:
        return
    duplicates = duplicate_compilations(database)
    if duplicates:
        raise ValueError(
            "Identical sources are compiled into multiple objects; share their implementation targets:\n"
            + "\n".join(duplicates)
        )
    receipt.write_text(expected)
