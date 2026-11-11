"""Validate local C++26 SDKs without installing or downloading anything."""

import os
from pathlib import Path

COMPILERS = {
    "clang-glibc": "bin/clang++",
    "clang-musl": "bin/x86_64-unknown-linux-musl-clang++",
    "gcc-glibc": "bin/x86_64-unknown-linux-gnu-g++",
    "gcc-musl": "bin/x86_64-unknown-linux-musl-g++",
}
REFLECTION_PROBE = """#include <meta>
#include <string_view>
struct Note { int value; };
struct [[=Note{7}]] Value { int member; };
template <class... Ts> using First = Ts...[0];
static_assert(std::meta::is_type(^^Value));
static_assert(std::meta::annotations_of(^^Value).size() == 1);
static_assert(std::is_same_v<First<int, double>, int>);
static_assert(true, std::string_view("C++26 required"));
int main() { return 0; }
"""


def get_toolchain_root() -> Path:
    override = os.environ.get("NEXORA_TOOLCHAIN_ROOT") or os.environ.get("UARCH_TOOLCHAIN_ROOT")
    return Path(override) if override else Path.home() / ".local/toolchain"


def check_toolchain(name, out, directory):
    compiler = get_toolchain_root() / name / COMPILERS[name]
    if not compiler.is_file():
        raise ValueError(f"Local compiler is missing: {compiler}")
    source = directory / f"{name}.cc"
    source.write_text(REFLECTION_PROBE)
    flags = ["-freflection-latest", "-stdlib=libc++"] if name.startswith("clang") else ["-freflection"]
    out.run_command([compiler, "--version"])
    out.run_command([compiler, "-std=c++26", *flags, "-fno-exceptions", "-fno-rtti", "-fsyntax-only", source])
