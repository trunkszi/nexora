from pathlib import Path

import pytest
from cli.cmd_build import ensure_configured
from cli.preset import get_preset_cache_variable, get_preset_compiler
from cli.utils import configured_build_directory


@pytest.mark.parametrize("compiler", ["clang", "gcc"])
@pytest.mark.parametrize("abi", ["glibc", "musl"])
def test_vcpkg_manifest_wiring(compiler, abi):
    preset = f"{compiler}-{abi}-release"
    home = Path.home()
    assert get_preset_cache_variable(preset, "CMAKE_TOOLCHAIN_FILE") == str(
        home / ".vcpkg/scripts/buildsystems/vcpkg.cmake"
    )
    assert get_preset_cache_variable(preset, "VCPKG_TARGET_TRIPLET") == f"x64-linux-{compiler}-{abi}"
    assert get_preset_cache_variable(preset, "VCPKG_HOST_TRIPLET") == "x64-linux-gcc-glibc"
    assert get_preset_cache_variable(preset, "VCPKG_OVERLAY_PORTS") == str(home / ".local/vcpkg")
    chainload = get_preset_cache_variable(preset, "VCPKG_CHAINLOAD_TOOLCHAIN_FILE")
    assert chainload.endswith(f"cmake/toolchain/{compiler}-{abi}.cmake")
    assert get_preset_compiler(preset)


@pytest.mark.parametrize(
    ("preset", "triplet"),
    [
        ("clang-glibc-asan-ubsan", "x64-linux-clang-glibc-asan"),
        ("gcc-glibc-asan-ubsan", "x64-linux-gcc-glibc-asan"),
    ],
)
def test_asan_triplet(preset, triplet):
    assert get_preset_cache_variable(preset, "VCPKG_TARGET_TRIPLET") == triplet
    assert get_preset_cache_variable(preset, "CMAKE_MAP_IMPORTED_CONFIG_DEBUG") == "Release;None;"


def test_asan_presets_do_not_set_ccache_prefix():
    import json

    presets = json.loads((Path(__file__).resolve().parents[3] / "CMakePresets.json").read_text())
    for name in ("gcc-glibc-asan-ubsan", "clang-glibc-asan-ubsan"):
        preset = next(item for item in presets["configurePresets"] if item["name"] == name)
        assert "CCACHE_PREFIX" not in preset.get("environment", {})


def test_configure_forwards_vcpkg_toolchain(tmp_path):
    class Output:
        def __init__(self):
            self.commands = []

        def run_command(self, command, **kwargs):
            self.commands.append(command)

    output = Output()
    ensure_configured("gcc-glibc-release", output, build_dir=tmp_path, static=False)
    command = output.commands[0]
    toolchain = str(Path.home() / ".vcpkg/scripts/buildsystems/vcpkg.cmake")
    assert f"-DCMAKE_TOOLCHAIN_FILE={toolchain}" in command
    assert "-DVCPKG_TARGET_TRIPLET=x64-linux-gcc-glibc" in command
    assert not any(part.startswith("-DCMAKE_PREFIX_PATH=") for part in command)


def test_foreign_build_is_rejected(tmp_path):
    (tmp_path / "CMakeCache.txt").write_text("CMAKE_HOME_DIRECTORY:INTERNAL=/foreign/source\n")
    with pytest.raises(ValueError, match="not configured for this checkout"):
        configured_build_directory(tmp_path)
