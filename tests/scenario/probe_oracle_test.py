#!/usr/bin/env python3
"""Compare native probe checksums against integer/byte host oracles."""
import re
import subprocess
import sys

MASK64 = (1 << 64) - 1


def oracle(probe: str, count: int, seed: int) -> int:
    if probe == "socket_step":
        initial = seed & 0xFFFF
        increasing = min(count, (1 << 32) - 1 - initial)
        total = increasing * initial + increasing * (increasing + 1) // 2
        total += (count - increasing) * ((1 << 32) - 1)
        return ((total << 32) + 3 * count) & MASK64
    if probe == "h2_frame_header":
        return ((seed & 255) + 2) * count & MASK64
    if probe == "pool_select":
        rounds, tail = divmod(count, 16)
        return (rounds * 120 + tail * (tail - 1) // 2) & MASK64
    payload = bytes((seed + index) & 255 for index in range(8))
    mask = bytes((seed & 255, 0x37, 0x81, 0xAB))
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    even = int.from_bytes(payload, "little")
    odd = int.from_bytes(masked, "little")
    return ((count // 2) * even + ((count + 1) // 2) * odd) & MASK64


def main() -> None:
    binary = sys.argv[1]
    for probe in ("socket_step", "h2_frame_header", "ws_mask", "pool_select"):
        for count in (1, 17, 33, 512, 2560, 4608):
            for seed in (1, 255, 65535):
                output = subprocess.check_output(
                    [binary, "--probe", probe, "--iterations", f"{count:010d}", "--seed", str(seed)], text=True
                )
                match = re.fullmatch(rf"probe={probe} iterations=(\d+) checksum=(\d+)\n", output)
                assert match is not None, output
                assert int(match[1]) == count and int(match[2]) == oracle(probe, count, seed), (probe, count, seed, output)
    print("72 native probe checksums match independent host oracles")


if __name__ == "__main__":
    main()
