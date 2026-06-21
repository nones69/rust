"""Audit CIDR blocks from a file and flag overlapping or reserved ranges."""

import ipaddress
import sys
from pathlib import Path

from ip_discrambler import Discrambler


def load_cidrs(path: str) -> list[str]:
    lines = Path(path).read_text().splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def main() -> None:
    infile = sys.argv[1] if len(sys.argv) > 1 else "cidrs.txt"
    client = Discrambler()
    cidrs = load_cidrs(infile)

    print(f"Auditing {len(cidrs)} CIDR blocks\n")
    for cidr in cidrs:
        summary = client.analyze_subnet(cidr)
        flags = []
        if summary.is_private:
            flags.append("private")
        if summary.is_reserved:
            flags.append("reserved")
        flag_text = ", ".join(flags) if flags else "public"
        print(
            f"{summary.cidr:<24} hosts={summary.total_hosts:<12} "
            f"usable={summary.usable_hosts:<12} [{flag_text}]"
        )

    # Overlap detection (pairwise)
    nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]
    for i, left in enumerate(nets):
        for right in nets[i + 1 :]:
            if left.overlaps(right):
                print(f"OVERLAP: {left} <-> {right}")


if __name__ == "__main__":
    main()