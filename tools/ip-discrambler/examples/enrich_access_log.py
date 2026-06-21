"""Parse an Nginx access log and enrich each client IP with geo + threat data."""

import re
import sys
from collections import OrderedDict

from ip_discrambler import Discrambler

IP_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s")


def extract_ips(log_path: str) -> list[str]:
    seen: OrderedDict[str, None] = OrderedDict()
    with open(log_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            match = IP_RE.match(line)
            if match:
                seen.setdefault(match.group(1), None)
    return list(seen.keys())


def main() -> None:
    log_path = sys.argv[1] if len(sys.argv) > 1 else "access.log"
    client = Discrambler(max_concurrency=30)
    ips = extract_ips(log_path)
    results = client.lookup_batch_sync(ips, include_rdns=False)

    print(f"{'IP':<16} {'Country':<20} {'City':<16} {'Threat':>6}")
    print("-" * 62)
    for r in results:
        print(
            f"{r.ip:<16} {(r.country or '-'):<20} {(r.city or '-'):<16} {r.threat_score:>6}"
        )


if __name__ == "__main__":
    main()