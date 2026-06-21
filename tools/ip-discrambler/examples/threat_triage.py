"""Score IPs from a file and export high-risk entries to CSV."""

import csv
import sys
from pathlib import Path

from ip_discrambler import Discrambler

THRESHOLD = 50


def main() -> None:
    infile = sys.argv[1] if len(sys.argv) > 1 else "ips.txt"
    outfile = sys.argv[2] if len(sys.argv) > 2 else "high_risk.csv"

    ips = [
        line.strip()
        for line in Path(infile).read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]

    client = Discrambler(max_concurrency=25)
    results = client.lookup_batch_sync(ips, include_rdns=False)
    risky = [r for r in results if r.threat_score >= THRESHOLD]

    with open(outfile, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "country", "org", "threat_score", "abuse_confidence"])
        for r in risky:
            writer.writerow([r.ip, r.country, r.org, r.threat_score, r.abuse_confidence])

    print(f"Flagged {len(risky)}/{len(results)} IPs (threshold >= {THRESHOLD}) -> {outfile}")


if __name__ == "__main__":
    main()