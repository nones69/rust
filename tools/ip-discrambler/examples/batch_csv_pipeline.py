"""Example: CSV in -> enriched CSV out."""

import csv
import sys

from ip_discrambler import Discrambler


def main():
    infile = sys.argv[1] if len(sys.argv) > 1 else "ips.csv"
    outfile = sys.argv[2] if len(sys.argv) > 2 else "enriched.csv"

    client = Discrambler(max_concurrency=20)

    with open(infile, newline="") as f:
        reader = csv.reader(f)
        ips = [row[0] for row in reader if row]

    results = client.lookup_batch_sync(ips, include_rdns=False)

    with open(outfile, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "country", "city", "asn", "org", "threat_score"])
        for r in results:
            writer.writerow([r.ip, r.country, r.city, r.asn, r.org, r.threat_score])

    print(f"Enriched {len(results)} IPs -> {outfile}")


if __name__ == "__main__":
    main()
