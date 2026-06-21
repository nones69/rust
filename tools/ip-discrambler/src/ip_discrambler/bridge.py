"""JSON bridge for IntentOS and other non-Python callers."""

from __future__ import annotations

import json
import sys

from . import Discrambler


def _emit(payload: object) -> None:
    print(json.dumps(payload, indent=2))


def main() -> None:
    if len(sys.argv) < 3:
        print(
            json.dumps(
                {
                    "error": "usage: python -m ip_discrambler.bridge <lookup|subnet|policy> <arg>"
                }
            ),
            file=sys.stderr,
        )
        sys.exit(2)

    cmd = sys.argv[1].lower()
    arg = sys.argv[2]
    client = Discrambler()

    if cmd == "lookup":
        result = client.lookup_sync(arg, include_rdns=True)
        _emit(result.to_dict())
        return

    if cmd == "subnet":
        summary = client.analyze_subnet(arg)
        _emit(summary.to_dict())
        return

    if cmd == "policy":
        result = client.lookup_sync(arg, include_rdns=False)
        score = int(result.threat_score)
        allowed = score < 75
        _emit(
            {
                "ip": result.ip,
                "allowed": allowed,
                "threat_score": score,
                "abuse_confidence": result.abuse_confidence,
                "country": result.country,
                "org": result.org,
                "asn": result.asn,
                "errors": result.errors,
                "discrambler": result.to_dict(),
            }
        )
        return

    print(json.dumps({"error": f"unknown command: {cmd}"}), file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main()
