# IP-Discrambler

Lightweight, high-performance utility for resolving, decoding, and analyzing IP
address information — including geolocation, WHOIS data, subnet parsing, and
threat intelligence lookups.

This copy is embedded in the IntentKernel repository as a supporting tool for
enriching network telemetry with geolocation, ownership, and reputation data
before capability-policy decisions are made.

## Quick start

```bash
cd tools/ip-discrambler
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env
# (optional) add API keys to .env
ipdis lookup 8.8.8.8
ipdis subnet 192.168.1.0/24 --expand
```

## Usage

```bash
# Single IP
ipdis lookup 8.8.8.8

# Batch from file
ipdis lookup --file ips.txt --output json > results.json

# CIDR analysis
ipdis subnet 10.0.0.0/8 --expand --limit 16

# Threat intelligence (requires API keys)
ipdis threat 45.33.32.156 --providers abuseipdb,virustotal
```

## Python API

```python
from ip_discrambler import Discrambler

client = Discrambler(timeout=15, max_concurrency=100)
result = client.lookup_sync("8.8.8.8")
print(result.country, result.asn, result.threat_score)

results = client.lookup_batch_sync(["1.1.1.1", "8.8.4.4"])
subnet = client.analyze_subnet("10.0.0.0/8")
```

## Integration with IntentKernel

IP-Discrambler results can feed into the IntentKernel policy engine:

- A network capability request can be denied if `threat_score > threshold`.
- Geolocation data can restrict capabilities by country/region.
- WHOIS/ASN data supports organizational trust decisions.

## Development

```bash
pip install -e ".[dev]"
pytest tests/
ruff check src tests
```

## License

MIT
