"""Runtime configuration loaded from environment variables / .env."""

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass
class Config:
    """IP-Discrambler configuration."""

    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    shodan_api_key: str = ""
    maxmind_db_path: str = ""
    request_timeout: float = 10.0
    max_concurrency: int = 50
    reverse_dns_timeout: float = 2.0

    @classmethod
    def from_env(cls, env_path: str = ".env") -> "Config":
        if Path(env_path).exists():
            load_dotenv(env_path)
        return cls(
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", ""),
            virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", ""),
            shodan_api_key=os.getenv("SHODAN_API_KEY", ""),
            maxmind_db_path=os.getenv("MAXMIND_DB_PATH", ""),
            request_timeout=float(os.getenv("REQUEST_TIMEOUT", "10.0")),
            max_concurrency=int(os.getenv("MAX_CONCURRENCY", "50")),
            reverse_dns_timeout=float(os.getenv("REVERSE_DNS_TIMEOUT", "2.0")),
        )

    def has_threat_provider(self, provider: str) -> bool:
        if provider.lower() == "abuseipdb":
            return bool(self.abuseipdb_api_key)
        if provider.lower() == "virustotal":
            return bool(self.virustotal_api_key)
        if provider.lower() == "shodan":
            return bool(self.shodan_api_key)
        return False
