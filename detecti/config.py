"""Configuration settings for DetecTI-CLI using Pydantic Settings."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# Define the global base directory for DetecTI-CLI data
custom_path = os.getenv("DETECTI_HOME", str(Path.home() / ".detecti"))
DETECTI_HOME = Path(custom_path)
DETECTI_HOME.mkdir(parents=True, exist_ok=True)


def is_placeholder_key(val: Optional[str]) -> bool:
    """Check if a string represents an unconfigured placeholder or template value."""
    if not val or not isinstance(val, str):
        return True
    cleaned = val.strip().lower()
    if not cleaned:
        return True
    if cleaned in ("none", "null", "undefined", "dummy", "xxx", "placeholder", "changeme", "example"):
        return True
    placeholder_prefixes_or_suffixes = (
        "insert_your_",
        "your_api",
        "your_token",
        "your_key",
        "seu_",
        "sua_",
        "_aqui",
        "_here",
        "token_aqui",
        "chave_aqui",
        "api_key_here",
        "changeme",
        "<insert",
    )
    if any(p in cleaned for p in placeholder_prefixes_or_suffixes):
        return True
    if cleaned.startswith("<") and cleaned.endswith(">"):
        return True
    return False


def sanitize_api_key(val: Optional[str]) -> Optional[str]:
    """Return stripped string if valid and not a placeholder, else None."""
    if not val or is_placeholder_key(val):
        return None
    return val.strip()


def _find_legacy_api_key() -> Optional[str]:
    """Look for legacy API.txt file in working directory or package root."""
    candidate_paths = [
        DETECTI_HOME / "API.txt",
        Path.cwd() / "API.txt",
        Path(__file__).resolve().parent / "API.txt",
        Path(__file__).resolve().parent.parent / "API.txt",
    ]
    for path in candidate_paths:
        if path.is_file():
            try:
                content = path.read_text(encoding="utf-8").strip()
                sanitized = sanitize_api_key(content)
                if sanitized:
                    return sanitized
            except Exception:
                pass
    return None


class Settings(BaseSettings):
    """DetecTI Application Settings."""

    model_config = SettingsConfigDict(
        env_file=(str(DETECTI_HOME / ".env"), ".env", "detecti-cli/.env", "threattrack/.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        env_prefix="DETECTI_",
    )

    # API Keys (can also be read from direct standard env vars like SHODAN_API_KEY)
    shodan_api_key: Optional[str] = Field(
        default=None,
        validation_alias="SHODAN_API_KEY",
        description="Shodan.io API key",
    )
    nvd_api_key: Optional[str] = Field(
        default=None,
        validation_alias="NVD_API_KEY",
        description="National Vulnerability Database API key (optional, allows faster queries)",
    )
    whoisfreaks_api_key: Optional[str] = Field(
        default=None,
        validation_alias="WHOISFREAKS_API_KEY",
        description="WhoisFreaks API key for reverse WHOIS",
    )
    securitytrails_api_key: Optional[str] = Field(
        default=None,
        validation_alias="SECURITYTRAILS_API_KEY",
        description="SecurityTrails API key",
    )
    github_token: Optional[str] = Field(
        default=None,
        validation_alias="GITHUB_TOKEN",
        description="GitHub personal access token for PoC queries",
    )
    censys_pat_token: Optional[str] = Field(
        default=None,
        validation_alias="CENSYS_PAT_TOKEN",
        description="Censys Platform API v3 Personal Access Token (PAT)",
    )
    censys_org_id: Optional[str] = Field(
        default=None,
        validation_alias="CENSYS_ORG_ID",
        description="Censys Platform API v3 Organization ID (optional)",
    )
    censys_api_id: Optional[str] = Field(
        default=None,
        validation_alias="CENSYS_API_ID",
        description="Legacy Censys Search API ID (fallback)",
    )
    censys_api_secret: Optional[str] = Field(
        default=None,
        validation_alias="CENSYS_API_SECRET",
        description="Legacy Censys Search API Secret (fallback)",
    )

    # HTTP Client Configuration
    http_timeout: float = Field(default=15.0, description="HTTP timeout in seconds")
    http_max_retries: int = Field(default=3, description="Max HTTP retries for failed requests")
    http_backoff_factor: float = Field(default=0.5, description="Exponential backoff factor")
    http_concurrency_limit: int = Field(default=10, description="Max concurrent async requests")
    user_agent: str = Field(
        default="DetecTI-CLI/2.0 (+https://github.com/detectisec/DetecTI-CLI)",
        description="HTTP User-Agent header",
    )

    # Rate Limiting Delays
    nvd_delay_without_key: float = Field(default=6.0, description="Rate limit delay in seconds without NVD key")
    nvd_delay_with_key: float = Field(default=0.6, description="Rate limit delay in seconds with NVD key")
    hackertarget_delay: float = Field(default=1.0, description="Delay between HackerTarget free requests")
    shodan_delay: float = Field(default=1.05, description="Rate limit delay in seconds for Shodan REST API (1 request/s limit)")

    # Threat Intelligence Endpoint URLs
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    epss_api_url: str = "https://api.first.org/data/v1/epss"
    cisa_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    crtsh_api_url: str = "https://crt.sh"
    github_poc_api_url: str = "https://poc-in-github.motikan2010.net/api/v1"
    exploit_db_base_url: str = "https://www.exploit-db.com/exploits"
    hackertarget_reverse_ip_url: str = "https://api.hackertarget.com/reverseiplookup"
    hackertarget_whois_url: str = "https://api.hackertarget.com/whois"
    whoisfreaks_reverse_whois_url: str = "https://api.whoisfreaks.com/v1.0/reversewhois"
    censys_platform_api_url: str = "https://api.platform.censys.io/v3"
    censys_hosts_api_url: str = "https://api.platform.censys.io/v3/global"

    @model_validator(mode="after")
    def populate_fallback_keys(self) -> Settings:
        """Fallback to direct environment variables or API.txt if not set, filtering out placeholders."""
        raw_shodan = self.shodan_api_key or os.getenv("SHODAN_API_KEY") or _find_legacy_api_key()
        self.shodan_api_key = sanitize_api_key(raw_shodan)

        raw_nvd = self.nvd_api_key or os.getenv("NVD_API_KEY")
        self.nvd_api_key = sanitize_api_key(raw_nvd)

        raw_whois = self.whoisfreaks_api_key or os.getenv("WHOISFREAKS_API_KEY")
        self.whoisfreaks_api_key = sanitize_api_key(raw_whois)

        raw_sectrails = self.securitytrails_api_key or os.getenv("SECURITYTRAILS_API_KEY")
        self.securitytrails_api_key = sanitize_api_key(raw_sectrails)

        raw_github = self.github_token or os.getenv("GITHUB_TOKEN")
        self.github_token = sanitize_api_key(raw_github)

        raw_censys_pat = self.censys_pat_token or os.getenv("CENSYS_PAT_TOKEN")
        self.censys_pat_token = sanitize_api_key(raw_censys_pat)

        raw_censys_org = self.censys_org_id or os.getenv("CENSYS_ORG_ID")
        self.censys_org_id = sanitize_api_key(raw_censys_org)

        raw_censys_id = self.censys_api_id or os.getenv("CENSYS_API_ID")
        self.censys_api_id = sanitize_api_key(raw_censys_id)

        raw_censys_secret = self.censys_api_secret or os.getenv("CENSYS_API_SECRET")
        self.censys_api_secret = sanitize_api_key(raw_censys_secret)

        return self


# Global singleton settings instance
settings = Settings()
