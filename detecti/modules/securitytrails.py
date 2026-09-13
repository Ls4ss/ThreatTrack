"""SecurityTrails passive collection module."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Any, Dict, List, Optional

from detecti.config import settings
from detecti.core.models import Finding, FindingType, HostInfoData
from detecti.modules.base import BaseModule

logger = logging.getLogger("detecti.securitytrails")


class SecurityTrailsModule(BaseModule):
    """SecurityTrails module for subdomains and reverse IP."""

    name: str = "securitytrails"
    description: str = "SecurityTrails API for DNS and Reverse IP"
    category: str = "recon"

    def is_configured(self) -> bool:
        """Check if valid SecurityTrails API key is set."""
        from detecti.config import is_placeholder_key
        return bool(settings.securitytrails_api_key and not is_placeholder_key(settings.securitytrails_api_key))

    async def run(
        self,
        target: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """Execute SecurityTrails queries based on target input type."""
        if not self.is_configured():
            logger.warning("SecurityTrails API key is not configured. Skipping module.")
            return []

        target = target.strip()
        findings: List[Finding] = []
        headers = {
            "APIKEY": settings.securitytrails_api_key,
            "Accept": "application/json"
        }

        # Check if target is an IP or a domain
        try:
            ip_obj = ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            self.notify(f"Querying SecurityTrails Reverse IP for {target}...")
            # Query reverse DNS using DSL or IP endpoint
            url = "https://api.securitytrails.com/v1/dns/search"
            payload = {
                "filter": {
                    "ipv4": target
                }
            }
            try:
                resp = await self.http_client.post(
                    url=url,
                    headers=headers,
                    json=payload,
                    timeout=10.0,
                    max_retries=2,
                    raise_for_status=True,
                )
                data = resp.json()
                records = data.get("records", [])
                self.notify(f"Found {len(records)} domains resolving to {target} via SecurityTrails.")
                for rec in records:
                    hostname = rec.get("hostname")
                    if hostname:
                        findings.append(
                            Finding(
                                type=FindingType.HOST_INFO,
                                target=target,
                                source="SecurityTrails",
                                data=HostInfoData(
                                    ip=target,
                                    associated_fqdns=[hostname],
                                ),
                                severity="info",
                                description=f"SecurityTrails mapped {hostname} to IP {target}"
                            )
                        )
            except Exception as e:
                logger.error(f"SecurityTrails IP search error for {target}: {e}")
                self.notify(f"Error querying SecurityTrails for IP: {e}")
        else:
            self.notify(f"Querying SecurityTrails subdomains for {target}...")
            url = f"https://api.securitytrails.com/v1/domain/{target}/subdomains"
            try:
                resp = await self.http_client.get(
                    url=url,
                    headers=headers,
                    timeout=10.0,
                    max_retries=2,
                    raise_for_status=True,
                )
                data = resp.json()
                subdomains = data.get("subdomains", [])
                self.notify(f"Found {len(subdomains)} subdomains for {target} via SecurityTrails.")
                for sub in subdomains:
                    fqdn = f"{sub}.{target}"
                    findings.append(
                        Finding(
                            type=FindingType.HOST_INFO,
                            target=target,
                            source="SecurityTrails",
                            data=HostInfoData(
                                associated_fqdns=[fqdn]
                            ),
                            severity="info",
                            description=f"SecurityTrails discovered subdomain {fqdn}"
                        )
                    )
            except Exception as e:
                logger.error(f"SecurityTrails domain search error for {target}: {e}")
                self.notify(f"Error querying SecurityTrails for domain: {e}")

        return findings
