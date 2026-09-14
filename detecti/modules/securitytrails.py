"""SecurityTrails advanced intelligence module (DSL & Anti-WAF)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from detecti.config import settings
from detecti.core.models import Finding, FindingType, HostInfoData
from detecti.modules.base import BaseModule

logger = logging.getLogger("detecti.securitytrails")


class SecurityTrailsModule(BaseModule):
    """Smart SecurityTrails module for comprehensive attack surface pivoting."""

    name: str = "securitytrails"
    description: str = "SecurityTrails API for DSL intelligence, WHOIS pivoting, and Anti-WAF Origin IP discovery"
    category: str = "recon"

    def is_configured(self) -> bool:
        """Check if valid SecurityTrails API key is set."""
        from detecti.config import is_placeholder_key
        return bool(settings.securitytrails_api_key and not is_placeholder_key(settings.securitytrails_api_key))

    async def _scroll_dsl_query(self, query: str, max_pages: int = 5) -> List[str]:
        """Fetch domains using the SecurityTrails DSL search list API with pagination."""
        headers = {
            "APIKEY": settings.securitytrails_api_key,
            "Accept": "application/json"
        }
        url = "https://api.securitytrails.com/v1/domains/list"
        
        all_domains = []
        page = 1
        
        while page <= max_pages:
            payload = {"query": query}
            
            try:
                # Note: The DSL API uses URL query params for pagination, e.g., ?page=1
                page_url = f"{url}?page={page}"
                resp = await self.http_client.post(
                    url=page_url,
                    headers=headers,
                    json=payload,
                    timeout=15.0,
                    max_retries=2,
                )
                
                # If 404/403, might be wrong endpoint or permissions. We'll fallback to search/list if domains/list fails.
                if resp.status_code == 404:
                    page_url = f"https://api.securitytrails.com/v1/search/list?page={page}"
                    resp = await self.http_client.post(
                        url=page_url,
                        headers=headers,
                        json=payload,
                        timeout=15.0,
                        max_retries=2,
                        raise_for_status=True
                    )
                else:
                    resp.raise_for_status()

                data = resp.json()
                records = data.get("records", [])
                for rec in records:
                    hostname = rec.get("hostname")
                    if hostname:
                        all_domains.append(hostname)
                
                meta = data.get("meta", {})
                total_pages = meta.get("max_page", 1)
                
                if page >= total_pages:
                    break
                    
                page += 1
            except Exception as e:
                logger.debug(f"SecurityTrails DSL error on page {page}: {e}")
                if hasattr(e, "response") and e.response is not None and e.response.status_code == 403:
                    self.notify("SecurityTrails API: DSL feature requires a commercial subscription (403 Forbidden).")
                elif page == 1:
                    self.notify(f"SecurityTrails API error: {e}")
                break
                
        return all_domains

    async def _fetch_historical_dns(self, domain: str) -> List[str]:
        """Fetch historical A records to find potential Origin IPs (WAF Bypass)."""
        headers = {
            "APIKEY": settings.securitytrails_api_key,
            "Accept": "application/json"
        }
        url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        ips = set()
        
        try:
            resp = await self.http_client.get(
                url=url,
                headers=headers,
                timeout=10.0,
                max_retries=1
            )
            if resp.status_code == 200:
                data = resp.json()
                records = data.get("records", [])
                for rec in records:
                    for val in rec.get("values", []):
                        ip = val.get("ip")
                        if ip:
                            ips.add(ip)
        except Exception as e:
            logger.debug(f"Historical DNS error for {domain}: {e}")
            
        return list(ips)

    async def _fetch_subdomains(self, domain: str) -> List[str]:
        """Fetch subdomains for an apex domain."""
        headers = {
            "APIKEY": settings.securitytrails_api_key,
            "Accept": "application/json"
        }
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        subs = []
        
        try:
            resp = await self.http_client.get(
                url=url,
                headers=headers,
                timeout=15.0,
                max_retries=2,
                raise_for_status=True
            )
            data = resp.json()
            subdomains = data.get("subdomains", [])
            for sub in subdomains:
                subs.append(f"{sub}.{domain}")
        except Exception as e:
            logger.debug(f"Subdomain fetch error for {domain}: {e}")
            
        return subs

    async def run(
        self,
        target: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """Execute SecurityTrails smart queries based on target input type."""
        if not self.is_configured():
            logger.warning("SecurityTrails API key is not configured. Skipping module.")
            return []

        target = target.strip()
        context = context or {}
        target_type = context.get("target_type", "domain")
        findings: List[Finding] = []
        
        # ----------------------------------------------------
        # Routing Logic based on Target Type
        # ----------------------------------------------------
        
        if target_type == "ip":
            self.notify(f"Querying SecurityTrails Reverse IP (DSL) for {target}...")
            # Detect if it's a subnet (CIDR) or single IP
            if "/" in target:
                query = f"ipv4 = '{target}'"
            else:
                query = f"ipv4 = '{target}'"
                
            domains = await self._scroll_dsl_query(query)
            if domains:
                self.notify(f"Found {len(domains)} domains hosted on {target} via SecurityTrails.")
                for d in domains:
                    findings.append(Finding(
                        type=FindingType.SUBDOMAIN if context.get("root_domain") and d.endswith(context.get("root_domain", "")) else FindingType.ASSOCIATED_DOMAIN,
                        target=target,
                        value=d,
                        source="SecurityTrails",
                        host_ip=target.split("/")[0],  # map back to target if it's an IP
                        metadata={"description": f"SecurityTrails Reverse IP mapping to {target}"}
                    ))

        elif target_type == "email":
            self.notify(f"Querying Reverse WHOIS for {target} via SecurityTrails...")
            query = f"whois_email = '{target}'"
            domains = await self._scroll_dsl_query(query)
            if domains:
                self.notify(f"Found {len(domains)} domains registered by {target}.")
                for d in domains:
                    findings.append(Finding(
                        type=FindingType.ASSOCIATED_DOMAIN,
                        target=target,
                        value=d,
                        source="SecurityTrails Reverse WHOIS",
                        metadata={"description": f"Domain registered by {target}"}
                    ))

        elif target_type == "org":
            self.notify(f"Querying Corporate Assets for {target} via SecurityTrails...")
            query = f"whois_organization = '{target}' OR whois_name = '{target}'"
            domains = await self._scroll_dsl_query(query)
            if domains:
                self.notify(f"Found {len(domains)} domains owned by organization {target}.")
                for d in domains:
                    findings.append(Finding(
                        type=FindingType.ASSOCIATED_DOMAIN,
                        target=target,
                        value=d,
                        source="SecurityTrails Org Recon",
                        metadata={"description": f"Asset owned by {target}"}
                    ))

        elif target_type == "asn":
            self.notify(f"Querying ASN Footprint for {target} via SecurityTrails...")
            asn_num = target.replace("asn:", "").replace("AS", "").strip()
            query = f"asn = '{asn_num}'"
            domains = await self._scroll_dsl_query(query)
            if domains:
                self.notify(f"Found {len(domains)} domains hosted in AS{asn_num}.")
                for d in domains:
                    findings.append(Finding(
                        type=FindingType.ASSOCIATED_DOMAIN,
                        target=target,
                        value=d,
                        source="SecurityTrails ASN Mapping",
                        metadata={"description": f"Domain hosted within AS{asn_num}"}
                    ))

        elif target_type in ("domain", "subdomain"):
            self.notify(f"Running multi-layered SecurityTrails recon for {target}...")
            
            # Fire both Subdomain Enumeration and Historical DNS concurrently
            subs_task = asyncio.create_task(self._fetch_subdomains(target))
            hist_task = asyncio.create_task(self._fetch_historical_dns(target))
            
            subs, hist_ips = await asyncio.gather(subs_task, hist_task, return_exceptions=False)
            
            if subs:
                self.notify(f"Found {len(subs)} subdomains for {target} via SecurityTrails.")
                for sub in subs:
                    findings.append(Finding(
                        type=FindingType.SUBDOMAIN,
                        target=target,
                        value=sub,
                        source="SecurityTrails",
                        metadata={"description": f"SecurityTrails discovered subdomain {sub}"}
                    ))
            
            if hist_ips:
                self.notify(f"Found {len(hist_ips)} historical IPs for {target} (Anti-WAF).")
                for ip in hist_ips:
                    # Tag this specifically as a Historical IP
                    finding = Finding(
                        type=FindingType.HOST_INFO,
                        target=target,
                        value=ip,
                        source="SecurityTrails Historical DNS",
                        host_ip=ip,
                        host_info=HostInfoData(ip=ip, associated_fqdns=[target]),
                        metadata={"description": f"Historical Origin IP mapped for {target}", "tags": ["Historical IP", "WAF Bypass Candidate"]}
                    )
                    findings.append(finding)

        return findings
