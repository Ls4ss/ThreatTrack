"""Core Asynchronous Orchestration and Intelligence Correlation Engine."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

import httpx
import tldextract
from detecti.config import settings

from detecti.core.models import (
    Finding,
    FindingType,
    HostInfoData,
    HostResult,
    PortData,
    ScanResult,
    SeverityLevel,
    VulnerabilityData,
)
from detecti.modules.base import BaseModule
from detecti.modules.censys import CensysModule
from detecti.modules.crtsh import CrtshModule
from detecti.modules.exploitdb import ExploitDBModule
from detecti.modules.nvd import NVDModule
from detecti.modules.reverse_whois import ReverseWhoisModule
from detecti.modules.securitytrails import SecurityTrailsModule
from detecti.modules.shodan import ShodanModule
from detecti.utils.http import AsyncHTTPClient, http_client

logger = logging.getLogger("detecti.engine")


def _clean_source(src: str) -> str:
    """Normalize source names (e.g. 'Censys Platform v3' -> 'Censys', 'Shodan DNS' -> 'Shodan')."""
    if not src:
        return "Unknown"
    lower = src.lower()
    if "shodan" in lower:
        return "Shodan"
    if "censys" in lower:
        return "Censys"
    if "crtsh" in lower or "crt.sh" in lower:
        return "crt.sh"
    if "whois" in lower:
        return "Reverse WHOIS"
    return src


class ThreatTrackEngine:
    """Async execution runner orchestrating modules, target classification, and correlation."""

    MODULE_REGISTRY: Dict[str, type[BaseModule]] = {
        "shodan": ShodanModule,
        "censys": CensysModule,
        "crtsh": CrtshModule,
        "reverse_whois": ReverseWhoisModule,
        "securitytrails": SecurityTrailsModule,
        "nvd": NVDModule,
        "exploitdb": ExploitDBModule,
    }

    def __init__(
        self,
        client: Optional['AsyncHTTPClient'] = None,
        progress_callback: Optional[Callable[[str, str], None]] = None,
        db_manager = None,
    ):
        self.http_client = client or http_client
        self.progress_callback = progress_callback
        self.db_manager = db_manager
        self.current_input_target: Optional[str] = None
        self.modules: Dict[str, BaseModule] = {
            name: cls(client=self.http_client, progress_callback=self._notify)
            for name, cls in self.MODULE_REGISTRY.items()
        }

    def _notify(self, module_name: str, message: str) -> None:
        if self.progress_callback:
            self.progress_callback(module_name, message)
        logger.info(f"[{module_name}] {message}")
        if self.db_manager:
            level = "error" if "error" in message.lower() or "fail" in message.lower() else "info"
            self.db_manager.add_scan_log(level=level, message=f"[{module_name}] {message}", input_target=self.current_input_target)

    def parse_target_metadata(self, target: str) -> Dict[str, Any]:
        """Extract canonical target type, cleaned host/domain, port, and root domain supporting full URLs and subdomains."""
        raw = target.strip()

        KNOWN_FILE_EXTENSIONS = {
            ".txt", ".list", ".csv", ".targets", ".ips", ".log", ".json", ".yaml", ".yml", ".conf", ".cfg"
        }
        target_path = Path(raw)
        is_file_like = (
            target_path.suffix.lower() in KNOWN_FILE_EXTENSIONS
            or raw.startswith(("./", "../", "/", "~/"))
            or "\\" in raw
            or target_path.is_file()
        )
        if is_file_like and not raw.startswith("http"):
            if not target_path.is_file():
                raise FileNotFoundError(f"Target file not found: {raw}")
            return {"type": "file", "clean_target": raw, "root_domain": None, "subdomain": None, "port": None}

        if raw.upper().startswith("CVE-"):
            return {"type": "cve", "clean_target": raw.upper(), "root_domain": None, "subdomain": None, "port": None}

        if "@" in raw and " " not in raw and "://" not in raw:
            domain_part = raw.split("@", 1)[1] if "@" in raw else None
            return {"type": "email", "clean_target": raw, "root_domain": domain_part, "subdomain": None, "port": None}

        clean = raw
        if clean.startswith("host:"):
            clean = clean[5:].strip()
        elif clean.startswith("domain:"):
            clean = clean[7:].strip()

        port: Optional[int] = None
        if "://" in clean or "/" in clean or (":" in clean and " " not in clean):
            # Check if valid CIDR network
            try:
                ipaddress.ip_network(clean, strict=False)
                return {"type": "cidr", "clean_target": clean, "root_domain": None, "subdomain": None, "port": None}
            except ValueError:
                pass

            # Parse as URL / Host:Port
            url_candidate = clean if "://" in clean else f"http://{clean}"
            try:
                parsed = httpx.URL(url_candidate)
                extracted_host = parsed.host
                if parsed.port:
                    port = parsed.port
                clean = extracted_host or clean
            except Exception:
                pass

        if "/" in clean:
            clean = clean.split("/")[0]
        if ":" in clean:
            parts = clean.split(":")
            clean = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass

        clean = clean.strip().lower()

        # Check IP
        try:
            ipaddress.ip_address(clean)
            return {"type": "ip", "clean_target": clean, "root_domain": None, "subdomain": None, "port": port}
        except ValueError:
            pass

        # Check Domain / Subdomain with tldextract
        import tldextract
        ext = tldextract.extract(clean)
        if ext.domain and ext.suffix and " " not in clean:
            root_domain = ext.registered_domain or f"{ext.domain}.{ext.suffix}"
            subdomain = ext.subdomain if ext.subdomain else None
            return {
                "type": "domain",
                "clean_target": clean,
                "root_domain": root_domain,
                "subdomain": subdomain,
                "is_subdomain": bool(subdomain),
                "port": port,
            }

        # Check Shodan Search Queries / Dorks
        SHODAN_DORK_KEYWORDS = (
            "org:", "product:", "port:", "city:", "country:", "ssl:", "os:",
            "title:", "html:", "asn:", "net:", "has_vuln:", "vuln:", "tag:",
            "http.title:", "http.html:", "http.status:", "cloud.provider:",
            "host:", "domain:", "query:", "search:"
        )
        raw_lower = raw.lower()
        if any(kw in raw_lower for kw in SHODAN_DORK_KEYWORDS) or (" " in raw and ":" in raw):
            query_val = raw
            if query_val.lower().startswith("query:") or query_val.lower().startswith("search:"):
                query_val = query_val.split(":", 1)[1].strip()
            return {"type": "query", "clean_target": query_val, "root_domain": None, "subdomain": None, "port": None}

        # If it is not an IP, CIDR, Domain with valid TLD, CVE, Email, existing File, or valid Query Dork -> Invalid Target
        raise ValueError(
            f"Invalid target or file not found: '{raw}'. "
            f"Target must be a valid IP, CIDR, Domain, URL, CVE, existing File, or Shodan Query filter (e.g., org:'Target', port:443)."
        )

    def classify_target(self, target: str) -> str:
        """Identify target classification (ip, cidr, domain, cve, query, file, email, invalid)."""
        try:
            meta = self.parse_target_metadata(target)
            return meta.get("type", "invalid")
        except Exception:
            return "invalid"

    async def verify_environment_apis(self, enabled_modules: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
        """Verify API keys present in the environment/config and perform non-blocking pre-flight checks."""
        active_mod_names = (
            [m for m in enabled_modules if m in self.modules]
            if enabled_modules and "all" not in enabled_modules
            else list(self.modules.keys())
        )
        
        status_report: Dict[str, Dict[str, Any]] = {}

        # 1. Shodan
        if "shodan" in active_mod_names:
            shodan_mod: ShodanModule = self.modules["shodan"]  # type: ignore
            if shodan_mod.is_configured():
                is_valid, status_msg = await shodan_mod.validate_credentials_detailed()
                status_report["shodan"] = {
                    "name": "Shodan",
                    "configured": True,
                    "valid": is_valid,
                    "status": status_msg if not is_valid else "Active & Valid",
                    "tier": "Standard API",
                }
            else:
                status_report["shodan"] = {
                    "name": "Shodan",
                    "configured": False,
                    "valid": False,
                    "status": "Not Configured (Required for Shodan recon)",
                    "tier": "None",
                }

        # 2. Censys
        if "censys" in active_mod_names:
            censys_mod: CensysModule = self.modules["censys"]  # type: ignore
            if censys_mod.is_configured():
                is_valid, status_msg = await censys_mod.validate_credentials_detailed()
                status_report["censys"] = {
                    "name": "Censys",
                    "configured": True,
                    "valid": is_valid,
                    "status": status_msg if not is_valid else "Active & Valid",
                    "tier": "PAT Token" if censys_mod.pat_token else "Legacy API",
                }
            else:
                status_report["censys"] = {
                    "name": "Censys",
                    "configured": False,
                    "valid": False,
                    "status": "Not Configured / Placeholder (Bypassed)",
                    "tier": "None",
                }

        # 3. NVD
        if "nvd" in active_mod_names:
            nvd_mod: NVDModule = self.modules["nvd"]  # type: ignore
            if nvd_mod.is_configured():
                status_report["nvd"] = {
                    "name": "NVD (NIST)",
                    "configured": True,
                    "valid": True,
                    "status": "Active (High-speed 0.6s rate limit)",
                    "tier": "API Key",
                }
            else:
                status_report["nvd"] = {
                    "name": "NVD (NIST)",
                    "configured": False,
                    "valid": True,
                    "status": "Active (Public mode, 6.0s rate limit)",
                    "tier": "Free / Public",
                }

        # 4. WhoisFreaks / Reverse WHOIS
        if "reverse_whois" in active_mod_names:
            whois_mod: ReverseWhoisModule = self.modules["reverse_whois"]  # type: ignore
            if whois_mod.is_configured():
                status_report["reverse_whois"] = {
                    "name": "WhoisFreaks",
                    "configured": True,
                    "valid": True,
                    "status": "Active (WhoisFreaks API)",
                    "tier": "Paid API",
                }
            else:
                status_report["reverse_whois"] = {
                    "name": "WhoisFreaks",
                    "configured": False,
                    "valid": True,
                    "status": "Active (HackerTarget / RDAP Fallback)",
                    "tier": "Free OSINT",
                }

        # 5. SecurityTrails
        if "securitytrails" in active_mod_names:
            st_mod = self.modules["securitytrails"]
            if st_mod.is_configured():
                status_report["securitytrails"] = {
                    "name": "SecurityTrails",
                    "configured": True,
                    "valid": True,
                    "status": "Active (API Key)",
                    "tier": "Standard API",
                }
            else:
                status_report["securitytrails"] = {
                    "name": "SecurityTrails",
                    "configured": False,
                    "valid": False,
                    "status": "Not Configured (Bypassed)",
                    "tier": "None",
                }

        # 6. ExploitDB / GitHub Token
        if "exploitdb" in active_mod_names:
            from config import is_placeholder_key
            has_gh = bool(settings.github_token and not is_placeholder_key(settings.github_token))
            status_report["exploitdb"] = {
                "name": "ExploitDB / GitHub PoCs",
                "configured": has_gh,
                "valid": True,
                "status": "Active (Local ExploitDB + Authenticated GitHub PoCs)" if has_gh else "Active (Local ExploitDB + Public PoC API)",
                "tier": "GitHub Token" if has_gh else "Public PoC API",
            }

        return status_report

    async def scan(
        self,
        target: str,
        enabled_modules: Optional[List[str]] = None,
        cvss_filter: Optional[str] = None,
        skip_preflight: bool = False,
    ) -> ScanResult:
        self.current_input_target = target
        start_time = time.monotonic()
        meta = self.parse_target_metadata(target)
        target_type = meta["type"]
        clean_target = meta["clean_target"]
        root_domain = meta.get("root_domain")
        target_port = meta.get("port")

        # Handle file input containing multiple targets
        if target_type == "file":
            return await self._scan_file(target, enabled_modules, cvss_filter)

        active_mod_names = (
            [m for m in enabled_modules if m in self.modules]
            if enabled_modules and "all" not in enabled_modules
            else list(self.modules.keys())
        )

        # Pre-flight API verification layer: validate all APIs present in environment/config (if not skipped)
        if not skip_preflight:
            self._notify("engine", "Verifying environment API credentials and endpoints...")
            api_statuses = await self.verify_environment_apis(active_mod_names)
            for mod, info in api_statuses.items():
                if info.get("configured") and not info.get("valid"):
                    self._notify(mod, f"{info.get('name')}: {info.get('status')}")

        result = ScanResult(
            target=clean_target,
            target_type=target_type,
            started_at=datetime.now(timezone.utc),
            modules_run=active_mod_names,
        )

        context: Dict[str, Any] = {
            "target": clean_target,
            "raw_target": target,
            "target_type": target_type,
            "root_domain": root_domain,
            "port": target_port,
            "cves": set(),
            "warnings": [],
        }
        raw_recon_findings: List[Finding] = []

        # Direct DNS Resolution for Domain / Subdomain / URL targets
        if target_type == "domain":
            try:
                addr_info = await asyncio.get_event_loop().getaddrinfo(clean_target, None)
                resolved_ips = {res[4][0] for res in addr_info if res and len(res) > 4 and res[4]}
                for rip in resolved_ips:
                    raw_recon_findings.append(
                        Finding(
                            type=FindingType.HOST_INFO,
                            target=clean_target,
                            value=rip,
                            source="DNS Resolution",
                            host_ip=rip,
                            host_info=HostInfoData(
                                ip=rip,
                                hostnames=[clean_target],
                                domains=[root_domain] if root_domain else [clean_target],
                            ),
                        )
                    )
            except Exception as exc:
                logger.debug(f"Direct DNS resolution for {clean_target}: {exc}")

        # ----------------------------------------------------
        # Stage 1: Recon & Discovery (Shodan Primary Query, Censys, crt.sh, Reverse WHOIS)
        # ----------------------------------------------------
        recon_tasks = []
        is_direct_ip = (target_type == "ip")
        has_shodan = "shodan" in active_mod_names and self.modules["shodan"].is_configured()
        has_censys = "censys" in active_mod_names and self.modules["censys"].is_configured()

        if target_type == "cve":
            context["cves"].add(clean_target.upper())
        else:
            # 1. Shodan Search / Host Lookup
            if has_shodan:
                self._notify("shodan", f"Querying Shodan for {clean_target}...")
                recon_tasks.append(self.modules["shodan"].run(clean_target, context))

            # 2. Censys Direct Host Lookup (Executed in Stage 1 for direct IP targets, or as fallback if Shodan is not configured)
            if has_censys and (is_direct_ip or not has_shodan):
                self._notify("censys", f"Querying Censys for {clean_target}...")
                recon_tasks.append(self.modules["censys"].run(clean_target, context))

            # 3. Certificate Transparency (Uses root domain to capture full subdomain hierarchy)
            if target_type in ("domain", "email") and "crtsh" in active_mod_names:
                query_dom = root_domain or clean_target
                self._notify("crtsh", f"Querying Certificate Transparency for {query_dom}...")
                recon_tasks.append(self.modules["crtsh"].run(query_dom, context))

            # 4. Reverse WHOIS
            if target_type in ("domain", "ip", "email") and "reverse_whois" in active_mod_names:
                query_whois = root_domain or clean_target
                self._notify("reverse_whois", f"Performing Reverse WHOIS lookup for {query_whois}...")
                recon_tasks.append(self.modules["reverse_whois"].run(query_whois, context))

            # 5. SecurityTrails
            if target_type in ("domain", "ip") and "securitytrails" in active_mod_names:
                st_target = root_domain or clean_target if target_type == "domain" else clean_target
                self._notify("securitytrails", f"Querying SecurityTrails for {st_target}...")
                recon_tasks.append(self.modules["securitytrails"].run(st_target, context))

        if recon_tasks:
            recon_results = await asyncio.gather(*recon_tasks, return_exceptions=True)
            for res in recon_results:
                if isinstance(res, list):
                    raw_recon_findings.extend(res)
                elif isinstance(res, Exception):
                    logger.error(f"Error during recon stage: {res}")

        # ----------------------------------------------------
        # Scope Governance: Determine Organization / ASN Scope Filters
        # ----------------------------------------------------
        target_org = None
        target_asn = None
        clean_lower = clean_target.lower()
        if "org:" in clean_lower:
            import re
            m = re.search(r'org:\s*["\']?([^"\']+)["\']?', clean_target, re.IGNORECASE)
            if m:
                target_org = m.group(1).strip()
        if "asn:" in clean_lower:
            import re
            m = re.search(r'asn:\s*["\']?([^"\']+)["\']?', clean_target, re.IGNORECASE)
            if m:
                target_asn = m.group(1).strip().upper()

        initial_org_ips = set()
        if target_org or target_asn:
            for f in raw_recon_findings:
                if f.host_ip and "shodan" in f.source.lower():
                    initial_org_ips.add(f.host_ip)

        # ----------------------------------------------------
        # Stage 1.2: Subdomain & Domain DNS Resolution & Recursive IP Mapping
        # (Resolves all subdomains and associated domains discovered via crt.sh/WHOIS/Shodan to their active A/AAAA IPs)
        # ----------------------------------------------------
        discovered_subdomains: Set[str] = set()
        subdomain_finding_refs: Dict[str, List[Finding]] = {}
        for f in raw_recon_findings:
            if f.type in (FindingType.SUBDOMAIN, FindingType.ASSOCIATED_DOMAIN) and f.value:
                sub_val = f.value.strip().lower()
                if sub_val.startswith("*."):
                    sub_val = sub_val[2:]
                if sub_val and "." in sub_val and " " not in sub_val and not sub_val.startswith("@"):
                    # Scope enforcement for domain targets: Only resolve and expand subdomains belonging to the target domain hierarchy
                    if target_type == "domain" and root_domain:
                        if not (sub_val == root_domain or sub_val.endswith(f".{root_domain}")):
                            continue
                    discovered_subdomains.add(sub_val)
                    subdomain_finding_refs.setdefault(sub_val, []).append(f)

        if discovered_subdomains and target_type != "cve":
            self._notify("engine", f"Resolving DNS A-records for {len(discovered_subdomains)} discovered domains & subdomains...")
            
            dns_semaphore = asyncio.Semaphore(50)
            loop = asyncio.get_event_loop()

            async def _resolve_subdomain(sub: str) -> tuple[str, Set[str]]:
                async with dns_semaphore:
                    try:
                        addr_info = await loop.getaddrinfo(sub, None)
                        ips = {res[4][0] for res in addr_info if res and len(res) > 4 and res[4]}
                        return sub, ips
                    except Exception:
                        return sub, set()

            resolve_results = await asyncio.gather(*[_resolve_subdomain(s) for s in discovered_subdomains])
            
            # Authoritative IP Target Gating: If target is a direct IP, only accept domains whose live DNS resolves back to target IP!
            is_ip_scan = (target_type == "ip")
            target_ip_clean = clean_target if is_ip_scan else None

            for sub, ips in resolve_results:
                if ips:
                    # In an IP scan, if the resolved IPs do NOT include the target IP, this domain has migrated elsewhere or is behind a WAF
                    if is_ip_scan and target_ip_clean and target_ip_clean not in ips:
                        # Tag it as WAF Bypass / Origin Match instead of dropping
                        for sub_finding in subdomain_finding_refs.get(sub, []):
                            if sub_finding in raw_recon_findings:
                                sub_finding.metadata["is_waf_bypass"] = True
                                # Anchor the finding's host_ip to the TARGET IP (the origin), NOT the CDN IP!
                                sub_finding.host_ip = target_ip_clean
                        continue

                    for ip in ips:
                        # Scope enforcement: If target is an Organization or ASN, ignore foreign resolved IPs!
                        if (target_org or target_asn) and ip not in initial_org_ips:
                            continue
                        
                        # In IP scan, only inject host info for the target IP itself
                        if is_ip_scan and target_ip_clean and ip != target_ip_clean:
                            continue

                        raw_recon_findings.append(
                            Finding(
                                type=FindingType.HOST_INFO,
                                target=sub,
                                value=ip,
                                source="DNS Resolution",
                                host_ip=ip,
                                host_info=HostInfoData(
                                    ip=ip,
                                    hostnames=[sub],
                                    domains=[root_domain] if root_domain else [sub],
                                ),
                            )
                        )
                        for sub_finding in subdomain_finding_refs.get(sub, []):
                            if not sub_finding.host_ip:
                                sub_finding.host_ip = ip

        # ----------------------------------------------------
        # Stage 1.3: Recursive Threat Intelligence Feedback Loop (Shodan & Censys)
        # (Feeds all resolved subdomain IPs back into Shodan & Censys for full port, service, banner & CVE discovery)
        # ----------------------------------------------------

        target_scopes: Set[str] = set()
        if root_domain:
            target_scopes.add(root_domain.lower())
        if target_type == "domain":
            target_scopes.add(clean_target.lower())

        if (has_shodan or has_censys) and target_type != "cve":
            all_known_ips = set()
            for f in raw_recon_findings:
                hip = f.host_ip or (f.host_info.ip if f.host_info else None)
                if hip:
                    if target_org or target_asn:
                        if hip in initial_org_ips:
                            all_known_ips.add(hip)
                    else:
                        all_known_ips.add(hip)

            # 1. Shodan Recursive Host Enrichment
            if has_shodan and all_known_ips:
                already_queried_shodan_ips = {
                    f.host_ip for f in raw_recon_findings 
                    if f.host_ip and "shodan" in f.source.lower() and f.type == FindingType.HOST_INFO
                }
                shodan_enrich_ips = [ip for ip in all_known_ips if ip not in already_queried_shodan_ips]
                
                if shodan_enrich_ips:
                    self._notify("shodan", f"Retrofeeding {len(shodan_enrich_ips)} resolved subdomain IPs to Shodan for port & CVE profiling...")
                    shodan_mod: ShodanModule = self.modules["shodan"]  # type: ignore
                    shodan_tasks = [shodan_mod.get_host_info(ip) for ip in shodan_enrich_ips]
                    shodan_results = await asyncio.gather(*shodan_tasks, return_exceptions=True)
                    for res in shodan_results:
                        if isinstance(res, list):
                            for f in res:
                                if target_org and f.host_info and f.host_info.org:
                                    if target_org.lower() not in f.host_info.org.lower():
                                        continue
                                if target_asn and f.host_info and f.host_info.asn:
                                    if target_asn.lower() not in f.host_info.asn.lower():
                                        continue
                                if f.host_info and f.host_info.hostnames and target_scopes:
                                    f.host_info.hostnames = [h for h in f.host_info.hostnames if any(h.lower() == s or h.lower().endswith(f".{s}") for s in target_scopes)]
                                if f.host_info and f.host_info.domains and target_scopes:
                                    f.host_info.domains = [d for d in f.host_info.domains if any(d.lower() == s or d.lower().endswith(f".{s}") for s in target_scopes)]
                                raw_recon_findings.append(f)
                        elif isinstance(res, Exception):
                            logger.debug(f"Shodan recursive enrichment exception: {res}")

            # 2. Censys Recursive Host Enrichment
            if has_censys and all_known_ips:
                already_queried_censys_ips = {
                    f.host_ip for f in raw_recon_findings 
                    if f.host_ip and "censys" in f.source.lower() and f.type == FindingType.HOST_INFO
                }
                censys_enrich_ips = [ip for ip in all_known_ips if ip not in already_queried_censys_ips]
                
                if censys_enrich_ips:
                    self._notify("censys", f"Enriching {len(censys_enrich_ips)} discovered host IPs with Censys port & service dossiers...")
                    censys_mod: CensysModule = self.modules["censys"]  # type: ignore
                    censys_tasks = [censys_mod.get_host_info(ip) for ip in censys_enrich_ips]
                    censys_results = await asyncio.gather(*censys_tasks, return_exceptions=True)
                    for res in censys_results:
                        if isinstance(res, list):
                            for f in res:
                                if target_org and f.host_info and f.host_info.org:
                                    if target_org.lower() not in f.host_info.org.lower():
                                        continue
                                if target_asn and f.host_info and f.host_info.asn:
                                    if target_asn.lower() not in f.host_info.asn.lower():
                                        continue
                                if f.host_info and f.host_info.hostnames and target_scopes:
                                    f.host_info.hostnames = [h for h in f.host_info.hostnames if any(h.lower() == s or h.lower().endswith(f".{s}") for s in target_scopes)]
                                if f.host_info and f.host_info.domains and target_scopes:
                                    f.host_info.domains = [d for d in f.host_info.domains if any(d.lower() == s or d.lower().endswith(f".{s}") for s in target_scopes)]
                                raw_recon_findings.append(f)
                        elif isinstance(res, Exception):
                            logger.debug(f"Censys recursive enrichment exception: {res}")

        # ----------------------------------------------------
        # Group Discoveries per Host
        # ----------------------------------------------------
        hosts_map: Dict[str, HostResult] = {}
        host_cves_map: Dict[str, Set[str]] = {}
        all_unique_cves: Set[str] = set(context["cves"])
        domain_findings: List[Finding] = []

        for f in raw_recon_findings:
            clean_src = _clean_source(f.source)

            if f.type in (FindingType.SUBDOMAIN, FindingType.ASSOCIATED_DOMAIN):
                if (target_org or target_asn) and (not f.host_ip or f.host_ip not in initial_org_ips):
                    continue
                domain_findings.append(f)
                if not f.host_ip:
                    continue

            host_ip = f.host_ip or (f.host_info.ip if f.host_info else None)
            if not host_ip and f.type == FindingType.VULNERABILITY and target_type == "cve":
                # Standalone CVE scan
                all_unique_cves.add(f.value.upper())
                continue

            # Scope enforcement for Organization and ASN targets
            if (target_org or target_asn) and host_ip:
                if host_ip not in initial_org_ips:
                    if target_org and f.host_info and f.host_info.org and target_org.lower() not in f.host_info.org.lower():
                        continue
                    if target_asn and f.host_info and f.host_info.asn and target_asn.lower() not in f.host_info.asn.lower():
                        continue

            if host_ip:
                if host_ip not in hosts_map:
                    hosts_map[host_ip] = HostResult(ip=host_ip)
                    host_cves_map[host_ip] = set()

                host_obj = hosts_map[host_ip]
                if clean_src and clean_src not in host_obj.sources:
                    host_obj.sources.append(clean_src)

                if f.type == FindingType.HOST_INFO and f.host_info:
                    hi = f.host_info
                    in_scope_hnames = [h for h in hi.hostnames if not target_scopes or any(h.lower() == s or h.lower().endswith(f".{s}") for s in target_scopes)]
                    in_scope_doms = [d for d in hi.domains if not target_scopes or any(d.lower() == s or d.lower().endswith(f".{s}") for s in target_scopes)]
                    host_obj.hostnames = sorted(list(set(host_obj.hostnames + in_scope_hnames)))
                    host_obj.domains = sorted(list(set(host_obj.domains + in_scope_doms)))
                    host_obj.org = hi.org or host_obj.org
                    host_obj.isp = hi.isp or host_obj.isp
                    host_obj.asn = hi.asn or host_obj.asn
                    host_obj.os = hi.os or host_obj.os
                    host_obj.country_name = hi.country_name or host_obj.country_name
                    host_obj.country_code = hi.country_code or host_obj.country_code
                    host_obj.city = hi.city or host_obj.city
                    host_obj.region_code = hi.region_code or host_obj.region_code
                    host_obj.postal_code = hi.postal_code or host_obj.postal_code
                    host_obj.latitude = hi.latitude if hi.latitude is not None else host_obj.latitude
                    host_obj.longitude = hi.longitude if hi.longitude is not None else host_obj.longitude
                    if hi.vulns:
                        for v in hi.vulns:
                            if v.upper().startswith("CVE-"):
                                host_cves_map[host_ip].add(v.upper())
                                all_unique_cves.add(v.upper())

                elif f.type == FindingType.OPEN_PORT and f.port_info:
                    pi = f.port_info
                    # Check for existing port on this host
                    matching_port = next(
                        (p for p in host_obj.ports if p.port == pi.port and p.transport.lower() == pi.transport.lower()),
                        None,
                    )
                    if matching_port:
                        # Complement and enrich existing port without duplicating
                        if clean_src and clean_src not in matching_port.sources:
                            matching_port.sources.append(clean_src)
                        for s in pi.sources:
                            clean_s = _clean_source(s)
                            if clean_s and clean_s not in matching_port.sources:
                                matching_port.sources.append(clean_s)

                        matching_port.product = matching_port.product or pi.product
                        matching_port.version = matching_port.version or pi.version
                        matching_port.service = matching_port.service or pi.service
                        matching_port.banner = matching_port.banner or pi.banner
                        matching_port.url = matching_port.url or pi.url
                        matching_port.ssl = matching_port.ssl or pi.ssl
                    else:
                        if clean_src and clean_src not in pi.sources:
                            pi.sources.append(clean_src)
                        host_obj.ports.append(pi)

                elif f.type == FindingType.VULNERABILITY:
                    cve = f.value.upper()
                    if cve.startswith("CVE-"):
                        host_cves_map[host_ip].add(cve)
                        all_unique_cves.add(cve)

                elif f.type == FindingType.SUBDOMAIN and f.value:
                    if f.value not in host_obj.hostnames:
                        host_obj.hostnames.append(f.value)
                    if f.metadata.get("is_waf_bypass"):
                        waf_list = host_obj.metadata.setdefault("waf_bypassed_domains", [])
                        if f.value not in waf_list:
                            waf_list.append(f.value)

                elif f.type == FindingType.ASSOCIATED_DOMAIN and f.value:
                    if f.value not in host_obj.domains:
                        host_obj.domains.append(f.value)
                    if f.metadata.get("is_waf_bypass"):
                        waf_list = host_obj.metadata.setdefault("waf_bypassed_domains", [])
                        if f.value not in waf_list:
                            waf_list.append(f.value)

        # ----------------------------------------------------
        # Ensure Target Anchor in Hosts Map & Domain Discoveries
        # (Guarantees target nodes exist on DetecTIHound graph for active recon staging)
        # ----------------------------------------------------
        clean_target = target
        if clean_target.startswith("host:"):
            clean_target = clean_target[5:]
        elif clean_target.startswith("domain:"):
            clean_target = clean_target[7:]

        if target_type == "ip" and clean_target not in hosts_map:
            hosts_map[clean_target] = HostResult(
                ip=clean_target,
                sources=["Target (Awaiting Active Recon)"],
            )
            host_cves_map[clean_target] = set()

        if target_type == "domain" and not domain_findings and not any(clean_target in h.domains or clean_target in h.hostnames for h in hosts_map.values()):
            domain_findings.append(
                Finding(
                    type=FindingType.SUBDOMAIN,
                    target=clean_target,
                    value=clean_target,
                    source="Target",
                )
            )

        # ----------------------------------------------------
        # Stage 1.4: Automatic IP Enrichment Fallback (BGP / RDAP / IP WHOIS)
        # (Enriches hosts lacking ASN/Org metadata when threat intel APIs return 0 results)
        # ----------------------------------------------------
        ips_needing_enrichment = [
            ip for ip, h in hosts_map.items()
            if not h.asn or not h.org
        ]

        if ips_needing_enrichment and target_type != "cve":
            self._notify("engine", f"Enriching network metadata (ASN/Org/Geo) for {len(ips_needing_enrichment)} unresolved IP(s)...")
            
            enrich_semaphore = asyncio.Semaphore(15)
            async def _enrich_single_ip(ip_addr: str):
                async with enrich_semaphore:
                    # Primary: ip-api.com
                    try:
                        async with httpx.AsyncClient(timeout=3.5, follow_redirects=True) as client:
                            url = f"http://ip-api.com/json/{ip_addr}?fields=status,country,countryCode,city,regionName,org,as,asname,lat,lon,query"
                            resp = await client.get(url, headers={"User-Agent": "DetecTI/1.0"})
                            if resp.status_code == 200:
                                data = resp.json()
                                if data.get("status") == "success":
                                    return ip_addr, data
                    except Exception as e:
                        logger.debug(f"IP enrichment primary failed for {ip_addr}: {e}")

                    # Secondary: RIPE Stat Network Info API
                    try:
                        async with httpx.AsyncClient(timeout=3.5, follow_redirects=True) as client:
                            url = f"https://stat.ripe.net/data/network-info/data.json?resource={ip_addr}"
                            resp = await client.get(url, headers={"User-Agent": "DetecTI/1.0"})
                            if resp.status_code == 200:
                                r_data = resp.json()
                                if r_data and "data" in r_data:
                                    asns = r_data["data"].get("asns", [])
                                    asn_str = f"AS{asns[0]}" if asns else None
                                    return ip_addr, {"as": asn_str, "org": asn_str}
                    except Exception as e:
                        logger.debug(f"IP enrichment secondary failed for {ip_addr}: {e}")

                    return ip_addr, None

            enrich_results = await asyncio.gather(*[_enrich_single_ip(ip) for ip in ips_needing_enrichment])
            for ip_addr, meta in enrich_results:
                if meta and ip_addr in hosts_map:
                    h_obj = hosts_map[ip_addr]
                    if not h_obj.asn and meta.get("as"):
                        import re
                        as_raw = meta.get("as", "")
                        as_match = re.search(r"(AS\d+)", as_raw, re.IGNORECASE)
                        h_obj.asn = as_match.group(1).upper() if as_match else as_raw
                    if not h_obj.org:
                        h_obj.org = meta.get("org") or meta.get("asname")
                    if not h_obj.country_name and meta.get("country"):
                        h_obj.country_name = meta.get("country")
                    if not h_obj.country_code and meta.get("countryCode"):
                        h_obj.country_code = meta.get("countryCode")
                    if not h_obj.city and meta.get("city"):
                        h_obj.city = meta.get("city")
                    if not h_obj.region_code and meta.get("regionName"):
                        h_obj.region_code = meta.get("regionName")
                    if h_obj.latitude is None and meta.get("lat") is not None:
                        h_obj.latitude = meta.get("lat")
                    if h_obj.longitude is None and meta.get("lon") is not None:
                        h_obj.longitude = meta.get("lon")
                    if "BGP/RDAP Enrichment" not in h_obj.sources:
                        h_obj.sources.append("BGP/RDAP Enrichment")

        # ----------------------------------------------------
        # Stage 2: Threat Intelligence & Vulnerability Enrichment (NVD, EPSS, CISA KEV)
        # ----------------------------------------------------
        enriched_vulns: Dict[str, VulnerabilityData] = {}
        if all_unique_cves and "nvd" in active_mod_names:
            self._notify("nvd", f"Enriching {len(all_unique_cves)} CVEs with NVD, EPSS & CISA KEV...")
            nvd_mod: NVDModule = self.modules["nvd"]  # type: ignore
            await nvd_mod._ensure_cisa_kev_loaded()

            nvd_tasks = [nvd_mod.enrich_cve(cve) for cve in all_unique_cves]
            nvd_results = await asyncio.gather(*nvd_tasks, return_exceptions=True)

            for cve, vdata in zip(all_unique_cves, nvd_results):
                if isinstance(vdata, Exception):
                    logger.warning(f"Failed to enrich {cve}: {vdata}")
                elif isinstance(vdata, VulnerabilityData):
                    enriched_vulns[cve] = vdata

        # ----------------------------------------------------
        # Stage 3: Exploit & PoC Intelligence (ExploitDB + GitHub)
        # ----------------------------------------------------
        if all_unique_cves and "exploitdb" in active_mod_names:
            self._notify("exploitdb", f"Hunting exploits & GitHub PoCs for {len(all_unique_cves)} CVEs...")
            xdb_mod: ExploitDBModule = self.modules["exploitdb"]  # type: ignore
            xdb_tasks = [xdb_mod.get_exploits_for_cve(cve) for cve in all_unique_cves]
            xdb_results = await asyncio.gather(*xdb_tasks, return_exceptions=True)

            for cve, exps in zip(all_unique_cves, xdb_results):
                if isinstance(exps, list) and cve in enriched_vulns:
                    enriched_vulns[cve].exploits = exps

        # ----------------------------------------------------
        # Stage 4: Attach Enriched Vulnerabilities to Specific Hosts
        # ----------------------------------------------------
        for host_ip, host_obj in hosts_map.items():
            cves_for_this_host = host_cves_map.get(host_ip, set())
            host_vulns: List[VulnerabilityData] = []

            for cve in sorted(cves_for_this_host):
                if cve in enriched_vulns:
                    vdata = enriched_vulns[cve]
                    # Apply CVSS filter if requested
                    if cvss_filter:
                        if vdata.cvss_severity != cvss_filter.upper():
                            continue
                    host_vulns.append(vdata)

            # Sort host vulns by CVSS score descending
            host_vulns.sort(key=lambda x: (x.cvss_score or 0.0), reverse=True)
            host_obj.vulnerabilities = host_vulns

        # ----------------------------------------------------
        # Stage 5: Compile Final Findings & Output
        # ----------------------------------------------------
        final_findings: List[Finding] = []
        final_findings.extend(domain_findings)

        for host_ip, host_obj in hosts_map.items():
            host_sources_str = ", ".join(host_obj.sources) if host_obj.sources else "Recon"

            # Host finding
            final_findings.append(
                Finding(
                    type=FindingType.HOST_INFO,
                    target=target,
                    value=host_ip,
                    source=host_sources_str,
                    host_ip=host_ip,
                    host_info=HostInfoData(
                        ip=host_ip,
                        hostnames=host_obj.hostnames,
                        domains=host_obj.domains,
                        org=host_obj.org,
                        isp=host_obj.isp,
                        asn=host_obj.asn,
                        os=host_obj.os,
                        country_name=host_obj.country_name,
                        city=host_obj.city,
                        region_code=host_obj.region_code,
                        postal_code=host_obj.postal_code,
                        latitude=host_obj.latitude,
                        longitude=host_obj.longitude,
                        ports=[p.port for p in host_obj.ports],
                        vulns=[v.cve_id for v in host_obj.vulnerabilities],
                    ),
                )
            )

            # Port findings with combined sources
            for p in host_obj.ports:
                port_sources_str = ", ".join(dict.fromkeys(p.sources)) if p.sources else host_sources_str
                final_findings.append(
                    Finding(
                        type=FindingType.OPEN_PORT,
                        target=target,
                        value=f"{host_ip}:{p.port}",
                        source=port_sources_str,
                        host_ip=host_ip,
                        port_info=p,
                    )
                )

            # Vulnerability findings attached to this host
            for v in host_obj.vulnerabilities:
                final_findings.append(
                    Finding(
                        type=FindingType.VULNERABILITY,
                        target=target,
                        value=v.cve_id,
                        source="NVD+EPSS+CISA",
                        host_ip=host_ip,
                        vulnerability=v,
                    )
                )
                for exp in v.exploits:
                    final_findings.append(
                        Finding(
                            type=FindingType.EXPLOIT,
                            target=target,
                            value=f"{v.cve_id} - {exp.title}",
                            source=exp.source,
                            host_ip=host_ip,
                            exploit=exp,
                        )
                    )

        # Standalone CVE scan without hosts
        if not hosts_map and target_type == "cve":
            for cve, vdata in enriched_vulns.items():
                if cvss_filter and vdata.cvss_severity != cvss_filter.upper():
                    continue
                final_findings.append(
                    Finding(
                        type=FindingType.VULNERABILITY,
                        target=target,
                        value=cve,
                        source="NVD+EPSS+CISA",
                        vulnerability=vdata,
                    )
                )
                for exp in vdata.exploits:
                    final_findings.append(
                        Finding(
                            type=FindingType.EXPLOIT,
                            target=target,
                            value=f"{cve} - {exp.title}",
                            source=exp.source,
                            exploit=exp,
                        )
                    )

        result.hosts = list(hosts_map.values())
        result.findings = final_findings
        result.warnings = list(dict.fromkeys(context.get("warnings", [])))
        result.completed_at = datetime.now(timezone.utc)
        result.elapsed_seconds = time.monotonic() - start_time
        result.calculate_summary()

        self._notify("engine", f"Scan completed in {result.elapsed_seconds:.2f}s with {len(result.hosts)} hosts and {len(result.findings)} findings.")
        return result

    async def _scan_file(
        self,
        file_path: str,
        enabled_modules: Optional[List[str]],
        cvss_filter: Optional[str],
    ) -> ScanResult:
        """Process file containing targets line-by-line with pre-flight check executed once and live progress."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Input file not found: {file_path}")

        lines = [line.strip() for line in path.read_text().splitlines() if line.strip() and not line.startswith("#")]
        total = len(lines)
        self._notify("engine", f"Loaded {total} targets from {file_path}")

        active_mod_names = (
            [m for m in enabled_modules if m in self.modules]
            if enabled_modules and "all" not in enabled_modules
            else list(self.modules.keys())
        )

        # Pre-flight API verification layer: validate all APIs once for the batch
        self._notify("engine", "Verifying environment API credentials and endpoints...")
        api_statuses = await self.verify_environment_apis(active_mod_names)
        for mod, info in api_statuses.items():
            if info.get("configured") and not info.get("valid"):
                self._notify(mod, f"{info.get('name')}: {info.get('status')}")

        combined_result = ScanResult(
            target=file_path,
            target_type="file",
            started_at=datetime.now(timezone.utc),
            modules_run=enabled_modules or list(self.MODULE_REGISTRY.keys()),
        )

        all_findings: List[Finding] = []
        all_hosts: List[HostResult] = []
        all_warnings: List[str] = []

        for idx, line in enumerate(lines, 1):
            self._notify("engine", f"Processing target [{idx}/{total}]: {line}")
            sub_res = await self.scan(
                line,
                enabled_modules=enabled_modules,
                cvss_filter=cvss_filter,
                skip_preflight=True,
            )
            all_findings.extend(sub_res.findings)
            all_hosts.extend(sub_res.hosts)
            all_warnings.extend(sub_res.warnings)

        combined_result.hosts = all_hosts
        combined_result.findings = all_findings
        combined_result.warnings = list(dict.fromkeys(all_warnings))
        combined_result.completed_at = datetime.now(timezone.utc)
        combined_result.elapsed_seconds = (combined_result.completed_at - combined_result.started_at).total_seconds()
        combined_result.calculate_summary()
        self._notify("engine", f"Batch scan finished: processed {total} targets with {len(all_findings)} findings.")
        return combined_result


# Alias for backward compatibility and clean branding
DetectIEngine = ThreatTrackEngine

