"""SQLite storage manager for DetecTI-CLI EASM data persistence."""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from detecti.core.models import (
    CISAKEVData,
    EPSSData,
    ExploitData,
    Finding,
    FindingType,
    HostResult,
    PortData,
    ScanResult,
    SeverityLevel,
    VulnerabilityData,
)
from .schema import SCHEMA_SQL


def _is_in_scope(hostname: str, target_scopes: Set[str]) -> bool:
    if not hostname or not target_scopes:
        return True
    h = str(hostname).strip().lower()
    if h.startswith("*."):
        h = h[2:]
    if h.startswith("http://"):
        h = h[7:]
    elif h.startswith("https://"):
        h = h[8:]
    if "/" in h:
        h = h.split("/")[0]
    if ":" in h:
        h = h.split(":")[0]
    
    for scope in target_scopes:
        s = str(scope).strip().lower()
        if s.startswith("*."):
            s = s[2:]
        if s.startswith("http://"):
            s = s[7:]
        elif s.startswith("https://"):
            s = s[8:]
        if "/" in s:
            s = s.split("/")[0]
        if ":" in s:
            s = s.split(":")[0]
        
        if h == s or h.endswith(f".{s}"):
            return True
    return False


class DatabaseManager:
    """Manages SQLite database operations for EASM scan results."""

    def __init__(self, db_path: Path):
        """Initialize database manager with path to SQLite file."""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    def _init_database(self) -> None:
        """Initialize database schema if it doesn't exist and run schema migrations."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(SCHEMA_SQL)
            
            # Auto-migrate: ensure source column exists in vulnerabilities table
            try:
                cols = [row[1] for row in conn.execute("PRAGMA table_info(vulnerabilities)").fetchall()]
                if "source" not in cols:
                    conn.execute("ALTER TABLE vulnerabilities ADD COLUMN source TEXT")
            except Exception:
                pass

            # Auto-migrate: ensure postal_code, latitude, longitude exist in ip_addresses table
            try:
                ip_cols = [row[1] for row in conn.execute("PRAGMA table_info(ip_addresses)").fetchall()]
                if "postal_code" not in ip_cols:
                    conn.execute("ALTER TABLE ip_addresses ADD COLUMN postal_code TEXT")
                if "latitude" not in ip_cols:
                    conn.execute("ALTER TABLE ip_addresses ADD COLUMN latitude REAL")
                if "longitude" not in ip_cols:
                    conn.execute("ALTER TABLE ip_addresses ADD COLUMN longitude REAL")
            except Exception:
                pass

            # Auto-migrate: ensure metadata column exists in subdomains table for WAF bypass tags
            try:
                sub_cols = [row[1] for row in conn.execute("PRAGMA table_info(subdomains)").fetchall()]
                if "metadata" not in sub_cols:
                    conn.execute("ALTER TABLE subdomains ADD COLUMN metadata TEXT")
            except Exception:
                pass

            # Auto-clean: deduplicate any existing redundant services per (ip_id, port, protocol)
            self._deduplicate_services(conn)
                
            conn.commit()

    def _deduplicate_services(self, conn: sqlite3.Connection) -> None:
        """Merge and clean up duplicate service entries for the same (ip_id, port, protocol)."""
        try:
            duplicates = conn.execute("""
                SELECT ip_id, port, LOWER(protocol), COUNT(*)
                FROM services
                GROUP BY ip_id, port, LOWER(protocol)
                HAVING COUNT(*) > 1
            """).fetchall()

            for ip_id, port, proto, cnt in duplicates:
                rows = conn.execute("""
                    SELECT id, sources, banner, service_name, product, version, url, ssl
                    FROM services
                    WHERE ip_id = ? AND port = ? AND LOWER(protocol) = ?
                    ORDER BY rowid ASC
                """, (ip_id, port, proto)).fetchall()

                if not rows:
                    continue

                primary_id = rows[0][0]
                merged_sources = set()
                merged_banner = ""
                merged_name = ""
                merged_prod = ""
                merged_ver = ""
                merged_url = ""
                merged_ssl = 0
                dup_ids = [r[0] for r in rows[1:]]

                for r in rows:
                    cur_id, cur_sources_raw, cur_banner, cur_name, cur_prod, cur_ver, cur_url, cur_ssl = r
                    if cur_sources_raw:
                        try:
                            s_list = json.loads(cur_sources_raw)
                            if isinstance(s_list, list):
                                merged_sources.update(s_list)
                            else:
                                merged_sources.add(str(s_list))
                        except Exception:
                            merged_sources.add(cur_sources_raw)
                    if cur_banner and not merged_banner:
                        merged_banner = cur_banner
                    if cur_name and not merged_name and not str(cur_name).startswith("service-"):
                        merged_name = cur_name
                    if cur_prod and not merged_prod:
                        merged_prod = cur_prod
                    if cur_ver and not merged_ver:
                        merged_ver = cur_ver
                    if cur_url and not merged_url:
                        merged_url = cur_url
                    if cur_ssl:
                        merged_ssl = 1

                # Re-link vulnerabilities from duplicate service rows to primary_id
                if dup_ids:
                    placeholders = ",".join("?" for _ in dup_ids)
                    conn.execute(f"UPDATE vulnerabilities SET service_id = ? WHERE service_id IN ({placeholders})", [primary_id] + dup_ids)
                    conn.execute(f"DELETE FROM services WHERE id IN ({placeholders})", dup_ids)

                conn.execute("""
                    UPDATE services
                    SET sources = ?, banner = ?, service_name = ?, product = ?, version = ?, url = ?, ssl = ?
                    WHERE id = ?
                """, (
                    json.dumps(sorted(list(merged_sources))) if merged_sources else None,
                    merged_banner,
                    merged_name or f"service-{port}",
                    merged_prod,
                    merged_ver,
                    merged_url,
                    merged_ssl,
                    primary_id
                ))
        except Exception:
            pass

    def _get_or_create_domain(self, conn: sqlite3.Connection, domain_name: str) -> str:
        """Get existing domain ID or create new domain record."""
        cursor = conn.execute("SELECT id FROM domains WHERE name = ?", (domain_name,))
        row = cursor.fetchone()
        if row:
            return row[0]
        
        domain_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO domains (id, name) VALUES (?, ?)",
            (domain_id, domain_name)
        )
        return domain_id

    def _get_or_create_ip(self, conn: sqlite3.Connection, host: HostResult) -> str:
        """Get existing IP ID or create new IP record."""
        cursor = conn.execute("SELECT id FROM ip_addresses WHERE ip = ?", (host.ip,))
        row = cursor.fetchone()
        if row:
            # Update existing record with new metadata
            conn.execute("""
                UPDATE ip_addresses 
                SET asn = COALESCE(?, asn), 
                    org = COALESCE(?, org),
                    country = COALESCE(?, country),
                    city = COALESCE(?, city),
                    region_code = COALESCE(?, region_code),
                    postal_code = COALESCE(?, postal_code),
                    latitude = COALESCE(?, latitude),
                    longitude = COALESCE(?, longitude)
                WHERE ip = ?
            """, (host.asn, host.org, host.country_name, host.city, host.region_code, host.postal_code, host.latitude, host.longitude, host.ip))
            return row[0]
        
        ip_id = str(uuid.uuid4())
        conn.execute("""
            INSERT INTO ip_addresses (id, ip, asn, org, country, city, region_code, postal_code, latitude, longitude)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip_id, host.ip, host.asn, host.org, host.country_name, host.city, host.region_code, host.postal_code, host.latitude, host.longitude))
        return ip_id

    def _store_subdomains(
        self,
        conn: sqlite3.Connection,
        findings: List[Finding],
        target_scopes: Optional[Set[str]] = None,
        hosts: Optional[List[HostResult]] = None,
    ) -> Dict[str, str]:
        """Store subdomain findings in database and return subdomain_name -> subdomain_id mapping."""
        subdomain_map = {}
        
        # Helper to register any candidate subdomain
        def _register_subdomain_candidate(raw_name: str, meta: Optional[Dict] = None) -> None:
            if not raw_name:
                return
            cand = raw_name.strip().lower()
            
            # Sanitize URL artifacts into pure FQDNs
            if cand.startswith("http://"):
                cand = cand[7:]
            elif cand.startswith("https://"):
                cand = cand[8:]
            if "/" in cand:
                cand = cand.split("/")[0]
            if ":" in cand:
                if cand.startswith("[") and "]" in cand:
                    cand = cand.split("]")[0][1:]
                elif cand.count(":") == 1:
                    cand = cand.split(":")[0]
                    
            if cand.startswith("*."):
                cand = cand[2:]
            
            if target_scopes and not _is_in_scope(cand, target_scopes):
                return

            if '.' in cand and ' ' not in cand and not cand.replace('.', '').isdigit():
                try:
                    import tldextract
                    ext = tldextract.extract(cand)
                    domain = ext.registered_domain if ext.registered_domain else '.'.join(cand.split('.')[-2:])
                except Exception:
                    parts = cand.split('.')
                    domain = '.'.join(parts[-2:]) if len(parts) >= 2 else cand
                
                if domain:
                    if target_scopes and not _is_in_scope(domain, target_scopes):
                        return

                    domain_id = self._get_or_create_domain(conn, domain)
                    
                    cursor = conn.execute(
                        "SELECT id FROM subdomains WHERE domain_id = ? AND name = ?",
                        (domain_id, cand)
                    )
                    row = cursor.fetchone()
                    if row:
                        subdomain_id = row[0]
                    else:
                        subdomain_id = str(uuid.uuid4())
                        conn.execute("""
                            INSERT INTO subdomains (id, domain_id, name)
                            VALUES (?, ?, ?)
                        """, (subdomain_id, domain_id, cand))
                    
                    if meta:
                        try:
                            meta_json = json.dumps(meta)
                            conn.execute("UPDATE subdomains SET metadata = ? WHERE id = ?", (meta_json, subdomain_id))
                        except Exception:
                            pass

                    subdomain_map[cand] = subdomain_id

        # 1. Register subdomains from FindingType.SUBDOMAIN, ASSOCIATED_DOMAIN and targets
        for finding in findings:
            if finding.type in (FindingType.SUBDOMAIN, FindingType.ASSOCIATED_DOMAIN) and finding.value:
                _register_subdomain_candidate(finding.value, finding.metadata)
            if finding.target:
                _register_subdomain_candidate(finding.target)
            if finding.type == FindingType.HOST_INFO and finding.host_info:
                for hname in finding.host_info.hostnames:
                    _register_subdomain_candidate(hname)
                for dname in finding.host_info.domains:
                    _register_subdomain_candidate(dname)

        # 2. Register subdomains from hosts.hostnames and hosts.domains
        if hosts:
            for host in hosts:
                if host.hostnames:
                    for hname in host.hostnames:
                        _register_subdomain_candidate(hname, host.metadata if host.metadata.get("waf_bypassed_domains") and hname in host.metadata["waf_bypassed_domains"] else None)
                if host.domains:
                    for dname in host.domains:
                        _register_subdomain_candidate(dname, host.metadata if host.metadata.get("waf_bypassed_domains") and dname in host.metadata["waf_bypassed_domains"] else None)
        
        return subdomain_map

    def _store_services(self, conn: sqlite3.Connection, ip_id: str, host: HostResult) -> Dict[str, str]:
        """Store services for a host and return service_id mapping with strict deduplication."""
        service_ids = {}
        seen_ports = set()
        
        for port in host.ports:
            port_key = (port.port, (port.transport or "tcp").lower())
            if port_key in seen_ports:
                continue
            seen_ports.add(port_key)
            
            # Check if this service already exists for this IP
            cursor = conn.execute("""
                SELECT id, sources, banner, service_name, product, version, url, ssl 
                FROM services 
                WHERE ip_id = ? AND port = ? AND LOWER(protocol) = LOWER(?)
            """, (ip_id, port.port, port.transport or "tcp"))
            existing = cursor.fetchone()
            
            if existing:
                service_id, cur_sources_raw, cur_banner, cur_name, cur_prod, cur_ver, cur_url, cur_ssl = existing
                merged_sources = set()
                if cur_sources_raw:
                    try:
                        p_sources = json.loads(cur_sources_raw)
                        if isinstance(p_sources, list):
                            merged_sources.update(p_sources)
                        else:
                            merged_sources.add(str(p_sources))
                    except Exception:
                        merged_sources.add(cur_sources_raw)
                if port.sources:
                    merged_sources.update(port.sources)
                
                new_banner = port.banner if port.banner else (cur_banner or "")
                new_name = port.service if (port.service and not str(port.service).startswith("service-")) else (cur_name or "")
                new_prod = port.product if port.product else (cur_prod or "")
                new_ver = port.version if port.version else (cur_ver or "")
                new_url = port.url if port.url else (cur_url or "")
                new_ssl = 1 if (port.ssl or cur_ssl) else 0
                
                conn.execute("""
                    UPDATE services
                    SET sources = ?, banner = ?, service_name = ?, product = ?, version = ?, url = ?, ssl = ?
                    WHERE id = ?
                """, (json.dumps(sorted(list(merged_sources))), new_banner, new_name, new_prod, new_ver, new_url, new_ssl, service_id))
            else:
                service_id = str(uuid.uuid4())
                sources_json = json.dumps(port.sources) if port.sources else None
                conn.execute("""
                    INSERT INTO services (id, ip_id, port, protocol, service_name, product, version, banner, url, ssl, sources)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    service_id, ip_id, port.port, port.transport, port.service,
                    port.product, port.version, port.banner, port.url, port.ssl, sources_json
                ))
            
            service_ids[f"{port.port}/{port.transport}"] = service_id
            service_ids[f"{port.port}"] = service_id
        
        return service_ids

    def _store_vulnerabilities(self, conn: sqlite3.Connection, ip_id: str, host: HostResult, service_ids: Dict[str, str]) -> None:
        """Store vulnerabilities for a host, linking to services when possible."""
        for vuln in host.vulnerabilities:
            vuln_id = str(uuid.uuid4())
            
            # Serialize CISA KEV data if present
            cisa_kev_json = None
            if vuln.cisa_kev:
                cisa_kev_json = json.dumps(vuln.cisa_kev.model_dump())
            
            # Get EPSS data
            epss_score = vuln.epss.epss_score if vuln.epss else None
            epss_percentile = vuln.epss.epss_percentile if vuln.epss else None
            
            # Try to associate vulnerability with a specific service
            # This creates the HOST -> Service -> Vulnerability relationship
            service_id = None
            
            # Look for service associations based on vulnerability metadata
            # This could be enhanced with more sophisticated matching logic
            if hasattr(vuln, 'metadata') and vuln.metadata:
                # Check if vulnerability metadata contains port information
                vuln_port = vuln.metadata.get('port')
                if vuln_port:
                    # Find matching service by port
                    for port_key, sid in service_ids.items():
                        if str(vuln_port) in port_key:
                            service_id = sid
                            break
            
            # If no specific service match, try to associate with common vulnerable services
            if not service_id and service_ids:
                # For web vulnerabilities, associate with HTTP/HTTPS services
                if any(keyword in (vuln.description or "").lower() for keyword in ["web", "http", "ssl", "tls", "apache", "nginx", "iis"]):
                    # Find HTTP/HTTPS service
                    for port_key, sid in service_ids.items():
                        if any(port in port_key for port in ["80/", "443/", "8080/", "8443/"]):
                            service_id = sid
                            break
                
                # For SSH vulnerabilities, associate with SSH service
                elif any(keyword in (vuln.description or "").lower() for keyword in ["ssh", "openssh"]):
                    for port_key, sid in service_ids.items():
                        if "22/" in port_key:
                            service_id = sid
                            break
                
                # For other cases, associate with the first available service if only one exists
                elif len(service_ids) == 1:
                    service_id = list(service_ids.values())[0]
            
            # Serialize exploit data if present
            exploits_json = None
            if vuln.exploits:
                exploits_json = json.dumps([exp.model_dump() for exp in vuln.exploits])
            
            # Get CVSS score and severity
            cvss_score = getattr(vuln, 'cvss_score', None)
            cvss_version = getattr(vuln, 'cvss_version', None)
            severity = vuln.cvss_severity.value if hasattr(getattr(vuln, 'cvss_severity', None), 'value') else str(getattr(vuln, 'cvss_severity', 'UNKNOWN'))
            cwe_id = getattr(vuln, 'cwe_id', None)
            cwe_name = getattr(vuln, 'cwe_name', None)
            is_cisa_kev = getattr(vuln, 'in_cisa_kev', False)
            source = getattr(vuln, 'source', None) or "Unknown"
            
            conn.execute("""
                INSERT INTO vulnerabilities (
                    id, service_id, ip_id, cve_id, severity, cvss_score, cvss_version,
                    description, cwe_id, cwe_name, epss_score, epss_percentile,
                    is_cisa_kev, cisa_kev_data, source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                vuln_id, service_id, ip_id, vuln.cve_id, severity, cvss_score, cvss_version,
                vuln.description, cwe_id, cwe_name, epss_score, epss_percentile,
                is_cisa_kev, cisa_kev_json, source
            ))
            
            # Store individual exploits in the exploits table for detailed querying
            if vuln.exploits:
                for exp in vuln.exploits:
                    exploit_id = str(uuid.uuid4())
                    conn.execute("""
                        INSERT INTO exploits (id, vulnerability_id, title, source, url, verified, author, date, exploit_type)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        exploit_id, vuln_id, exp.title, exp.source, exp.url,
                        getattr(exp, 'verified', False), getattr(exp, 'author', None),
                        getattr(exp, 'date', None), getattr(exp, 'exploit_type', None)
                    ))

    def save_scan_result(self, result: ScanResult) -> None:
        """Save a complete ScanResult into the SQLite database."""
        with sqlite3.connect(self.db_path) as conn:
            # Store scan metadata
            modules_json = json.dumps(result.modules_run)
            conn.execute("""
                INSERT INTO scan_results (
                    id, target, target_type, started_at, completed_at, elapsed_seconds,
                    modules_run, total_findings, total_hosts
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.scan_id, result.target, result.target_type,
                result.started_at.isoformat(), 
                result.completed_at.isoformat() if result.completed_at else None,
                result.elapsed_seconds, modules_json, len(result.findings), len(result.hosts)
            ))
            
            # Determine in-scope target roots
            target_scopes: Set[str] = set()
            clean_target = result.target.strip().lower()
            if clean_target.startswith("http://"):
                clean_target = clean_target[7:]
            elif clean_target.startswith("https://"):
                clean_target = clean_target[8:]
            if "/" in clean_target:
                clean_target = clean_target.split("/")[0]
            if ":" in clean_target:
                clean_target = clean_target.split(":")[0]

            if result.target_type == "domain":
                try:
                    import tldextract
                    ext = tldextract.extract(clean_target)
                    if ext.registered_domain:
                        target_scopes.add(ext.registered_domain.lower())
                except Exception:
                    pass
                target_scopes.add(clean_target)
            elif result.target_type == "file":
                from pathlib import Path
                fpath = Path(result.target)
                if fpath.exists() and fpath.is_file():
                    for line in fpath.read_text().splitlines():
                        l_clean = line.strip().lower()
                        if l_clean and not l_clean.startswith("#"):
                            if l_clean.startswith("http://"):
                                l_clean = l_clean[7:]
                            elif l_clean.startswith("https://"):
                                l_clean = l_clean[8:]
                            if "/" in l_clean:
                                l_clean = l_clean.split("/")[0]
                            if ":" in l_clean:
                                l_clean = l_clean.split(":")[0]
                            if "." in l_clean and not l_clean.replace(".", "").isdigit():
                                try:
                                    import tldextract
                                    ext = tldextract.extract(l_clean)
                                    if ext.registered_domain:
                                        target_scopes.add(ext.registered_domain.lower())
                                except Exception:
                                    pass
                                target_scopes.add(l_clean)

            if not target_scopes:
                for f in result.findings:
                    if f.type == FindingType.SUBDOMAIN and f.value:
                        try:
                            import tldextract
                            ext = tldextract.extract(f.value)
                            if ext.registered_domain:
                                target_scopes.add(ext.registered_domain.lower())
                        except Exception:
                            pass

            # Store subdomain findings and get mapping
            subdomain_map = self._store_subdomains(conn, result.findings, target_scopes, result.hosts)
            
            # Store host data
            ip_map = {}  # ip -> ip_id mapping
            for host in result.hosts:
                ip_id = self._get_or_create_ip(conn, host)
                ip_map[host.ip] = ip_id
                
                service_ids = self._store_services(conn, ip_id, host)
                self._store_vulnerabilities(conn, ip_id, host, service_ids)

                # Link all hostnames associated with this host to the IP
                if host.hostnames:
                    for hname in host.hostnames:
                        hname_clean = hname.strip().lower()
                        if hname_clean.startswith("*."):
                            hname_clean = hname_clean[2:]
                        if hname_clean in subdomain_map:
                            conn.execute("""
                                INSERT OR IGNORE INTO subdomain_ips (subdomain_id, ip_id)
                                VALUES (?, ?)
                            """, (subdomain_map[hname_clean], ip_id))
            
            # Map specific authoritative DNS resolutions & finding associations (subdomain -> IP)
            for finding in result.findings:
                hip = finding.host_ip or (finding.host_info.ip if finding.host_info else None)
                if hip and hip in ip_map:
                    target_ip_id = ip_map[hip]

                    # 1. Authoritative hostnames tied to this specific host finding
                    if finding.host_info and finding.host_info.hostnames:
                        for hname in finding.host_info.hostnames:
                            hname_clean = hname.strip().lower()
                            if hname_clean.startswith("*."):
                                hname_clean = hname_clean[2:]
                            if hname_clean in subdomain_map:
                                conn.execute("""
                                    INSERT OR IGNORE INTO subdomain_ips (subdomain_id, ip_id)
                                    VALUES (?, ?)
                                """, (subdomain_map[hname_clean], target_ip_id))
                    
                    # 2. Subdomain finding with explicit host_ip
                    if finding.type == FindingType.SUBDOMAIN and finding.value and finding.host_ip == hip:
                        sub_val = finding.value.strip().lower()
                        if sub_val.startswith("*."):
                            sub_val = sub_val[2:]
                        if sub_val in subdomain_map:
                            conn.execute("""
                                INSERT OR IGNORE INTO subdomain_ips (subdomain_id, ip_id)
                                VALUES (?, ?)
                            """, (subdomain_map[sub_val], target_ip_id))

            conn.commit()

    def store_scan_result(self, result: ScanResult) -> None:
        """Alias for save_scan_result."""
        self.save_scan_result(result)

    def get_summary_stats(self) -> Dict[str, int]:
        """Get summary statistics for the database."""
        with sqlite3.connect(self.db_path) as conn:
            stats = {}
            
            try:
                # Get target from scan results
                cursor = conn.execute("SELECT target FROM scan_results ORDER BY created_at DESC LIMIT 1")
                row = cursor.fetchone()
                if row:
                    stats['target'] = row[0]
            except Exception:
                stats['target'] = "Unknown"
            
            try:
                # Count domains and subdomains
                cursor = conn.execute("SELECT COUNT(*) FROM domains")
                stats['total_domains'] = cursor.fetchone()[0]
            except Exception:
                stats['total_domains'] = 0
            
            try:
                cursor = conn.execute("SELECT COUNT(*) FROM subdomains")
                stats['total_subdomains'] = cursor.fetchone()[0]
            except Exception:
                stats['total_subdomains'] = 0
            
            try:
                # Count IPs and services
                cursor = conn.execute("SELECT COUNT(*) FROM ip_addresses")
                stats['total_ips'] = cursor.fetchone()[0]
            except Exception:
                stats['total_ips'] = 0
            
            try:
                cursor = conn.execute("SELECT COUNT(*) FROM services")
                stats['open_services'] = cursor.fetchone()[0]
            except Exception:
                stats['open_services'] = 0
            
            try:
                # Count verified active services (strictly requiring active verification like Masscan/Nuclei/Active)
                cursor = conn.execute("SELECT sources FROM services")
                verified_count = 0
                for (s_raw,) in cursor.fetchall():
                    s_list = []
                    if s_raw:
                        try:
                            s_list = json.loads(s_raw)
                            if not isinstance(s_list, list):
                                s_list = [str(s_list)]
                        except Exception:
                            s_list = [s_raw]
                    is_active = any(
                        isinstance(s, str) and ("masscan" in s.lower() or "active" in s.lower() or "nuclei" in s.lower())
                        for s in s_list
                    )
                    if is_active:
                        verified_count += 1
                stats['verified_services'] = verified_count
            except Exception:
                stats['verified_services'] = 0
            
            try:
                # Count unique vulnerabilities by CVE ID
                cursor = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM vulnerabilities")
                stats['total_vulnerabilities'] = cursor.fetchone()[0]
            except Exception:
                stats['total_vulnerabilities'] = 0
            
            try:
                cursor = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM vulnerabilities WHERE is_cisa_kev = 1")
                stats['cisa_kev_count'] = cursor.fetchone()[0]
            except Exception:
                stats['cisa_kev_count'] = 0
            
            try:
                cursor = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM vulnerabilities WHERE epss_score > 0.5")
                stats['high_epss_count'] = cursor.fetchone()[0]
            except Exception:
                stats['high_epss_count'] = 0
            
            return stats

    def reconstruct_scan_result(self) -> Optional[ScanResult]:
        """Reconstruct a complete ScanResult model from the database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Fetch scan metadata
            scan_row = conn.execute("SELECT * FROM scan_results ORDER BY created_at DESC LIMIT 1").fetchone()
            if not scan_row:
                # Check if there are ip_addresses or domains to construct a basic scan
                first_ip = conn.execute("SELECT ip FROM ip_addresses LIMIT 1").fetchone()
                first_domain = conn.execute("SELECT name FROM domains LIMIT 1").fetchone()
                target = first_domain['name'] if first_domain else (first_ip['ip'] if first_ip else "unknown")
                target_type = "domain" if first_domain else "ip"
                scan_id = str(uuid.uuid4())
                started_at = datetime.now(timezone.utc)
                completed_at = started_at
                elapsed_seconds = 0.0
                modules_run = []
            else:
                target = scan_row['target']
                target_type = scan_row['target_type']
                scan_id = scan_row['id']
                try:
                    started_at = datetime.fromisoformat(scan_row['started_at'])
                except Exception:
                    started_at = datetime.now(timezone.utc)
                try:
                    completed_at = datetime.fromisoformat(scan_row['completed_at']) if scan_row['completed_at'] else None
                except Exception:
                    completed_at = None
                elapsed_seconds = scan_row['elapsed_seconds'] or 0.0
                try:
                    modules_run = json.loads(scan_row['modules_run']) if scan_row['modules_run'] else []
                except Exception:
                    modules_run = []

            # Fetch Hosts
            hosts = []
            ip_rows = conn.execute("SELECT * FROM ip_addresses").fetchall()
            for ip_row in ip_rows:
                ip_id = ip_row['id']
                ip_addr = ip_row['ip']

                # Hostnames
                hostnames = [r[0] for r in conn.execute("""
                    SELECT s.name FROM subdomains s
                    JOIN subdomain_ips si ON s.id = si.subdomain_id
                    WHERE si.ip_id = ?
                """, (ip_id,)).fetchall()]

                # Domains
                domains = [r[0] for r in conn.execute("""
                    SELECT DISTINCT d.name FROM domains d
                    JOIN subdomains s ON d.id = s.domain_id
                    JOIN subdomain_ips si ON s.id = si.subdomain_id
                    WHERE si.ip_id = ?
                """, (ip_id,)).fetchall()]

                # Services
                ports = []
                service_rows = conn.execute("SELECT * FROM services WHERE ip_id = ?", (ip_id,)).fetchall()
                for s_row in service_rows:
                    sources = []
                    if s_row['sources']:
                        try:
                            sources = json.loads(s_row['sources'])
                        except Exception:
                            sources = [s_row['sources']]
                    
                    ports.append(PortData(
                        port=s_row['port'],
                        transport=s_row['protocol'] or 'tcp',
                        service=s_row['service_name'],
                        product=s_row['product'],
                        version=s_row['version'],
                        banner=s_row['banner'],
                        url=s_row['url'],
                        ssl=bool(s_row['ssl']),
                        sources=sources
                    ))

                # Vulnerabilities
                vulns = []
                vuln_rows = conn.execute("SELECT * FROM vulnerabilities WHERE ip_id = ?", (ip_id,)).fetchall()
                for v_row in vuln_rows:
                    exploits = []
                    exp_rows = conn.execute("SELECT * FROM exploits WHERE vulnerability_id = ?", (v_row['id'],)).fetchall()
                    for e_row in exp_rows:
                        exploits.append(ExploitData(
                            title=e_row['title'],
                            source=e_row['source'],
                            url=e_row['url'],
                            verified=bool(e_row['verified']),
                            author=e_row['author'],
                            date=e_row['date'],
                            exploit_type=e_row['exploit_type']
                        ))

                    cisa_kev = None
                    if v_row['cisa_kev_data']:
                        try:
                            cisa_kev = CISAKEVData(**json.loads(v_row['cisa_kev_data']))
                        except Exception:
                            cisa_kev = CISAKEVData(in_cisa_kev=True)
                    elif v_row['is_cisa_kev']:
                        cisa_kev = CISAKEVData(in_cisa_kev=True)

                    epss = None
                    if v_row['epss_score'] is not None:
                        epss = EPSSData(
                            epss_score=v_row['epss_score'],
                            epss_percentile=v_row['epss_percentile'] or 0.0
                        )

                    sev_str = v_row['severity'] or "UNKNOWN"
                    sev = SeverityLevel(sev_str) if sev_str in SeverityLevel._value2member_map_ else SeverityLevel.UNKNOWN

                    vulns.append(VulnerabilityData(
                        cve_id=v_row['cve_id'],
                        cvss_score=v_row['cvss_score'],
                        cvss_version=v_row['cvss_version'],
                        cvss_severity=sev,
                        description=v_row['description'],
                        cwe_id=v_row['cwe_id'],
                        cwe_name=v_row['cwe_name'],
                        epss=epss,
                        cisa_kev=cisa_kev,
                        exploits=exploits
                    ))

                hosts.append(HostResult(
                    ip=ip_addr,
                    hostnames=hostnames,
                    domains=domains,
                    org=ip_row['org'],
                    asn=ip_row['asn'],
                    country_name=ip_row['country'],
                    city=ip_row['city'],
                    region_code=ip_row['region_code'],
                    ports=ports,
                    vulnerabilities=vulns
                ))

            # Findings
            findings = []
            for s_row in conn.execute("SELECT name FROM subdomains").fetchall():
                findings.append(Finding(
                    type=FindingType.SUBDOMAIN,
                    target=target,
                    value=s_row['name'],
                    source="recon"
                ))

            result = ScanResult(
                scan_id=scan_id,
                target=target,
                target_type=target_type,
                started_at=started_at,
                completed_at=completed_at,
                elapsed_seconds=elapsed_seconds,
                modules_run=modules_run,
                hosts=hosts,
                findings=findings
            )
            result.calculate_summary()
            return result

    def merge_active_scan_services(self, target: str, open_ports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge Masscan active scan results into the database with deduplication.
        
        - If target is FQDN/domain/subdomain: locates or resolves associated IP(s) and applies open ports.
        - If service exists on the IP: updates sources (appends 'Masscan' to mark as Confirmed Active) and updates banner.
        - If service is new on the IP: creates new service entry with source 'Masscan' (Confirmed Active).
        """
        import uuid
        import json
        import ipaddress
        import socket
        
        added_services = 0
        updated_services = 0
        target = target.strip()
        
        with sqlite3.connect(self.db_path) as conn:
            is_ip = False
            try:
                ipaddress.ip_address(target)
                is_ip = True
            except ValueError:
                is_ip = False

            ip_ids = []
            if is_ip:
                cursor = conn.execute("SELECT id FROM ip_addresses WHERE ip = ?", (target,))
                row = cursor.fetchone()
                if row:
                    ip_ids.append(row[0])
                else:
                    new_ip_id = str(uuid.uuid4())
                    conn.execute("""
                        INSERT INTO ip_addresses (id, ip, org, country, asn)
                        VALUES (?, ?, ?, ?, ?)
                    """, (new_ip_id, target, "Active Target", "Unknown", "Unknown"))
                    ip_ids.append(new_ip_id)
            else:
                # 1. Authoritative DNS resolution for FQDN
                resolved_raw_ips = []
                try:
                    addr_info = socket.getaddrinfo(target, None, socket.AF_UNSPEC)
                    if addr_info:
                        resolved_raw_ips = list(dict.fromkeys([ai[4][0] for ai in addr_info if ai and ai[4]]))
                except Exception:
                    pass

                # 2. Ensure subdomain node exists in database
                sub_row = conn.execute("SELECT id, domain_id FROM subdomains WHERE LOWER(name) = LOWER(?)", (target,)).fetchone()
                if sub_row:
                    sub_id, dom_id = sub_row[0], sub_row[1]
                else:
                    # Find matching parent domain
                    dom_id = None
                    for d_id, d_name in conn.execute("SELECT id, name FROM domains").fetchall():
                        d_clean = d_name.lower().strip()
                        if target.lower() == d_clean or target.lower().endswith(f".{d_clean}"):
                            dom_id = d_id
                            break
                    if not dom_id:
                        dom_id = str(uuid.uuid4())
                        conn.execute("INSERT OR IGNORE INTO domains (id, name) VALUES (?, ?)", (dom_id, target))
                        d_fetch = conn.execute("SELECT id FROM domains WHERE LOWER(name) = LOWER(?)", (target,)).fetchone()
                        if d_fetch:
                            dom_id = d_fetch[0]

                    sub_id = str(uuid.uuid4())
                    conn.execute("INSERT OR IGNORE INTO subdomains (id, domain_id, name) VALUES (?, ?, ?)", (sub_id, dom_id, target))
                    s_fetch = conn.execute("SELECT id FROM subdomains WHERE LOWER(name) = LOWER(?)", (target,)).fetchone()
                    if s_fetch:
                        sub_id = s_fetch[0]

                # 3. For each resolved IP: create IP node if new, and bind RESOLVES_TO via subdomain_ips
                for res_ip in resolved_raw_ips:
                    ip_row = conn.execute("SELECT id FROM ip_addresses WHERE ip = ?", (res_ip,)).fetchone()
                    if ip_row:
                        cur_ip_id = ip_row[0]
                    else:
                        cur_ip_id = str(uuid.uuid4())
                        conn.execute("""
                            INSERT INTO ip_addresses (id, ip, org, country, asn)
                            VALUES (?, ?, ?, ?, ?)
                        """, (cur_ip_id, res_ip, "Active Target", "Unknown", "Unknown"))

                    if cur_ip_id not in ip_ids:
                        ip_ids.append(cur_ip_id)

                    # Ensure direct link between FQDN and IP
                    conn.execute("""
                        INSERT OR IGNORE INTO subdomain_ips (subdomain_id, ip_id)
                        VALUES (?, ?)
                    """, (sub_id, cur_ip_id))

                # 4. If DNS resolution was offline/empty, fallback to any existing database links
                if not ip_ids:
                    sub_cursor = conn.execute("""
                        SELECT ip_addresses.id FROM ip_addresses
                        JOIN subdomain_ips ON subdomain_ips.ip_id = ip_addresses.id
                        JOIN subdomains ON subdomains.id = subdomain_ips.subdomain_id
                        WHERE LOWER(subdomains.name) = LOWER(?)
                    """, (target,))
                    for r in sub_cursor.fetchall():
                        ip_ids.append(r[0])

            # 4. Iterate through discovered ports for each associated IP
            for ip_id in set(ip_ids):
                for p in open_ports:
                    port_num = int(p.get("port", 0))
                    if port_num <= 0:
                        continue
                    proto = (p.get("protocol") or "tcp").lower()
                    service_name = p.get("service_name") or f"service-{port_num}"
                    product = p.get("product") or ""
                    version = p.get("version") or ""
                    banner = p.get("banner") or ""
                    ssl_flag = bool(p.get("ssl", False) or port_num == 443)
                    
                    # Check if this service already exists for this IP
                    s_cursor = conn.execute("""
                        SELECT id, sources, banner, service_name, product, version, ssl 
                        FROM services 
                        WHERE ip_id = ? AND port = ? AND (LOWER(protocol) = LOWER(?) OR protocol IS NULL OR protocol = '')
                    """, (ip_id, port_num, proto))
                    existing_svc = s_cursor.fetchone()
                    
                    if not existing_svc:
                        s_cursor = conn.execute("""
                            SELECT id, sources, banner, service_name, product, version, ssl 
                            FROM services 
                            WHERE ip_id = ? AND port = ?
                        """, (ip_id, port_num))
                        existing_svc = s_cursor.fetchone()
                    
                    if existing_svc:
                        svc_id, cur_sources_raw, cur_banner, cur_name, cur_prod, cur_ver, cur_ssl = existing_svc
                        sources_list = []
                        if cur_sources_raw:
                            try:
                                sources_list = json.loads(cur_sources_raw)
                                if not isinstance(sources_list, list):
                                    sources_list = [str(sources_list)]
                            except Exception:
                                sources_list = [cur_sources_raw]
                        
                        if "Masscan" not in sources_list:
                            sources_list.append("Masscan")
                        
                        # Update banner if active scan discovered a banner (override if new banner found)
                        new_banner = banner if banner else (cur_banner or "")
                        new_name = cur_name if (cur_name and not cur_name.startswith("service-")) else service_name
                        new_prod = product if product else (cur_prod or "")
                        new_ver = version if version else (cur_ver or "")
                        new_ssl = cur_ssl or (1 if ssl_flag else 0)
                        
                        conn.execute("""
                            UPDATE services 
                            SET sources = ?, banner = ?, service_name = ?, product = ?, version = ?, ssl = ?
                            WHERE id = ?
                        """, (json.dumps(sources_list), new_banner, new_name, new_prod, new_ver, new_ssl, svc_id))
                        updated_services += 1
                    else:
                        # Insert new service
                        new_svc_id = str(uuid.uuid4())
                        sources_json = json.dumps(["Masscan"])
                        conn.execute("""
                            INSERT INTO services (id, ip_id, port, protocol, service_name, product, version, banner, ssl, sources)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (new_svc_id, ip_id, port_num, proto, service_name, product, version, banner, 1 if ssl_flag else 0, sources_json))
                        added_services += 1
            
            # 3. Update scan_results metadata if present
            try:
                scan_row = conn.execute("SELECT id, modules_run FROM scan_results ORDER BY started_at DESC LIMIT 1").fetchone()
                if scan_row:
                    scan_id, cur_modules_raw = scan_row
                    modules_list = []
                    if cur_modules_raw:
                        try:
                            modules_list = json.loads(cur_modules_raw)
                            if not isinstance(modules_list, list):
                                modules_list = [str(modules_list)]
                        except Exception:
                            modules_list = [cur_modules_raw]
                    
                    if "masscan" not in modules_list and "Masscan" not in modules_list:
                        modules_list.append("masscan")
                    
                    # Count total services as findings
                    total_svc = conn.execute("SELECT COUNT(*) FROM services").fetchone()[0]
                    total_hosts = conn.execute("SELECT COUNT(*) FROM ip_addresses").fetchone()[0]
                    
                    conn.execute("""
                        UPDATE scan_results 
                        SET modules_run = ?, total_findings = ?, total_hosts = ?, completed_at = ?
                        WHERE id = ?
                    """, (
                        json.dumps(modules_list),
                        total_svc,
                        total_hosts,
                        datetime.now(timezone.utc).isoformat(),
                        scan_id
                    ))
            except Exception as e:
                pass  # Non-fatal if scan_results doesn't exist yet

            conn.commit()
            
        return {
            "target": target,
            "ip": target,
            "added_services": added_services,
            "updated_services": updated_services,
            "total_open": len(open_ports),
        }

    def unverify_services(
        self,
        service_ids: Optional[List[str]] = None,
        ip_addresses: Optional[List[str]] = None,
        all_services: bool = False
    ) -> Dict[str, Any]:
        """Remove Masscan / active verification status from specified services or IPs.
        
        Preserves service metadata, ports, banners, and passive sources so they can be re-validated.
        """
        import json
        unverified_count = 0
        affected_ids = []

        with sqlite3.connect(self.db_path) as conn:
            query = "SELECT id, sources FROM services WHERE 1=1"
            params = []

            if not all_services:
                conditions = []
                if service_ids:
                    id_candidates = set()
                    for s in service_ids:
                        if s:
                            s_str = str(s).strip()
                            id_candidates.add(s_str)
                            if s_str.startswith("srv_"):
                                id_candidates.add(s_str[4:])
                            else:
                                id_candidates.add(f"srv_{s_str}")
                    if id_candidates:
                        placeholders = ",".join("?" for _ in id_candidates)
                        conditions.append(f"id IN ({placeholders})")
                        params.extend(list(id_candidates))

                if ip_addresses:
                    ip_candidates = set()
                    for ip in ip_addresses:
                        if ip:
                            ip_str = str(ip).strip()
                            ip_candidates.add(ip_str)
                            if ip_str.startswith("ip_"):
                                ip_candidates.add(ip_str[3:])
                            else:
                                ip_candidates.add(f"ip_{ip_str}")
                    if ip_candidates:
                        ip_placeholders = ",".join("?" for _ in ip_candidates)
                        conditions.append(f"ip_id IN (SELECT id FROM ip_addresses WHERE ip IN ({ip_placeholders}) OR id IN ({ip_placeholders}))")
                        params.extend(list(ip_candidates))
                        params.extend(list(ip_candidates))
                
                if conditions:
                    query += f" AND ({' OR '.join(conditions)})"
                else:
                    return {"success": True, "unverified_count": 0, "affected_service_ids": []}

            cursor = conn.execute(query, params)
            rows = cursor.fetchall()

            for svc_id, cur_sources_raw in rows:
                sources_list = []
                if cur_sources_raw:
                    try:
                        parsed = json.loads(cur_sources_raw)
                        if isinstance(parsed, list):
                            sources_list = parsed
                        else:
                            sources_list = [str(parsed)]
                    except Exception:
                        sources_list = [cur_sources_raw]
                
                had_masscan = any("masscan" in str(s).lower() or "active" in str(s).lower() for s in sources_list)
                if had_masscan or not sources_list:
                    new_sources = [s for s in sources_list if "masscan" not in str(s).lower() and "active" not in str(s).lower()]
                    if not new_sources:
                        new_sources = ["Passive"]
                    
                    conn.execute("UPDATE services SET sources = ? WHERE id = ?", (json.dumps(new_sources), svc_id))
                    unverified_count += 1
                    affected_ids.append(f"srv_{svc_id}")

            conn.commit()

        return {
            "success": True,
            "unverified_count": unverified_count,
            "affected_service_ids": affected_ids
        }

    def merge_nuclei_findings(
        self,
        findings: List[Dict[str, Any]],
        fallback_ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """Atomically persist or update Nuclei vulnerability findings into SQLite.
        
        - Matches findings with existing IP and Service nodes in database.
        - Updates timestamp / description if vulnerability node already exists (deduplication).
        - Inserts new vulnerability records with correct severity, CVSS, and EPSS metrics.
        - Inserts PoC/references into exploits table.
        """
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database {self.db_path} does not exist.")

        added_vulns = 0
        updated_vulns = 0

        with sqlite3.connect(self.db_path) as conn:
            # Map IPs to ip_id
            ip_row_map = {row[1]: row[0] for row in conn.execute("SELECT id, ip FROM ip_addresses").fetchall()}
            
            # Map (ip_id, port) to service_id
            service_row_map = {}
            for sid, iid, port, proto in conn.execute("SELECT id, ip_id, port, protocol FROM services").fetchall():
                service_row_map[(iid, port)] = sid
                service_row_map[(iid, f"{port}/{proto}")] = sid

            for f in findings:
                raw_ip = f.get("ip") or fallback_ip or ""
                host = f.get("host") or ""
                port = f.get("port")
                
                # If raw_ip is hostname/url, extract clean IP or try matching
                ip_id = None
                if raw_ip and raw_ip in ip_row_map:
                    ip_id = ip_row_map[raw_ip]
                elif fallback_ip and fallback_ip in ip_row_map:
                    ip_id = ip_row_map[fallback_ip]
                
                if not ip_id:
                    target_candidate = raw_ip or fallback_ip or host
                    if target_candidate:
                        clean_candidate = target_candidate.replace("https://", "").replace("http://", "").split(":")[0].strip()
                        sub_ip_row = conn.execute("""
                            SELECT ip_addresses.id FROM ip_addresses
                            JOIN subdomain_ips ON subdomain_ips.ip_id = ip_addresses.id
                            JOIN subdomains ON subdomains.id = subdomain_ips.subdomain_id
                            WHERE LOWER(subdomains.name) = LOWER(?)
                        """, (clean_candidate,)).fetchone()
                        if sub_ip_row:
                            ip_id = sub_ip_row[0]
                        else:
                            try:
                                addr_info = socket.getaddrinfo(clean_candidate, None, socket.AF_UNSPEC)
                                if addr_info:
                                    res_ip = addr_info[0][4][0]
                                    ip_row = conn.execute("SELECT id FROM ip_addresses WHERE ip = ?", (res_ip,)).fetchone()
                                    if ip_row:
                                        ip_id = ip_row[0]
                                    else:
                                        ip_id = str(uuid.uuid4())
                                        conn.execute("""
                                            INSERT INTO ip_addresses (id, ip, org, country, asn)
                                            VALUES (?, ?, ?, ?, ?)
                                        """, (ip_id, res_ip, "Active Target", "Unknown", "Unknown"))
                                    ip_row_map[res_ip] = ip_id
                                    
                                    # Ensure subdomain and link
                                    s_row = conn.execute("SELECT id FROM subdomains WHERE LOWER(name) = LOWER(?)", (clean_candidate,)).fetchone()
                                    if s_row:
                                        s_id = s_row[0]
                                    else:
                                        s_id = str(uuid.uuid4())
                                        d_row = conn.execute("SELECT id FROM domains LIMIT 1").fetchone()
                                        d_id = d_row[0] if d_row else None
                                        conn.execute("INSERT OR IGNORE INTO subdomains (id, domain_id, name) VALUES (?, ?, ?)", (s_id, d_id, clean_candidate))
                                    conn.execute("INSERT OR IGNORE INTO subdomain_ips (subdomain_id, ip_id) VALUES (?, ?)", (s_id, ip_id))
                            except Exception:
                                pass

                if not ip_id and len(ip_row_map) == 1:
                    ip_id = list(ip_row_map.values())[0]

                # Match service_id if port is known
                service_id = None
                if ip_id and port:
                    service_id = service_row_map.get((ip_id, port))
                    if not service_id:
                        # Try matching just port in services table
                        s_row = conn.execute("SELECT id FROM services WHERE ip_id = ? AND port = ?", (ip_id, port)).fetchone()
                        if s_row:
                            service_id = s_row[0]
                        else:
                            # Create service dynamically so finding is anchored to port
                            new_svc_id = str(uuid.uuid4())
                            conn.execute("""
                                INSERT INTO services (id, ip_id, port, protocol, service_name, ssl, sources)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                            """, (new_svc_id, ip_id, port, "tcp", f"service-{port}", 1 if port == 443 else 0, json.dumps(["Nuclei"])))
                            service_id = new_svc_id
                            service_row_map[(ip_id, port)] = new_svc_id

                    if service_id:
                        # Ensure service sources include active verification
                        svc_row = conn.execute("SELECT sources FROM services WHERE id = ?", (service_id,)).fetchone()
                        if svc_row:
                            cur_sources_raw = svc_row[0]
                            sources_list = []
                            if cur_sources_raw:
                                try:
                                    sources_list = json.loads(cur_sources_raw)
                                    if not isinstance(sources_list, list):
                                        sources_list = [str(sources_list)]
                                except Exception:
                                    sources_list = [cur_sources_raw]
                            if "Nuclei" not in sources_list:
                                sources_list.append("Nuclei")
                                conn.execute("UPDATE services SET sources = ? WHERE id = ?", (json.dumps(sources_list), service_id))

                cve_id = (f.get("cve_id") or f.get("template_id") or "UNKNOWN").strip()
                severity = (f.get("severity") or "INFO").upper()
                description = f.get("description") or f.get("name") or ""
                cwe_id = f.get("cwe_id")
                cwe_name = f.get("cwe_name")
                cvss_score = f.get("cvss_score")
                epss_score = f.get("epss_score")
                
                # Check if this vulnerability record already exists for this service/ip
                query = "SELECT id, description, created_at FROM vulnerabilities WHERE cve_id = ?"
                params: List[Any] = [cve_id]
                if service_id:
                    query += " AND service_id = ?"
                    params.append(service_id)
                elif ip_id:
                    query += " AND ip_id = ?"
                    params.append(ip_id)

                existing_vuln = conn.execute(query, params).fetchone()

                if existing_vuln:
                    vuln_id = existing_vuln[0]
                    # Update timestamp and description if new one has more details
                    new_desc = description if len(description) > len(existing_vuln[1] or "") else existing_vuln[1]
                    conn.execute("""
                        UPDATE vulnerabilities
                        SET severity = ?, cvss_score = COALESCE(?, cvss_score), description = ?, source = COALESCE(source, 'Nuclei'), created_at = ?
                        WHERE id = ?
                    """, (severity, cvss_score, new_desc, datetime.now(timezone.utc).isoformat(), vuln_id))
                    updated_vulns += 1
                else:
                    vuln_id = str(uuid.uuid4())
                    conn.execute("""
                        INSERT INTO vulnerabilities (
                            id, ip_id, service_id, cve_id, severity, cvss_score, cvss_version,
                            description, cwe_id, cwe_name, epss_score, epss_percentile, is_cisa_kev, source, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        vuln_id, ip_id, service_id, cve_id, severity, cvss_score, "3.1" if cvss_score else None,
                        description, cwe_id, cwe_name, epss_score, None, 0, "Nuclei", datetime.now(timezone.utc).isoformat()
                    ))
                    added_vulns += 1

                # Insert references/exploits if provided
                for ref_url in f.get("references", []):
                    if ref_url and isinstance(ref_url, str):
                        exploit_exists = conn.execute("SELECT id FROM exploits WHERE vulnerability_id = ? AND url = ?", (vuln_id, ref_url)).fetchone()
                        if not exploit_exists:
                            conn.execute("""
                                INSERT INTO exploits (id, vulnerability_id, title, source, url, verified, created_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                            """, (
                                str(uuid.uuid4()), vuln_id, f.get("name") or cve_id, "Nuclei",
                                ref_url, 1, datetime.now(timezone.utc).isoformat()
                            ))

            conn.commit()

        return {
            "added_vulnerabilities": added_vulns,
            "updated_vulnerabilities": updated_vulns,
            "total_processed": len(findings),
        }

    def add_scan_log(self, level: str, message: str, target: Optional[str] = None, timestamp: Optional[str] = None, input_target: Optional[str] = None) -> int:
        """Insert a scan execution log entry into SQLite."""
        if not timestamp:
            timestamp = datetime.now().strftime("%H:%M:%S")
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("""
                INSERT INTO scan_logs (timestamp, level, message, target, input_target)
                VALUES (?, ?, ?, ?, ?)
            """, (timestamp, level, message, target, input_target))
            conn.commit()
            return cur.lastrowid or 0

    def get_scan_logs(self, limit: int = 150, target: Optional[str] = None) -> List[Dict]:
        """Retrieve recent scan execution logs from SQLite."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if target:
                rows = conn.execute("""
                    SELECT id, timestamp, level, message, target, input_target, created_at
                    FROM scan_logs
                    WHERE target = ? OR input_target = ?
                    ORDER BY id ASC
                    LIMIT ?
                """, (target, target, limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT id, timestamp, level, message, target, input_target, created_at
                    FROM (
                        SELECT id, timestamp, level, message, target, input_target, created_at
                        FROM scan_logs
                        ORDER BY id DESC
                        LIMIT ?
                    )
                    ORDER BY id ASC
                """, (limit,)).fetchall()

            return [
                {
                    "id": row["id"],
                    "timestamp": row["timestamp"],
                    "level": row["level"],
                    "message": row["message"],
                    "target": row["target"],
                    "input_target": row["input_target"],
                }
                for row in rows
            ]

    @staticmethod
    def get_db_path_for_target(target: str, data_dir: Optional[Path] = None) -> Path:
        """Generate standardized database path for a target."""
        if data_dir is None:
            data_dir = Path.cwd() / "data" / "dbs"
        
        # Sanitize target name for filename
        safe_target = "".join(c if c.isalnum() or c in ".-_" else "_" for c in target)
        safe_target = safe_target[:50]  # Limit length
        
        return data_dir / f"{safe_target}.sqlite"

