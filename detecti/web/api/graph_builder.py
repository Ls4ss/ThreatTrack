"""Graph data builder for Cytoscape.js visualization."""

import sqlite3
from typing import Dict, List, Optional, Set
from detecti.core.database.storage import DatabaseManager


class GraphBuilder:
    """Builds Cytoscape.js graph data from SQLite database."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def build_graph(self, active_targets: Optional[List[str]] = None) -> Dict:
        """Build complete graph with nodes and edges for Cytoscape.js.
        
        Host-Centric Architecture:
        - Target Root connects directly to Host IPs via CONTAINS_TARGET
        - Explicit FQDN targets connect to Target Root (CONTAINS_TARGET) and IP (RESOLVES_TO)
        - All enumerated domains/subdomains are embedded as rich metadata in target_root
        """
        nodes = []
        edges = []
        
        with sqlite3.connect(self.db.db_path) as conn:
            # 1. Determine target root information (from scan_results)
            target_name = None
            target_type = None
            try:
                cursor = conn.execute("SELECT target, target_type FROM scan_results ORDER BY created_at DESC LIMIT 1")
                row = cursor.fetchone()
                if row:
                    target_name, target_type = row
            except Exception:
                pass

            # 2. Build domain & subdomain nodes (only explicit targets spawned as graph nodes)
            domain_nodes, domain_edges, root_target_node, subdomain_to_ips, domain_to_ips, explicit_targets = self._build_domain_nodes(
                conn, target_name, target_type, active_targets=active_targets
            )
            if root_target_node:
                nodes.append(root_target_node)
            nodes.extend(domain_nodes)
            edges.extend(domain_edges)
            
            # 3. Build IP nodes connected to target root or resolved by visible FQDNs
            spawned_fqdn_ids = {n["data"]["id"] for n in domain_nodes}
            targets_list = root_target_node["data"].get("targets_list", []) if root_target_node else []
            ip_nodes, ip_edges = self._build_ip_nodes(
                conn,
                subdomain_to_ips,
                domain_to_ips,
                spawned_fqdn_ids=spawned_fqdn_ids,
                target_name=target_name,
                target_type=target_type,
                targets_list=targets_list,
                explicit_targets=explicit_targets,
                root_target_node=root_target_node
            )

            # Determine which IPs to spawn: only explicit targets or if in discovery mode
            # We NO LONGER spawn IPs just because a parent FQDN is marked.
            is_discovery = (target_type == "discovery" or not explicit_targets)
            visible_ip_nodes = [n for n in ip_nodes if is_discovery or n["data"]["ip"].lower() in explicit_targets or str(n["data"]["id"]).replace("ip_", "").lower() in explicit_targets]
            
            connected_ip_ids = {n["data"]["id"] for n in visible_ip_nodes}
            nodes.extend(visible_ip_nodes)
            edges.extend(ip_edges)
            
            # 4. Build service nodes connected to in-scope IPs
            service_nodes, service_edges = self._build_service_nodes(conn)
            visible_service_nodes = [n for n in service_nodes if any(e["data"]["target"] == n["data"]["id"] and e["data"]["source"] in connected_ip_ids for e in service_edges)]
            visible_service_edges = [e for e in service_edges if e["data"]["source"] in connected_ip_ids]
            nodes.extend(visible_service_nodes)
            edges.extend(visible_service_edges)
            
            # 5. Build vulnerability nodes connected to in-scope services/IPs
            vuln_nodes, vuln_edges = self._build_vulnerability_nodes(conn)
            visible_srv_and_ip_ids = connected_ip_ids.union({n["data"]["id"] for n in visible_service_nodes})
            visible_vuln_edges = [e for e in vuln_edges if e["data"]["source"] in visible_srv_and_ip_ids]
            visible_vuln_node_ids = {e["data"]["target"] for e in visible_vuln_edges}
            visible_vuln_nodes = [n for n in vuln_nodes if n["data"]["id"] in visible_vuln_node_ids]
            nodes.extend(visible_vuln_nodes)
            edges.extend(visible_vuln_edges)
        
        # --- EMBED PASSIVE DATA FOR FQDN INSPECTOR ---
        # To support the inspector showing data without spawning the nodes visually:
        # Build lookups for all passive data
        ip_data_map = {n["data"]["id"]: n["data"] for n in ip_nodes}
        srv_data_map = {n["data"]["id"]: n["data"] for n in service_nodes}
        vuln_data_map = {n["data"]["id"]: n["data"] for n in vuln_nodes}
        
        # Build relationship mappings (all edges, even if not spawned)
        ip_to_srvs = {}
        for e in service_edges:
            src = e["data"]["source"]
            tgt = e["data"]["target"]
            if src not in ip_to_srvs: ip_to_srvs[src] = []
            ip_to_srvs[src].append(tgt)
            
        srv_or_ip_to_vulns = {}
        for e in vuln_edges:
            src = e["data"]["source"]
            tgt = e["data"]["target"]
            if src not in srv_or_ip_to_vulns: srv_or_ip_to_vulns[src] = []
            srv_or_ip_to_vulns[src].append(tgt)
            
        # For each spawned FQDN node, embed its unspawned passive data
        for n in nodes:
            if n["data"]["type"] in ("domain", "subdomain"):
                nid = n["data"]["id"]
                n_ips = []
                n_srvs = []
                n_vulns = []
                
                # Get IPs for this FQDN
                ip_ids = set()
                if n["data"]["type"] == "domain":
                    dom_id = nid.replace("dom_", "")
                    ip_ids = domain_to_ips.get(int(dom_id) if dom_id.isdigit() else dom_id, set())
                else:
                    sub_id = nid.replace("sub_", "")
                    ip_ids = subdomain_to_ips.get(int(sub_id) if sub_id.isdigit() else sub_id, set())
                    
                for ip_id in ip_ids:
                    ip_node_id = f"ip_{ip_id}"
                    if ip_node_id in ip_data_map:
                        n_ips.append(ip_data_map[ip_node_id])
                    
                    for srv_id in ip_to_srvs.get(ip_node_id, []):
                        if srv_id in srv_data_map:
                            n_srvs.append(srv_data_map[srv_id])
                        for vuln_id in srv_or_ip_to_vulns.get(srv_id, []):
                            if vuln_id in vuln_data_map:
                                n_vulns.append(vuln_data_map[vuln_id])
                                
                    for vuln_id in srv_or_ip_to_vulns.get(ip_node_id, []):
                        if vuln_id in vuln_data_map:
                            n_vulns.append(vuln_data_map[vuln_id])
                            
                n["data"]["passive_ips"] = n_ips
                n["data"]["passive_services"] = n_srvs
                n["data"]["passive_vulns"] = n_vulns

        # Filter edges to only keep those where both source and target are spawned
        spawned_node_ids = {n["data"]["id"] for n in nodes}
        valid_edges = [e for e in edges if e["data"]["source"] in spawned_node_ids and e["data"]["target"] in spawned_node_ids]
        
        return {
            "elements": {
                "nodes": nodes,
                "edges": valid_edges
            }
        }
    
    def _build_domain_nodes(
        self,
        conn: sqlite3.Connection,
        target_name: str | None = None,
        target_type: str | None = None,
        active_targets: Optional[List[str]] = None
    ) -> tuple[List[Dict], List[Dict], Dict | None, Dict[str, set], Dict[str, set]]:
        """Build domain and subdomain inventory and spawn nodes ONLY for explicit targets."""
        nodes = []
        edges = []
        root_target_node = None
        
        # Get all domains
        cursor = conn.execute("SELECT id, name FROM domains ORDER BY name")
        domains_list = cursor.fetchall()
        
        # Get all subdomains
        cursor_s = conn.execute("SELECT id, name FROM subdomains ORDER BY name")
        all_subs_raw = cursor_s.fetchall()
        
        targets_list = []
        explicit_targets = set()
        if target_name:
            if target_type == "file":
                from pathlib import Path
                try:
                    from config import DETECTI_HOME
                except ImportError:
                    DETECTI_HOME = Path.home() / ".detecti"
                clean_path = str(target_name).strip()
                candidates = [
                    Path(clean_path),
                    DETECTI_HOME / clean_path,
                    DETECTI_HOME / "data" / clean_path,
                    DETECTI_HOME / "data" / "targets" / clean_path,
                    DETECTI_HOME / "tests" / clean_path,
                ]
                # Also try adding standard text extensions
                if "." not in clean_path:
                    for ext in [".txt", ".scope", ".list"]:
                        candidates.append(Path(f"{clean_path}{ext}"))
                        candidates.append(DETECTI_HOME / f"{clean_path}{ext}")
                        candidates.append(DETECTI_HOME / "data" / f"{clean_path}{ext}")

                file_obj = None
                for cand in candidates:
                    if cand.exists() and cand.is_file():
                        file_obj = cand
                        break
                
                if file_obj:
                    try:
                        targets_list = [line.strip() for line in file_obj.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip() and not line.startswith("#")]
                    except Exception:
                        pass
                
                if not targets_list:
                    try:
                        cursor_logs = conn.execute(
                            "SELECT DISTINCT input_target FROM scan_logs WHERE input_target IS NOT NULL AND input_target != ?",
                            (target_name,)
                        )
                        targets_list = [r[0].strip() for r in cursor_logs.fetchall() if r[0] and r[0].strip()]
                    except Exception:
                        pass
            elif target_type in ("domain", "ip", "subdomain"):
                targets_list = [target_name]

        def _normalize_target_item(t: str) -> str:
            t = str(t).strip().lower()
            if t.startswith("http://"):
                t = t[7:]
            elif t.startswith("https://"):
                t = t[8:]
            if "/" in t:
                t = t.split("/")[0]
            if ":" in t:
                if t.startswith("[") and "]" in t:
                    t = t.split("]")[0][1:]
                elif t.count(":") == 1:
                    t = t.split(":")[0]
            return t

        explicit_targets = {_normalize_target_item(t) for t in targets_list if _normalize_target_item(t)}
        if active_targets:
            for at in active_targets:
                norm = _normalize_target_item(at)
                if norm:
                    explicit_targets.add(norm)

        root_target_node = {
            "data": {
                "id": "target_root",
                "label": target_name or "Target Root",
                "type": "target",
                "name": target_name or "Target Root",
                "target_type": target_type or "query",
                "targets_list": targets_list,
                "is_root": True
            }
        }

        # Query all subdomains and their resolved IPs
        has_metadata = False
        try:
            sub_cols = [r[1] for r in conn.execute("PRAGMA table_info(subdomains)").fetchall()]
            has_metadata = "metadata" in sub_cols
        except Exception:
            pass

        meta_select = "s.metadata" if has_metadata else "NULL as metadata"

        cursor_subs = conn.execute(f"""
            SELECT s.id, s.name, s.domain_id, d.name as domain_name, si.ip_id, ip.ip, {meta_select}
            FROM subdomains s
            JOIN domains d ON s.domain_id = d.id
            LEFT JOIN subdomain_ips si ON s.id = si.subdomain_id
            LEFT JOIN ip_addresses ip ON si.ip_id = ip.id
            ORDER BY s.name ASC
        """)
        
        subdomain_to_ips: Dict[str, set] = {}
        domain_to_ips: Dict[str, set] = {}
        subdomain_info_map: Dict[str, Dict] = {}
        domain_resolved_ips_map: Dict[str, list] = {}
        domain_waf_map: Dict[str, bool] = {}
        
        import json
        for sub_id, sub_name, domain_id, domain_name, ip_id, ip_addr, metadata_raw in cursor_subs.fetchall():
            is_waf = False
            if metadata_raw:
                try:
                    meta_dict = json.loads(metadata_raw)
                    is_waf = meta_dict.get("is_waf_bypass", False)
                except Exception:
                    pass

            is_apex = (sub_name.strip().lower() == domain_name.strip().lower())
            if ip_id:
                subdomain_to_ips.setdefault(sub_id, set()).add(ip_id)
                if is_apex:
                    domain_to_ips.setdefault(domain_id, set()).add(ip_id)
                    if is_waf:
                        domain_waf_map[domain_id] = True
                    # Track domain resolved IPs (apex)
                    domain_ips_list = domain_resolved_ips_map.setdefault(domain_id, [])
                    if not any(r["id"] == f"ip_{ip_id}" for r in domain_ips_list):
                        domain_ips_list.append({"id": f"ip_{ip_id}", "ip": ip_addr})

            if not is_apex:
                if sub_id not in subdomain_info_map:
                    subdomain_info_map[sub_id] = {
                        "id": sub_id,
                        "name": sub_name,
                        "domain_id": domain_id,
                        "domain_name": domain_name,
                        "is_waf_bypass": is_waf,
                        "ips": [],
                        "resolved_ips": []
                    }
                elif is_waf:
                    subdomain_info_map[sub_id]["is_waf_bypass"] = True

                if ip_addr and ip_addr not in subdomain_info_map[sub_id]["ips"]:
                    subdomain_info_map[sub_id]["ips"].append(ip_addr)
                    subdomain_info_map[sub_id]["resolved_ips"].append({"id": f"ip_{ip_id}", "ip": ip_addr})

        all_domains = [{"id": d[0], "name": d[1]} for d in domains_list]
        all_subdomains = list(subdomain_info_map.values())

        # Embed complete DNS inventory inside target_root for instant Asset Inspector access
        if root_target_node:
            root_target_node["data"]["all_domains"] = all_domains
            root_target_node["data"]["all_subdomains"] = all_subdomains
            root_target_node["data"]["total_domains"] = len(all_domains)
            root_target_node["data"]["total_subdomains"] = len(all_subdomains)



# 2. Topologically hierarchical node spawning
        domains_to_spawn = set()
        subdomains_to_spawn = set()

        # Determine which domains are explicit targets (or parents of explicit targets) to receive CONTAINS_TARGET
        explicit_domains = set()
        for domain_id, domain_name in domains_list:
            if domain_name.lower() in explicit_targets or str(domain_id).lower() in explicit_targets:
                domains_to_spawn.add(domain_id)
                explicit_domains.add(domain_id)
        
        for sub_id, sub_info in subdomain_info_map.items():
            if sub_info["name"].lower() in explicit_targets or str(sub_id).lower() in explicit_targets:
                subdomains_to_spawn.add(sub_id)
                domains_to_spawn.add(sub_info["domain_id"])
                explicit_domains.add(sub_info["domain_id"])
            elif any(ip in explicit_targets for ip in sub_info["ips"]):
                subdomains_to_spawn.add(sub_id)
                domains_to_spawn.add(sub_info["domain_id"])
                explicit_domains.add(sub_info["domain_id"])
                
        cursor_all_ips = conn.execute("SELECT id, ip FROM ip_addresses")
        ip_id_to_str = {str(r[0]): r[1].lower() for r in cursor_all_ips.fetchall()}
        for domain_id, ip_ids in domain_to_ips.items():
            if domain_id not in domains_to_spawn:
                if any(ip_id_to_str.get(str(ip_id)) in explicit_targets or str(ip_id).lower() in explicit_targets for ip_id in ip_ids):
                    domains_to_spawn.add(domain_id)
                    explicit_domains.add(domain_id)

        for domain_id, domain_name in domains_list:
            if domain_id in domains_to_spawn:
                dname_lower = domain_name.lower()
                domain_subs = [s for s in all_subdomains if s.get("domain_id") == domain_id or s.get("domain_name", "").lower() == dname_lower]
                is_waf = domain_waf_map.get(domain_id, False)
                node_data = {
                    "id": f"dom_{domain_id}",
                    "label": f"🛡️ [Origin] {domain_name}" if is_waf else domain_name,
                    "type": "domain",
                    "name": domain_name,
                    "related_subdomains": domain_subs,
                    "subdomain_count": len(domain_subs),
                    "resolved_ips": domain_resolved_ips_map.get(domain_id, []),
                    "is_target": (dname_lower in explicit_targets),
                    "is_root": False,
                    "is_waf_bypass": is_waf
                }
                classes = []
                if node_data["is_target"]: classes.append("is-target")
                if is_waf: classes.append("is-waf-bypass")
                nodes.append({"data": node_data, "classes": " ".join(classes)})
                
                if root_target_node:
                    if domain_id in explicit_domains:
                        edges.append({"data": {"id": f"e_target_dom_{domain_id}", "source": "target_root", "target": f"dom_{domain_id}", "label": "CONTAINS_TARGET"}})
                    else:
                        edges.append({"data": {"id": f"e_target_dom_{domain_id}", "source": "target_root", "target": f"dom_{domain_id}", "label": "MATCHES_DOMAIN"}})

        for sub_id, sub_info in subdomain_info_map.items():
            if sub_id in subdomains_to_spawn:
                sname_lower = sub_info["name"].lower()
                parent_dom_id = sub_info["domain_id"]
                sub_related = [s for s in all_subdomains if s.get("domain_id") == parent_dom_id and s.get("id") != sub_id]
                is_waf = sub_info.get("is_waf_bypass", False)
                node_data = {
                    "id": f"sub_{sub_id}",
                    "label": f"🛡️ [Origin] {sub_info['name']}" if is_waf else sub_info["name"],
                    "type": "subdomain",
                    "name": sub_info["name"],
                    "domain_id": parent_dom_id,
                    "domain_name": sub_info["domain_name"],
                    "resolved_ips": sub_info.get("resolved_ips", []),
                    "related_subdomains": sub_related,
                    "is_target": (sname_lower in explicit_targets),
                    "is_waf_bypass": is_waf
                }
                classes = []
                if node_data["is_target"]: classes.append("is-target")
                if is_waf: classes.append("is-waf-bypass")
                nodes.append({"data": node_data, "classes": " ".join(classes)})
                
                parent_dom_id = sub_info["domain_id"]
                edges.append({"data": {"id": f"e_dom_sub_{sub_id}", "source": f"dom_{parent_dom_id}", "target": f"sub_{sub_id}", "label": "HAS_SUBDOMAIN"}})

        if root_target_node:
            explore_leads = []
            ip_stats = {}
            cursor_ips = conn.execute("""
                SELECT ip.id, ip.ip,
                       COUNT(DISTINCT s.id) as service_count,
                       COUNT(DISTINCT CASE WHEN s.sources LIKE '%masscan%' OR s.sources LIKE '%active%' THEN s.id END) as verified_service_count,
                       COUNT(DISTINCT v.id) as vuln_count,
                       MAX(CASE WHEN v.is_cisa_kev = 1 THEN 1 ELSE 0 END) as has_kev,
                       COUNT(DISTINCT CASE WHEN v.is_cisa_kev = 1 THEN v.id END) as kev_count,
                       COUNT(DISTINCT CASE WHEN v.severity = 'CRITICAL' THEN v.id END) as critical_count,
                       COUNT(DISTINCT CASE WHEN v.severity = 'HIGH' THEN v.id END) as high_count,
                       MAX(v.epss_score) as max_epss,
                       COUNT(DISTINCT CASE WHEN v.epss_score >= 0.20 THEN v.id END) as high_epss_count,
                       COUNT(DISTINCT e.id) as poc_count,
                       GROUP_CONCAT(DISTINCT s.id) as srv_ids,
                       GROUP_CONCAT(DISTINCT (CASE WHEN v.cve_id IS NOT NULL AND TRIM(v.cve_id) != '' AND UPPER(v.cve_id) != 'UNKNOWN' THEN LOWER(REPLACE(v.cve_id, ' ', '_')) ELSE v.id END)) as vuln_ids
                FROM ip_addresses ip
                LEFT JOIN services s ON ip.id = s.ip_id
                LEFT JOIN vulnerabilities v ON ip.id = v.ip_id OR s.id = v.service_id
                LEFT JOIN exploits e ON v.id = e.vulnerability_id
                GROUP BY ip.id, ip.ip
            """)
            for row in cursor_ips.fetchall():
                ip_id, ip, s_cnt, vs_cnt, v_cnt, has_kev, k_cnt, c_cnt, h_cnt, max_epss, h_epss_cnt, poc_cnt, srv_ids_str, vuln_ids_str = row
                max_epss = max_epss or 0.0
                
                s_list = [f"srv_{x}" for x in str(srv_ids_str).split(",")] if srv_ids_str else []
                v_list = [f"vuln_{x}" for x in str(vuln_ids_str).split(",")] if vuln_ids_str else []

                stats = {
                    "service_count": s_cnt,
                    "verified_service_count": vs_cnt,
                    "vuln_count": v_cnt,
                    "has_kev": bool(has_kev),
                    "kev_count": k_cnt,
                    "critical_count": c_cnt,
                    "high_count": h_cnt,
                    "max_epss": max_epss,
                    "high_epss_count": h_epss_cnt,
                    "poc_count": poc_cnt,
                    "service_ids": s_list,
                    "vuln_ids": v_list
                }
                ip_stats[ip_id] = stats
                score = (k_cnt * 1000000) + (poc_cnt * 200000) + (h_epss_cnt * 100000) + (max_epss * 50000) + (c_cnt * 50000) + (h_cnt * 20000) + (vs_cnt * 5000) + (v_cnt * 1000) + (s_cnt * 100)
                explore_leads.append({
                    "id": f"ip_{ip_id}",
                    "label": ip,
                    "display_name": ip,
                    "type": "ip",
                    "three_d_score": score,
                    **stats
                })
            
            subdomain_stats = {}
            for sub_id, sub_info in subdomain_info_map.items():
                s_stats = {"service_count": 0, "verified_service_count": 0, "vuln_count": 0, "has_kev": False, "kev_count": 0, "critical_count": 0, "high_count": 0, "max_epss": 0.0, "high_epss_count": 0, "poc_count": 0, "service_ids": set(), "vuln_ids": set()}
                ips = subdomain_to_ips.get(sub_id, set())
                for ip_id in ips:
                    if ip_id in ip_stats:
                        st = ip_stats[ip_id]
                        for k in ["service_count", "verified_service_count", "vuln_count", "kev_count", "critical_count", "high_count", "high_epss_count", "poc_count"]:
                            s_stats[k] += st[k]
                        s_stats["has_kev"] = s_stats["has_kev"] or st["has_kev"]
                        s_stats["max_epss"] = max(s_stats["max_epss"], st["max_epss"])
                        s_stats["service_ids"].update(st.get("service_ids", []))
                        s_stats["vuln_ids"].update(st.get("vuln_ids", []))
                
                s_stats_final = {**s_stats, "service_ids": list(s_stats["service_ids"]), "vuln_ids": list(s_stats["vuln_ids"])}
                subdomain_stats[sub_id] = s_stats_final
                score = (s_stats["kev_count"] * 1000000) + (s_stats["poc_count"] * 200000) + (s_stats["high_epss_count"] * 100000) + (s_stats["max_epss"] * 50000) + (s_stats["critical_count"] * 50000) + (s_stats["high_count"] * 20000) + (s_stats["verified_service_count"] * 5000) + (s_stats["vuln_count"] * 1000) + (s_stats["service_count"] * 100)
                explore_leads.append({
                    "id": f"sub_{sub_id}",
                    "label": sub_info["name"],
                    "display_name": sub_info["name"],
                    "type": "subdomain",
                    "three_d_score": score,
                    **s_stats_final
                })

            for domain_id, domain_name in domains_list:
                d_stats = {"service_count": 0, "verified_service_count": 0, "vuln_count": 0, "has_kev": False, "kev_count": 0, "critical_count": 0, "high_count": 0, "max_epss": 0.0, "high_epss_count": 0, "poc_count": 0, "service_ids": set(), "vuln_ids": set()}
                for ip_id in domain_to_ips.get(domain_id, set()):
                    if ip_id in ip_stats:
                        st = ip_stats[ip_id]
                        for k in ["service_count", "verified_service_count", "vuln_count", "kev_count", "critical_count", "high_count", "high_epss_count", "poc_count"]:
                            d_stats[k] += st[k]
                        d_stats["has_kev"] = d_stats["has_kev"] or st["has_kev"]
                        d_stats["max_epss"] = max(d_stats["max_epss"], st["max_epss"])
                        d_stats["service_ids"].update(st.get("service_ids", []))
                        d_stats["vuln_ids"].update(st.get("vuln_ids", []))
                for sub_id, sub_info in subdomain_info_map.items():
                    if sub_info["domain_id"] == domain_id:
                        st = subdomain_stats.get(sub_id, {})
                        if st:
                            for k in ["service_count", "verified_service_count", "vuln_count", "kev_count", "critical_count", "high_count", "high_epss_count", "poc_count"]:
                                d_stats[k] += st.get(k, 0)
                            d_stats["has_kev"] = d_stats["has_kev"] or st.get("has_kev", False)
                            d_stats["max_epss"] = max(d_stats["max_epss"], st.get("max_epss", 0.0))
                            d_stats["service_ids"].update(st.get("service_ids", []))
                            d_stats["vuln_ids"].update(st.get("vuln_ids", []))
                
                d_stats_final = {**d_stats, "service_ids": list(d_stats["service_ids"]), "vuln_ids": list(d_stats["vuln_ids"])}
                score = (d_stats["kev_count"] * 1000000) + (d_stats["poc_count"] * 200000) + (d_stats["high_epss_count"] * 100000) + (d_stats["max_epss"] * 50000) + (d_stats["critical_count"] * 50000) + (d_stats["high_count"] * 20000) + (d_stats["verified_service_count"] * 5000) + (d_stats["vuln_count"] * 1000) + (d_stats["service_count"] * 100)
                explore_leads.append({
                    "id": f"dom_{domain_id}",
                    "label": domain_name,
                    "display_name": domain_name,
                    "type": "domain",
                    "three_d_score": score,
                    **d_stats_final
                })
            
            root_target_node["data"]["explore_leads"] = explore_leads


        return nodes, edges, root_target_node, subdomain_to_ips, domain_to_ips, explicit_targets
    
    def _build_ip_nodes(
        self,
        conn: sqlite3.Connection,
        subdomain_to_ips: Dict[str, set],
        domain_to_ips: Dict[str, set],
        spawned_fqdn_ids: Optional[Set[str]] = None,
        target_name: Optional[str] = None,
        target_type: Optional[str] = None,
        targets_list: Optional[List[str]] = None,
        explicit_targets: Optional[Set[str]] = None,
        root_target_node: Optional[Dict] = None
    ) -> tuple[List[Dict], List[Dict]]:
        nodes = []
        edges = []
        cols = {r[1] for r in conn.execute("PRAGMA table_info(ip_addresses)").fetchall()}
        select_post = ", postal_code" if "postal_code" in cols else ", '' as postal_code"
        select_geo = ", latitude, longitude" if ("latitude" in cols and "longitude" in cols) else ", NULL as latitude, NULL as longitude"

        cursor = conn.execute(f"""
            SELECT id, ip, org, country, city, region_code, asn {select_post} {select_geo}
            FROM ip_addresses
        """)
        ip_rows = cursor.fetchall()

        cursor_stats = conn.execute("""
            SELECT ip.id, 
                   GROUP_CONCAT(DISTINCT s.id) as srv_ids,
                   GROUP_CONCAT(DISTINCT (CASE WHEN v.cve_id IS NOT NULL AND TRIM(v.cve_id) != '' AND UPPER(v.cve_id) != 'UNKNOWN' THEN LOWER(REPLACE(v.cve_id, ' ', '_')) ELSE v.id END)) as vuln_ids
            FROM ip_addresses ip
            LEFT JOIN services s ON ip.id = s.ip_id
            LEFT JOIN vulnerabilities v ON ip.id = v.ip_id OR s.id = v.service_id
            GROUP BY ip.id
        """)
        ip_extra_stats = {}
        for row in cursor_stats.fetchall():
            ip_id_stat, srv_ids_str, vuln_ids_str = row
            ip_extra_stats[ip_id_stat] = {
                "service_ids": [f"srv_{x}" for x in str(srv_ids_str).split(",")] if srv_ids_str else [],
                "vuln_ids": [f"vuln_{x}" for x in str(vuln_ids_str).split(",")] if vuln_ids_str else []
            }

        cursor_fqdns = conn.execute("""
            SELECT DISTINCT si.ip_id, s.name, si.resolution_type, si.subdomain_id, s.domain_id
            FROM subdomain_ips si
            JOIN subdomains s ON si.subdomain_id = s.id
            ORDER BY LENGTH(s.name) ASC, s.name ASC
        """)
        ip_to_fqdns: Dict[str, List[str]] = {}
        sub_res_map = {}
        dom_res_map = {}
        for ip_id, fqdn, res_type, sub_id, dom_id in cursor_fqdns.fetchall():
            if fqdn:
                ip_to_fqdns.setdefault(str(ip_id), []).append(fqdn)
            rt = res_type or "RESOLVES_TO"
            sub_res_map[(str(sub_id), str(ip_id))] = rt
            
            # For domains (apex), if this is an apex domain, dom_id will be mapped
            # Wait, any subdomain belonging to dom_id resolving to ip_id could map. We only want apex.
            # So let's just keep track of best resolution type for a domain to an IP.
            # Active beats historical.
            k = (str(dom_id), str(ip_id))
            if k not in dom_res_map or rt == "RESOLVES_TO":
                dom_res_map[k] = rt

        
        fqdn_set = spawned_fqdn_ids or set()
        ips_resolved_by_visible_fqdns = set()
        targets_set = set(t.strip().lower() for t in targets_list) if targets_list else set()
        if explicit_targets:
            targets_set.update(explicit_targets)
        
        # Calculate which IPs already receive RESOLVES_TO from a visible FQDN node
        for sub_id, ip_ids in subdomain_to_ips.items():
            if f"sub_{sub_id}" in fqdn_set:
                for ip_id in ip_ids:
                    ips_resolved_by_visible_fqdns.add(str(ip_id))

        for dom_id, ip_ids in domain_to_ips.items():
            if f"dom_{dom_id}" in fqdn_set:
                for ip_id in ip_ids:
                    ips_resolved_by_visible_fqdns.add(str(ip_id))

        # Check if scan mode is Threat Intel Query / Shodan Discovery Mode
        is_query_discovery = (target_type in ("query", "shodan", "asn", "org", "network"))

        for ip_id, ip, org, country, city, region_code, asn, postal_code, latitude, longitude in ip_rows:
            fqdns = ip_to_fqdns.get(str(ip_id), [])
            is_explicit_ip_tgt = bool((ip and ip.strip().lower() in targets_set) or str(ip_id) in targets_set)
            extra = ip_extra_stats.get(ip_id, {"service_ids": [], "vuln_ids": []})
            node_dict = {
                "data": {
                    "id": f"ip_{ip_id}",
                    "label": ip,
                    "type": "ip",
                    "ip": ip,
                    "org": org or "Unknown",
                    "country": country or "Unknown",
                    "city": city or "",
                    "region_code": region_code or "",
                    "postal_code": postal_code or "",
                    "latitude": latitude,
                    "longitude": longitude,
                    "asn": asn or "Unknown",
                    "fqdns": fqdns,
                    "fqdn_count": len(fqdns),
                    "service_ids": extra["service_ids"],
                    "vuln_ids": extra["vuln_ids"],
                    "is_target": is_explicit_ip_tgt
                }
            }
            if is_explicit_ip_tgt:
                node_dict["classes"] = "is-target"
            nodes.append(node_dict)

            # Connect Target Root -> Host IP via CONTAINS_TARGET:
            # 1. IP is explicitly listed as a direct target OR Query Discovery Mode.
            # 2. Strict Lineage Rule: NEVER connect to root if it has a visible FQDN parent (Domain/Subdomain).
            has_visible_fqdn_parent = str(ip_id) in ips_resolved_by_visible_fqdns
            # Always connect to target_root if the IP has no FQDN parent, so it doesn't float!
            should_connect_root_to_ip = (is_explicit_ip_tgt or is_query_discovery) and not has_visible_fqdn_parent

            if root_target_node and should_connect_root_to_ip:
                edges.append({
                    "data": {
                        "id": f"e_root_ip_{ip_id}",
                        "source": "target_root",
                        "target": f"ip_{ip_id}",
                        "label": "CONTAINS_TARGET"
                    }
                })
        
        # Connect FQDN targets -> IPs (RESOLVES_TO) ONLY if the node exists in graph.
        # If the FQDN is an explicit target, we show ALL its resolved IPs.
        # If the FQDN was merely spawned to support an explicitly targeted IP, we ONLY connect to the targeted IPs!
        cursor_all_ips = conn.execute("SELECT id, ip FROM ip_addresses")
        ip_id_to_str = {str(r[0]): r[1].lower() for r in cursor_all_ips.fetchall()}

        # Re-verify if fqdns are explicit targets
        cursor_fqdns_check = conn.execute("SELECT id, name FROM domains UNION SELECT id, name FROM subdomains")
        fqdn_id_to_name = {f"dom_{r[0]}": r[1].lower() for r in cursor_fqdns_check.fetchall()}
        cursor_fqdns_check = conn.execute("SELECT id, name FROM subdomains")
        for r in cursor_fqdns_check.fetchall():
            fqdn_id_to_name[f"sub_{r[0]}"] = r[1].lower()

        for sub_id, ip_ids in subdomain_to_ips.items():
            sub_node_id = f"sub_{sub_id}"
            if sub_node_id in fqdn_set:
                is_fqdn_targeted = fqdn_id_to_name.get(sub_node_id) in explicit_targets
                for ip_id in ip_ids:
                    ip_str = ip_id_to_str.get(str(ip_id), "")
                    if True:
                        rtype = sub_res_map.get((str(sub_id), str(ip_id)), "RESOLVES_TO")
                        edges.append({"data": {"id": f"e_sub_ip_{sub_id}_{ip_id}", "source": sub_node_id, "target": f"ip_{ip_id}", "label": rtype}})

        for dom_id, ip_ids in domain_to_ips.items():
            dom_node_id = f"dom_{dom_id}"
            if dom_node_id in fqdn_set:
                is_fqdn_targeted = fqdn_id_to_name.get(dom_node_id) in explicit_targets
                for ip_id in ip_ids:
                    ip_str = ip_id_to_str.get(str(ip_id), "")
                    if True:
                        rtype = dom_res_map.get((str(dom_id), str(ip_id)), "RESOLVES_TO")
                        edges.append({"data": {"id": f"e_dom_ip_{dom_id}_{ip_id}", "source": dom_node_id, "target": f"ip_{ip_id}", "label": rtype}})

        # Embed all discovered Host IPs inside root_target_node for instant inspector access
        if root_target_node:
            all_ips_summary = [
                {
                    "id": n["data"]["id"],
                    "ip": n["data"]["ip"],
                    "org": n["data"]["org"],
                    "country": n["data"]["country"],
                    "city": n["data"]["city"],
                    "asn": n["data"]["asn"],
                    "fqdns": n["data"]["fqdns"],
                    "fqdn_count": n["data"]["fqdn_count"]
                }
                for n in nodes
            ]
            root_target_node["data"]["all_ips"] = all_ips_summary
            root_target_node["data"]["total_ips"] = len(all_ips_summary)
        
        return nodes, edges
    
    def _build_service_nodes(self, conn: sqlite3.Connection) -> tuple[List[Dict], List[Dict]]:
        """Build service/port nodes with active scan differentiation."""
        import json
        nodes = []
        edges = []
        
        cursor = conn.execute("""
            SELECT id, ip_id, port, protocol, service_name, product, version, banner, ssl, url, sources
            FROM services
            ORDER BY rowid ASC
        """)
        
        seen_services = {}
        
        for service_id, ip_id, port, protocol, service_name, product, version, banner, ssl, url, sources_raw in cursor.fetchall():
            proto_str = (protocol or "tcp").lower()
            key = (ip_id, port, proto_str)
            
            # Parse sources
            sources_list = []
            if sources_raw:
                try:
                    parsed = json.loads(sources_raw)
                    if isinstance(parsed, list):
                        sources_list = parsed
                    else:
                        sources_list = [str(parsed)]
                except Exception:
                    sources_list = [sources_raw]
            
            has_masscan = any("masscan" in str(s).lower() for s in sources_list)
            
            if key in seen_services:
                # Merge into existing node data
                existing_node = seen_services[key]
                cur_sources = set(existing_node["data"]["sources"])
                cur_sources.update(sources_list)
                existing_node["data"]["sources"] = sorted(list(cur_sources))
                if has_masscan:
                    existing_node["data"]["is_active_scan"] = True
                    existing_node["data"]["verified_active"] = True
                if banner and not existing_node["data"]["banner"]:
                    existing_node["data"]["banner"] = banner
                if service_name and (not existing_node["data"]["service"] or existing_node["data"]["service"] == "unknown"):
                    existing_node["data"]["service"] = service_name
                continue
            
            label = f"{port}/{proto_str}"
            service_type = "https" if ssl else "http" if port in [80, 8080, 8000] else "service"
            
            node_obj = {
                "data": {
                    "id": f"srv_{service_id}",
                    "label": label,
                    "type": service_type,
                    "port": port,
                    "protocol": protocol,
                    "service": service_name or "unknown",
                    "product": product or "",
                    "version": version or "",
                    "banner": banner or "",
                    "ssl": bool(ssl),
                    "url": url or "",
                    "sources": sources_list,
                    "is_active_scan": has_masscan,
                    "verified_active": has_masscan,
                }
            }
            seen_services[key] = node_obj
            nodes.append(node_obj)
            
            # Edge from IP to service
            edges.append({
                "data": {
                    "id": f"e_ip_srv_{ip_id}_{service_id}",
                    "source": f"ip_{ip_id}",
                    "target": f"srv_{service_id}",
                    "label": "EXPOSES",
                    "is_active_scan": has_masscan,
                    "verified_active": has_masscan
                }
            })
        
        return nodes, edges
    
    def _build_vulnerability_nodes(self, conn: sqlite3.Connection) -> tuple[List[Dict], List[Dict]]:
        """Build vulnerability nodes with risk indicators and PoC information.
        
        Consolidates vulnerability nodes by CVE ID (or vuln ID) so that identical
        vulnerabilities affecting multiple services or IPs share a single node on the graph
        with incoming HAS_VULN edges from each affected service/IP.
        """
        nodes = []
        edges = []
        seen_vuln_node_ids = set()
        seen_edge_ids = set()
        
        try:
            # Ensure source column exists
            try:
                cols = [r[1] for r in conn.execute("PRAGMA table_info(vulnerabilities)").fetchall()]
                has_source_col = "source" in cols
            except Exception:
                has_source_col = False

            source_select = "v.source" if has_source_col else "'NVD' as source"

            cursor = conn.execute(f"""
                SELECT v.id, v.ip_id, v.service_id, v.cve_id, v.severity, v.cvss_score, 
                       v.epss_score, v.is_cisa_kev, v.description, {source_select},
                       COUNT(e.id) as exploit_count,
                       ip.id as resolved_ip_id, ip.ip, ip.org, ip.country, ip.asn,
                       s.port, s.protocol, s.service_name, s.product, s.version, s.url, s.ssl
                FROM vulnerabilities v
                LEFT JOIN exploits e ON v.id = e.vulnerability_id
                LEFT JOIN services s ON v.service_id = s.id
                LEFT JOIN ip_addresses ip ON COALESCE(v.ip_id, s.ip_id) = ip.id
                GROUP BY v.id, v.ip_id, v.service_id, v.cve_id, v.severity, v.cvss_score, 
                         v.epss_score, v.is_cisa_kev, v.description, {source_select},
                         ip.id, ip.ip, ip.org, ip.country, ip.asn,
                         s.port, s.protocol, s.service_name, s.product, s.version, s.url, s.ssl
            """)
            
            for row in cursor.fetchall():
                (vuln_id, ip_id, service_id, cve_id, severity, cvss_score, epss_score, 
                 is_cisa_kev, description, vuln_source, exploit_count, resolved_ip_id, ip_address, 
                 org, country, asn, port, protocol, service_name, product, version, url, ssl) = row
                
                # Build vulnerability label - keep it simple with just CVE ID
                label = cve_id or "Unknown CVE"
                # Use normalized CVE node ID if available to merge identical CVEs into one node
                clean_cve = (cve_id or "").strip()
                node_id = f"vuln_{clean_cve.replace(' ', '_').lower()}" if clean_cve and clean_cve.upper() != "UNKNOWN" else f"vuln_{vuln_id}"
                
                # Determine risk level for styling
                risk_level = "low"
                if is_cisa_kev:
                    risk_level = "critical"
                elif epss_score and epss_score > 0.5:
                    risk_level = "high"
                elif severity in ["CRITICAL", "HIGH"]:
                    risk_level = "high" if severity == "HIGH" else "critical"
                elif severity == "MEDIUM":
                    risk_level = "medium"
                
                # Only construct the node data once per unique CVE
                if node_id not in seen_vuln_node_ids:
                    seen_vuln_node_ids.add(node_id)
                    
                    # Get exploit details for this vulnerability
                    exploit_cursor = conn.execute("""
                        SELECT title, source, url, verified, author, date, exploit_type
                        FROM exploits WHERE vulnerability_id = ?
                    """, (vuln_id,))
                    
                    exploits = []
                    for exploit_row in exploit_cursor.fetchall():
                        exploits.append({
                            "title": exploit_row[0],
                            "source": exploit_row[1],
                            "url": exploit_row[2],
                            "verified": bool(exploit_row[3]),
                            "author": exploit_row[4],
                            "date": exploit_row[5],
                            "exploit_type": exploit_row[6]
                        })
                    
                    nodes.append({
                        "data": {
                            "id": node_id,
                            "label": label,
                            "type": "vulnerability",
                            "cve_id": cve_id or "Unknown",
                            "severity": severity or "UNKNOWN",
                            "cvss_score": cvss_score or 0,
                            "epss_score": epss_score or 0,
                            "is_cisa_kev": bool(is_cisa_kev),
                            "risk_level": risk_level,
                            "source": vuln_source or ("Nuclei" if not clean_cve.startswith("CVE-") else "NVD"),
                            "description": description or "",
                            "exploit_count": exploit_count,
                            "exploits": exploits,
                            "has_pocs": exploit_count > 0,
                            "ip": ip_address or "",
                            "ip_id": f"ip_{resolved_ip_id}" if resolved_ip_id else (f"ip_{ip_id}" if ip_id else None),
                            "org": org or "",
                            "country": country or "",
                            "asn": asn or "",
                            "service_id": f"srv_{service_id}" if service_id else None,
                            "port": port,
                            "protocol": protocol,
                            "service": service_name or "",
                            "product": product or "",
                            "version": version or "",
                            "url": url or "",
                            "ssl": bool(ssl) if ssl is not None else False
                        }
                    })
                
                # Create HAS_VULN edge from Service or IP to the deduplicated Vulnerability node
                vuln_sev = (severity or "UNKNOWN").upper()
                if service_id:
                    edge_id = f"e_srv_vuln_{service_id}_{node_id}"
                    if edge_id not in seen_edge_ids:
                        seen_edge_ids.add(edge_id)
                        edges.append({
                            "data": {
                                "id": edge_id,
                                "source": f"srv_{service_id}",
                                "target": node_id,
                                "label": "HAS_VULN",
                                "vuln_severity": vuln_sev,
                            }
                        })
                elif ip_id:
                    edge_id = f"e_ip_vuln_{ip_id}_{node_id}"
                    if edge_id not in seen_edge_ids:
                        seen_edge_ids.add(edge_id)
                        edges.append({
                            "data": {
                                "id": edge_id,
                                "source": f"ip_{ip_id}",
                                "target": node_id,
                                "label": "HAS_VULN",
                                "vuln_severity": vuln_sev,
                            }
                        })
        except Exception as e:
            print(f"Error building vulnerability nodes: {e}")
        
        return nodes, edges
