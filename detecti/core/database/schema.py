"""SQLite schema definition for DetecTI-CLI EASM database."""

SCHEMA_SQL = """
-- Target Domains
CREATE TABLE IF NOT EXISTS domains (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Subdomains
CREATE TABLE IF NOT EXISTS subdomains (
    id TEXT PRIMARY KEY,
    domain_id TEXT NOT NULL,
    name TEXT NOT NULL,
    status_code INTEGER,
    cname TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id)
);

-- IP Addresses
CREATE TABLE IF NOT EXISTS ip_addresses (
    id TEXT PRIMARY KEY,
    ip TEXT UNIQUE NOT NULL,
    asn TEXT,
    org TEXT,
    country TEXT,
    city TEXT,
    region_code TEXT,
    postal_code TEXT,
    latitude REAL,
    longitude REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Mapping Subdomain to IP (DNS Resolutions)
CREATE TABLE IF NOT EXISTS subdomain_ips (
    subdomain_id TEXT NOT NULL,
    ip_id TEXT NOT NULL,
    resolution_type TEXT DEFAULT 'RESOLVES_TO',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (subdomain_id, ip_id),
    FOREIGN KEY (subdomain_id) REFERENCES subdomains(id),
    FOREIGN KEY (ip_id) REFERENCES ip_addresses(id)
);

-- Exposed Ports & Services
CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    ip_id TEXT NOT NULL,
    resolution_type TEXT DEFAULT 'RESOLVES_TO',
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    service_name TEXT,
    product TEXT,
    version TEXT,
    banner TEXT,
    url TEXT,
    ssl BOOLEAN DEFAULT 0,
    sources TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ip_id) REFERENCES ip_addresses(id)
);

-- Vulnerabilities & EPSS/KEV Intelligence
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    service_id TEXT,
    ip_id TEXT,
    cve_id TEXT NOT NULL,
    severity TEXT,
    cvss_score REAL,
    cvss_version TEXT,
    description TEXT,
    cwe_id TEXT,
    cwe_name TEXT,
    epss_score REAL,
    epss_percentile REAL,
    is_cisa_kev BOOLEAN DEFAULT 0,
    cisa_kev_data TEXT,
    source TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (service_id) REFERENCES services(id),
    FOREIGN KEY (ip_id) REFERENCES ip_addresses(id)
);

-- Exploits and PoCs
CREATE TABLE IF NOT EXISTS exploits (
    id TEXT PRIMARY KEY,
    vulnerability_id TEXT NOT NULL,
    title TEXT NOT NULL,
    source TEXT NOT NULL,
    url TEXT NOT NULL,
    verified BOOLEAN DEFAULT 0,
    author TEXT,
    date TEXT,
    exploit_type TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
);

-- Scan Results Metadata
CREATE TABLE IF NOT EXISTS scan_results (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    elapsed_seconds REAL,
    modules_run TEXT,
    total_findings INTEGER DEFAULT 0,
    total_hosts INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scan Live Logs Persistence
CREATE TABLE IF NOT EXISTS scan_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    target TEXT,
    input_target TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_subdomains_domain_id ON subdomains(domain_id);
CREATE INDEX IF NOT EXISTS idx_services_ip_id ON services(ip_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_service_id ON vulnerabilities(service_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_ip_id ON vulnerabilities(ip_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_exploits_vulnerability_id ON exploits(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_target ON scan_results(target);
CREATE INDEX IF NOT EXISTS idx_scan_logs_target ON scan_logs(target);
CREATE INDEX IF NOT EXISTS idx_scan_logs_id ON scan_logs(id);
"""
