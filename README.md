##### Shodan + ExploitDB
# SPLOIT
### Consult and discover exploits for vulnerabilities related to your target

##### python3 sploit -h
        ┌ USAGE: python3 sploit.py <SHODAN_FILTER> <VULN_OPTIONS>
        |
        └── [+] <SHODAN_FILTER>
        |    └─ [!] FREE FILTER
        |    |   └─  host:    ─  Ex.: host:142.250.191.68
        |    |       └─────────  Ex.: host:142.250.191.68/24
        |    |
        |    └─ [!] FILTERS WITH API CREDITS
        |    |   └─  port:    ─  Ex.: port:8080
        |    |   └─  product: ─  Ex.: product:OpenSSH
        |    |   └─  country: ─  Ex.: country:US
        |    |   └─  state:   ─  Ex.: state:California
        |    |   └─  city:    ─  Ex.: city:Sunnyvale
        |    |   └─  org:     ─  Ex.: org:google
        |    |   └─  asn:     ─  Ex.: asn:AS15169
        |    |   └─  isp:     ─  Ex.: isp:Google LLC
        |    |   └─  [!] MORE FILTERS: https://www.shodan.io/search/filters
        |    |
        |    └─  [!] CONCATENATE FILTERS
        |         └─  Ex.: python3 sploit.py "org:google product:OpenSSH"
        |
        └── [+] <VULN_OPTIONS>
             └─  --cve    ─  Show CVE only
             └─  --xpl    ─  Search for Exploits in ExploitDB
             └─  --nvd    ─  Search references in NVD
