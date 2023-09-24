import time
import shodan
import requests
import cve_searchsploit as cs
import argparse
import sys
   
banner = f"""
        ┏━━━━━━━━━━━━━━━━━━━━━[ Dev. by: Lucas S. (Ls4ss) - https://me.log.br ]━━━━━━━━━━━━━━━━━━━━━\n        ┃
        ┏━ USAGE: python3 {sys.argv[0]} <FILTER> <VULN_OPTIONS>
        ┃
        ┗━━ [+] <FILTER>
        ┃    ┗━ [!] CUSTOM FILTERS
        ┃    ┃   ┗━  file:    ━  Ex.: file:FILE_LIST.txt (Input IP_range/IP_address/Domains)       
        ┃    ┃   ┗━  host:    ━  Ex.: host:142.250.191.68
        ┃    ┃   ┗━  domain:  ━  Ex.: domain:spacex.com
        ┃    ┃       
        ┃    ┗━ [!] SHODAN FILTERS
        ┃    ┃   ┗━  port:    ━  Ex.: port:"8080"
        ┃    ┃   ┗━  product: ━  Ex.: product:"OpenSSH"
        ┃    ┃   ┗━  country: ━  Ex.: country:"US"
        ┃    ┃   ┗━  state:   ━  Ex.: state:"California"
        ┃    ┃   ┗━  city:    ━  Ex.: city:"Sunnyvale"
        ┃    ┃   ┗━  org:     ━  Ex.: org:"google"
        ┃    ┃   ┗━  asn:     ━  Ex.: asn:"AS15169"
        ┃    ┃   ┗━  isp:     ━  Ex.: isp:"Google LLC"
        ┃    ┃   ┗━  [!] MORE FILTERS: https://www.shodan.io/search/filters
        ┃    ┃
        ┃    ┗━ [!] CONCATENATE FILTERS
        ┃        ┗━  Ex.: python3 {sys.argv[0]} "org:google product:OpenSSH" [--nvd] [--xdb] [--git]
        ┃       
        ┗━━ [+] <VULN_OPTIONS>
        ┃    ┗━ [!] --cvss  ━  CVE Severity Details
        ┃    ┃   ┗━  CVSS Filters: ━ Ex.: --cvss:critical, --cvss:high, --cvss:medium, --cvss:low
        ┃    ┗━ [!] --xdb   ━  Search for Exploits in ExploitDB
        ┃    ┃   ┗━  --xdbupdate  ━  Refreshing ExploitDB (root required)
        ┃    ┗━  --nvd   ━  Search references in NVD
        ┃    ┗━  --git   ━  Search PoCs in GitHub
        ┃    ┗━  --cve   ━  Only CVE's
        ┃
        ┗━━━━━━━━━━━━━━━━━━━━━[ Dev. by: Lucas S. (Ls4ss) - https://me.log.br ]━━━━━━━━━━━━━━━━━━━━━
                        """   
def get_banner():
    print(banner)

nvdurl = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
xplurl = "https://www.exploit-db.com/exploits/"
giturl = "https://poc-in-github.motikan2010.net/api/v1/?cve_id="

# Configurar o analisador de argumentos
parser = argparse.ArgumentParser(description=banner, formatter_class=argparse.RawDescriptionHelpFormatter)

# Use nargs=argparse.REMAINDER para capturar todos os argumentos restantes
parser.add_argument('others_args', nargs=argparse.REMAINDER, help=argparse.SUPPRESS)

parser.add_argument("--xdbupdate", action="store_true", help=argparse.SUPPRESS)
# Analisar os argumentos da linha de comando
args = parser.parse_args()

def get_xdb_update():
    cs.update_db()

def get_shodan_api_key():
    with open("API.txt", "r") as api_file:
        return api_file.read().strip()
                        
class ShodanInfoGetter:
    def __init__(self, shodan_api_key):
        self.api = shodan.Shodan(shodan_api_key)

    def get_host_info(self, ip):
        try:
            host = self.api.host(ip)
            return host
        except Exception as e:
            return None

    def get_cve_info(self, ip):
        try:
            host = self.api.host(ip)
            return host['vulns']
        except Exception as e:
            return []

class VulnInfoGetter:
    def get_vuln_option(item):
            if "--xdb" in args.others_args:
                VulnInfoGetter.get_xdb_info(item)
            if "--git" in args.others_args:
                VulnInfoGetter.get_git_info(item)
            if "--nvd" in args.others_args:
                response = requests.get(nvdurl+item)
                nvdreq = response.json()
                VulnInfoGetter.get_nvd_info(item, nvdreq)

# CONSULTANDO REFERENCIAS DAS CVES NO NVD
    def get_nvd_info(item, nvdreq):
        lenth = len(nvdreq['vulnerabilities'][0]['cve']['references'])
        for x in range(lenth):
            print(f"        ┃   ┃   ┗━ [!] NVD: {nvdreq['vulnerabilities'][0]['cve']['references'][x]['url']}")
        time.sleep(6)                

# CONSULTANDO CVES NO EXPLOIP-DB
    def get_xdb_info(item):
        exploitdb = cs.edbid_from_cve(item)
        if len(exploitdb) > 0:
            for id in exploitdb:
                print(f"        ┃   ┃   ┗━ [!] Exploit: {xplurl}{id}")

# CONSULTANDO CVES NO GITHUB
    def get_git_info(item):
        gitpoc = giturl + item
        response = requests.get(gitpoc)
        if response.status_code == 200:
            data = response.json()
            if "pocs" in data and data["pocs"]:
                for poc in data['pocs']:
                    print(f"        ┃   ┃   ┗━ [!] GitHub PoC: {poc['html_url']}")
                    
    def get_cvss_info(nvdreq, severity, item):
        try:
            if nvdreq['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'] == severity:
                print(f"        ┃   ┃\n        ┃   ┗━ [+] {item} - [!] CVSS v3.1: {nvdreq['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']} - {nvdreq['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']}")
                VulnInfoGetter.get_vuln_option(item)

        except:
            if nvdreq['vulnerabilities'][0]['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'] == severity:
                print(f"        ┃   ┃\n        ┃   ┗━ [+] {item} - [!] CVSS v2: {nvdreq['vulnerabilities'][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']} - {nvdreq['vulnerabilities'][0]['cve']['metrics']['cvssMetricV2'][0]['baseSeverity']}")
                VulnInfoGetter.get_vuln_option(item)
        time.sleep(6)

def main(ip):

    SHODAN_API_KEY = get_shodan_api_key()
    info_getter = ShodanInfoGetter(SHODAN_API_KEY)

    host_info = info_getter.get_host_info(ip)
    if host_info:
        print(f"\n        ┏━ [!] ┃━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[ IP: {host_info['ip_str']} ]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┃")
        print(f"        ┃   ┗━ [+] Organization: {host_info.get('org', 'n/a')}")
        print(f"        ┃   ┗━ [+] Domains: {host_info.get('domains', 'n/a')}")
        print(f"        ┃   ┗━ [+] Operating System: {host_info.get('os', 'n/a')}")
        print(f"        ┃   ┗━ [+] Location: {host_info.get('country_name', 'n/a')} ━ {host_info.get('city','n/a')} ━ {host_info.get('region_code', 'n/a')}")
        print(f"        ┃\n        ┗━ [!] Shodan Ports")
        for item in host_info['data']:

            if "product" in item and "version" in item:
                print(f"        ┃   ┗━ [+] {item['port']} - {item['product']} v{item['version']}")
            if "product" in item and "version" not in item:
                print(f"        ┃   ┗━ [+] {item['port']} - {item['product']}")
            if "port" in item and "product" not in item and "version" not in item:
                print(f"        ┃   ┗━ [+] {item['port']}")

            if "http" in item and "ssl" in item:
                    print(f"        ┃   ┃   ┗━ [+] https://{ip}:{item['port']}")
            if "http" in item and "ssl" not in item:
                    print(f"        ┃   ┃   ┗━ [+] http://{ip}:{item['port']}")

            print(f"        ┃   ┃    ")

    cve_info = info_getter.get_cve_info(ip)
    if cve_info:

        print(f"        ┃\n        ┗━ [!] {len(cve_info)} CVE-IDs identified in {ip}")
        
        # LISTANDO CVES
        for item in cve_info:
                # CONDICAO PARA LISTAR CVES COM CVSS
                if "--cvss" in args.others_args:
                    response = requests.get(nvdurl+item)
                    nvdreq = response.json()
                    try:
                        print(f"        ┃   ┃\n        ┃   ┗━ [+] {item} - [!] CVSS v3.1: {nvdreq['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']} - {nvdreq['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']}")
                    except:
                        print(f"        ┃   ┃\n        ┃   ┗━ [+] {item} - [!] CVSS v2: {nvdreq['vulnerabilities'][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']} - {nvdreq['vulnerabilities'][0]['cve']['metrics']['cvssMetricV2'][0]['baseSeverity']}")
                    time.sleep(6)
                    VulnInfoGetter.get_vuln_option(item)

                elif "--cve" in args.others_args:
                    print(f"        ┃   ┃\n        ┃   ┗━ [+] {item}")
                    VulnInfoGetter.get_vuln_option(item)

                #CONDICAO PARA CVSS CRITICAL
                if "--cvss:critical" in args.others_args:
                    response = requests.get(nvdurl+item)
                    nvdreq = response.json()
                    severity = 'CRITICAL'
                    VulnInfoGetter.get_cvss_info(nvdreq, severity, item)
                    
                #CONDICAO PARA CVSS HIGH
                if "--cvss:high" in args.others_args:
                    response = requests.get(nvdurl+item)
                    nvdreq = response.json()
                    severity = 'HIGH'
                    VulnInfoGetter.get_cvss_info(nvdreq, severity, item)

                #CONDICAO PARA CVSS MEDIUM
                if "--cvss:medium" in args.others_args:
                    response = requests.get(nvdurl+item)
                    nvdreq = response.json()
                    severity = 'MEDIUM'
                    VulnInfoGetter.get_cvss_info(nvdreq, severity, item)

                #CONDICAO PARA CVSS LOW
                if "--cvss:low" in args.others_args:
                    response = requests.get(nvdurl+item)
                    nvdreq = response.json()
                    severity = 'LOW'
                    VulnInfoGetter.get_cvss_info(nvdreq, severity, item)
        print(f"        ┃\n        ┗━")

if __name__ == "__main__":
    main()
