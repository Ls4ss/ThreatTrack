import sys
from getinfo import hostinfo, cvecheck
import shodan
from tqdm import tqdm
import ipcalc

with open("API.txt", "r") as API:
        SHODAN_API_KEY = API.read()
api = shodan.Shodan(SHODAN_API_KEY)

def options():
        print (f"""
        ┌ USAGE: python3 {sys.argv[0]} <SHODAN_FILTER> <VULN_OPTIONS>
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
        |         └─  Ex.: python3 {sys.argv[0]} "org:google product:OpenSSH"  
        |       
        └── [+] <VULN_OPTIONS>
             └─  --cve    ─  Show CVE only
             └─  --xpl    ─  Search for Exploits in ExploitDB
             └─  --nvd    ─  Search references in NVD
                """)
        
        
        
def calcr(ip):
                pgr = tqdm(total=int(len(ipcalc.Network(ip)) - 2), desc="Starting")
                for address in ipcalc.Network(ip):
                        try:
                                pgr.update(1)
                                ip = str(address)
                                pgr.set_description(f"IP Address: {ip}")
                                hostinfo(ip)
                                cvecheck(ip)
                        except Exception as err:
                                pgr.write(f"[-]CVEs not found: {ip}")


def shodan_search(page, loopcount):
    query = api.search(query=shodan_query, page=page)
    total = query['total']
    pgr = tqdm(total=int(total))
    if total == 0:
            pgr.write(f"\n [!] IP's not found for this query, check the filter used")
            pgr.clear()
            options()
            sys.exit()
    page_total = len(query['matches'])
    pgr.write(f"[!] {loopcount}/{total}")
    pgr.write("[!] This query will consume your API credits")
    for x in range(page_total):
        ip = query['matches'][x]['ip_str']
        hostinfo(ip)
        cvecheck(ip)
        pgr.update(1)
    if loopcount != total:
        page = page + 1
        loopcount = loopcount + 1
        shodan_search(page, loopcount)
    else:
        sys.exit(1)        
        
        
try:

        shodan_query = sys.argv[1]
                
        if shodan_query[0:5] == "host:":
                ip = shodan_query[5:]
                if shodan_query[-3:-2] == "/":
                        calcr(ip)
                else:
                        pass
                hostinfo(ip)
                cvecheck(ip)
        
        elif shodan_query == "--help":
                options()

        elif shodan_query == "-h":
                options()
        
        else:
                loopcount = 1
                page = 1
                try:
                        shodan_search(page, loopcount)
                except Exception as e:
                        options()
                        print(e)
                        


except Exception as e:
        options()
        print(e)
        pass
