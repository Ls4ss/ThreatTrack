import time
import shodan
import requests
from tqdm import tqdm
import cve_searchsploit as cs
import traceback
import sys

APIKEY = open("API.txt", "r")
SHODAN_API_KEY = APIKEY.read().splitlines()

api = shodan.Shodan(SHODAN_API_KEY)
nvdurl = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
try:
        
        def hostinfo(ip):
                try:
                        host = api.host(ip)
                # Print general info
                        tqdm.write(f"""
   [!] IP: {host['ip_str']}
    |  [+]  Organization: {host.get('org', 'n/a')}
    |  [+]  Domains: {host.get('domains', 'n/a')}
    |  [+]  Operating System: {host.get('os', 'n/a')}
    |""")

                        tqdm.write("    | [!] Ports")
                
                        for item in host['data']:
                                tqdm.write(f"    |   [+] Port: {item['port']}")
                        tqdm.write(f"    |")
                except Exception as e:
                        tqdm.write(f"\n    | [-] {ip} - No information available for that IP")
                        
        def cvecheck(ip):
                try:
                        host = api.host(ip)
                        cves = host['vulns']
                        if sys.argv[2] == "--cve":
                                tqdm.write(f"    | [!] {len(cves)} CVE-IDs identified in {ip}")
                                for item in cves:
                                        tqdm.write(f"    |   [+] {item}")
                                sys.exit()
                        else:
                                pass
                        tqdm.write(f"    | [!] {len(cves)} CVE-IDs identified in {ip}")
                
                        count = 0
                        for item in cves:
                                try:
                                        exploitdb = cs.edbid_from_cve(item)
                                        
                                        if len(exploitdb) == 0:
                                                tqdm.write(f"    |")
                                                tqdm.write(f"    |   [+] {item}")
                                                try:
                                                        if sys.argv[2] == "--nvd" or len(sys.argv[2]) == 0:
                                                                nvdget(item)
                                                except Exception as err:
                                                        tqdm.write(f"{err}")
                                                tqdm.write(f"    |     [!] Exploit Not Found")
                                                
                                                count = count + 1
                                except Exception as err:
                                        tqdm.write(f"Error: {ip} - {err}")
                                        traceback.print_exc()
                                
                        xpl = 0
                        tqdm.write(f"    |")
                        tqdm.write(f"    | [!] Found {len(cves)-count} CVEs with related exploits")                
                        pgr = tqdm(total=int(len(cves) - count))
                        for item in cves:                            
                                try:
                                        pgr.set_description(f"CVE-ID: {item}")
                                        url = "https://www.exploit-db.com/exploits/"
                                        exploitdb = cs.edbid_from_cve(item)
                                        if len(exploitdb) > 0:
                                                tqdm.write(f"    |")
                                                pgr.write(f"    |   [+] {item}")
                                                #nvdget(item)
                                                
                                
                                        for id in exploitdb:
                                                try:
                                                        if sys.argv[2] == "--nvd" or "":
                                                                nvdget(item)
                                                except Exception as err:
                                                        tqdm.write(f"{err}")
                                                pgr.write(f"    |     [!] Exploit: {url}{id}")
                                                xpl = xpl + 1
                                                #pgr.update(1)
                                except Exception as err:
                                        pgr.write(f"Error: {ip} - {err}")
                                        traceback.print_exc()
                                
                        pgr.set_description(f"    | [!] Found {xpl} exploits for {len(cves)-count} CVEs")
                        tqdm.write(f"    |")
                        pgr.clear()
                except Exception as e:
                        tqdm.write(f"    | [-] {ip} - CVEs not found!")
        
        def nvdget(item):
                response = requests.get(nvdurl+item)
                alist = response.json()
                lenth = len(alist['vulnerabilities'][0]['cve']['references'])
                time.sleep(5)
                for x in range(lenth):
                        #nvd = alist['vulnerabilities'][0]['cve']['references'][x]['url']
                        tqdm.write(f"    |     [+] NVD: {alist['vulnerabilities'][0]['cve']['references'][x]['url']}")
                        
except:
        pass
