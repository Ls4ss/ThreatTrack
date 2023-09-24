import sys
import getinfo
import shodan
import ipcalc
import ipaddress

APIKEY = open("API.txt", "r")
SHODAN_API_KEY = APIKEY.read().splitlines()

api = shodan.Shodan(SHODAN_API_KEY)   
        
#IPCAL - CALCULA A RANGE
def calcr(ip):
        for address in ipcalc.Network(ip):
                try:
                        ip = str(address)
                        getinfo.main(ip)
                except Exception as err:
                        print(f"{err}")

# FUNCAO PARA UTILIZAR DEMAIS CONSULTAS DO SHODAN
def shodan_search(page, loopcount, shodan_query):
        query = api.search(query=shodan_query, page=page)
        total = api.count(query=shodan_query)
        if total['total'] == 0:
                    print(f"\n           [!] IP's not found for this query, check the filter used")
                    #options()
                    sys.exit()
        print(f"\n        ┏━ [!] Found {total['total']} results for this query")
        print("        ┗━ [!] This query will consume your API credits")
        for x in range(total['total']):
                ip = query['matches'][x]['ip_str']
                getinfo.main(ip)
        if loopcount != total[total]:
                page = page + 1
                loopcount = loopcount + 1
                shodan_search(page, loopcount, shodan_query)
        else:
                sys.exit(1)

def get_domain(domain):
        shodan_get_domain = api.dns.domain_info(domain=domain, history=True, type=None, page=1)
        print("\n           [!] This query will consume your API credits")
        print(f"\n        ┏━ [!] ┃━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[ {domain} ]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┃")
        for x in shodan_get_domain['data']:
                print(f"        ┃   ┗━ [+] DOMAIN: {x['subdomain']}.{domain} TYPE: {x['type']}\n        ┃   ┃   ┗━ [+] VALUE: {x['value']}\n        ┃   ┃")

        for x in shodan_get_domain['data']:
                try:
                        ip = str(ipaddress.ip_address(x['value']))
                        getinfo.main(ip)        
                except Exception as e:
                        pass

def main():                             
        try:
                shodan_query = sys.argv[1]
        # CONDICAO PARA REALIZAR CONSULTAS GRATUITAS NA API DO SHODAN                
                if shodan_query[0:5] == "host:":
                        ip = shodan_query[5:]
                        if shodan_query[-3:-2] == "/":
                                calcr(ip)
                        else:
                                getinfo.main(ip)

        # IMPLEMENTACAO DA ENTRADA DE DADOS VIA ARQUIVO                
                elif shodan_query[0:5] == "file:":
                        file_list = shodan_query[5:]
                        with open(file_list, 'r') as file:
                                        for line in file:
                                                line_file = line.strip()
                                                if line_file[-3:-2] == "/":
                                                        ip = line_file
                                                        calcr(ip)
                                                else:
                                                        try:
                                                                ip = str(ipaddress.ip_address(line_file))
                                                                getinfo.main(ip)
                                                        except:
                                                                domain = line.strip()
                                                                get_domain(domain)

                elif shodan_query[0:7] == "domain:":
                        domain = shodan_query[7:]
                        get_domain(domain)
                elif shodan_query == "--xdbupdate":
                        getinfo.get_xdb_update()

                else:
                        loopcount = 1
                        page = 1
                        try:
                                shodan_search(page, loopcount, shodan_query)
                        except Exception as e:
                                print(e)
                                
        except Exception as e:
                print("[+] Err:", e)
                getinfo.get_banner()
                pass
if __name__ == "__main__":
    main()
