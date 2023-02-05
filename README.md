<h6 align="center">Shodan + ExploitDB</h6>
<h1 align="center">SPLOIT</h1>

### [Help](https://github.com/Ls4ss/Sploit/blob/main/README.md#help-1) [Example](https://github.com/Ls4ss/Sploit/blob/main/README.md#example) [Install](https://github.com/Ls4ss/Sploit/blob/main/README.md#install)

### Help
<img width="700" src=https://raw.githubusercontent.com/Ls4ss/Sploit/main/example/help.png>

### Example
<img width="700" src=https://raw.githubusercontent.com/Ls4ss/Sploit/main/example/xpl.png>

### Install

        git clone https://github.com/Ls4ss/Sploit.git

        pip3 install -r requirements.txt
        
##### Get your API Shodan - https://account.shodan.io/
##### Insert your API Shodan in API.txt

##### python3 sploit.py -h
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
