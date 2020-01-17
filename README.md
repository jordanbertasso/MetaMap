# MetaMap
### A simple Python script to run a Metasploit module over the hosts in an Nmap scan

## Usage
```
usage: metamap.py [-h] (--xml-file XML_FILE | --regex-file REGEX_FILE | --target TARGET_IP) [--filter [SUBNET [SUBNET ...]]] [--verbose] [--debug]
                  [--module-options MODULE_OPTIONS]
                  output-file module-path

Run the IP addresses in a Nmap xml file or any file containing IP addresses through a Metasploit module.

positional arguments:
  output-file           File to contain the Metasploit module output
  module-path           Full path to the module e.g. "auxiliary/scanner/rdp/cve_2019_0708_bluekeep"

optional arguments:
  -h, --help            show this help message and exit
  --xml-file XML_FILE, -x XML_FILE
                        Nmap xml file containing scan results
  --regex-file REGEX_FILE, -r REGEX_FILE
                        Any file containing seperated IP addresses. IP addresses will be captured using a regular expression
  --target TARGET_IP, -t TARGET_IP
                        Single target IP
  --filter [SUBNET [SUBNET ...]], -f [SUBNET [SUBNET ...]]
                        Subnet to exclude from the scan e.g. "10.10.10.0/24 10.11.0.0/16"
  --verbose, -v         Display Metasploit output
  --debug, -d           Display debug output
  --module-options MODULE_OPTIONS, -m MODULE_OPTIONS
                        Semi-colon seperated commands to set options e.g. "set ShowProgressPercent 1; set VERBOSE true;"
```

## Example
```
python3 metamap.py --xml-file rdp_nmap.xml --filter 10.10.10.0/24 10.11.0.0/16 --module-options "set showprogressPercent 1; set VERBOSE true;" out.txt "auxiliary/scanner/rdp/cve_2019_0708_bluekeep"
```
