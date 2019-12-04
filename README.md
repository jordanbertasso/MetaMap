# MetaMap
### A simple Python script to run a Metasploit module over the hosts in an Nmap scan

## Usage
```
usage: metamap.py [-h] [--display-output] [--module-options MODULE_OPTIONS]
                  [--filter [SUBNET [SUBNET ...]]]
                  input-file output-file module-path

Run the IP addresses in a Nmap xml file through a Metasploit module.

positional arguments:
  input-file            Nmap xml file containing scan results
  output-file           File to contain the Metasploit module output
  module-path           Full path to the module e.g.
                        "auxiliary/scanner/rdp/cve_2019_0708_bluekeep"

optional arguments:
  -h, --help            show this help message and exit
  --display-output, -d  Display Metasploit output
  --module-options MODULE_OPTIONS, -m MODULE_OPTIONS
                        Semi-colon seperated commands to set options e.g. "set
                        ShowProgressPercent 1; set VERBOSE true;"
  --filter [SUBNET [SUBNET ...]], -f [SUBNET [SUBNET ...]]
                        Subnet to exclude from the scan e.g. "10.10.10.0/24
                        10.11.0.0/16"
```

## Example
```
python3 metamap.py --filter 10.10.10.0/24 10.11.0.0/16 -m "set showprogressPercent 1; set VERBOSE true;" rdp.xml out.txt auxiliary/scanner/rdp/cve_2019_0708_bluekeep
```
