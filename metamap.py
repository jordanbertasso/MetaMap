#!/usr/bin/env python3

import argparse
import subprocess
import tempfile
import re
import mmap
import xmltodict

from ipaddress import ip_network

def main():
    args = init_argparse()

    ip_list = []
    if args.xml_file:
        ip_list = xml_to_ips(args.xml_file)
    else:
        ip_list = ip_list_from_re(args.regex_file)

    if args.filter_subnets:
        filtered_ips = filter_out_hosts(ip_list, args.filter_subnets)

    run_module(args.module_path, filtered_ips, args.output_file, args.module_options, args.display_output)
    
    return

def init_argparse():
    parser = argparse.ArgumentParser(
        description='Run the IP addresses in a Nmap xml file or any file containing IP addresses through a Metasploit module.')

    parser.add_argument('output_file', type=str,
                        metavar='output-file',
                        help='File to contain the Metasploit module output')

    parser.add_argument('module_path', type=str,
                        metavar='module-path',
                        help='Full path to the module e.g. "auxiliary/scanner/rdp/cve_2019_0708_bluekeep"')

    exclusive_file_group = parser.add_mutually_exclusive_group(required=True)

    exclusive_file_group.add_argument('--xml-file', '-x', type=str,
                        dest='xml_file',
                        help='Nmap xml file containing scan results')

    exclusive_file_group.add_argument('--regex-file', '-r', type=str,
                        dest='regex_file',
                        help='Any file containing seperated IP addresses. IP addresses will be captured\
                              using a regular expression')

    parser.add_argument('--filter', '-f', type=str,
                        dest='filter_subnets',
                        metavar='SUBNET',
                        nargs='*',
                        help='Subnet to exclude from the scan e.g. "10.10.10.0/24 10.11.0.0/16"')

    parser.add_argument('--display-output', '-d',
                        action='store_true',
                        help='Display Metasploit output')

    parser.add_argument('--module-options', '-m', type=str,
                        help='Semi-colon seperated commands to set options e.g. "set ShowProgressPercent 1; set VERBOSE true;"')

    args = parser.parse_args()
    return args

def ip_list_from_re(filename):
    """
    Extract all of the scanned IP addresses
    from a Nmap gnmap file to a list.
    """

    with open(filename, 'r+b') as f:
        data = mmap.mmap(f.fileno(), 0)
        ips = re.findall(b'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', data)
        ips = [ip.decode() for ip in ips]
        ips = list(set(ips))

    return ips

def xml_to_ips(filename):
    """
    Extract all of the scanned IP addresses
    from a Nmap xml file to a list.
    """

    ip_list = []

    with open(filename, 'r') as f:
        xml_dict = xmltodict.parse(f.read())

        for host in xml_dict['nmaprun']['host']:
            try:
                ip_list.append(host['address']['@addr'])
            except:
                try:
                    ip_list.append(host['address'][0]['@addr'])
                except Exception as e:
                    print(e)
                    continue

    return ip_list


def filter_out_hosts(host_list, subnets):
    """
    Remove a list of subnets from a list
    of IP addresses
    """

    filtered_list = host_list

    for subnet in subnets:
        sub = ip_network(subnet)
        print(f'[FILTERING]: {sub}')
        filtered_list = [ip for ip in filter(
            lambda ip: not ip_network(ip).subnet_of(sub), filtered_list)]

    return filtered_list


def run_module(module_path, ip_list, output_file, module_options, display_output):
    """
    Run a Metasploit module based on the `module_path`,
    with:
    RHOST: `ip_list`
    EXTRA OPTIONS: `module_options`
    $ spool `output_file`

    `display_output` will decide whether the Metasploits
    output is printed to the terminal or not.
    """

    f = tempfile.NamedTemporaryFile(mode="w+", delete=False)
    for ip in ip_list:
        f.write(f'{ip}\n')
    f.close()

    print(f'[IP LIST]: {f.name}')

    args = ['msfconsole', '-qx',
            f'use {module_path}; set rhosts file:{f.name}; {module_options}; spool {output_file}; run; exit;']
    print(f'[RUNNING]: {"".join(args)}')

    if display_output:
        p = subprocess.Popen(args)
        p.communicate() 
    else:
        p = subprocess.Popen(args, stdout=subprocess.DEVNULL)
        p.wait()

#TODO - Output positive Metasploit hosts to csv

if __name__ == '__main__':
    main()
