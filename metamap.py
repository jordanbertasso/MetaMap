#!/usr/bin/env python3

import argparse
import xmltodict
import subprocess
import tempfile

from ipaddress import ip_network

def main():
    args = init_argparse()

    ip_list = xml_to_ips(args.input_file)

    if args.filter_subnets:
        filtered_ips = filter_out_hosts(ip_list, args.filter_subnets)

    run_module(args.module_path, filtered_ips, args.output_file, args.module_options, args.display_output)
    
    return

def init_argparse():
    parser = argparse.ArgumentParser(
        description='Run the IP addresses in a Nmap xml file through a Metasploit module.')

    parser.add_argument('input_file', type=str,
                        metavar='input-file',
                        help='Nmap xml file containing scan results')

    parser.add_argument('output_file', type=str,
                        metavar='output-file',
                        help='File to contain the Metasploit module output')

    parser.add_argument('module_path', type=str,
                        metavar='module-path',
                        help='Full path to the module e.g. "auxiliary/scanner/rdp/cve_2019_0708_bluekeep"')

    parser.add_argument('--display-output', '-d',
                        action='store_true',
                        help='Display Metasploit output')

    parser.add_argument('--module-options', '-m', type=str,
                        help='Semi-colon seperated commands to set options e.g. "set ShowProgressPercent 1; set VERBOSE true;"')

    parser.add_argument('--filter', '-f', type=str,
                        dest='filter_subnets',
                        metavar='SUBNET',
                        nargs='*',
                        help='Subnet to exclude from the scan e.g. "10.10.10.0/24 10.11.0.0/16"')

    args = parser.parse_args()
    return args


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
