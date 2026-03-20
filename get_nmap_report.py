import argparse
import pyperclip
import xmltodict

RED = '\033[91m'
GREEN = '\033[92m'
BLUE = '\033[94m'
RESET = '\033[0m'

def main():
    parser = argparse.ArgumentParser(description="Nmap script to run a detailed scan based on open ports")
    parser.add_argument("-f", "--file", type=str, help="XML File nmap report with open ports")

    args = parser.parse_args()

    if args.file:
        print(f"Reading Nmap report from: {args.file}")
        get_nmap_report(args.file)
    else:
        print(f"{RED}No file specified.{RESET}")

def get_nmap_report(file):
    with open(file, 'r',encoding='utf-8') as f:
        xml_content = f.read()

    scan_data = xmltodict.parse(xml_content)
    hosts = scan_data['nmaprun']['host']
    # If only one host, 'host' will be a dict. If multiple, it will be a list of dicts.
    #print(hosts)
    if isinstance(hosts, list):
        for host in hosts:
            print(f"{BLUE}Host: {host['status']['@state']} - {host['address']['@addr']}{RESET}")
            get_open_ports(host)
    else:
        print(f"{BLUE}Host: {hosts['status']['@state']} - {hosts['address']['@addr']}{RESET}")
        get_open_ports(hosts)
    
def get_open_ports(host):
    port_list = []
    if 'ports' in host:
        ports = host['ports']['port']
        if isinstance(ports, list):
            for port in ports:
                if port['state']['@state'] == 'open':
                    #print(f"Open Port: {port['@portid']} - {port['@protocol']}")
                    port_list.append(port['@portid'])
        else:
            if ports['state']['@state'] == 'open':
                #print(f"Open Port: {ports['@portid']} - {ports['@protocol']}")   
                port_list.append(ports['@portid'])

    full_nmap_command = f"nmap -sCV -p {','.join(port_list)} {host['address']['@addr']} -oA detailed_scan"
    pyperclip.copy(full_nmap_command)
    print(f"Nmap command copied to clipboard: {GREEN}{full_nmap_command}{RESET}")
    print(f"{BLUE}xsltproc  detailed_scan.xml -o detailed_scan.html{RESET}")


if __name__ == "__main__":
    main()