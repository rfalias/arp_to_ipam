#!/usr/bin/env python3
import argparse
import urllib3
import json
import easysnmp
import ipaddress
from easysnmp import Session
from phpipam_client import PhpIpamClient, GET, PATCH
import phpipam_client
import configparser
urllib3.disable_warnings()

# Store information about an address
class ipobject:
    def __init__(self):
        self.mac = None
        self.ip = None


# Store information about subnets from phpipam
class subnetobj:
    def __init__(self):
        self.section_id = None
        self.subnet_id = None
        self.network = None
        self.netmask = None
        self.name = None
        self.ips = list()


def get_subnet_addresses(subnetobj, username, password, server):
    username = username
    appcode = password
    ipam = PhpIpamClient(
        url=server,
        app_id=username,
        username=username,
        password=appcode,
        user_agent='snmpscanner', # custom user-agent header
        ssl_verify = False
    )
    ips = list()
    addresses = list()
    try:
        addresses = ipam.get(f"/subnets/{subnetobj.subnet_id}/addresses/")
    except:
        pass
    for address in addresses:
        ips.append(address["ip"])
    return ips


# Create an IP address in a given subnet
def create_address(ip, subnetId, username, password, server):
    result = ""
    username = username
    appcode = password
    ipam = PhpIpamClient(
        url=server,
        app_id=username,
        username=username,
        password=appcode,
        user_agent='snmpscanner', # custom user-agent header
        ssl_verify = False
    )
    # read objecs
    try:
        ipam.post(f"/addresses/?subnetId={subnetId}&ip={ip}",
                  {'description':'Added via SNMP', 'excludePing':1})
        result = f"Created IP Address {ip} in subnet {subnetId}"
    except phpipam_client.client.PhpIpamException as e:
        if "IP address already exists" in str(e):
            result = "IP Already Exists"
    return result


# Get all subnets from the IPAM server
def get_ipam_subnets(username, password, server):
    username = username
    appcode = password
    ipam = PhpIpamClient(
        url=server,
        app_id=username,
        username=username,
        password=appcode,
        user_agent='snmpscanner', # custom user-agent header
        ssl_verify = False
    )
    all_subnets = list()
    sections = ipam.get('/sections/')
    for section in sections:
        id = section["id"]
        subnets = ""
        try:
            subnets = ipam.get(f"/sections/{id}/subnets")
        except:
            pass

        for subnet in subnets:
            net = subnetobj()
            net.section_id = id
            net.subnet_id = subnet["id"]
            net.network = subnet["subnet"]
            net.netmask = subnet["mask"]
            net.name = subnet["description"]
            net.ips = get_subnet_addresses(net,username,password,server)
            all_subnets.append(net)
    return all_subnets


# Run SNMP query against list of routers, return list of ip objects
def snmp_arp_scan(username, password, servers, quiet=False):
    addresses = list()
    for server in servers:
        if not quiet:
            print(f"Querying SNMP Target {server} with mib {servers[server]}")
        session = Session(
                  hostname=server,
                  security_level='auth_with_privacy',
                  version=3,
                  security_username=username,
                  auth_protocol='SHA',
                  auth_password=password,
                  privacy_password=password,
                  privacy_protocol='AES',
                  use_sprint_value=True
        )
        net_phys_addr = ""
        try:
            net_phys_addr = session.walk(servers[server])
        except:
            if not quiet:
                print("Unable to contact SNMP server, check connection details")
            continue
        for item in net_phys_addr:
            oid=item.oid,
            oid_index=item.oid_index,
            snmp_type=item.snmp_type,
            value=item.value
            ind_spl = oid_index[0].split('.')
            if "ipNetToPhysicalPhysAddress" in oid:
                ip = ".".join(ind_spl[2:len(ind_spl)])
            else:
                ip = ".".join(ind_spl[1:len(ind_spl)])
            obj = ipobject()
            obj.mac = value
            obj.ip = ip
            addresses.append(obj)
    return addresses



# Query IPAM server for subnets, compare IP address against known IPAM networks
# if an address fits within a given network, create a record that it's used
def populate_ipam_from_arp(config, dryrun=False, quiet=False, showskipped=False):
    ipam_user = config['ipam']['username']
    ipam_pass = config['ipam']['appcode']
    ipam_server = config['ipam']['server']
    snmp_user = config['snmp']['username']
    snmp_pass = config['snmp']['password']
    snmp_servers = json.loads(config['snmp']['servers'])
    ips = snmp_arp_scan(snmp_user, snmp_pass, snmp_servers, quiet)
    subnets = get_ipam_subnets(ipam_user, ipam_pass, ipam_server)
    for ip in ips:
        ipa = ipaddress.ip_address(ip.ip)
        for subnet in subnets:
            network = ipaddress.ip_network(f"{subnet.network}/{subnet.netmask}")
            if ip.ip in subnet.ips:
                if not quiet and showskipped:
                    print(f"{ip.ip} is in {subnet.network} - {subnet.name} - Skipped")
                continue
            if ipa in network:
                cres = "Dry Run"
                if not dryrun:
                    cres = create_address(ip.ip, subnet.subnet_id, ipam_user, ipam_pass, ipam_server)
                if not quiet:
                    print(f"{ip.ip} is in {subnet.network} - {subnet.name} - {cres}")


if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read('/etc/ipam/arp.conf')
    parser = argparse.ArgumentParser(description='arp to ipam')
    parser.add_argument('-d', '--dry-run', required=False, action='store_true', help="Dry Run")
    parser.add_argument('-q', '--quiet', required=False, action='store_true', help="Quiet")
    parser.add_argument('--show-skipped', required=False, action='store_true', help="Show IP's that were skipped due to existing already")
    args = parser.parse_args()
    populate_ipam_from_arp(config, args.dry_run, args.quiet, args.show_skipped)





