#!/usr/bin/env python3
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
            print(f"No data for subnet {id}")
        
        for subnet in subnets:
            net = subnetobj()
            net.section_id = id
            net.subnet_id = subnet["id"]
            net.network = subnet["subnet"]
            net.netmask = subnet["mask"]
            net.name = subnet["description"]
            all_subnets.append(net)
    return all_subnets


# Run SNMP query against list of routers, return list of ip objects
def snmp_arp_scan(username, password, servers):
    addresses = list()
    for server in servers:
        print(f"Querying SNMP Target {server}")
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
        net_phys_addr = session.walk('IP-MIB::ipNetToMediaPhysAddress')
        for item in net_phys_addr:
            oid=item.oid,
            oid_index=item.oid_index,
            snmp_type=item.snmp_type,
            value=item.value
            ind_spl = oid_index[0].split('.')
            ip = ".".join(ind_spl[1:len(ind_spl)])
            obj = ipobject()
            obj.mac = value
            obj.ip = ip
            addresses.append(obj)
    return addresses



# Query IPAM server for subnets, compare IP address against known IPAM networks
# if an address fits within a given network, create a record that it's used
def populate_ipam_from_arp(config):
    ipam_user = config['ipam']['username']
    ipam_pass = config['ipam']['appcode']
    ipam_server = config['ipam']['server']
    snmp_user = config['snmp']['username']
    snmp_pass = config['snmp']['password']
    snmp_servers = json.loads(config['snmp']['servers'])
    ips = snmp_arp_scan(snmp_user, snmp_pass, snmp_servers)
    subnets = get_ipam_subnets(ipam_user, ipam_pass, ipam_server)
    for ip in ips:
        ipa = ipaddress.ip_address(ip.ip)
        for subnet in subnets:
            network = ipaddress.ip_network(f"{subnet.network}/{subnet.netmask}")
            if ipa in network:
                cres = create_address(ip.ip, subnet.subnet_id, ipam_user, ipam_pass, ipam_server)
                print(f"{ip.ip} is in {subnet.network} - {subnet.name} - {cres}")


if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read('/etc/ipam/arp.conf')
    
    populate_ipam_from_arp(config)




