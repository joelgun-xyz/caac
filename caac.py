import argparse
import os
import sys
import yaml
import subprocess
import dns.resolver
import tqdm
import time 
import click
import requests
import binascii



__authors__ = "joelgun"
__copyright__ = ""
__credits__ = ["joelgun"]
__license__ = "MIT"
__date__ = "Some galaxy far far away"
__version__ = "1.0"
__maintainer__ = "joelgun"
__email__ = "twitter://@joelgun"
__status__ = "production"
__description__ = "CAA record checker / creator"

logo_string = '''   


                             .oOOOo.     Oo       Oo     .oOOOo.  
                            .O     o    o  O     o  O   .O     o  
                            o          O    o   O    o  o         
                            o         oOooOoOo oOooOoOo o         
                            o         o      O o      O o         
                            O         O      o O      o O         
                            `o     .o o      O o      O `o     .o 
                             `OoooO'  O.     O O.     O  `OoooO'  
                            @joelgun - v1.0
                     
                     
'''

def logo():
    print(logo_string)
    pass

def get_ctm_data(domain):

    detected_ca = list()
    all_ca_data = list()
    found_ctm_ca = list()
    found_ctm_legacy_ca = list()

    print(f"\n\n[ +++ ]  Trying to find all CA's over CTM Logs....\n\n")

    certspotter_url = ' https://api.certspotter.com/v1/issuances?domain='+ domain +'&include_subdomains=true&expand=dns_names&expand=issuer'
    response = requests.get(certspotter_url)
    ca_data = response.json()
    progressbar_unique()
   
    for ca_d in ca_data:
        ca_row = ca_d.get('issuer').get('name')
        ca_lst = ca_row.split()
        found_ca = ca_lst[1].replace("O=" , "" , 1)
        all_ca_data.append(found_ca.lower())

    found_all_ca = list(set(tuple(all_ca_data)))
    
    for cas in found_all_ca:
        for ca_v in certificate_authorities['certauthvalues']:
            res = ca_v.lower().find(cas)
            if res >= 0:
                found_ctm_ca.append(certificate_authorities['certauthvalues'][ca_v])
        for ca_v in certificate_authorities['certauthvalues_legacy']:
            res = ca_v.lower().find(cas)
            if res >= 0:
                found_ctm_legacy_ca.append(certificate_authorities['certauthvalues_legacy'][ca_v])

    return found_ctm_ca, found_ctm_legacy_ca

def progressbar_unique():
    for i in tqdm.trange(int(1e2), miniters=int(1e1), ascii=True,
                     desc="1337", dynamic_ncols=True):
        time.sleep(0.01)

def progressbar_mass():
   for i in trange(10):
        for j in trange(int(1e7), leave=False, unit_scale=True):
            pass

def goodbye():
    print("see you lator, aligator!")

def create_caa(domain):
    contact_email = str()
    print("\n\n[ +++ ] Generate a CAA policy. \n")
    value = click.prompt('Enter 1 for CTM generated and 2 for input generated.', type=int)
    if value == 1:
        found_ca_ctm, found_ca_ctm_legacy = get_ctm_data(domain)
        if click.confirm('\n\nDo you want to add an emailadresss to the record?'):
            contact_email = click.prompt('\n\nEnter a emailaddress for iodef entry, eg. ca@yourcompany.com ', type=str)
        else:
           pass 
        generate_caa(domain, found_ca_ctm, found_ca_ctm_legacy, contact_email)

    elif value == 2:
        ca_values = input("Enter your CA's comma seperated eg. (swisssign.com,digicert.com): ")
        cas_input = ca_values.split(",")
        if click.confirm('Do you want to add an emailaddress to the record?'):
            contact_email = click.prompt('Enter a emailaddress for iodef entry, eg. ca@yourcompany.com', type=str)
        generate_caa(domain, cas_input,found_ca_ctm_legacy,contact_email)
      
    else:
        pass
   
def generate_caa(domain, cas,cas_legacy, contact_email=False):
    
    print("\n[ >>>> ] ENTRIES [ <<<< ]\n")
    print("Generic - For Google Cloud DNS, Route 53, DNSimple, and other hosted DNS services: \n")
    print(f" Name   |    Type  |  Value                ")
    print("-------------------------------------------- >>\n")
    print(f'  {domain}.     CAA     0 issue "{cas[0]}"')
    for ca_entries in cas[1:]:
        print(f'              CAA     0 issue "{ca_entries}"')
    if contact_email:
        print(f'              CAA     0 iodef "{contact_email}"')

    print("\n\nStandard Zone File - For BIND ≥9.9.6, PowerDNS ≥4.0.0, NSD ≥4.0.1, Knot DNS ≥2.2.0\n")
    print(f" Name   |    Type  |  Value                ")
    print("-------------------------------------------- >>\n")
    for ca_entries in cas:
        print(f'  {domain}.  IN   CAA     0 issue "{ca_entries}"')
    if contact_email:
        print(f' {domain}.  IN    CAA     0 iodef "{contact_email}"')

    print("\n\nLegacy Zone File (RFC 3597 Syntax) - For BIND <9.9.6, NSD <4.0.1, Windows Server 2016\n")
    print(f" Name   |    Type  |  Value                ")
    print("-------------------------------------------- >>\n")
    for ca_entries_legacy in cas_legacy:
            print(f"  {domain}.     IN TYPE257    \# {ca_entries_legacy}")

    print("\n\ndnsmasq\n")
    print(f" Name   |    Type  |  Value                ")
    print("-------------------------------------------- >>\n")
    for ca_entries in cas:
        value = 'issue'+ca_entries
        hexvalue = binascii.hexlify(value.encode())
        print(f"  --dns-rr={domain},257,{'0005'+hexvalue.decode().upper()}")
    if contact_email:
        value = 'iodef'+contact_email
        hexvalue = binascii.hexlify(value.encode())
        print(f"  --dns-rr={domain},257,{'0005'+hexvalue.decode().upper()}")
    print("\n\n\n\n")
def caa_check(domain):
    try:
        records = dns.resolver.query(domain, 'CAA')
        
        print('\n\n[ +++ ] Found an entry for "{}"!\n'.format(domain))
        for record in records:
           print('{}. {} '.format(domain,record))
        print('\n')
    except:
        print("\n\n[ +++ ] There was no CAA Record!\n")
        if click.confirm('Do you want to create one?'):
            create_caa(domain)
        else:
           goodbye()
def caa_check_bulk(domains):
    domain_list = domains.split(",")
    for domain in domain_list:
        try:
            records = dns.resolver.query(domain, 'CAA')
            print('\n\n[ +++ ] Found an entry for "{}"!\n'.format(domain))
            for record in records:
                print(f'{domain}. {record} ')
                
        except:
            print(f"\n\n[ +++ ] There was no CAA record for {domain}!\n\n") 
    print("\n")

def main():
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(", ".join(__authors__), __date__)
    )

    parser.add_argument("-d", help="Checks domain for CAA record and let's you generate one")
    parser.add_argument("-bd", help="checks a bulk of domain for CAA record")

    args = parser.parse_args()

    if args.d:
        progressbar_unique()
       
        caa_check(args.d)
    elif args.bd:
        caa_check_bulk(args.bd)
    else:
        print(f"\n\n  [ !! ] No domain provided\n")
        print(f"  [ >> ] Usage: Checks domain for CAA record and let's you generate one >> python3 caac.py -d example.com\n\n")
        print(f"  [ >> ] Usage: Checks domain for CAA record and let's you generate one >> python3 caac.py -bd example.com,example2.com,example3.com\n\n")

if __name__ == '__main__':
    logo()
    with open('certificate_authorities.yaml', 'r') as f:
        certificate_authorities = yaml.safe_load(f)
    main()