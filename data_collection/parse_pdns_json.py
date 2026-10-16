# ------------------------------------------------------------------------------
# Malicious Node Identification for DNS Data Using Graph Convolutional Networks (ICRAIE 2022)
#
# parse_pdns_json.py
#
#   Reads passive DNS records (one JSON object per line) and extracts the
#   resolving IP (first A record), the FQDN and its primary domain.
#
# Input       : aravindData        - passive DNS records in JSON lines format
# Output      : entries.csv        - ip, fqdn, primary_domain
#
# Author      : Aravind M
# ------------------------------------------------------------------------------


import traceback
import json

f = open('aravindData')
f2 = open("entries.csv", "a+")
lines = f.readlines()
for line in lines:
    data1 = json.loads(line)
    ip1 = data1["a"]
    if len(ip1) !=0:
        ip = ip1[0]
    else:
        ip = ''       
    print("ip: ", ip)
    fqdn = data1["fqdn"]
    print("fqdn: ", fqdn)
    pdom = data1["primary_domain"]
    print("here primary domain is", pdom)
    print('\n')
    f2.write(str(ip)+','+fqdn+','+ pdom+ ','+'\n')
    '''for i in domains:
        print(i)
        f2.write(str(ip) + ',' + i + '\n')
    '''
# Closing file
f.close()

