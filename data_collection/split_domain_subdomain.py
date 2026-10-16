# ------------------------------------------------------------------------------
# Malicious Node Identification for DNS Data Using Graph Convolutional Networks (ICRAIE 2022)
#
# split_domain_subdomain.py
#
#   Splits a list of domains (with their resolving IPs) into primary domains
#   and subdomains using tldextract.
#
# Input       : benign_5L_domains_ip_generated.csv  - domain, ip
# Output      : cisco_pdom_ip_list.csv              - primary domain, ip
#               cisco_sdom_ip_list.csv              - subdomain, ip
#               cisco_sdom_found_out_pdoms_list.csv - subdomain, primary domain
#
# Author      : Aravind M
# ------------------------------------------------------------------------------


import csv
import tldextract
import traceback

f1 = open('benign_5L_domains_ip_generated.csv', 'r')


f2 = open('cisco_pdom_ip_list.csv', 'a+')
f3 = open('cisco_sdom_ip_list.csv', 'a+')
f4 = open('cisco_sdom_found_out_pdoms_list.csv', 'a+')

lines = f1.readlines()
i = 0
f2.write('pdom' + ',' + 'resolving_ip' + '\n')
f3.write('sdom' + ',' + 'resolving_ip' + '\n')
f4.write('sdom' + ',' + 'pdom' + '\n')

for row in lines:
    v = row.split(',')
    v[0] = v[0].replace('\n', '')
    v[1] = v[1].replace('\n', '')

    try:
        ext = tldextract.extract(v[0])
        primary_domain = '.'.join(ext[1:])
        subdomain = '.'.join(ext[0:])
        if primary_domain == v[0]:
            f2.write(primary_domain + ',' + v[1] + '\n')
            f2.flush()

        elif subdomain == v[0]:
            f3.write(subdomain + ',' + v[1] + '\n')
            f4.write(subdomain + ',' + primary_domain + '\n')
            f3.flush()
            f4.flush()
        print(v[0] + ',' + primary_domain + ',' + subdomain + ',' + str(v[1]))
        i += 1
    except Exception as e:
        print("error occurred on", row[1])
        traceback.print_stack()
f2.close()
f3.close()
f4.close()

