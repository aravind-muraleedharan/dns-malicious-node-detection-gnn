# ------------------------------------------------------------------------------
# Malicious Node Identification for DNS Data Using Graph Convolutional Networks (ICRAIE 2022)
#
# extract_ips.py
#
#   Extracts the IP column from a domain-IP mapping file.
#
# Input       : mal_final_ip_domain_mapping.csv - domain, ip
# Output      : final_ips_only.csv              - one IP per line
#
# Author      : Aravind M
# ------------------------------------------------------------------------------


fread = open('mal_final_ip_domain_mapping.csv', 'r')
fwrite = open('final_ips_only.csv', 'a+')

lines = fread.readlines()
for line in lines:
    line = line.replace('\n', '')
    v = line.split(',')
    fwrite.write(str(v[1]) + '\n')
    fwrite.flush()
    
