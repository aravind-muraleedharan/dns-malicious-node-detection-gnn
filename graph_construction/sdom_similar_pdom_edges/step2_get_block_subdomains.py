# ------------------------------------------------------------------------------
# Malicious Node Identification for DNS Data Using Graph Convolutional Networks (ICRAIE 2022)
#
# step2_get_block_subdomains.py
#
#   Subdomain-to-primary-domain similarity edges, step 2: picks the subdomain at
#   each block start index as the representative of that block.
#
# Input       : only_index.csv, input_files/list_sdoms.csv
# Output      : specific_subdomains.csv
#
# Author      : Aravind M
# ------------------------------------------------------------------------------


f = open('only_index.csv', 'r')
sdom_file = open('input_files/list_sdoms.csv', 'r')
sdoms = sdom_file.readlines()
list_sdom = []

for d in sdoms:
    d = d.replace('\n', '')
    list_sdom.append(d)

list = []

fread = f.readlines()
for line in fread:
    line = line.replace('\n', '')
    list.append(list_sdom[int(line)])


fwrite = open('specific_subdomains.csv', 'a+')

for l in list:
    fwrite.write(l+'\n')
fwrite.close()
f.close()
