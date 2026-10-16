# ------------------------------------------------------------------------------
# Malicious Node Identification for DNS Data Using Graph Convolutional Networks (ICRAIE 2022)
#
# step1_get_block_start_indices.py
#
#   Subdomain-to-primary-domain similarity edges, step 1: takes the start index
#   of each block (from similar_edges_blocked/step1).
#
# Input       : indices.csv
# Output      : only_index.csv     - one block start index per line
#
# Author      : Aravind M
# ------------------------------------------------------------------------------


f = open('indices.csv', 'r')
list = []
fread = f.readlines()
for line in fread:
    line = line.replace('\n', '')
    v = line.split(',')
    list.append(v[0])
    # list.append(v[1])

fwrite = open('only_index.csv', 'a+')

for l in list:
    fwrite.write(str(l)+'\n')
fwrite.close()
f.close()
