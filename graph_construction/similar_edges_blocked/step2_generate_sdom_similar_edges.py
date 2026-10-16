# ------------------------------------------------------------------------------
# Malicious Node Identification for DNS Data Using Graph Convolutional Networks (ICRAIE 2022)
#
# step2_generate_sdom_similar_edges.py
#
#   Subdomain similarity edges, step 2: compares subdomains only within each
#   block and writes the pairs with Levenshtein distance < 2 (sdom_similar edges).
#
# Input       : input_files/list_sdoms.csv, indices.csv
# Output      : file.csv           - source, target
#
# Author      : Aravind M
# ------------------------------------------------------------------------------


import Levenshtein as l
import tensorflow as tf

fread = open('input_files/list_sdoms.csv', 'r')
all_subdomains = fread.readlines()
list_all_subdomains = []
for line in all_subdomains:
    line = line.replace('\n', '')
    list_all_subdomains.append(line)
fread.close()
index_file = open('indices.csv', 'r')
indices = index_file.readlines()

fwrite_similar = open('file.csv', 'a+')
fwrite_similar.write('source' + ',' + 'target' + '\n')

with tf.compat.v1.Session() as sess:
    def call(subdomain, start, end):
        for a in range(start, end):
            if subdomain != list_all_subdomains[a]:
                if l.distance(subdomain, list_all_subdomains[a]) < 2:
                    row1 = subdomain + ',' + list_all_subdomains[a] + '\n'
                    row2 = list_all_subdomains[a] + ',' + subdomain + '\n'
                    if row1 not in fwrite_similar:
                        if row2 not in fwrite_similar:
                            fwrite_similar.write(row1)
                            fwrite_similar.flush()

    for index in indices:
        index = index.replace('\n', '')
        print(index)
        idx = index.split(',')
        for b in range(int(idx[0]), int(idx[1])):
            call(list_all_subdomains[b], int(idx[0]), int(idx[1]))

    fwrite_similar.close()

