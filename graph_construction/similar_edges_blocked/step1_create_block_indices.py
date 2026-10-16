# ------------------------------------------------------------------------------
# Malicious Node Identification for DNS Data Using Graph Convolutional Networks (ICRAIE 2022)
#
# step1_create_block_indices.py
#
#   Subdomain similarity edges, step 1: walks the sorted subdomain list and
#   splits it into blocks of consecutive similar names (a new block starts where
#   the Levenshtein distance between neighbours is > 2).
#
# Input       : input_files/list_sdoms.csv (sorted)
# Output      : indices.csv        - start, end index of each block
#
# Author      : Aravind M
# ------------------------------------------------------------------------------


import Levenshtein as l
import tensorflow as tf

fread = open('input_files/list_sdoms.csv', 'r')
all_subdomains = fread.readlines()
subdomains = []
for line in all_subdomains:
    line = line.replace('\n', '')
    subdomains.append(line)
fread.close()

fwrite_similar = open('indices.csv', 'a+')
# fwrite_similar.write('source' + ',' + 'target' + '\n')

with tf.compat.v1.Session() as sess:

    start_count = 0
    for i in range(len(subdomains)):
        print("Processing the element number  |", i)
        if i == len(subdomains)-1:
            i = i-1
        if l.distance(subdomains[i], subdomains[i+1]) > 2:
            fwrite_similar.write(str(start_count) + ',' + str(i) + '\n')
            start_count = i
    fwrite_similar.close()

