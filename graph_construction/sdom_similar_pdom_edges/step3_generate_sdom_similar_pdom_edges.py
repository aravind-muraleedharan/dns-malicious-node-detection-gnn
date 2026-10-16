# ------------------------------------------------------------------------------
# Malicious Node Identification for DNS Data Using Graph Convolutional Networks (ICRAIE 2022)
#
# step3_generate_sdom_similar_pdom_edges.py
#
#   Subdomain-to-primary-domain similarity edges, step 3: connects representative
#   subdomains to primary domains with Levenshtein distance < 2.
#   (This edge type is not part of the final graph used in the paper.)
#
# Input       : specific_subdomains.csv, input_files/list_pdoms.csv
# Output      : final.csv          - source, target
#
# Author      : Aravind M
# ------------------------------------------------------------------------------


import Levenshtein as l

file1 = 'specific_subdomains.csv'
file2 = 'input_files/list_pdoms.csv'
fwrite = 'final.csv'


def similar_edges(file1, file2, fwrite):
    fwrite_similar = open(fwrite, 'a+')
    fwrite_similar.write('source' + ',' + 'target' + '\n')
    l1 = open(file1, 'r')
    l2 = open(file2, 'r')
    list1 = l1.readlines()
    list2 = l2.readlines()
    i = 1
    for line1 in list1:
        print(f"creating similar edges for {i}")
        line1 = line1.replace('\n', '')
        for line2 in list2:
            line2 = line2.replace('\n', '')
            if line1 != line2:
                dist = l.distance(line1, line2)
                if dist < 2:
                    row1 = line1 + ',' + line2 + '\n'
                    row2 = line2 + ',' + line1 + '\n'
                    if row1 not in fwrite_similar and row2 not in fwrite_similar:
                        fwrite_similar.write(line1 + ',' + line2 + '\n')
                        fwrite_similar.flush()
                else:
                    continue
        i += 1
    fwrite_similar.close()


similar_edges(file1, file2, fwrite)
