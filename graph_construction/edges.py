# ------------------------------------------------------------------------------
# Malicious Node Identification for DNS Data Using Graph Convolutional Networks (ICRAIE 2022)
#
# edges.py
#
#   Edge generation functions for the knowledge graph.
#     similar_edges       - domain names with Levenshtein distance < 2
#     apex_edges          - subdomain -> its primary domain
#     same_pdom_diff_tld  - same domain name with a different TLD
#     generate_edge_list  - writes edges_list.csv (edge type -> edge file)
#
# Input       : input_files/list_pdoms.csv, input_files/list_sdoms.csv
# Output      : edge_files/*.csv    - source, target
#
# Author      : Aravind M
# ------------------------------------------------------------------------------


import tldextract
import Levenshtein as l


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


def apex_edges(sdom_file, fwrite):

    fwrite_apex = open(fwrite, 'a+')
    fwrite_apex.write('source' + ',' + 'target' + '\n')
    sdom = open(sdom_file, 'r')
    sdoms = sdom.readlines()
    i = 1
    for line in sdoms:
        print(f"creating apex edges for {i}")
        line = line.replace('\n', '')
        ext = tldextract.extract(line)
        primary_domain = '.'.join(ext[1:])
        row = line + ',' + primary_domain + '\n'
        if row not in fwrite_apex:
            fwrite_apex.write(line + ',' + primary_domain + '\n')
            fwrite_apex.flush()
        i += 1
    fwrite_apex.close()


def same_pdom_diff_tld(pdom_file1, pdom_file2, fwrite):

    fwrite_tld = open(fwrite, 'a+')
    fwrite_tld.write('source' + ',' + 'target' + '\n')
    pdom1 = open(pdom_file1, 'r')
    pdom2 = open(pdom_file2, 'r')
    pdoms1 = pdom1.readlines()
    pdoms2 = pdom2.readlines()
    i = 1
    for line1 in pdoms1:
        print(f"creating same_pdom_diff_tld edges for {i}")
        line1 = line1.replace('\n', '')
        ext1 = tldextract.extract(line1)
        domain1 = ext1[1]
        for line2 in pdoms2:
            line2 = line2.replace('\n', '')
            ext2 = tldextract.extract(line2)
            domain2 = ext2[1]
            if line1 != line2:
                if domain2 == domain1:
                    row1 = line1 + ',' + line2 + '\n'
                    row2 = line2 + ',' + line1 + '\n'
                    if row1 not in fwrite_tld and row2 not in fwrite_tld:
                        fwrite_tld.write(line1 + ',' + line2 + '\n')
                        fwrite_tld.flush()
        i += 1
    fwrite_tld.close()


def generate_edge_list(source_nodes, target_nodes, edge_type, file_loc, fwrite):

    file = open(fwrite, 'a+')
    print("generating_edges_list")
    for i in range(len(source_nodes)):
        file.write(source_nodes[i] + ',' + target_nodes[i] + ',' + edge_type[i] + ',' + file_loc[i] + '\n')
        file.flush()

