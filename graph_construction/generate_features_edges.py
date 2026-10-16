# ------------------------------------------------------------------------------
# Malicious Node Identification for DNS Data Using Graph Convolutional Networks (ICRAIE 2022)
#
# generate_features_edges.py
#
#   Driver script: generates node feature files for the node types listed in
#   nodes_list, and (commented section) the edge files and edges_list.csv.
#
# Input       : input_files/
# Output      : node_files/, edge_files/
#
# Author      : Aravind M
# ------------------------------------------------------------------------------


import re
import os
import traceback
import tldextract
import numpy as np
import Levenshtein as l
from collections import Counter
import geoip2.database
import ipaddress
import Levenshtein as l
import tldextract
from node_features import *
from edges import *

# Generating nodes along with features and labels

# nodes_list = ['primary_domain', 'subdomain', 'ip']
nodes_list = ['ip']

for node in nodes_list:
    generate_node_features(node)
'''
# generating edges

sdom_node_file = 'input_files/list_sdoms.csv'
pdom_node_file = 'input_files/list_pdoms.csv'

apex_edges_file = 'edge_files/apex_edges.csv'
pdom_similar_edges_file = 'edge_files/pdom_similar_edges.csv'
sdom_similar_edges_file = 'edge_files/sdom_similar_edges.csv'
sdom_similar_pdom_edges_file = 'edge_files/sdom_similar_pdom_edges.csv'
same_pdom_diff_tld_file = 'edge_files/same_pdom_diff_tld_edges.csv'

# apex_edges(sdom_node_file, apex_edges_file)
# similar_edges(sdom_node_file, pdom_node_file, sdom_similar_pdom_edges_file)
# similar_edges(sdom_node_file, sdom_node_file, sdom_similar_edges_file)
similar_edges(pdom_node_file, pdom_node_file, pdom_similar_edges_file)

# same_pdom_diff_tld(pdom_node_file, pdom_node_file, same_pdom_diff_tld_file)

source_nodes = ['subdomain_nodes', 'subdomain_nodes', 'primary_domain_nodes', 'subdomain_nodes', 'primary_domain_nodes',
                'primary_domain_nodes', 'subdomain_nodes']
target_nodes = ['primary_domain_nodes', 'ip_nodes', 'ip_nodes', 'subdomain_nodes', 'primary_domain_nodes',
                'primary_domain_nodes', 'primary_domain_nodes']
edge_type = ['apex', 'resolving_sdom', 'resolving_pdom', 'sdom_similar', 'pdom_similar', 'same_pdom_diff_tld',
             'sdom_similar_pdom']
file_loc = ['edge_files/apex_edges.csv', 'edge_files/resolving_sdom_edges.csv', 'edge_files/resolving_pdom_edges.csv',
            'edge_files/sdom_similar_edges.csv', 'edge_files/pdom_similar_edges.csv', 'edge_files/same_pdom_diff_tld_edges.csv', 'edge_files/sdom_similar_pdom_edges.csv']

edge_list = 'edge_files/edges_list.csv'
# generate_edge_list(source_nodes, target_nodes, edge_type, file_loc, edge_list)

'''
