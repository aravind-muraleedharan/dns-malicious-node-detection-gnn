# ------------------------------------------------------------------------------
# Malicious Node Identification for DNS Data Using Graph Convolutional Networks (ICRAIE 2022)
#
# data_object_generation.py
#
#   Builds the PyTorch Geometric dataset. Loads node features and labels
#   (1 = malicious, 0 = benign, 2 = unlabelled) and the edges listed in
#   edges_list.csv into a HeteroData object, and creates random train / val /
#   test masks (50 / 20 / 30) over the labelled nodes of each type.
#   to_homogeneous() pads all node features to a common 132-dim vector,
#   converts the graph to a homogeneous one and saves it as 'bigdata'.
#
# Input       : node_files/*.csv, edge_files/edges_list.csv and the edge files it lists
# Output      : bigdata            - homogeneous graph object (torch.save)
#
# Author      : Aravind M
# ------------------------------------------------------------------------------


import torch
import pandas as pd
from typing import Optional, Callable
from sklearn import preprocessing
from torch_geometric.data import (InMemoryDataset, HeteroData, Data)
from torch_geometric.nn.conv.rgcn_conv import masked_edge_index
import torch_geometric.transforms as T
import os
import numpy as np

# Defining node_path
pdom_path = 'node_files/nodes.pdom.csv'
sdom_path = 'node_files/nodes.sdom.csv'
ip_path = 'node_files/nodes.ips.csv'

# Data Preparation


def load_node_csv(path, node_type, index_col):

    df = pd.read_csv(path, index_col=index_col)
    mapping = {index: i for i, index in enumerate(df.index.unique())}
    # generating labels vector
    labels = df['label'].apply(lambda x: 1 if x == 'malicious' else (0 if x == 'benign' else 2))
    if node_type == 'pdom':
        node_features = torch.from_numpy(df[['num_a', 'num_b', 'num_c', 'num_d', 'num_e', 'num_f', 'num_g', 'num_h',
                                             'num_i', 'num_j', 'num_k', 'num_l', 'num_m', 'num_n', 'num_o', 'num_p',
                                             'num_q', 'num_r', 'num_s', 'num_t', 'num_u', 'num_v', 'num_w', 'num_x',
                                             'num_y', 'num_z', 'num_0', 'num_1', 'num_2', 'num_3', 'num_4', 'num_5',
                                             'num_6', 'num_7', 'num_8', 'num_9', 'num_.', 'num_!', 'num_#', 'num_$',
                                             'num_%', 'num_&', 'num_comma', 'num_;', 'num_’', 'domain_length',
                                             'num_digits', 'entropy', 'entropy/dom_len', 'is_ip_in',
                                             'num_special_chara', 'count_sus_words', 'total_num_alphabets',
                                             'num_digits/domain_length', 'num_special_chara/domain_length',
                                             'num_alphabets/domain_length', 'similar_cisco_top1k', 'is_TLD_cisco_top',
                                             'is_in_cisco_top_1M', 'num_hyphens_uscores_less4', 'num_dots_less3',
                                             'is_TLD_present', 'max_num_repeating_chara',
                                             'max_num_repeating_digits']].values)
        node_features = node_features.float()
    elif node_type == 'sdom':
        node_features = torch.from_numpy(df[['num_a', 'num_b', 'num_c', 'num_d', 'num_e', 'num_f', 'num_g', 'num_h',
                                             'num_i', 'num_j', 'num_k', 'num_l', 'num_m', 'num_n', 'num_o', 'num_p',
                                             'num_q', 'num_r', 'num_s', 'num_t', 'num_u', 'num_v', 'num_w', 'num_x',
                                             'num_y', 'num_z', 'num_0', 'num_1', 'num_2', 'num_3', 'num_4', 'num_5',
                                             'num_6', 'num_7', 'num_8', 'num_9', 'num_.', 'num_!', 'num_#', 'num_$',
                                             'num_%', 'num_&', 'num_comma', 'num_;', 'num_’', 'domain_length',
                                             'num_digits', 'entropy', 'entropy/dom_len', 'is_ip_in',
                                             'num_special_chara', 'count_sus_words', 'total_num_alphabets',
                                             'num_digits/domain_length', 'num_special_chara/domain_length',
                                             'num_alphabets/domain_length', 'similar_cisco_top1k', 'is_TLD_cisco_top',
                                             'is_in_cisco_top_1M', 'num_hyphens_uscores_less4', 'num_dots_less3',
                                             'is_TLD_present', 'max_num_repeating_chara',
                                             'max_num_repeating_digits']].values)
        node_features = node_features.float()
    elif node_type == 'ip':
        node_features = torch.from_numpy(df[['cc', 'asn', 'subnet', 'version']].values)

        node_features = node_features.float()
    return node_features, mapping, labels

# Reading edges into the program


def load_edge_csv(path, src_index_col, src_mapping, dst_index_col, dst_mapping,
                  encoders=None):
    edges = pd.read_csv(path)
    src = [src_mapping[index] for index in edges[src_index_col]]
    dst = [dst_mapping[index] for index in edges[dst_index_col]]
    edge_index = torch.tensor([src, dst])

    # Don't know if needed the following
    # edges = edges_sorted.drop_duplicates(['source', 'target'])
    edge_attr = None
    if encoders is not None:
        edge_attrs = [encoder(edges[col]) for col, encoder in encoders.items()]
        edge_attr = torch.cat(edge_attrs, dim=-1)
    return edge_index, edge_attr


class Edge_Type_Encoder(object):
    def __init__(self, model_node_attr='all-MiniLM-L6-v2', device=None):
        self.device = device
        self.model = SentenceTransformer(model_node_attr, device=device)

    @torch.no_grad()
    def __call__(self, df):
        node_label = self.model.encode(df.values, show_progress_bar=True,
                                       convert_to_tensor=True, device=self.device)
        return node_label.cpu()


data = HeteroData()


class DNS(InMemoryDataset):
    def __init__(self, root: str, is_multigraph=False, num_test=0.3, num_val=0.2,
                 transform: Optional[Callable] = None,
                 pre_transform: Optional[Callable] = None):
        super().__init__(root, transform, pre_transform)
        processed = self._load_dataset(root, is_multigraph, num_test=num_test, num_val=num_val)
        self.data, self.slices = self.collate([processed])

    def _load_dataset(self, root, is_multigraph, num_test=0.3, num_val=0.2, balance_gt=False):

        pdom_node_features, pdom_node_mapping, pdom_labels = load_node_csv(
            pdom_path, node_type='pdom', index_col='node')
        sdom_node_features, sdom_node_mapping, sdom_labels = load_node_csv(
            sdom_path, node_type='sdom', index_col='node')

        ip_node_features, ip_node_mapping, ip_labels = load_node_csv(
            ip_path, node_type='ip', index_col='node')

        data['primary_domain_nodes'].num_nodes = len(pdom_node_mapping)
        data['primary_domain_nodes'].x = pdom_node_features
        data['primary_domain_nodes'].y = torch.from_numpy(pdom_labels.values)

        data['subdomain_nodes'].num_nodes = len(sdom_node_mapping)
        data['subdomain_nodes'].x = sdom_node_features
        data['subdomain_nodes'].y = torch.from_numpy(sdom_labels.values)

        data['ip_nodes'].num_nodes = len(ip_node_mapping)
        data['ip_nodes'].x = ip_node_features
        data['ip_nodes'].y = torch.from_numpy(ip_labels.values)
        print(data)
        data.num_classes = 2
        # generating_edges
        edge_list = open('edge_files/edges_list.csv', 'r')
        reader = edge_list.readlines()
        for row in reader:
            print(row)
            row = row.split(',')
            source_node = row[0].replace('\n', '')
            target_node = row[1].replace('\n', '')
            edge_type = row[2].replace('\n', '')
            file_path = row[3].replace('\n', '')
            if source_node == 'ip_nodes':
                source_mapping = ip_node_mapping
            elif source_node == 'primary_domain_nodes':
                source_mapping = pdom_node_mapping
            elif source_node == 'subdomain_nodes':
                source_mapping = sdom_node_mapping

            if target_node == 'ip_nodes':
                target_mapping = ip_node_mapping
            elif target_node == 'primary_domain_nodes':
                target_mapping = pdom_node_mapping
            elif target_node == 'subdomain_nodes':
                target_mapping = sdom_node_mapping

            edge_index, edge_label = load_edge_csv(
                file_path,
                src_index_col='source',
                src_mapping=source_mapping,
                dst_index_col='target',
                dst_mapping=target_mapping,
                encoders=None,
            )

            data[source_node, edge_type, target_node].edge_index = edge_index
        # labels and masking

        pdom_labeled = pdom_labels.values < 2
        pdom_labeled_indices = pdom_labeled.nonzero()[0]
        n_pdom_nodes = len(pdom_labeled_indices)
        perm_pdom = torch.randperm(n_pdom_nodes)

        test_idx = pdom_labeled_indices[perm_pdom[:int(n_pdom_nodes * num_test)]]
        val_idx = pdom_labeled_indices[perm_pdom[int(n_pdom_nodes * num_test):int(n_pdom_nodes * (num_test + num_val))]]
        train_idx = pdom_labeled_indices[perm_pdom[int(n_pdom_nodes * (num_test + num_val)):]]
        for v, idx in [('train', train_idx), ('test', test_idx), ('val', val_idx)]:
            mask = torch.zeros(data['primary_domain_nodes'].num_nodes, dtype=torch.bool)
            mask[idx] = True
            data['primary_domain_nodes'][f'{v}_mask'] = mask

        sdom_labeled = sdom_labels.values <2
        sdom_labeled_indices = sdom_labeled.nonzero()[0]
        n_sdom_nodes = len(sdom_labeled_indices)
        perm_sdom = torch.randperm(n_sdom_nodes)

        test_idx = sdom_labeled_indices[perm_sdom[:int(n_sdom_nodes * num_test)]]
        val_idx = sdom_labeled_indices[perm_sdom[int(n_sdom_nodes * num_test):int(n_sdom_nodes * (num_test + num_val))]]
        train_idx = sdom_labeled_indices[perm_sdom[int(n_sdom_nodes * (num_test + num_val)):]]
        for v, idx in [('train', train_idx), ('test', test_idx), ('val', val_idx)]:
            mask = torch.zeros(data['subdomain_nodes'].num_nodes, dtype=torch.bool)
            mask[idx] = True
            data['subdomain_nodes'][f'{v}_mask'] = mask

        ip_labeled = ip_labels.values < 2
        ip_labeled_indices = ip_labeled.nonzero()[0]
        n_ip_nodes = len(ip_labeled_indices)
        perm_ip = torch.randperm(n_ip_nodes)

        test_idx = ip_labeled_indices[perm_ip[:int(n_ip_nodes * num_test)]]
        val_idx = ip_labeled_indices[perm_ip[int(n_ip_nodes * num_test):int(n_ip_nodes * (num_test + num_val))]]
        train_idx = ip_labeled_indices[perm_ip[int(n_ip_nodes * (num_test + num_val)):]]
        for v, idx in [('train', train_idx), ('test', test_idx), ('val', val_idx)]:
            mask = torch.zeros(data['ip_nodes'].num_nodes, dtype=torch.bool)
            mask[idx] = True
            data['ip_nodes'][f'{v}_mask'] = mask
        print(data)
        return data

    # edges = edges_sorted.drop_duplicates(['source', 'target'])

    # Creating a homogeneous graph object out of the available heterodata

    def to_homogeneous(self, transform=None) -> Data:
        homo_data = self.data.clone()
        features_shape = sum([node_features.shape[1] for _, node_features in homo_data.x_dict.items()])
        # print(features_shape)
        mask_types = ['train_mask', 'val_mask', 'test_mask']
        masks = {k: [] for k in mask_types}
        y = []

        node_map = {node_type: i for i, node_type in enumerate(homo_data.node_types)}
        edge_map = {i: (node_map[edge_type[0]], node_map[edge_type[2]]) for i, edge_type in
                    enumerate(homo_data.edge_types)}

        l_padding = 0
        for node_type, node_features in homo_data.x_dict.items():
            node_features = node_features.numpy()
            r_padding = features_shape - node_features.shape[1] - l_padding
            features = []
            for node_feature in node_features:
                resized = np.pad(node_feature, (l_padding, r_padding), 'constant', constant_values=(0, 0))
                features.append(resized)

            if 'y' in homo_data[node_type]:
                y.append(homo_data[node_type].y)
                for mask_type in mask_types:
                    masks[mask_type].append(homo_data[node_type][mask_type])
            else:
                y.append(torch.full((node_features.shape[0],), 2))
                for mask_type in mask_types:
                    masks[mask_type].append(torch.zeros(node_features.shape[0], dtype=torch.bool))

            l_padding += node_features.shape[1]
            homo_data[node_type].x = torch.from_numpy(np.array(features)).float()

        homo_data = homo_data.to_homogeneous(add_edge_type=True, add_node_type=True)

        for mask_type, mask in masks.items():
            homo_data[mask_type] = torch.cat(mask)

        homo_data.y = torch.cat(y)
        # homo_data.edge_map = edge_map
        num_nodes = homo_data.num_nodes

        if transform is not None:
            transform(homo_data)
        homo_data.num_nodes = num_nodes
        homo_data.num_features = 132
        print(homo_data)
        torch.save(homo_data, 'bigdata')
        return homo_data
