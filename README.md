# Malicious Node Identification for DNS Data Using Graph Convolutional Networks

Code for the paper:

> Aravind M, Sujadevi V G, Manu R Krishnan, Prem Sankar A U, Soumajit Pal, Anu Vazhayil, Geetapriya Sridharan, Prabaharan Poornachandran.
> **Malicious Node Identification for DNS Data Using Graph Convolutional Networks.**
> 2022 IEEE 7th International Conference on Recent Advances and Innovations in Engineering (ICRAIE).
> DOI: [10.1109/ICRAIE56454.2022.10054347](https://doi.org/10.1109/ICRAIE56454.2022.10054347)

The paper builds a heterogeneous knowledge graph of DNS data (6.23 million nodes, 93 million edges) with primary domains, subdomains and IP addresses as nodes, and classifies nodes as malicious or benign using a GCN.

The dataset is not included in this repository. A small fictional sample in the same formats is provided in [`data/sample/`](data/).

## Repository structure

```
data_collection/
    parse_pdns_json.py                  extract (ip, fqdn, primary domain) from passive DNS JSON records
    split_domain_subdomain.py           separate primary domains and subdomains (tldextract)
    enumerate_subdomains_sublist3r.py   enumerate subdomains of a domain list using Sublist3r
    resolve_domains_to_ips.py           resolve domains to IPs (A records) using a list of DNS resolvers
    expand_multi_ip_rows.py             convert "domain,ip1,ip2,..." rows into one (domain, ip) pair per row
    extract_ips.py                      extract the IP column from a domain-IP mapping file

graph_construction/
    node_features.py                    lexical features for domain nodes (64) and IP features (4) with labels
    edges.py                            apex, similar-name and same-domain-different-TLD edges
    generate_features_edges.py          driver script for node features and edges
    run_processes.py                    runs generate_features_edges.py
    similar_edges_blocked/              subdomain similarity edges (Levenshtein distance < 2) on sorted blocks
        step1_create_block_indices.py
        step2_generate_sdom_similar_edges.py
    sdom_similar_pdom_edges/            subdomain-to-primary-domain similarity edges (not used in the final graph)
        step1_get_block_start_indices.py
        step2_get_block_subdomains.py
        step3_generate_sdom_similar_pdom_edges.py
    similar_edges_multithreaded.py      earlier multithreaded version of subdomain similarity edges

data/
    README.md                           expected file formats
    sample/                             small fictional dataset in the same formats

model/
    data_object_generation.py           builds the PyTorch Geometric HeteroData object and converts it to homogeneous
    train_evaluate_gcn.py               2-layer GCN training and evaluation (GAT uses the same script with GATConv)
    evaluate_gcn_checkpoint.py          evaluation of a saved GCN checkpoint
```

## Graph

| Node type | Features |
|---|---|
| primary domain | 64 lexical features |
| subdomain | 64 lexical features |
| IP | country code, ASN, subnet, IP version |

| Edge type | Source → Target |
|---|---|
| apex | subdomain → primary domain |
| resolving_sdom | subdomain → IP |
| resolving_pdom | primary domain → IP |
| sdom_similar | subdomain → subdomain |
| pdom_similar | primary domain → primary domain |
| same_pdom_diff_tld | primary domain → primary domain |

## Setup

The code was written for Python 3.6 and the package versions in `requirements.txt` (PyTorch 1.10, PyTorch Geometric 2.0.3, numpy 1.19, tldextract 3.x). Newer versions of numpy (>= 1.24) and tldextract (>= 4) are not compatible with parts of the code. Python 3.8 is the newest version that supports all pinned packages.

```
pip install "setuptools<70"
pip install torch==1.10.2
pip install torch-scatter==2.0.9 torch-sparse==0.6.12 -f https://data.pyg.org/whl/torch-1.10.0+cpu.html
pip install -r requirements.txt
```

Node feature generation (`node_features.py`) also needs the MaxMind GeoIP2 City and GeoLite2 ASN databases and the Cisco Umbrella top-1M list in `input_files/` (see [data/README.md](data/README.md)).

The scripts were run from a single working directory containing the data folders:

```
input_files/    node lists, labelled malicious/benign lists, Cisco Umbrella top lists, TLD list, MaxMind GeoIP2 databases
node_files/     generated node feature files
edge_files/     generated edge files and edges_list.csv
```

Run each script with that directory as the current working directory. All file paths in the scripts are relative to it.

## Models

Two model architectures are compared in the paper (Table II). Both use the same pipeline: the same graph built by `data_object_generation.py`, the same train / validation / test split, the same optimizer (Adam, learning rate 5e-3, weight decay 5e-4) and the same evaluation.

| Model | Layer | Configuration |
|---|---|---|
| GCN | `GCNConv` | 2 layers (`model/train_evaluate_gcn.py`) |
| GAT | `GATConv` | 8 attention heads, dropout 0.6 |

The GAT model follows `train_evaluate_gcn.py` with `GCNConv` replaced by `GATConv` from PyTorch Geometric.

Not included in this repository: the GAT training script, and the code for the experiments in Table III (Case I: identity matrix as the node feature matrix; Case III: denser graph with additional edges between IPs with the same ASN and country code, and between domains with the same TLD).

## Citation

```
@inproceedings{aravind2022malicious,
  title={Malicious Node Identification for DNS Data Using Graph Convolutional Networks},
  author={M, Aravind and V G, Sujadevi and Krishnan, Manu R and A U, Prem Sankar and Pal, Soumajit and Vazhayil, Anu and Sridharan, Geetapriya and Poornachandran, Prabaharan},
  booktitle={2022 IEEE 7th International Conference on Recent Advances and Innovations in Engineering (ICRAIE)},
  year={2022},
  doi={10.1109/ICRAIE56454.2022.10054347}
}
```

## License

MIT License. See [LICENSE](LICENSE).
