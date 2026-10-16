# Data

The dataset used in the paper (6.23 million nodes, 93 million edges) is not included in this repository.

`sample/` contains a small **fictional** dataset in the same formats, so the expected files and columns are clear. All names use reserved domains (`.test`, `.example`, `example.com/net/org`, RFC 2606), all IP addresses are from documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and ASNs are documentation ASNs (64496–64511). Labels in the sample are illustrative only.

```
sample/
├── input_files/                                inputs to graph_construction/
│   ├── list_pdoms.csv, list_sdoms.csv, list_ips.csv      one node per line
│   ├── mal_pdoms.csv,  mal_sdoms.csv,  mal_ips.csv       nodes labelled malicious
│   ├── benign_pdoms.csv, benign_sdoms.csv, benign_ips.csv  nodes labelled benign
│   ├── cisco_top_1000_domains.csv                        one domain per line
│   ├── cisco_top_1M.csv                                  rank,domain
│   ├── cisco_top-1m-TLD.csv                              one TLD per line
│   ├── list_of_all_TLDS_without_unicoded_ones.csv        IANA TLD list
│   └── cc_numeral_vs_alpha.csv                           ISO alpha-2 code,numeric code
├── node_files/                                 output of node_features.py, input to model/
│   ├── nodes.pdom.csv, nodes.sdom.csv          node, 64 domain features, label
│   └── nodes.ips.csv                           node, cc, asn, subnet, version, label
└── edge_files/                                 input to model/
    ├── edges_list.csv                          source type, target type, edge type, edge file
    └── *_edges.csv                             source,target
```

| | nodes | malicious | benign | unlabelled |
|---|---|---|---|---|
| primary domains | 38 | 14 | 14 | 10 |
| subdomains | 53 | 16 | 24 | 13 |
| IPs | 43 | 16 | 17 | 10 |

168 edges across the six edge types.

Labels are `malicious`, `benign` or `n_a` (unlabelled).

## Not included

- **MaxMind GeoIP2 databases** (`GeoIP2-City.mmdb`, `GeoLite2-ASN.mmdb`), used for the IP country code and ASN features. GeoLite2 databases can be downloaded from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) with a free account. In the sample, `cc` and `asn` values are filled in directly.
- **Cisco Umbrella top-1M list**, used for the Cisco top-list features. It is available from [Cisco Umbrella](https://umbrella-static.s3-us-west-1.amazonaws.com/index.html). The sample contains a short fictional list in the same format.

## Using the sample

Run the model scripts with `data/sample` as the working directory, for example:

```
cd data/sample
python ../../model/train_evaluate_gcn.py
```

