# ------------------------------------------------------------------------------
# Malicious Node Identification for DNS Data Using Graph Convolutional Networks (ICRAIE 2022)
#
# node_features.py
#
#   Feature generation and labelling for the three node types.
#     Domain nodes (primary domains, subdomains): 64 lexical features - counts of
#     each letter, digit and special character, length, entropy, suspicious
#     keywords, similarity to Cisco top domains, TLD checks, repeated characters.
#     IP nodes: country code, ASN (MaxMind GeoIP2), subnet and IP version.
#     Labels: malicious / benign / n_a (unlabelled) from the tagged node lists.
#
# Input       : input_files/        - node lists, malicious/benign lists, Cisco top lists,
#                                     TLD list, GeoIP2 databases
# Output      : node_files/nodes.pdom.csv, nodes.sdom.csv, nodes.ips.csv
#
# Author      : Aravind M
# ------------------------------------------------------------------------------


import re
import os
import traceback
import numpy as np
import Levenshtein as l
from collections import Counter
import geoip2.database
import ipaddress
import Levenshtein as l
import tldextract

# ******************************************Reading and Initializing****************************************************

# define set of all digits
all_digits = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

# define set of all letters
all_letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
               'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

# define set of all punctuations
punct = ['.', '!', '#', '$', '%', '&', ',', ';', '’']

# regex for checking whether an IP address is present in the domain/subdomain part
regex = "(([0-9]|[1-9][0-9]|1[0-9][0-9]|" \
        "2[0-4][0-9]|25[0-5])\\.){3}" \
        "([0-9]|[1-9][0-9]|1[0-9][0-9]|" \
        "2[0-4][0-9]|25[0-5])"
p = re.compile(regex)

# data for checking whether the TLD is in cisco top level TLDs
top_1M_TLDs = open('input_files/cisco_top-1m-TLD.csv', 'r')
cisco_tld = top_1M_TLDs.readlines()

# data for checking whether the domain is similar to cisco top 1000 domains
top_1k_cisco_domains = open('input_files/cisco_top_1000_domains.csv', 'r')
domains_top_cisco_1k = top_1k_cisco_domains.readlines()

# Reading cisco top 1M
cisco_top1M = open('input_files/cisco_top_1M.csv', 'r')

# Reading list of all available TLDs
all_tlds_list = open('input_files/list_of_all_TLDS_without_unicoded_ones.csv', 'r')
all_tlds = all_tlds_list.readlines()
tlds = []
for line in all_tlds:
    line = line.replace('\n', '')
    tlds.append(line)

# ***********************************************Section for Generating Labels******************************************************
# Reading the list of malicious & benign nodes for labeling purpose

mal_pdoms_file = 'input_files/mal_pdoms.csv'
mal_sdoms_file = 'input_files/mal_sdoms.csv'
mal_ips_file = 'input_files/mal_ips.csv'

benign_pdoms_file = 'input_files/benign_pdoms.csv'
benign_sdoms_file = 'input_files/benign_sdoms.csv'
benign_ips_file = 'input_files/benign_ips.csv'


def create_lists_tagged_nodes(fread):
    with open(fread, 'r') as f:
        list = []
        lines = f.readlines()
        for line in lines:
            line = line.replace('\n', '')
            list.append(line)
        f.close()
        return list


mal_pdoms = create_lists_tagged_nodes(mal_pdoms_file)
mal_sdoms = create_lists_tagged_nodes(mal_sdoms_file)
mal_ips = create_lists_tagged_nodes(mal_ips_file)
benign_pdoms = create_lists_tagged_nodes(benign_pdoms_file)
benign_sdoms = create_lists_tagged_nodes(benign_sdoms_file)
benign_ips = create_lists_tagged_nodes(benign_ips_file)


def assigning_label(node):
    if node in mal_pdoms:
        return 'malicious'
    elif node in benign_pdoms:
        return 'benign'
    elif node in benign_sdoms:
        return 'benign'
    elif node in benign_ips:
        return 'benign'
    elif node in mal_sdoms:
        return 'malicious'
    elif node in mal_ips:
        return 'malicious'
    else:
        return 'n_a'

# *************************************Generating Node Features(Main)*************************************************


def generate_node_features(node_type):
    if node_type == 'primary_domain':
        primary_domains_file = open('input_files/list_pdoms.csv', 'r')
        nodes_pdom = open('node_files/nodes.pdom.csv', 'a+')
        primary_domains = primary_domains_file.readlines()
        write_domain_features(nodes_pdom, primary_domains)
        nodes_pdom.close()

    if node_type == 'subdomain':
        subdomains_file = open('input_files/list_sdoms.csv', 'r')
        nodes_sdom = open('node_files/nodes.sdom.csv', 'a+')
        subdomains = subdomains_file.readlines()
        write_domain_features(nodes_sdom, subdomains)
        nodes_sdom.close()

    if node_type == 'ip':
        ips_file = open('input_files/list_ips.csv', 'r')
        nodes_ips = open('node_files/nodes.ips.csv', 'a+')
        ips = ips_file.readlines()
        write_ip_features(nodes_ips, ips)
        nodes_ips.close()


# ***********************************************Section for Node Features**********************************************


def num_alphabets(domain):
    num_char = 0
    for letter in all_letters:
        num = domain.count(letter)
        num_char = num_char + num
    return num_char


def ratio_ndig_nch(domain):
    # initialized value
    total_digits = 0
    total_letters = 0
    # iterate through all characters
    for s in domain:
        # if found in all_digits then increment total_digits by one
        if s in all_digits:
            total_digits += 1
        elif s in all_letters:
            total_letters += 1
    return total_digits / total_letters


def count_each_chara_digit_symbol(domain):
    list_ch_dig_symbol = []
    for letter in all_letters:
        list_ch_dig_symbol.append(domain.count(letter))
    for digit in all_digits:
        list_ch_dig_symbol.append(domain.count(digit))
    for punc in punct:
        list_ch_dig_symbol.append(domain.count(punc))
    return list_ch_dig_symbol


def presence_ip_address(domain):
    if re.search(p, domain):
        return 1
    else:
        return 0


def calc_entropy(domain):
    p, lens = Counter(domain), np.float(len(domain))
    return -np.sum(count / lens * np.log2(count / lens) for count in p.values())


def sus_word_count(domain):
    # Defining the list of suspicious words_count
    sus_list = ['confirm', 'account', 'secure', 'webscr', 'login', 'signin', 'submit', 'update', 'logon', 'secure',
                'wp', 'cmd', 'admin']
    i = 0
    for sus in sus_list:
        if sus in domain:
            i = i + 1
    return i


def num_puncs(domain):
    i = 0
    try:
        ext = tldextract.extract(domain)
        eval_part = ext[0] + '.' + ext[1]
        for punc in punct:
            if punc in eval_part:
                i = i + 1
        return i
    except Exception as e:
        traceback.print_stack()
        return 0


def num_digits(domain):
    i = 0
    for dig in all_digits:
        if dig in domain:
            i = i + domain.count(dig)
    return i


def tld_in_cisco_top_tld(domain):
    i = 0
    try:
        ext = tldextract.extract(domain)
        tld = ext[2]
        if tld in cisco_tld:
            i = 1
        return i
    except Exception as e:
        traceback.print_stack()
        return 0


def domain_similar_cisco_top_1k(domain):
    i = 0
    try:
        cisco_dom_names_only = []
        for dom in domains_top_cisco_1k:
            dom = dom.replace('\n', '')
            ext_cisco = tldextract.extract(dom)
            cisco_dom_names_only.append(ext_cisco[1])
            cisco_dom_names_only.append(ext_cisco[0])

        ext = tldextract.extract(domain)
        pdom_only = ext[1]
        for d in cisco_dom_names_only:
            if d != pdom_only:
                dist = l.distance(d, pdom_only)
                if dist < 2:
                    return 1
                else:
                    return 0
    except Exception as e:
        traceback.print_stack()
        return 0


def in_cisco_top1m(domain):
    top1M = cisco_top1M.readlines()
    list_top1M = []
    for line in top1M:
        line = line.replace('\n', '')
        list_top1M.append(line)
    if domain in list_top1M:
        return 1
    else:
        return 0


def hyphen_underscore(domain):
    num_hyph = domain.count('-')
    num_underscore = domain.count('_')
    tot = num_hyph + num_underscore
    if tot <= 4:
        return 0
    else:
        return 1


def num_dots(domain):
    ext = tldextract.extract(domain)
    eval_part = ext[0] + '.' + ext[1]
    count = eval_part.count('.')
    if count <= 3:
        return 0
    else:
        return 1


def max_num_repeated_char(domain):
    count = 0
    characters = []
    list_count = []
    for i in domain:
        characters.append(i)
    for i in range(len(characters)):
        if characters[i] in all_letters:
            for j in range((i + 1), len(characters) - 1):
                if characters[i] == characters[j]:
                    count = count + 1
                else:
                    break
            list_count.append(count)
    if len(list_count) != 0:
        return max(list_count)
    else:
        return 0


def max_num_repeated_digit(domain):
    count = 0
    digits = []
    list_count = []
    for i in domain:
        digits.append(i)
    for i in range(len(digits)):
        if digits[i] in all_digits:
            for j in range(i + 1, len(digits) - 1):
                if digits[i] == digits[j]:
                    count = count + 1
                else:
                    break
            list_count.append(count)
    if len(list_count) != 0:
        return max(list_count)
    else:
        return 0


def check_for_tld_in_domain(domain):
    for tld in tlds:
        if tld in domain:
            return 1
        else:
            return 0


# ***************************************** section for IP features ****************************************************

cc_reader = geoip2.database.Reader('input_files/GeoIP2-City.mmdb', 'r')
asn_reader = geoip2.database.Reader('input_files/GeoLite2-ASN.mmdb', 'r')

# Generating CC_Alpha_Numeral Map
cc_map = {}
with open('input_files/cc_numeral_vs_alpha.csv') as f1:
    lines = f1.readlines()
    for line in lines:
        line = line.replace("\n", "")
        values = line.split(",")
        cc_map[values[0]] = values[1]


def get_cc_asn(ip):
    try:
        response_cc = cc_reader.city(ip)
        cc = cc_map.get(response_cc.country.iso_code)
        response_asn = asn_reader.asn(ip)
        asn = response_asn.autonomous_system_number
        return int(cc), int(asn)
    except Exception as e:
        traceback.print_stack()
        return 1, 1


def subset_ip_version(ip):
    addr = ipaddress.ip_address(str(ip))
    subset = str(int(ipaddress.ip_address(str(ip))))
    version = addr.version
    return subset, version

# ************************************************* Writing down features **********************************************


def write_domain_features(feature_file, node_list):
    feature_file = feature_file
    node_list = node_list
    feature_file.write('node' + ',' + 'num_a' + ',' + 'num_b' + ',' + 'num_c' + ',' + 'num_d' + ',' + 'num_e' + ',' +
                       'num_f' + ',' + 'num_g' + ',' + 'num_h' + ',' + 'num_i' + ',' + 'num_j' + ',' + 'num_k' + ',' +
                       'num_l' + ',' + 'num_m' + ',' + 'num_n' + ',' + 'num_o' + ',' + 'num_p' + ',' + 'num_q' + ',' +
                       'num_r' + ',' + 'num_s' + ',' + 'num_t' + ',' + 'num_u' + ',' + 'num_v' + ',' + 'num_w' + ',' +
                       'num_x' + ',' + 'num_y' + ',' + 'num_z' + ',' + 'num_0' + ',' + 'num_1' + ',' + 'num_2' + ',' +
                       'num_3' + ',' + 'num_4' + ',' + 'num_5' + ',' + 'num_6' + ',' + 'num_7' + ',' + 'num_8' + ',' +
                       'num_9' + ',' + 'num_.' + ',' + 'num_!' + ',' + 'num_#' + ',' + 'num_$' + ',' + 'num_%' + ',' +
                       'num_&' + ',' + 'num_comma' + ',' + 'num_;' + ',' + 'num_’' + ',' + 'domain_length' + ',' +
                       'num_digits' + ',' + 'entropy' + ',' + 'entropy/dom_len' + ',' + 'is_ip_in' + ',' +
                       'num_special_chara' + ',' + 'count_sus_words' + ',' + 'total_num_alphabets' + ',' +
                       'num_digits/domain_length' + ',' + 'num_special_chara/domain_length' + ',' +
                       'num_alphabets/domain_length' + ',' + 'similar_cisco_top1k' + ',' + 'is_TLD_cisco_top' +
                       ',' + 'is_in_cisco_top_1M' + ',' + 'num_hyphens_uscores_less4' + ',' + 'num_dots_less3' +
                       ',' + 'is_TLD_present' + ',' + 'max_num_repeating_chara' + ',' +
                       'max_num_repeating_digits' + ',' + 'label' + '\n')
    feature_file.flush()

    num_element = 1
    for row in node_list:
        row = row.replace('\n', '')
        row = row.split(',')
        list_ch_dig_symbol = count_each_chara_digit_symbol(row[0])
        domain_length = len(row[0])
        num_digit = num_digits(row[0])
        entropy_value = calc_entropy(row[0])
        entropy_by_dom_len = entropy_value / domain_length
        # is_ip_in is written inbuilt
        num_punc = num_puncs(row[0])
        num_sus_keywords = sus_word_count(row[0])
        total_num_alphabets = num_alphabets(row[0])
        num_digits_by_domain_length = num_digit / domain_length
        num_special_chara_by_domain_length = num_punc / domain_length
        num_alphabets_by_domain_length = total_num_alphabets / domain_length
        similar_cisco_top1k = domain_similar_cisco_top_1k(row[0])
        is_TLD_cisco_top = tld_in_cisco_top_tld(row[0])
        is_in_cisco_top_1M = in_cisco_top1m(row[0])
        num_hyphens_uscores_less4 = hyphen_underscore(row[0])
        num_dots_less3 = num_dots(row[0])
        tld_in_domains = check_for_tld_in_domain(row[0])
        max_num_repeating_chara = max_num_repeated_char(row[0])
        max_num_repeating_digits = max_num_repeated_digit(row[0])
        label = assigning_label(row[0])
        # num_subdomains = num_sub_domains_sublist3r(row[0])
        # print(f"number_of_subdomains of {num_element} is {num_subdomains}\n")

        feature_file.write(row[0] + ',' + str(list_ch_dig_symbol[0]) + ',' + str(list_ch_dig_symbol[1]) + ',' + str(
            list_ch_dig_symbol[2]) + ',' + str(list_ch_dig_symbol[3]) + ',' + str(
            list_ch_dig_symbol[4]) + ',' + str(list_ch_dig_symbol[5]) + ',' + str(list_ch_dig_symbol[6]) + ',' + str(
            list_ch_dig_symbol[7]) + ',' + str(list_ch_dig_symbol[8]) + ',' + str(list_ch_dig_symbol[9]) + ',' + str(
            list_ch_dig_symbol[10]) + ',' + str(list_ch_dig_symbol[11]) + ',' + str(
            list_ch_dig_symbol[12]) + ',' + str(list_ch_dig_symbol[13]) + ',' + str(
            list_ch_dig_symbol[14]) + ',' + str(list_ch_dig_symbol[15]) + ',' + str(
            list_ch_dig_symbol[16]) + ',' + str(list_ch_dig_symbol[17]) + ',' + str(
            list_ch_dig_symbol[18]) + ',' + str(list_ch_dig_symbol[19]) + ',' + str(
            list_ch_dig_symbol[20]) + ',' + str(list_ch_dig_symbol[21]) + ',' + str(
            list_ch_dig_symbol[22]) + ',' + str(list_ch_dig_symbol[23]) + ',' + str(
            list_ch_dig_symbol[24]) + ',' + str(list_ch_dig_symbol[25]) + ',' + str(
            list_ch_dig_symbol[26]) + ',' + str(
            list_ch_dig_symbol[27]) + ',' + str(
            list_ch_dig_symbol[28]) + ',' + str(
            list_ch_dig_symbol[29]) + ',' + str(
            list_ch_dig_symbol[30]) + ',' + str(
            list_ch_dig_symbol[31]) + ',' + str(
            list_ch_dig_symbol[32]) + ',' + str(
            list_ch_dig_symbol[33]) + ',' + str(
            list_ch_dig_symbol[34]) + ',' + str(
            list_ch_dig_symbol[
                35]) + ',' + str(
            list_ch_dig_symbol[
                36]) + ',' + str(
            list_ch_dig_symbol[
                37]) + ',' + str(
            list_ch_dig_symbol[
                38]) + ',' + str(
            list_ch_dig_symbol[
                39]) + ',' + str(
            list_ch_dig_symbol[
                40]) + ',' + str(
            list_ch_dig_symbol[
                41]) + ',' + str(
            list_ch_dig_symbol[
                42]) + ',' + str(
            list_ch_dig_symbol[
                43]) + ',' + str(
            list_ch_dig_symbol[
                44]) + ',' + str(
            domain_length) + ',' + str(
            num_digit) + ',' + str(
            entropy_value) + ',' + str(
            entropy_by_dom_len) + ',' + str(
            presence_ip_address(
                row[
                    0])) + ',' + str(
            num_punc) + ',' + str(
            num_sus_keywords) + ',' + str(
            total_num_alphabets) + ',' + str(
            num_digits_by_domain_length) + ',' + str(
            num_special_chara_by_domain_length) + ',' + str(
            num_alphabets_by_domain_length) + ',' + str(
            similar_cisco_top1k) + ',' + str(
            is_TLD_cisco_top) + ',' + str(
            is_in_cisco_top_1M) + ',' + str(
            num_hyphens_uscores_less4) + ',' + str(
            num_dots_less3) + ',' + str(tld_in_domains) + ',' + str(
            max_num_repeating_chara) + ',' + str(
            max_num_repeating_digits) + ',' + label + '\n')

        print(f"written the domain element, number {num_element} | {row[0]}\n")
        feature_file.flush()
        num_element = num_element + 1


def write_ip_features(feature_file, node_list):
    feature_file = feature_file
    node_list = node_list
    feature_file.write('node' + ',' + 'cc' + ',' + 'asn' + ',' + 'subnet' + ',' + 'version' + ',' + 'label' + '\n')
    feature_file.flush()

    num_element = 1
    for row in node_list:
        row = row.replace('\n', '')
        row = row.split(',')
        cc_asn = get_cc_asn(row[0])
        cc, asn = cc_asn
        subset_version = subset_ip_version(row[0])
        subset, version = subset_version
        label = assigning_label(row[0])

        feature_file.write(str(row[0]) + ',' + str(cc) + ',' + str(asn) + ',' + str(subset) + ',' + str(version) + ',' + label + '\n')
        print(f"written the ip element, number {num_element} | {row[0]}\n")
        feature_file.flush()
        num_element = num_element + 1

