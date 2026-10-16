# ------------------------------------------------------------------------------
# Malicious Node Identification for DNS Data Using Graph Convolutional Networks (ICRAIE 2022)
#
# enumerate_subdomains_sublist3r.py
#
#   Enumerates the subdomains of each domain in the input list using Sublist3r
#   (search engines only, brute force disabled).
#
# Input       : xaa                        - one domain per line (a split of the domain list)
# Output      : 1_extracted_subdomains.csv - all subdomains found
#               1_num_subdomains.csv       - domain, number of subdomains found
#
# Author      : Aravind M
# ------------------------------------------------------------------------------


import os
import traceback
import sublist3r

f1 = open('1_extracted_subdomains.csv', 'a+')
f2 = open('1_num_subdomains.csv', 'a+')
f3 = open('xaa', 'r')


lines = f3.readlines()
for i in lines:
    i = i.replace('\n', '')
    os.system('clear')

    try:
        subdomains = sublist3r.main(i, 40, 'file_01.txt', ports= None, silent=False, verbose= False, enable_bruteforce= False, engines=None)
        f=open('file_01.txt', 'r')
        number_of_sub_domains = f.readlines()
        for p in number_of_sub_domains:
            print(p)
            f1.write(str(p))
            f1.flush()
        number = len(number_of_sub_domains)
        print("here is the number", number)
        f2.write(str(i) + ',' + str(number) + '\n')
        f2.flush()
        os.system('rm file_01.txt')

    except Exception as e:

        traceback.print_stack()

f1.close()
f2.close()

