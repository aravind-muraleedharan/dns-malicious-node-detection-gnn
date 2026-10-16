# ------------------------------------------------------------------------------
# Malicious Node Identification for DNS Data Using Graph Convolutional Networks (ICRAIE 2022)
#
# expand_multi_ip_rows.py
#
#   Converts rows of the form 'domain,ip1,ip2,...' into one (domain, ip) pair
#   per line.
#
# Input       : 789.csv            - domain, ip1, ip2, ...
# Output      : pdom_ip_new.csv    - domain, ip
#
# Author      : Aravind M
# ------------------------------------------------------------------------------


f=open('789.csv', 'r')
fwrite = open('pdom_ip_new.csv', 'a+')

lines = f.readlines()
i =0
for line in lines:
    line =line.replace('\n', '')
    v = line.split(',')
    if len(v) < 3:
        fwrite.write(v[0] + ',' + v[1] + '\n')
    elif len(v) >= 3:
        i = i+1
        print("yes")
        for i in range(1, (len(v)-1)):
            fwrite.write(v[0] + ',' + v[i] + '\n')
print("value", i)
