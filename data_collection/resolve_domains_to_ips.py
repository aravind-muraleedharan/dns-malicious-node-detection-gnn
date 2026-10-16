# ------------------------------------------------------------------------------
# Malicious Node Identification for DNS Data Using Graph Convolutional Networks (ICRAIE 2022)
#
# resolve_domains_to_ips.py
#
#   Resolves domains to IPv4 addresses (DNS A records). Each domain is queried
#   in its own thread against a randomly chosen resolver from resolvers_list,
#   through a SOCKS5 proxy (set the proxy details before running).
#
# Input       : domains.csv        - one domain per line
#               resolvers_list     - one DNS resolver IP per line
# Output      : now_domains_ips.csv - domain, ip1, ip2, ...
#               unresolved.csv      - domains that did not resolve
#
# Author      : Aravind M
# ------------------------------------------------------------------------------


import datetime
import queue
import threading
import time
import traceback
import warnings
from concurrent.futures import ThreadPoolExecutor
from random import *

import dns
import socks
# import stomp
from dns import query, message
from numpy.compat import long

proxy_host = "YOUR_PROXY_HOST"
port1 = 0
port2 = 0
port3 = 0

socks_host = proxy_host
socks_port = 1080
socks.set_default_proxy(proxy_type=socks.SOCKS5, addr=socks_host, port=socks_port, rdns=True, username='YOUR_PROXY_USER',
                        password='YOUR_PROXY_PASSWORD')
query.socket_factory = socks.socksocket
resolver_count = 0
resolvers = ()
resolvers_path = 'resolvers_list'

fwrite = open('now_domains_ips.csv', 'a+')
funresolved = open('unresolved.csv', 'a+')

with open(resolvers_path) as fp:
    Lines = fp.readlines()
    for line in Lines:
        if line.strip() != '':
            resolver_count += 1
            resolvers = resolvers + (line.strip(),)


def resolver_input_from_file(domain):
    index = randint(0, resolver_count - 1)
    dnsresolver = resolvers[index]
    # print("AT1: " + str(threading.active_count()))
    PdnsReaderFirst.get_data(domain, dnsresolver)


class DNSResolver:
    @staticmethod
    def get_pdns_data(fqdn, dnsresolver, tries):
        if '*' in fqdn:
            domain_modified = fqdn.replace('*', 'a')
        else:
            domain_modified = fqdn.strip()
        aRecMultiStr = ''
        aaaaRecMultiStr = ''
        nsRecMultiStr = ''
        mxRecMultiStr = ''
        result = ''
        try:
            today = time.localtime()
            epochtime = datetime.datetime(today.tm_year, today.tm_mon, today.tm_mday, 0, 0).timestamp()
            date_today = str(long(epochtime) * 1000)
            a_record_array = ''
            try:
                record_type = dns.rdatatype.A
                pdns_query = message.make_query(domain_modified, record_type)
                dns_message = query.udp(pdns_query, dnsresolver, 60)
                rrset = dns_message.answer
                for rset in rrset:
                    if rset.rdtype == 1:
                        for inner_rset in rrset:
                            for item in inner_rset:
                                if item.rdtype == 1:
                                    address = item.address
                                    # print(address)
                                    if aRecMultiStr.strip() == '':
                                        aRecMultiStr += str(address)
                                    else:
                                        aRecMultiStr += ',' + str(address)

            except:
                pass
                # print(dnsresolver)
                # traceback.print_exc()
            if aRecMultiStr is not None and len(aRecMultiStr)>1:
                fwrite.write(fqdn + ',' + aRecMultiStr + '\n')
                fwrite.flush()
            else:
                funresolved.write(fqdn + '\n')
                funresolved.flush()
            result = date_today + "," + domain_modified + "," + aRecMultiStr + "," + aaaaRecMultiStr + "," + "," + nsRecMultiStr + "," + mxRecMultiStr
            if (aRecMultiStr + aaaaRecMultiStr + nsRecMultiStr + mxRecMultiStr).strip() == '':
                if tries == 'first':
                    unresolved_domain_queue.put(domain_modified)
            else:
                return result
        except:
            if (aRecMultiStr + aaaaRecMultiStr + nsRecMultiStr + mxRecMultiStr).strip() is not None:
                return result


class PdnsReaderFirst:
    warnings.filterwarnings("ignore", category=FutureWarning)

    @staticmethod
    def get_data(fqdn, dnsresolver):
        try:
            result = DNSResolver.get_pdns_data(fqdn, dnsresolver, 'first')
            # fwrite.write(fqdn + ',' + result[2] + '\n')
            # print(result)
            #if result is not None:
            #    result_queue.put(result)
        except:
            print("Exception")
            traceback.print_exc()


num_element = 0
if __name__ == '__main__':
    # Event().wait()
    fread = open('domains.csv', 'r')
    domains = fread.readlines()
    counter=0;
    for domain in domains:
        print("Element number", num_element)
        num_element = num_element+1
        domain = domain.replace('\n', '')
        print(domain)
        counter+=1
        worker = threading.Thread(target=resolver_input_from_file, args=(domain,))
        worker.start()
        print("Active Count>>>>>:"+str(threading.active_count()))

        if(counter>=1000):
            time.sleep(62)
            worker.join()
            counter = 0

