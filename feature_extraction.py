import re
from pattern import *

def has_ip_address(url):
    ip_address_pattern = ipv4_pattern + "|" + ipv6_pattern
    match = re.search(ip_address_pattern, url)
    return -1 if match else 1

#main function which extracts feature from url
def main(url):
    ex_feature=[]
    ex_feature.append(has_ip_address(url))
    print(ex_feature)
    return ex_feature