# Purpose -
# Running this file (stand alone) - For extracting all the features from a web page for testing.
# Notes -
# 1 stands for legitimate
# 0 stands for suspicious
# -1 stands for phishing

from bs4 import BeautifulSoup
import urllib
import bs4
import re
import socket
import whois
from datetime import datetime
import time
from feature_extraction import FeatureExtract
# https://breakingcode.wordpress.com/2010/06/29/google-search-python/
# Previous package structure was modified. Import statements according to new structure added. Also code modified.
#from googlesearch import search

# This import is needed only when you run this file in isolation.
import sys

# Path of your local server. Different for different OSs.
LOCALHOST_PATH = "G:/5-sem/mini-2/Phising_detection_using_ML"
DIRECTORY_NAME = ""




def main(url):
    with open(LOCALHOST_PATH + DIRECTORY_NAME + '/markup.txt', 'r') as file:
        soup_string = file.read()

    soup = BeautifulSoup(soup_string, 'html.parser')

    status = []
    fe=FeatureExtract()

    notfound=0
    cnt=""
    try:
        cnt=urllib.request.urlopen(url).read()
    except:
        notfound=1
    hostname=fe.getDomain(url)
    dns = 1
    try:
        domain = whois.query(hostname)
    except:
        dns = -1
    
    status.append(fe.has_ip_address(url))
    status.append(fe.url_length(url))
    status.append(fe.shortening_service(url))
    status.append(fe.having_at_symbol(url))
    status.append(fe.redirection(url))
    status.append(fe.prefix_suffix_sep(url))
    status.append(fe.sub_domain(url))
    status.append(-1 if dns == -1 else fe.ssl_final_state(domain,url))
    status.append(-1 if dns == -1 else fe.domain_reg_len(url))

    status.append(fe.favicon(url,soup,notfound))
    status.append(fe.port(url))
    status.append(fe.https_token(url))
    status.append(fe.request_url(url,soup,notfound))
    status.append(fe.url_anchor(url,soup,notfound))
    status.append(fe.link_in_tag(url,soup,notfound))
    status.append(fe.sfh(url,soup,notfound))
    status.append(fe.submit_to_email(soup,notfound))

    status.append(-1 if dns == -1 else fe.abnormal_url(domain, url))

    status.append(fe.i_frame(soup,notfound))

    status.append(-1 if dns == -1 else fe.age_of_domain(domain))

    status.append(dns)

    status.append(fe.web_traffic(url))
    #status.append(google_index(url))
    status.append(fe.statistical_report(url, hostname))

    print('\n1. Having IP address\n2. URL Length\n3. URL Shortening service\n4. Having @ symbol\n'
          '5. Having double slash\n6. Having dash symbol(Prefix Suffix)\n7. Having multiple subdomains\n'
          '8. SSL Final State\n8. Domain Registration Length\n9. Favicon\n10. HTTP or HTTPS token in domain name\n'
          '11. Request URL\n12. URL of Anchor\n13. Links in tags\n14. SFH\n15. Submitting to email\n16. Abnormal URL\n'
          '17. IFrame\n18. Age of Domain\n19. DNS Record\n20. Web Traffic\n21. Google Index\n22. Statistical Reports\n')
    print(status)
    return status


# Use the below two lines if features_extraction.py is being run as a standalone file. If you are running this file as
# a part of the workflow pipeline starting with the chrome extension, comment out these two lines.
# if __name__ == "__main__":
#     if len(sys.argv) != 2:
#         print("Please use the following format for the command - `python2 features_extraction.py <url-to-be-tested>`")
#         exit(0)
#     main(sys.argv[1])
