import re
import pandas as pd

#getting raw urls
raw_data=pd.read_csv("raw_urls/phising.txt",header=None,names=['urls'])

class FeatureExtract:
    def __init__(self):
        pass

    def has_ip_address(self,url):
        match=re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4 in hexadecimal
                    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',url)     #Ipv6
        return -1 if match else 1
#prepare features
ip_address=[]

#Extracting features from url
fe=FeatureExtract()
nrows=len(raw_data["urls"])

for i in range(0,nrows):
    url=raw_data["urls"][i]
    print(i),print(url)
    ip_address.append(fe.has_ip_address(url))

#ip_address.append(fe.has_ip_address("http://31.220.111.56/asdq12/"))
print(ip_address)