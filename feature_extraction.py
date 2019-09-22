# 1 for legitimate
# 0 for suspisious
# -1 for phishing
import re
import pandas as pd
from urllib.parse import urlparse,urlencode


#getting raw urls
raw_data=pd.read_csv("raw_urls/phising.txt",header=None,names=['urls'])

class FeatureExtract:
    def __init__(self):
        pass

    def getProtocol(self,url):
        return urlparse(url).scheme
    
    def getDomain(self,url):
        return urlparse(url).netloc
    
    def getPath(self,url):
        return urlparse(url).path

    def has_ip_address(self,url):
        match=re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4 in hexadecimal
                    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',url)     #Ipv6
        return -1 if match else 1
    def url_length(self,url):
        thr1=54
        thr2=75
        if len(url)<thr1:
            return 1
        elif len(url)>=thr1 and len(url)<=thr2:
            return 0
        else:
            return -1
    def having_at_symbol(self,url):
        match= re.search('@',url)
        return -1 if match else 1
    def redirection(self,url):
        #implementation 1
        if "//" in urlparse(url).path:
            return -1            
        else:
            return 1
        #implementation 2
        #last_double_slash = url.rfind('//')
        #return -1 if last_double_slash > 6 else 1

#prepare features
ip_address=[]
long_url=[]
have_at_symbol=[]
redirect=[]
#Extracting features from url
fe=FeatureExtract()
nrows=len(raw_data["urls"])

for i in range(0,nrows):
    url=raw_data["urls"][i]
    print(i),print(url)
    ip_address.append(fe.has_ip_address(url))
    long_url.append(fe.url_length(url))
    have_at_symbol.append(fe.having_at_symbol(url))
    redirect.append(fe.redirection(url))
    print(fe.has_ip_address(url))
    print(fe.url_length(url))
    print(fe.having_at_symbol(url))
    print(fe.redirection(url))

#ip_address.append(fe.has_ip_address("http://31.220.111.56/asdq12/"))
#long_url.append(fe.url_length("http://e.webring.com/hub?sid=&amp;ring=hentff98&amp;id=&amp;list"))
#print(ip_address)
#print(long_url)
#print(fe.redirection("http://dj00.co.vu/css/?bsoul=Qg@xIHW%//yh/en/?i=34453&amp;i=34453"))
#print(urlparse("http://dj00.co.vu/css/?bsoul=Qg@xIHW%//yh/en/?i=34453&amp;i=34453").path)