# 1 for legitimate
# 0 for suspisious
# -1 for phishing
import re
import pandas as pd
from urllib.parse import urlparse,urlencode
from datetime import datetime
import whois
import time
import bs4
import requests
import urllib

#getting raw urls
#raw_data=pd.read_csv("raw_urls/phising.txt",header=None,names=['urls'])
raw_data=pd.read_csv("raw_urls/legitimate.txt",header=None,names=['urls'])


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
    def prefix_suffix_sep(self,url):
        if "-" in urlparse(url).netloc:
            return -1          
        else:
            return 1
    def sub_domain(self,url):
        thr1=3
        thr2=4
        if self.has_ip_address(url) == -1:
            match = re.search(
                '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                '([01]?\\d\\d?|2[0-4]\\d|25[0-5]))|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',
                url)
            ps = match.end()
            url = url[ps:]
        num_dots = [x.start() for x in re.finditer(r'\.', url)]
        if len(num_dots) <= thr1:
            return 1
        elif len(num_dots) == thr2:
            return 0
        else:
            return -1
    def shortening_service(self,url):
        match=re.search(r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net",url)
        return -1 if match else 1   
    def domain_reg_len(self,url):
        dns = 0
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1
        
        if dns == 1:
            return -1      #phishing
        else:
            expiration_date = domain_name.expiration_date
            today = time.strftime('%Y-%m-%d')
            today = datetime.strptime(today, '%Y-%m-%d')
            if expiration_date is None:
                return -1
            elif type(expiration_date) is list or type(today) is list :
                return 0     #If it is a type of list then we can't select a single value from list. So,it is regarded as suspected website  
            else:
                creation_date = domain_name.creation_date
                expiration_date = domain_name.expiration_date
                if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
                    try:
                        creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                        expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
                    except:
                        return 0
                registration_length = abs((expiration_date - today).days)
                if registration_length / 365 <= 1:
                    return -1 #phishing
                else:
                    return 1 # legitimate
    def favicon(self,url,soup,err):
        if err:
            return -1
        else:
            domain=urlparse(url).netloc
            for head in soup.find_all('head'):
                for head.link in soup.find_all('link', href=True):
                    dots = [x.start() for x in re.finditer(r'\.', head.link['href'])]
                    return 1 if url in head.link['href'] or len(dots) == 1 or domain in head.link['href'] else -1
            return 1
    def https_token(self,url):
        match = re.search(r"https://|http://", url)
        if match and match.start() == 0:
            url = url[match.end():]
        match = re.search('http|https', url)
        return -1 if match else 1
    def port(self,url):
        try:
            domain=self.getDomain(url)
            port = domain.split(":")[1]
            if port:
                return 1
            else:
                return -1
        except:
            return -1
    def request_url(self,url,soup,err):
        if err:
            return -1
        else:
            i = 0
            success = 0
            domain=self.getDomain(url)
            for img in soup.find_all('img', src=True):
                dots = [x.start() for x in re.finditer(r'\.', img['src'])]
                if url in img['src'] or domain in img['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for audio in soup.find_all('audio', src=True):
                dots = [x.start() for x in re.finditer(r'\.', audio['src'])]
                if url in audio['src'] or domain in audio['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for embed in soup.find_all('embed', src=True):
                dots = [x.start() for x in re.finditer(r'\.', embed['src'])]
                if url in embed['src'] or domain in embed['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for i_frame in soup.find_all('i_frame', src=True):
                dots = [x.start() for x in re.finditer(r'\.', i_frame['src'])]
                if url in i_frame['src'] or domain in i_frame['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            try:
                percentage = success / float(i) * 100
            except:
                return 1

            if percentage < 22.0:
                return 1
            elif 22.0 <= percentage < 61.0:
                return 0
            else:
                return -1


#prepare features
ip_address=[]
long_url=[]
have_at_symbol=[]
redirect=[]
pre_suf_sep=[]
sub_domains=[]
srt_service=[]
domain_registration_length=[]
favicon=[]
https_tkn=[]
port=[]
req_url=[]

#Extracting features from url
fe=FeatureExtract()
nrows=len(raw_data["urls"])

for i in range(0,nrows):
    url=raw_data["urls"][i]
    print(i),print(url)
    notfound=0
    cnt=""
    try:
        cnt=urllib.request.urlopen(url).read()
    except:
        notfound=1
    soup=bs4.BeautifulSoup(cnt,'html.parser')
    '''
    ip_address.append(fe.has_ip_address(url))
    long_url.append(fe.url_length(url))
    have_at_symbol.append(fe.having_at_symbol(url))
    redirect.append(fe.redirection(url))
    pre_suf_sep.append(fe.prefix_suffix_sep(url))
    sub_domains.append(fe.sub_domain(url))
    srt_service.append(fe.shortening_service(url))
    #domain_registration_length.append(fe.domain_reg_len(url))
    favicon.append(fe.favicon(url,soup,notfound))
    https_tkn.append(fe.https_token(url))
    port.append(fe.port(url))
    req_url.append(fe.request_url(url,soup,notfound))
    print(fe.has_ip_address(url))
    print(fe.url_length(url))
    print(fe.having_at_symbol(url))
    print(fe.redirection(url))
    print(fe.prefix_suffix_sep(url))
    print(fe.sub_domain(url))
    print(fe.shortening_service(url))
    #print(fe.domain_reg_len(url))
    print(fe.favicon(url,soup,notfound))
    print(fe.https_token(url))
    print(fe.port(url))
    '''
    print(fe.request_url(url,soup,notfound))

#ip_address.append(fe.has_ip_address("http://31.220.111.56/asdq12/"))
#long_url.append(fe.url_length("http://e.webring.com/hub?sid=&amp;ring=hentff98&amp;id=&amp;list"))
#print(ip_address)
#print(long_url)
#print(fe.redirection("http://dj00.co.vu/css/?bsoul=Qg@xIHW%//yh/en/?i=34453&amp;i=34453"))
#print(urlparse("http://dj00.co.vu/css/?bsoul=Qg@xIHW%//yh/en/?i=34453&amp;i=34453").path)