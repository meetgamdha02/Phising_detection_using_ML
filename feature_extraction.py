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
import socket
import ssl
#from googlesearch.googlesearch import GoogleSearch
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
    def ssl_final_state(self,domain,url):
        PORT = 443
        sock = socket.socket()
        sock.connect((domain, PORT))
        sock = ssl.wrap_socket(sock,
        # flag that certificate from the other side of connection is required
        # and should be validated when wrapping 
        cert_reqs=ssl.CERT_REQUIRED,
        # file with root certificates
        ca_certs="cacert.pem"  
        )
        # security hole here - there should be an error about mismatched host name
        # manual check of hostname
        cert = sock.getpeercert()
        for field in cert['subject']:
            if field[0][0] == 'commonName':
                certhost = field[0][1]
                if certhost != domain:
                        #raise ssl.SSLError("Host name '%s' doesn't match certificate host '%s'"
                         #% (domain, certhost))
                        return -1
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
    def url_anchor(self,url,soup,err):
        if err:
            return -1
        else:
            i = 0
            unsafe = 0
            domain=self.getDomain(url)
            for a in soup.find_all('a', href=True):
                # 2nd condition was 'JavaScript ::void(0)' but we put JavaScript because the space between javascript and ::
                # might not be
                # there in the actual a['href']
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (
                        url in a['href'] or domain in a['href']):
                    unsafe = unsafe + 1
                i = i + 1
                # print a['href']
            try:
                percentage = unsafe / float(i) * 100
            except:
                return 1
            if percentage < 31.0:
                return 1
                # return percentage
            elif 31.0 <= percentage < 67.0:
                return 0
            else:
                return -1
    def link_in_tag(self,url,soup,err):
        if err:
            return -1
        else:
            domain=self.getDomain(url)
            i = 0
            success = 0
            for link in soup.find_all('link', href=True):
                dots = [x.start() for x in re.finditer(r'\.', link['href'])]
                if url in link['href'] or domain in link['href'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for script in soup.find_all('script', src=True):
                dots = [x.start() for x in re.finditer(r'\.', script['src'])]
                if url in script['src'] or domain in script['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1
            try:
                percentage = success / float(i) * 100
            except:
                return 1

            if percentage < 17.0:
                return 1
            elif 17.0 <= percentage < 81.0:
                return 0
            else:
                return -1
    #server form handler
    def sfh(self,url,soup,err):
        if err:
            return -1
        else:
            domain=self.getDomain(url)
            for form in soup.find_all('form', action=True):
                if form['action'] == "" or form['action'] == "about:blank":
                    return -1
                elif url not in form['action'] and domain not in form['action']:
                    return 0
                else:
                    return 1
            return 1
    def submit_to_email(self,soup,err):
        if err:
            return -1
        else:
            for form in soup.find_all('form', action=True):
                return -1 if "mailto:" in form['action'] else 1
            return 1
    def abnormal_url(self,domain,url):
        hostname = domain.name
        match = re.search(hostname, url)
        return 1 if match else -1
    def i_frame(self,soup,err):
        if err:
            return -1
        else:
            for i_frame in soup.find_all('i_frame', width=True, height=True, frameBorder=True):
                # Even if one iFrame satisfies the below conditions, it is safe to return -1 for this method.
                if i_frame['width'] == "0" and i_frame['height'] == "0" and i_frame['frameBorder'] == "0":
                    return -1
                if i_frame['width'] == "0" or i_frame['height'] == "0" or i_frame['frameBorder'] == "0":
                    return 0
            # If none of the iframes have a width or height of zero or a frameBorder of size 0, then it is safe to return 1.
            return 1
    def age_of_domain(self,domain):
        creation_date = domain.creation_date
        expiration_date = domain.expiration_date
        ageofdomain = 0
        if expiration_date:
            ageofdomain = abs((expiration_date - creation_date).days)
        return -1 if ageofdomain / 30 < 6 else 1
    def web_traffic(self,url):
        try:
            rank = \
                bs4.BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), 'xml').find(
                    "REACH")['RANK']
        except TypeError:
            return -1
        rank = int(rank)
        return 1 if rank < 100000 else 0
    def google_index(self,url):
        site = GoogleSearch().search(url, 5)
        return 1 if site else -1
    def statistical_report(self,url, hostname):
        try:
            ip_address = socket.gethostbyname(hostname)
        except:
            return -1
        url_match = re.search(
            r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
        ip_match = re.search(
            '146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
            '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
            '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
            '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
            '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
            '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
            ip_address)
        if url_match:
            return -1
        elif ip_match:
            return -1
        else:
            return 1


#prepare features
ip_address=[]
long_url=[]
have_at_symbol=[]
redirect=[]
pre_suf_sep=[]
sub_domains=[]
SSL_final_state=[]
srt_service=[]
domain_registration_length=[]
favicon=[]
https_tkn=[]
port=[]
req_url=[]
url_anchor=[]
link_in_tags=[]
sfh=[]
submitting_to_email=[]
abnormal_url=[]
i_frame=[]
age_of_domain=[]
web_traffic=[]
google_index=[]
statistical_report=[]

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
    hostname=fe.getDomain(url)
    dns = 1
    try:
        domain = whois.query(hostname)
    except:
        dns = -1
    '''
    ip_address.append(fe.has_ip_address(url))
    long_url.append(fe.url_length(url))
    srt_service.append(fe.shortening_service(url))
    have_at_symbol.append(fe.having_at_symbol(url))
    redirect.append(fe.redirection(url))
    pre_suf_sep.append(fe.prefix_suffix_sep(url))
    sub_domains.append(fe.sub_domain(url))
    SSL_final_state.append(-1 if dns == -1 else fe.ssl_final_state(domain,url))
    domain_registration_length.append(fe.domain_reg_len(url))
    favicon.append(fe.favicon(url,soup,notfound))
    port.append(fe.port(url))
    https_tkn.append(fe.https_token(url))
    req_url.append(fe.request_url(url,soup,notfound))
    url_anchor.append(fe.url_anchor(url,soup,notfound))
    link_in_tags.append(fe.link_in_tag(url,soup,notfound))
    sfh.append(fe.sfh(url,soup,notfound))
    sumitting_to_email.append(fe.submit_to_email(soup,notfound))
    abnormal_url.append(-1 if dns == -1 else fe.abnormal_url(domain, url))
    i_frame.append(fe.i_frame(soup,notfound))
    age_of_domain.append(-1 if dns == -1 else fe.age_of_domain(domain))
    web_traffic.append(fe.web_traffic(url))
    google_index.append(fe.google_index(url))
    statistical_report.append(fe.statistical_report(url,hostname))
    print(fe.has_ip_address(url))
    print(fe.url_length(url))
    print(fe.having_at_symbol(url))
    print(fe.redirection(url))
    print(fe.prefix_suffix_sep(url))
    print(fe.sub_domain(url))
    print(fe.shortening_service(url))
    print(fe.domain_reg_len(url))
    print(fe.favicon(url,soup,notfound))
    print(fe.https_token(url))
    print(fe.port(url))
    print(fe.request_url(url,soup,notfound))
    print(fe.url_anchor(url,soup,notfound))
    print(fe.link_in_tag(url,soup,notfound))
    print(fe.sfh(url,soup,notfound))
    print(fe.submit_to_email(soup,notfound))
    print(-1 if dns == -1 else fe.abnormal_url(domain, url))
    print(-1 if dns == -1 else fe.ssl_final_state(domain,url))
    print(fe.i_frame(soup,notfound))
    print(-1 if dns == -1 else fe.age_of_domain(domain))
    print(fe.web_traffic(url))
    #google_index not working due to urllib2 not found
    print(fe.google_index(url))
    '''
    print(fe.statistical_report(url,hostname))
#ip_address.append(fe.has_ip_address("http://31.220.111.56/asdq12/"))
#long_url.append(fe.url_length("http://e.webring.com/hub?sid=&amp;ring=hentff98&amp;id=&amp;list"))
#print(ip_address)
#print(long_url)
#print(fe.redirection("http://dj00.co.vu/css/?bsoul=Qg@xIHW%//yh/en/?i=34453&amp;i=34453"))
#print(urlparse("http://dj00.co.vu/css/?bsoul=Qg@xIHW%//yh/en/?i=34453&amp;i=34453").path)