import ipaddress
import re
import urllib.request
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse


class FeatureExtraction:
    features = []
    def __init__(self,url):
        self.features = []
       # self.features.append(self.getDomain(url))
        self.features.append(self.havingIP(url))
        self.features.append(self.haveAtSign(url))
        self.features.append(self.getLength(url))
        self.features.append(self.getDepth(url))
        self.features.append(self.redirection(url))
        self.features.append(self.httpDomain(url))
        self.features.append(self.tinyURL(url))
        self.features.append(self.prefixSuffix(url))

        #Domain based features (4)
        dns = 0
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1

        self.features.append(dns)
        # features.append(web_traffic(url))
        self.features.append(1 if dns == 1 else domainAge(self.domain_name))
        #  features.append(1 if dns == 1 else domainEnd(domain_name))
      #self.features.append(self.label)

    def getDomain(self, url):
        domain = urlparse(url).netloc
        if re.match(r"^www.",domain):
            domain = domain.replace("www.","")
        return domain

# 2.Checks for IP address in URL (Have_IP)
    def havingIP(self, url):
        try:
            ipaddress.ip_address(url)
            ip = 1
        except:
            ip = 0
        return ip

# 3.Checks the presence of @ in URL (Have_At)
    def haveAtSign(self, url):
        if "@" in url:
            at = 1
        else:
            at = 0
        return at

#4.Finding the length of URL and categorizing (URL_Length)
    def getLength(self, url):
        if len(url) < 54:
            length = 0
        else:
            length = 1
        return length

# 5.Gives the depth of a URL 
    def getDepth(self, url):
        s = urlparse(url).path.split('/')
        depth = 0
        for j in range(len(s)):
            if len(s[j]) != 0:
                depth = depth+1
        return depth

# 6.Checking for redirection '//' in the url (Redirection)
    def redirection(self, url):
        pos = url.rfind('//')
        if pos > 6:
            if pos > 7:
                return 1
            else:
                return 0
        else:
            return 0

# 7.Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
    def httpDomain(self, url):
        domain = urlparse(url).netloc
        if 'https' in domain:
            return 1
        else:
            return 0


#listing shortening services
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

# 8. Checking for Shortening Services in URL (Tiny_URL)
    def tinyURL(self, url):
        match=re.search(self.shortening_services,url)
        if match:
            return 1
        else:
            return 0

# 9.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
    def prefixSuffix(self, url):
        if '-' in urlparse(url).netloc:
            return 1            # phishing
        else:
            return 0            # legitimate

#!pip install python-whois

# importing required packages for this section

# 11.DNS Record availability (DNS_Record)
# obtained in the featureExtraction function itself

# 12.Web traffic (Web_Traffic)
    def web_traffic(self, url):
        try:
            #Filling the whitespaces in the URL if any
            url = urllib.parse.quote(url)
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find(
            "REACH")['RANK']
            rank = int(rank)
        except TypeError:
            return 1
        if rank <100000:
            return 1
        else:
            return 0

# 13.Survival time of domain: The difference between termination time and creation time (Domain_Age)
    def domainAge(self, domain_name):
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
            try:
                creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
            except:
                return 1
        if ((expiration_date is None) or (creation_date is None)):
            return 1
        elif ((type(expiration_date) is list) or (type(creation_date) is list)):
            return 1
        else:
            ageofdomain = abs((expiration_date - creation_date).days)
            if ((ageofdomain/30) < 6):
                age = 1
            else:
                age = 0
        return age

# 14.End time of domain: The difference between termination time and current time (Domain_End)
    def domainEnd(self, domain_name):
        expiration_date = domain_name.expiration_date
        if isinstance(expiration_date,str):
            try:
                expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
            except:
                return 1
        if (expiration_date is None):
            return 1
        elif (type(expiration_date) is list):
            return 1
        else:
            today = datetime.now()
            end = abs((expiration_date - today).days)
            if ((end/30) < 6):
                end = 0
            else:
                end = 1
        return end


    def getFeaturesList(self):
        return self.features