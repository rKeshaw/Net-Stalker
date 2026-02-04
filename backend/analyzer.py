import requests
import whois
import ssl
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import re
from datetime import datetime

class BasicPhishingAnalyzer:
    def __init__(self, url):
        self.url = url
        self.features = {}
        self.features['geo_path'] = []
        
    def analyze(self):
        if not self._is_valid_url(self.url):
            return {"error": "Invalid URL format"}
        
        self.parsed_url = urlparse(self.url)
        
        if not self.parsed_url.scheme or not self.parsed_url.netloc:
            return {"error": "Invalid URL format - missing scheme or domain"}
            
        try:
            self.extract_url_features()
            self.check_domain_info()
            self.check_ssl()
            self.fetch_content()
            self.analyze_geo_path()
            return self.features
        except Exception as e:
            return {"error": str(e)}
    
    def _is_valid_url(self, url):
        if not url.startswith(('http://', 'https://')):
            return False
        return True
    
    def extract_url_features(self):
        self.features['url'] = self.url
        self.features['domain'] = self.parsed_url.netloc
        self.features['protocol'] = self.parsed_url.scheme
        self.features['path'] = self.parsed_url.path
        self.features['has_ip'] = self._check_ip_in_url()
        self.features['url_length'] = len(self.url)
        self.features['subdomain_count'] = len(self.parsed_url.netloc.split('.')) - 2
        
    def _check_ip_in_url(self):
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.search(ip_pattern, self.parsed_url.netloc))
    
    def check_domain_info(self):
        try:
            domain = self.parsed_url.netloc
            if domain.startswith('www.'):
                domain = domain[4:]
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                age_days = (datetime.now() - creation_date).days
                self.features['domain_age_days'] = age_days
            else:
                self.features['domain_age_days'] = "Hidden/Unknown"
        except Exception:
            self.features['domain_age_days'] = "Lookup Failed"
    
    def check_ssl(self):
        try:
            if self.parsed_url.scheme == 'https':
                context = ssl.create_default_context()
                with socket.create_connection((self.parsed_url.netloc, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.parsed_url.netloc) as ssock:
                        self.features['ssl_valid'] = True
            else:
                self.features['ssl_valid'] = False
        except:
            self.features['ssl_valid'] = False
    
    def fetch_content(self):
        try:
            self.response = requests.get(self.url, timeout=19, headers={
                'User-Agent': 'Mozilla/5.0 (PhishingAnalyzer/1.0)'
            })
            
            self.features['status_code'] = self.response.status_code
            self.features['final_url'] = self.response.url
            self.features['redirected'] = self.response.url != self.url
            
            soup = BeautifulSoup(self.response.text, 'html.parser')
            text_content = soup.get_text(separator=' ', strip=True)
            self.features['page_text'] = text_content[:2000]
            self.features['form_count'] = len(soup.find_all('form'))
            password_inputs = soup.find_all('input', {'type': 'password'})
            self.features['has_password_field'] = len(password_inputs) > 0
            
            links = soup.find_all('a', href=True)
            external_links = [l for l in links if self.parsed_url.netloc not in l['href']]
            self.features['external_link_count'] = len(external_links)
            
        except Exception as e:
            self.features['content_error'] = str(e)
            self.response = None

    def analyze_geo_path(self):
        if not hasattr(self, 'response') or not self.response:
            self._resolve_and_add_hop(self.url, 0, "Initial")
        else:
            hop_index = 0
            if self.response.history:
                for resp in self.response.history:
                    self._resolve_and_add_hop(resp.url, hop_index, "Redirect")
                    hop_index += 1
            self._resolve_and_add_hop(self.response.url, hop_index, "Final Destination")

        if self.features['geo_path']:
            final_hop = self.features['geo_path'][-1]
            
            self.features['hosting_ip'] = final_hop.get('ip')
            self.features['geo_location'] = {
                'country': final_hop.get('country'),
                'city': final_hop.get('city'),
                'isp': final_hop.get('isp'),
                'lat': final_hop.get('lat'),
                'lon': final_hop.get('lon')
            }

    def _resolve_and_add_hop(self, url, index, hop_type):
        try:
            domain = urlparse(url).netloc
            if ':' in domain:
                domain = domain.split(':')[0]
            
            try:
                ip_address = socket.gethostbyname(domain)
            except socket.gaierror:
                return

            api_url = f"http://ip-api.com/json/{ip_address}"
            resp = requests.get(api_url, timeout=5)
            
            if resp.status_code == 200:
                geo_data = resp.json()
                if geo_data.get('status') == 'success':
                    self.features['geo_path'].append({
                        'hop': index + 1,
                        'type': hop_type,
                        'url': url,
                        'domain': domain,
                        'ip': ip_address,
                        'country': geo_data.get('country'),
                        'city': geo_data.get('city'),
                        'isp': geo_data.get('isp'),
                        'lat': geo_data.get('lat'),
                        'lon': geo_data.get('lon')
                    })
                
        except Exception as e:
            pass
