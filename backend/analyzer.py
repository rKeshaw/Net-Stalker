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
        
    def analyze(self):
        """Run all basic analyses"""
        # Better URL validation
        if not self._is_valid_url(self.url):
            return {"error": "Invalid URL format"}
        
        self.parsed_url = urlparse(self.url)
        
        # Check if URL has proper scheme and netloc
        if not self.parsed_url.scheme or not self.parsed_url.netloc:
            return {"error": "Invalid URL format - missing scheme or domain"}
            
        try:
            self.extract_url_features()
            self.check_domain_info()
            self.check_ssl()
            self.fetch_content()
            return self.features
        except Exception as e:
            return {"error": str(e)}
    
    def _is_valid_url(self, url):
        """Validate URL format"""
        # Must start with http:// or https://
        if not url.startswith(('http://', 'https://')):
            return False
        
        # Basic regex for URL validation
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ipv4
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        return bool(url_pattern.match(url))
    
    def extract_url_features(self):
        """Extract basic URL structure features"""
        self.features['url'] = self.url
        self.features['domain'] = self.parsed_url.netloc
        self.features['protocol'] = self.parsed_url.scheme
        self.features['path'] = self.parsed_url.path
        self.features['has_ip'] = self._check_ip_in_url()
        self.features['url_length'] = len(self.url)
        self.features['subdomain_count'] = len(self.parsed_url.netloc.split('.')) - 2
        
    def _check_ip_in_url(self):
        """Check if URL contains IP address instead of domain"""
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.search(ip_pattern, self.parsed_url.netloc))
    
    def check_domain_info(self):
        """Get WHOIS information"""
        try:
            domain_info = whois.whois(self.parsed_url.netloc)
            if domain_info.creation_date:
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                age_days = (datetime.now() - creation_date).days
                self.features['domain_age_days'] = age_days
            else:
                self.features['domain_age_days'] = None
                
            self.features['registrar'] = domain_info.registrar
        except Exception as e:
            self.features['domain_age_days'] = None
            self.features['registrar'] = None
    
    def check_ssl(self):
        """Check SSL certificate validity"""
        try:
            if self.parsed_url.scheme == 'https':
                context = ssl.create_default_context()
                with socket.create_connection((self.parsed_url.netloc, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.parsed_url.netloc) as ssock:
                        cert = ssock.getpeercert()
                        self.features['ssl_valid'] = True
                        self.features['ssl_issuer'] = dict(x[0] for x in cert['issuer'])
            else:
                self.features['ssl_valid'] = False
                self.features['ssl_issuer'] = None
        except Exception:
            self.features['ssl_valid'] = False
            self.features['ssl_issuer'] = None
    
    def fetch_content(self):
        """Fetch and analyze page content"""
        try:
            response = requests.get(self.url, timeout=10, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            self.features['status_code'] = response.status_code
            self.features['final_url'] = response.url
            self.features['redirected'] = response.url != self.url
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract text content (limited for LLM)
            text_content = soup.get_text(separator=' ', strip=True)
            self.features['page_text'] = text_content[:2000]  # Limit to 2000 chars
            
            # Count forms
            forms = soup.find_all('form')
            self.features['form_count'] = len(forms)
            
            # Check for password inputs
            password_inputs = soup.find_all('input', {'type': 'password'})
            self.features['has_password_field'] = len(password_inputs) > 0
            
            # External links count
            links = soup.find_all('a', href=True)
            external_links = [l for l in links if self.parsed_url.netloc not in l['href']]
            self.features['external_link_count'] = len(external_links)
            
        except Exception as e:
            self.features['content_error'] = str(e)
