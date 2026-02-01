import email
from email import policy
from email.parser import BytesParser
import re
from datetime import datetime
from urllib.parse import urlparse
import hashlib

class EmailPhishingAnalyzer:
    # Bit hard-coded, but works for this purpose
    def __init__(self, email_content):
        """
        Initialize with email content (bytes or string)
        """
        if isinstance(email_content, str):
            email_content = email_content.encode('utf-8')
        
        self.email_content = email_content
        self.features = {}
        self.msg = None
        
    def analyze(self):
        """Run all email analyses"""
        try:
            # Parse email
            self.msg = BytesParser(policy=policy.default).parsebytes(self.email_content)
            
            self.extract_header_features()
            self.extract_sender_features()
            self.extract_content_features()
            self.extract_links()
            self.extract_attachments()
            self.check_authentication()
            
            return self.features
        except Exception as e:
            return {"error": f"Email parsing failed: {str(e)}"}
    
    def extract_header_features(self):
        """Extract basic email header information"""
        self.features['subject'] = self.msg.get('Subject', 'No Subject')
        self.features['from'] = self.msg.get('From', 'Unknown')
        self.features['to'] = self.msg.get('To', 'Unknown')
        self.features['date'] = self.msg.get('Date', 'Unknown')
        self.features['message_id'] = self.msg.get('Message-ID', 'Unknown')
        self.features['reply_to'] = self.msg.get('Reply-To', None)
        
        # Check for reply-to mismatch
        from_addr = self._extract_email_address(self.features['from'])
        reply_to_addr = self._extract_email_address(self.features['reply_to']) if self.features['reply_to'] else None
        self.features['reply_to_mismatch'] = (reply_to_addr is not None and from_addr != reply_to_addr)
    
    def extract_sender_features(self):
        """Analyze sender information"""
        from_addr = self._extract_email_address(self.features['from'])
        self.features['sender_email'] = from_addr
        
        if from_addr:
            # Extract domain
            domain = from_addr.split('@')[1] if '@' in from_addr else None
            self.features['sender_domain'] = domain
            
            # Check for suspicious patterns
            self.features['sender_has_numbers'] = bool(re.search(r'\d', from_addr.split('@')[0]))
            self.features['sender_domain_has_subdomain'] = len(domain.split('.')) > 2 if domain else False
        else:
            self.features['sender_domain'] = None
            self.features['sender_has_numbers'] = False
            self.features['sender_domain_has_subdomain'] = False
    
    def extract_content_features(self):
        """Analyze email body content"""
        # Get plain text body
        body_text = self._get_email_body()
        self.features['body_text'] = body_text[:2000]  # Limit for LLM
        self.features['body_length'] = len(body_text)
        
        # Check for urgency keywords
        urgency_keywords = [
            'urgent', 'immediate', 'action required', 'verify', 'suspend',
            'confirm', 'click here', 'act now', 'limited time', 'expire',
            'update', 'security alert', 'unusual activity'
        ] # hard-coded, but okay for demo

        urgency_count = sum(1 for keyword in urgency_keywords if keyword.lower() in body_text.lower())
        self.features['urgency_keyword_count'] = urgency_count
        
        # Check for financial keywords
        financial_keywords = ['bank', 'account', 'payment', 'credit card', 'paypal', 'transaction']
        financial_count = sum(1 for keyword in financial_keywords if keyword.lower() in body_text.lower())
        self.features['financial_keyword_count'] = financial_count
        
        # Check for spelling/grammar issues (simple heuristic)
        self.features['has_spelling_errors'] = self._check_spelling_errors(body_text)
    
    def extract_links(self):
        """Extract and analyze links in email"""
        body_text = self._get_email_body()
        
        # Extract URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, body_text)
        
        self.features['link_count'] = len(urls)
        self.features['links'] = urls[:10]  # Store first 10 links
        
        # Check for IP-based URLs
        ip_based_urls = [url for url in urls if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)]
        self.features['has_ip_based_url'] = len(ip_based_urls) > 0
        
        # Check for shortened URLs
        shortener_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
        shortened_urls = [url for url in urls if any(domain in url for domain in shortener_domains)]
        self.features['has_shortened_url'] = len(shortened_urls) > 0
        
        # Check for mismatched link text (if HTML)
        if self.msg.is_multipart():
            html_body = self._get_html_body()
            if html_body:
                self.features['link_text_mismatch'] = self._check_link_mismatch(html_body)
        else:
            self.features['link_text_mismatch'] = False
    
    def extract_attachments(self):
        """Analyze email attachments"""
        attachments = []
        
        for part in self.msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                if filename:
                    # Get file extension
                    ext = filename.split('.')[-1].lower() if '.' in filename else 'none'
                    
                    attachments.append({
                        'filename': filename,
                        'extension': ext,
                        'size': len(part.get_payload(decode=True)) if part.get_payload(decode=True) else 0
                    })
        
        self.features['attachment_count'] = len(attachments)
        self.features['attachments'] = attachments
        
        # Check for suspicious extensions
        suspicious_exts = ['exe', 'scr', 'bat', 'cmd', 'com', 'pif', 'vbs', 'js', 'jar', 'zip']
        has_suspicious = any(att['extension'] in suspicious_exts for att in attachments)
        self.features['has_suspicious_attachment'] = has_suspicious
    
    def check_authentication(self):
        """Check email authentication headers"""
        # SPF
        spf_header = self.msg.get('Received-SPF', '')
        self.features['spf_result'] = 'pass' if 'pass' in spf_header.lower() else 'fail/unknown'
        
        # DKIM
        dkim_header = self.msg.get('DKIM-Signature', '')
        self.features['has_dkim'] = bool(dkim_header)
        
        # Authentication-Results
        auth_results = self.msg.get('Authentication-Results', '')
        self.features['authentication_results'] = auth_results[:200] if auth_results else 'None'
    
    def _extract_email_address(self, email_field):
        """Extract email address from header field"""
        if not email_field:
            return None
        
        # Match email pattern
        match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', email_field)
        return match.group(0) if match else None
    
    def _get_email_body(self):
        """Extract plain text body"""
        if self.msg.is_multipart():
            for part in self.msg.walk():
                if part.get_content_type() == 'text/plain':
                    payload = part.get_payload(decode=True)
                    if payload:
                        return payload.decode('utf-8', errors='ignore')
        else:
            payload = self.msg.get_payload(decode=True)
            if payload:
                return payload.decode('utf-8', errors='ignore')
        
        return ""
    
    def _get_html_body(self):
        """Extract HTML body"""
        if self.msg.is_multipart():
            for part in self.msg.walk():
                if part.get_content_type() == 'text/html':
                    payload = part.get_payload(decode=True)
                    if payload:
                        return payload.decode('utf-8', errors='ignore')
        return None
    
    def _check_link_mismatch(self, html_body):
        """Check if link text doesn't match href"""
        # Simple check for <a href="X">Y</a> where X != Y
        pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
        matches = re.findall(pattern, html_body, re.IGNORECASE)
        
        for href, text in matches:
            # If text looks like a URL but doesn't match href
            if re.match(r'http[s]?://', text.strip()) and text.strip() != href:
                return True
        
        return False
    
    def _check_spelling_errors(self, text):
        """Simple heuristic for spelling errors"""
        # Check for excessive uppercase
        if len(text) > 50:
            upper_ratio = sum(1 for c in text if c.isupper()) / len(text)
            if upper_ratio > 0.3:
                return True
        
        # Check for repeated characters (e.g., "hellooo")
        if re.search(r'(.)\1{3,}', text):
            return True
        
        return False
