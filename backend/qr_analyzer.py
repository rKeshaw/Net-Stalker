from logging_config import get_logger
logger = get_logger(__name__)

import cv2
import numpy as np
from pyzbar import pyzbar
from PIL import Image
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs
import re
import os
import aiohttp
import asyncio
from external_apis import ExternalAPIAggregator

class QRCodeAnalyzer:
    """
    Dynamic QR Code Analyzer.
    Features:
    - URL Unfurling (Follows redirects to find true destination)
    - External Intelligence Integration (VirusTotal, OTX, etc.)
    - Heuristic Pattern Detection
    """
    
    def __init__(self):
        # We reuse the aggregator to avoid re-initializing API clients
        self.api_aggregator = ExternalAPIAggregator()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }

    async def analyze_screenshot(self, screenshot_path: str, page_url: str = None) -> Dict[str, Any]:
        """
        Analyze screenshot for QR codes using behavioral and reputation analysis.
        """
        result = {
            'qr_codes_found': 0,
            'qr_codes': [],
            'phishing_detected': False,
            'risk_level': 'none',
            'indicators': [],
            'processing_error': None
        }
        
        if not os.path.exists(screenshot_path):
            result['processing_error'] = 'Screenshot file not found'
            return result
        
        try:
            # Load and Preprocess Image
            image = cv2.imread(screenshot_path)
            if image is None:
                result['processing_error'] = 'Failed to load image format'
                return result
            
            # 1. Detect QR Codes
            raw_codes = self._detect_qr_codes(image)
            result['qr_codes_found'] = len(raw_codes)
            
            if not raw_codes:
                return result

            # 2. Analyze Codes Concurrently
            # We process all found QR codes in parallel for speed
            tasks = [self._analyze_single_qr(qr, page_url, i) for i, qr in enumerate(raw_codes)]
            analyzed_codes = await asyncio.gather(*tasks)
            
            result['qr_codes'] = analyzed_codes

            # 3. Aggregate Risk
            self._aggregate_risk(result)
            
        except Exception as e:
            result['processing_error'] = f"Global Analysis Error: {str(e)}"
        
        return result
    
    def _detect_qr_codes(self, image) -> List[Dict[str, Any]]:
        """Extract raw QR data using pyzbar"""
        codes = []
        try:
            # Convert to grayscale for better detection
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            decoded_objects = pyzbar.decode(gray)
            
            for obj in decoded_objects:
                codes.append({
                    'type': obj.type,
                    'data': obj.data.decode('utf-8', errors='ignore'),
                    'rect': obj.rect,
                    'polygon': obj.polygon
                })
        except Exception as e:
            logger.warning(f"QR Extraction Warning: {e}")
        return codes

    async def _analyze_single_qr(self, qr_data: Dict, page_url: str, index: int) -> Dict[str, Any]:
        """Deep analysis of a single QR code"""
        analysis = {
            'index': index,
            'data': qr_data['data'],
            'type': 'text',
            'is_phishing': False,
            'risk_score': 0,  # 0-100
            'indicators': [],
            'url_analysis': None
        }

        data = qr_data['data'].strip()

        # Check if data looks like a URL
        # Regex handles http/https and schemes like 'wifi:', 'mailto:'
        url_pattern = re.compile(r'^(?:http|ftp)s?://' 
                                 r'|^(?:mailto|tel|sms|wifi):', re.IGNORECASE)
        
        if url_pattern.match(data) or '.' in data[:20]: # Heuristic for "google.com" without http
            analysis['type'] = 'url'
            # normalize URL
            if not url_pattern.match(data) and '.' in data:
                data = f"https://{data}"

            await self._analyze_qr_url(data, analysis, page_url)
        else:
            # Static Text Analysis
            self._analyze_raw_text(data, analysis)

        # Final Risk Verdict
        if analysis['risk_score'] >= 75:
            analysis['is_phishing'] = True
            
        return analysis

    async def _analyze_qr_url(self, raw_url: str, analysis: Dict, page_url: str):
        """
        The Core Logic: Unfurl -> Scan -> heuristic check
        """
        analysis['url_analysis'] = {
            'raw_url': raw_url,
            'final_url': raw_url,
            'redirect_chain': [],
            'external_api_verdict': 'unknown'
        }

        # 1. Unfurl (Follow Redirects)
        try:
            final_url, history = await self._unfurl_url(raw_url)
            analysis['url_analysis']['final_url'] = final_url
            analysis['url_analysis']['redirect_chain'] = history
            
            # Detect Open Redirect Abuse (e.g., google.com -> malicious.com)
            if len(history) > 0:
                initial_domain = urlparse(raw_url).netloc
                final_domain = urlparse(final_url).netloc
                
                if initial_domain != final_domain:
                    # Check if we started at a "trusted" domain and ended up somewhere else
                    trusted_redirectors = ['google.com', 'bing.com', 'linkedin.com', 'facebook.com']
                    if any(t in initial_domain for t in trusted_redirectors):
                        analysis['indicators'].append(f"Suspicious Open Redirect: Started at {initial_domain}, ended at {final_domain}")
                        analysis['risk_score'] += 30

        except Exception as e:
            analysis['indicators'].append(f"URL Unfurling Failed: {str(e)}")
            # If we can't reach it, that's suspicious in itself for a QR code
            analysis['risk_score'] += 20 
            final_url = raw_url

        # 2. External Intelligence Scan
        # We scan the FINAL url, not just the initial one
        api_result = await self.api_aggregator.check_url(final_url)
        
        verdict = api_result.get('aggregated_verdict', 'unknown')
        analysis['url_analysis']['external_api_verdict'] = verdict
        
        if verdict == 'malicious':
            analysis['risk_score'] = 100
            analysis['indicators'].append(f"CRITICAL: Flagged as malicious by external threat intelligence ({api_result.get('summary')})")
        elif verdict == 'suspicious':
            analysis['risk_score'] += 50
            analysis['indicators'].append("Flagged as suspicious by external threat intelligence")

        # 3. Heuristic & Technical Checks on Final URL
        parsed_final = urlparse(final_url)
        
        # A. IP Address Check
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed_final.netloc):
            analysis['indicators'].append("Destination is a raw IP address (High Risk)")
            analysis['risk_score'] += 40

        # B. Suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.club', '.win', '.gq', '.cn', '.ru', '.zip']
        if any(parsed_final.netloc.endswith(tld) for tld in suspicious_tlds):
            analysis['indicators'].append(f"Destination uses suspicious TLD: {parsed_final.netloc}")
            analysis['risk_score'] += 25

        # C. HTTP vs HTTPS
        if parsed_final.scheme == 'http':
            analysis['indicators'].append("Destination is insecure (HTTP)")
            analysis['risk_score'] += 10

        # D. Domain Mismatch (if context provided)
        if page_url:
            page_domain = urlparse(page_url).netloc
            qr_domain = parsed_final.netloc
            # Simple check: if QR goes to a different domain than the page hosting it
            # This is common in phishing, but also common in ads. We add a low score.
            if page_domain and qr_domain and page_domain not in qr_domain and qr_domain not in page_domain:
                # Only flag if it's not a common CDN or social link
                common_external = ['facebook', 'twitter', 'linkedin', 'instagram', 'youtube']
                if not any(c in qr_domain for c in common_external):
                    analysis['indicators'].append(f"Cross-Domain QR: Page is {page_domain}, QR goes to {qr_domain}")
                    analysis['risk_score'] += 10

    async def _unfurl_url(self, url: str) -> tuple[str, List[str]]:
        """
        Follow HTTP redirects to find the absolute final destination.
        Returns: (final_url, list_of_hops)
        """
        history = []
        timeout = aiohttp.ClientTimeout(total=10)
        
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.head(url, headers=self.headers, allow_redirects=True) as response:
                    if response.history:
                        for resp in response.history:
                            history.append(str(resp.url))
                    return str(response.url), history
        except:
            # Fallback to GET if HEAD fails (some servers block HEAD)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=self.headers, allow_redirects=True) as response:
                     if response.history:
                        for resp in response.history:
                            history.append(str(resp.url))
                     return str(response.url), history

    def _analyze_raw_text(self, text: str, analysis: Dict):
        """Analyze non-URL text for risks (e.g. malicious command strings)"""
        # Check for command injection patterns
        if any(x in text for x in ['powershell', 'cmd.exe', '/bin/sh', 'curl ', 'wget ']):
            analysis['indicators'].append("Contains potential command injection strings")
            analysis['risk_score'] += 80
            analysis['type'] = 'malicious_payload'
        
        # Check for obfuscated encoding
        if len(text) > 20 and not ' ' in text:
            if re.match(r'^[A-Za-z0-9+/=]+$', text): # Base64-ish
                analysis['indicators'].append("Contains obfuscated/Base64 text string")
                analysis['risk_score'] += 20

    def _aggregate_risk(self, result: Dict):
        """Determine global risk level based on findings"""
        max_score = 0
        phishing_found = False
        
        for qr in result['qr_codes']:
            if qr['risk_score'] > max_score:
                max_score = qr['risk_score']
            if qr['is_phishing']:
                phishing_found = True
                
        result['phishing_detected'] = phishing_found
        
        if max_score >= 80:
            result['risk_level'] = 'critical'
        elif max_score >= 50:
            result['risk_level'] = 'high'
        elif max_score >= 20:
            result['risk_level'] = 'medium'
        elif max_score > 0:
            result['risk_level'] = 'low'