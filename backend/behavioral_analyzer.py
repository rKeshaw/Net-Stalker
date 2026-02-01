import asyncio
import os
import json
import time
import hashlib
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from playwright.async_api import async_playwright, Browser, Page, Error as PlaywrightError
from datetime import datetime
from PIL import Image
from qr_analyzer import QRCodeAnalyzer

class BehavioralAnalyzer:
    """Analyze URL behavior using headless browser"""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout * 1000  
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        self.screenshots_dir = "/tmp/phishing_screenshots"
        os.makedirs(self.screenshots_dir, exist_ok=True)

        self.honeypot_credentials = {
            'email': 'honeypot.test@phishdetector.local',
            'username': 'honeypot_user_test',
            'password': 'HoneyP0t!Test#2024'
        }
        self.qr_analyzer = QRCodeAnalyzer()
        
    async def analyze(self, url: str) -> Dict[str, Any]:
        """Perform behavioral analysis on URL with robust lifecycle management"""
        features = {
            'url': url,
            'analysis_timestamp': datetime.now().isoformat(),
            'success': False,
            'behavioral_indicators': []
        }
        
        # Initialize playwright outside try to ensure closeability
        playwright_mgr = None
        browser = None
        
        try:
            playwright_mgr = await async_playwright().start()
            
            # Use stable launch arguments for various environments
            browser = await playwright_mgr.chromium.launch(
                headless=True,
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage', # Fixes crashes in Docker/limited RAM
                    '--no-sandbox',           # Required for root/container environments
                    '--disable-setuid-sandbox',
                    '--single-process'        # Reduces memory overhead
                ]
            )
            
            # Context settings for better stealth/consistency
            context = await browser.new_context(
                viewport={'width': 1280, 'height': 800},
                user_agent=self.user_agent,
                ignore_https_errors=True # Phishing sites often have bad certs
            )
            
            page = await context.new_page()
            
            # --- Network & Console Tracking Setup ---
            network_data = {'requests': [], 'responses': [], 'failed_requests': [], 'redirects': [], 'form_submissions': []}
            page.on('request', lambda req: self._on_request(req, network_data))
            page.on('response', lambda res: self._on_response(res, network_data))
            page.on('requestfailed', lambda req: self._on_request_failed(req, network_data))
            
            console_logs = []
            page.on('console', lambda msg: console_logs.append({'type': msg.type, 'text': msg.text}))
            
            # --- Navigation ---
            start_time = time.time()
            try:
                # Use 'domcontentloaded' first for speed, then 'networkidle'
                response = await page.goto(url, wait_until='domcontentloaded', timeout=self.timeout)
                # Wait for network to settle if possible, but don't fail if it doesn't
                try:
                    await page.wait_for_load_state('networkidle', timeout=5000)
                except:
                    pass 
                
                features['load_time'] = round(time.time() - start_time, 2)
                features['success'] = True
                features['final_url'] = page.url
                features['status_code'] = response.status if response else None
                
            except PlaywrightError as e:
                features['error'] = f"Navigation failed: {str(e)}"
                return features # Early exit if site won't load
            
            # --- Feature Extraction ---
            features.update(await self._extract_page_features(page))

            form_submission_results = await self._submit_honeypot_forms(page, network_data)
            features['honeypot_submission'] = form_submission_results

            features['network'] = self._analyze_network(network_data, url)
            features['screenshot_path'] = await self._take_screenshot(page, url)
            features['behavioral_indicators'] = await self._detect_behavioral_anomalies(page)
            
            if features.get('screenshot_path'):
                # Analyze the screenshot we just took
                qr_results = await self.qr_analyzer.analyze_screenshot(
                    features['screenshot_path'], 
                    url
                )
                features['qr_analysis'] = qr_results
                if qr_results.get('indicators'):
                    features['behavioral_indicators'].extend(qr_results['indicators'])
                if qr_results.get('phishing_detected'):
                    features['behavioral_indicators'].append("CRITICAL: Malicious QR Code Detected")
                    
            features['console_errors'] = len([l for l in console_logs if l['type'] == 'error'])
            
        except Exception as e:
            features['error'] = f"System Error: {str(e)}"
            features['success'] = False
        finally:
            if browser:
                await browser.close()
            if playwright_mgr:
                await playwright_mgr.stop()
        
        return features
    
    def _on_request(self, request, network_data: Dict):
        """Track outgoing requests"""
        request_info = {
            'url': request.url,
            'method': request.method,
            'resource_type': request.resource_type,
            'timestamp': datetime.now().isoformat(),
            'has_post_data': False,
            'post_data': None
        }

        if request.method == 'POST':
            try:
                post_data = request.post_data
                if post_data:
                    request_info['post_data'] = post_data[:500]
                    request_info['has_post_data'] = True
            except:
                pass
        
        # Append once per request
        network_data['requests'].append(request_info)
    
    def _on_response(self, response, network_data: Dict):
        """Track responses"""
        network_data['responses'].append({
            'url': response.url,
            'status': response.status,
            'content_type': response.headers.get('content-type', ''),
            'timestamp': datetime.now().isoformat()
        })
        
        # Track redirects
        if 300 <= response.status < 400:
            network_data['redirects'].append({
                'from': response.url,
                'status': response.status,
                'location': response.headers.get('location', '')
            })
    
    def _on_request_failed(self, request, network_data: Dict):
        """Track failed requests"""
        network_data['failed_requests'].append({
            'url': request.url,
            'failure': request.failure,
            'timestamp': datetime.now().isoformat()
        })

    async def _submit_honeypot_forms(self, page: Page, network_data: Dict) -> Dict[str, Any]:
        """Submit honeypot credentials to detected forms"""
        submission_results = {
            'attempted': False,
            'forms_found': 0,
            'forms_submitted': 0,
            'submissions': [],
            'credential_harvesting_detected': False,
            'exfiltration_evidence': []
        }
        
        try:
            # Find all forms
            forms = await page.query_selector_all('form')
            submission_results['forms_found'] = len(forms)
            
            if len(forms) == 0:
                return submission_results
            
            # Analyze each form
            for i, form in enumerate(forms[:3]):  # Limit to first 3 forms
                try:
                    form_result = await self._analyze_and_submit_form(page, form, i, network_data)
                    if form_result:
                        submission_results['submissions'].append(form_result)
                        if form_result['submitted']:
                            submission_results['forms_submitted'] += 1
                            submission_results['attempted'] = True
                            
                            # Check for credential harvesting
                            if form_result.get('harvesting_indicators'):
                                submission_results['credential_harvesting_detected'] = True
                                submission_results['exfiltration_evidence'].extend(
                                    form_result.get('harvesting_indicators', [])
                                )
                    
                    # Wait between form submissions
                    await asyncio.sleep(1)
                    
                except Exception as e:
                    submission_results['submissions'].append({
                        'form_index': i,
                        'error': str(e),
                        'submitted': False
                    })
            
        except Exception as e:
            submission_results['error'] = str(e)
        
        return submission_results
    
    async def _analyze_and_submit_form(self, page: Page, form, form_index: int, network_data: Dict) -> Optional[Dict]:
        """Analyze and submit individual form with honeypot data"""
        
        result = {
            'form_index': form_index,
            'submitted': False,
            'action': None,
            'method': None,
            'inputs_filled': [],
            'pre_submission_url': page.url,
            'post_submission_url': None,
            'network_requests_before': len(network_data['requests']),
            'network_requests_after': 0,
            'harvesting_indicators': []
        }
        
        try:
            # Get form details
            action = await form.get_attribute('action')
            method = await form.get_attribute('method') or 'get'
            
            result['action'] = action
            result['method'] = method.lower()
            
            # Find inputs
            inputs = await form.query_selector_all('input, textarea')
            
            # Check if form is worth submitting (has password or email field)
            input_types = []
            for inp in inputs:
                inp_type = await inp.get_attribute('type')
                if inp_type:
                    input_types.append(inp_type.lower())
            
            has_password = 'password' in input_types
            has_email = 'email' in input_types
            
            # Only submit forms that look like login/credential forms
            if not (has_password or has_email):
                result['skipped'] = True
                result['reason'] = 'Not a credential form'
                return result
            
            # Fill form fields with honeypot data
            for inp in inputs:
                try:
                    inp_type = await inp.get_attribute('type') or 'text'
                    inp_name = await inp.get_attribute('name') or ''
                    inp_id = await inp.get_attribute('id') or ''
                    
                    # Check if input is visible and not disabled
                    is_visible = await inp.is_visible()
                    is_disabled = await inp.is_disabled()
                    
                    if not is_visible or is_disabled:
                        continue
                    
                    # Determine what to fill
                    value_filled = None
                    
                    if inp_type == 'password':
                        await inp.fill(self.honeypot_credentials['password'])
                        value_filled = 'honeypot_password'
                    elif inp_type == 'email' or 'email' in inp_name.lower() or 'email' in inp_id.lower():
                        await inp.fill(self.honeypot_credentials['email'])
                        value_filled = 'honeypot_email'
                    elif 'user' in inp_name.lower() or 'login' in inp_name.lower():
                        await inp.fill(self.honeypot_credentials['username'])
                        value_filled = 'honeypot_username'
                    elif inp_type == 'text' and not value_filled:
                        # Generic text field, might be username
                        await inp.fill(self.honeypot_credentials['username'])
                        value_filled = 'honeypot_username'
                    
                    if value_filled:
                        result['inputs_filled'].append({
                            'type': inp_type,
                            'name': inp_name,
                            'value_type': value_filled
                        })
                        
                except Exception as e:
                    continue
            
            # Only submit if we filled at least one field
            if not result['inputs_filled']:
                result['skipped'] = True
                result['reason'] = 'No fields could be filled'
                return result
            
            # Record network state before submission
            requests_before = len(network_data['requests'])
            
            # Take screenshot before submission
            pre_submit_screenshot = await self._take_screenshot(page, result['pre_submission_url'], f"pre_submit_{form_index}")
            result['pre_submit_screenshot'] = pre_submit_screenshot
            
            # Submit the form
            try:
                # Look for submit button
                submit_button = await form.query_selector('button[type="submit"], input[type="submit"], button:not([type])')
                
                if submit_button:
                    # Click submit button
                    await submit_button.click()
                else:
                    # Fallback: submit form programmatically
                    await form.evaluate('form => form.submit()')
                
                result['submitted'] = True
                
                # Wait for navigation or network activity
                try:
                    await page.wait_for_load_state('networkidle', timeout=5000)
                except:
                    pass  # Continue even if timeout
                
                await asyncio.sleep(3)  # Give time for any async requests
                
            except Exception as e:
                result['submission_error'] = str(e)
                return result
            
            # Capture post-submission state
            result['post_submission_url'] = page.url
            result['network_requests_after'] = len(network_data['requests'])
            
            # Take screenshot after submission
            post_submit_screenshot = await self._take_screenshot(page, result['post_submission_url'], f"post_submit_{form_index}")
            result['post_submit_screenshot'] = post_submit_screenshot
            
            # Analyze what happened
            result['harvesting_indicators'] = self._analyze_form_submission_behavior(
                result, 
                network_data,
                requests_before
            )
            
        except Exception as e:
            result['error'] = str(e)
        
        return result

    def _analyze_form_submission_behavior(self, result: Dict, network_data: Dict, requests_before: int) -> List[str]:
        """Analyze form submission behavior to detect credential harvesting"""
        indicators = []
        
        # Get new requests made after form submission
        new_requests = network_data['requests'][requests_before:]
        post_requests = [req for req in new_requests if req['method'] == 'POST']
        
        # Check 1: POST request to external domain with our honeypot data
        original_domain = urlparse(result['pre_submission_url']).netloc
        
        for req in post_requests:
            req_domain = urlparse(req['url']).netloc
            
            # Check if POST went to different domain
            if req_domain != original_domain:
                indicators.append({
                    'type': 'external_post',
                    'severity': 'critical',
                    'description': f'Credentials sent to external domain: {req_domain}',
                    'exfiltration_url': req['url'],
                    'evidence': 'POST request to different domain after form submission'
                })
            
            # Check if honeypot data appears in POST
            if req.get('post_data'):
                post_data = req['post_data'].lower()
                if (self.honeypot_credentials['email'].lower() in post_data or 
                    self.honeypot_credentials['password'].lower() in post_data):
                    indicators.append({
                        'type': 'honeypot_detected_in_post',
                        'severity': 'critical',
                        'description': 'Honeypot credentials detected in POST request',
                        'exfiltration_url': req['url'],
                        'evidence': 'Honeypot data found in network request'
                    })
        
        # Check 2: Redirect to legitimate site after submission (classic phishing behavior)
        if result['post_submission_url'] != result['pre_submission_url']:
            post_domain = urlparse(result['post_submission_url']).netloc
            pre_domain = urlparse(result['pre_submission_url']).netloc
            
            # Check if redirected to known legitimate sites
            legitimate_domains = [
                'google.com', 'facebook.com', 'microsoft.com', 'apple.com',
                'amazon.com', 'paypal.com', 'netflix.com', 'linkedin.com'
            ] # Could be expanded with a larger list (Just for a demo)
            
            for legit_domain in legitimate_domains:
                if legit_domain in post_domain and legit_domain not in pre_domain:
                    indicators.append({
                        'type': 'redirect_to_legitimate',
                        'severity': 'high',
                        'description': f'Redirected to legitimate site after credential submission: {post_domain}',
                        'evidence': f'Classic phishing: collect credentials then redirect to real {legit_domain}'
                    })
        
        # Check 3: Multiple POST requests (form resubmission to multiple endpoints)
        if len(post_requests) > 1:
            unique_domains = set(urlparse(req['url']).netloc for req in post_requests)
            if len(unique_domains) > 1:
                indicators.append({
                    'type': 'multiple_exfiltration_endpoints',
                    'severity': 'critical',
                    'description': f'Credentials sent to {len(unique_domains)} different domains',
                    'domains': list(unique_domains),
                    'evidence': 'Form data submitted to multiple endpoints'
                })
        
        # Check 4: Success without proper authentication
        if result['post_submission_url'] != result['pre_submission_url']:
            # If page changed after submitting fake credentials, that's suspicious
            if 'error' not in result['post_submission_url'].lower() and \
               'login' not in result['post_submission_url'].lower():
                indicators.append({
                    'type': 'accepted_fake_credentials',
                    'severity': 'high',
                    'description': 'Site accepted fake credentials without validation',
                    'evidence': 'No error page after submitting honeypot credentials'
                })
        
        return indicators
    
    async def _extract_page_features(self, page: Page) -> Dict[str, Any]:
        """Extract features from the loaded page"""
        features = {}
        
        try:
            # Page title
            features['title'] = await page.title()
            
            # Page content
            content = await page.content()
            features['content_length'] = len(content)
            
            # Forms analysis
            forms = await page.query_selector_all('form')
            features['form_count'] = len(forms)
            
            form_details = []
            for form in forms[:10]:  # Analyze first 10 forms
                form_info = await self._analyze_form(form)
                if form_info:
                    form_details.append(form_info)
            
            features['forms'] = form_details
            
            # Input fields
            password_inputs = await page.query_selector_all('input[type="password"]')
            email_inputs = await page.query_selector_all('input[type="email"]')
            text_inputs = await page.query_selector_all('input[type="text"]')
            
            features['has_password_field'] = len(password_inputs) > 0
            features['has_email_field'] = len(email_inputs) > 0
            features['total_input_fields'] = len(password_inputs) + len(email_inputs) + len(text_inputs)
            
            # Links analysis
            links = await page.query_selector_all('a[href]')
            features['link_count'] = len(links)
            
            external_links = []
            internal_links = []
            parsed_url = urlparse(page.url)
            
            for link in links[:100]:  # Check first 100 links
                try:
                    href = await link.get_attribute('href')
                    if href:
                        link_parsed = urlparse(href)
                        if link_parsed.netloc and link_parsed.netloc != parsed_url.netloc:
                            external_links.append(href)
                        else:
                            internal_links.append(href)
                except:
                    pass
            
            features['external_links_count'] = len(external_links)
            features['internal_links_count'] = len(internal_links)
            features['external_links_sample'] = external_links[:10]
            
            # Iframes
            iframes = await page.query_selector_all('iframe')
            features['iframe_count'] = len(iframes)
            
            iframe_sources = []
            for iframe in iframes:
                try:
                    src = await iframe.get_attribute('src')
                    if src:
                        iframe_sources.append(src)
                except:
                    pass
            
            features['iframe_sources'] = iframe_sources
            
            # Scripts
            scripts = await page.query_selector_all('script')
            features['script_count'] = len(scripts)
            
            external_scripts = 0
            for script in scripts:
                try:
                    src = await script.get_attribute('src')
                    if src:
                        script_parsed = urlparse(src)
                        if script_parsed.netloc and script_parsed.netloc != parsed_url.netloc:
                            external_scripts += 1
                except:
                    pass
            
            features['external_scripts_count'] = external_scripts
            
            # Meta tags
            meta_tags = await page.query_selector_all('meta')
            features['meta_tag_count'] = len(meta_tags)
            
            # Check for specific meta tags
            features['has_viewport_meta'] = await page.query_selector('meta[name="viewport"]') is not None
            features['has_description_meta'] = await page.query_selector('meta[name="description"]') is not None
            
            # Images
            images = await page.query_selector_all('img')
            features['image_count'] = len(images)
            
            # Favicon
            favicon = await page.query_selector('link[rel*="icon"]')
            features['has_favicon'] = favicon is not None
            
            # Check for common brand indicators
            features['brand_indicators'] = await self._detect_brand_indicators(page)
            
        except Exception as e:
            features['extraction_error'] = str(e)
        
        return features
    
    async def _analyze_form(self, form) -> Optional[Dict[str, Any]]:
        """Analyze individual form"""
        try:
            action = await form.get_attribute('action')
            method = await form.get_attribute('method')
            
            inputs = await form.query_selector_all('input')
            input_types = []
            input_names = []
            
            for inp in inputs:
                inp_type = await inp.get_attribute('type')
                inp_name = await inp.get_attribute('name')
                if inp_type:
                    input_types.append(inp_type)
                if inp_name:
                    input_names.append(inp_name)
            
            return {
                'action': action,
                'method': method or 'get',
                'input_types': input_types,
                'input_names': input_names,
                'has_password': 'password' in input_types,
                'has_email': 'email' in input_types,
                'input_count': len(inputs)
            }
        except:
            return None
    
    def _analyze_network(self, network_data: Dict, original_url: str) -> Dict[str, Any]:
        """Analyze network traffic patterns"""
        analysis = {
            'total_requests': len(network_data['requests']),
            'total_responses': len(network_data['responses']),
            'failed_requests': len(network_data['failed_requests']),
            'redirect_count': len(network_data['redirects'])
        }
        
        # Analyze domains contacted
        domains_contacted = set()
        for req in network_data['requests']:
            try:
                domain = urlparse(req['url']).netloc
                if domain:
                    domains_contacted.add(domain)
            except:
                pass
        
        analysis['unique_domains'] = len(domains_contacted)
        analysis['domains_list'] = list(domains_contacted)[:20]  # Top 20
        
        # Check for suspicious patterns
        original_domain = urlparse(original_url).netloc
        
        # Third-party requests
        third_party = [
            req for req in network_data['requests']
            if original_domain not in req['url']
        ]
        
        analysis['third_party_requests'] = len(third_party)
        analysis['third_party_ratio'] = round(
            len(third_party) / max(len(network_data['requests']), 1), 2
        )
        
        # Check for data exfiltration patterns
        post_requests = [
            req for req in network_data['requests']
            if req['method'] == 'POST'
        ]
        
        analysis['post_requests'] = len(post_requests)
        analysis['post_to_external'] = len([
            req for req in post_requests
            if original_domain not in req['url']
        ])
        
        # Analyze resource types
        resource_types = {}
        for req in network_data['requests']:
            rtype = req.get('resource_type', 'unknown')
            resource_types[rtype] = resource_types.get(rtype, 0) + 1
        
        analysis['resource_types'] = resource_types
        
        # Check for suspicious status codes
        suspicious_statuses = [
            res for res in network_data['responses']
            if res['status'] >= 400
        ]
        
        analysis['error_responses'] = len(suspicious_statuses)
        
        return analysis
    
    async def _detect_behavioral_anomalies(self, page: Page) -> List[str]:
        """Detect suspicious behavioral patterns"""
        indicators = []
        
        try:
            # Check for auto-submit forms
            auto_submit_script = """
                () => {
                    const forms = document.querySelectorAll('form');
                    let hasAutoSubmit = false;
                    forms.forEach(form => {
                        const onload = form.getAttribute('onload');
                        const onsubmit = form.getAttribute('onsubmit');
                        if (onload && onload.includes('submit')) hasAutoSubmit = true;
                        if (onsubmit && onsubmit.includes('setTimeout')) hasAutoSubmit = true;
                    });
                    return hasAutoSubmit;
                }
            """
            
            has_auto_submit = await page.evaluate(auto_submit_script)
            if has_auto_submit:
                indicators.append("Auto-submit form detected")
            
            # Check for hidden iframes
            hidden_iframes_script = """
                () => {
                    const iframes = document.querySelectorAll('iframe');
                    let hiddenCount = 0;
                    iframes.forEach(iframe => {
                        const style = window.getComputedStyle(iframe);
                        if (style.display === 'none' || style.visibility === 'hidden' || 
                            parseInt(style.width) === 0 || parseInt(style.height) === 0) {
                            hiddenCount++;
                        }
                    });
                    return hiddenCount;
                }
            """
            
            hidden_iframes = await page.evaluate(hidden_iframes_script)
            if hidden_iframes > 0:
                indicators.append(f"{hidden_iframes} hidden iframe(s) detected")
            
            # Check for suspicious JavaScript patterns
            suspicious_js_script = """
                () => {
                    const scripts = document.querySelectorAll('script');
                    const indicators = [];
                    
                    scripts.forEach(script => {
                        const content = script.textContent || '';
                        
                        // Check for obfuscation
                        if (content.includes('eval(') || content.includes('unescape(')) {
                            indicators.push('Obfuscated JavaScript detected');
                        }
                        
                        // Check for suspicious API calls
                        if (content.includes('XMLHttpRequest') && content.includes('password')) {
                            indicators.push('Suspicious data transmission detected');
                        }
                        
                        // Check for keyloggers
                        if (content.includes('keydown') || content.includes('keypress')) {
                            indicators.push('Keylogger pattern detected');
                        }
                    });
                    
                    return [...new Set(indicators)];
                }
            """
            
            js_indicators = await page.evaluate(suspicious_js_script)
            indicators.extend(js_indicators)
            
            # Check for fake address bar
            fake_address_bar_script = """
                () => {
                    const inputs = document.querySelectorAll('input[type="text"], input[type="url"]');
                    let hasFakeAddressBar = false;
                    
                    inputs.forEach(input => {
                        const style = window.getComputedStyle(input);
                        const rect = input.getBoundingClientRect();
                        
                        // Check if input looks like an address bar
                        if (rect.top < 100 && rect.width > 400 && 
                            (input.placeholder && input.placeholder.toLowerCase().includes('http'))) {
                            hasFakeAddressBar = true;
                        }
                    });
                    
                    return hasFakeAddressBar;
                }
            """
            
            has_fake_address_bar = await page.evaluate(fake_address_bar_script)
            if has_fake_address_bar:
                indicators.append("Fake address bar detected")
            
            # Check for right-click disable
            right_click_disabled_script = """
                () => {
                    return document.oncontextmenu !== null;
                }
            """
            
            right_click_disabled = await page.evaluate(right_click_disabled_script)
            if right_click_disabled:
                indicators.append("Right-click disabled")
            
            # Check for popup behavior
            popup_script = """
                () => {
                    const scripts = document.querySelectorAll('script');
                    let hasPopup = false;
                    
                    scripts.forEach(script => {
                        const content = script.textContent || '';
                        if (content.includes('window.open') || content.includes('popup')) {
                            hasPopup = true;
                        }
                    });
                    
                    return hasPopup;
                }
            """
            
            has_popup = await page.evaluate(popup_script)
            if has_popup:
                indicators.append("Popup mechanism detected")
            
            # Check for clipboard access
            clipboard_script = """
                () => {
                    const scripts = document.querySelectorAll('script');
                    let hasClipboard = false;
                    
                    scripts.forEach(script => {
                        const content = script.textContent || '';
                        if (content.includes('clipboard')) {
                            hasClipboard = true;
                        }
                    });
                    
                    return hasClipboard;
                }
            """
            
            has_clipboard = await page.evaluate(clipboard_script)
            if has_clipboard:
                indicators.append("Clipboard access detected")
            
        except Exception as e:
            indicators.append(f"Detection error: {str(e)}")
        
        return indicators
    
    async def _detect_brand_indicators(self, page: Page) -> Dict[str, Any]:
        """Detect brand impersonation indicators"""
        brands = {
            'paypal': ['paypal', 'pp'],
            'amazon': ['amazon', 'amzn'],
            'microsoft': ['microsoft', 'msft', 'outlook', 'office365'],
            'google': ['google', 'gmail'],
            'facebook': ['facebook', 'fb'],
            'apple': ['apple', 'icloud'],
            'bank': ['bank', 'banking', 'chase', 'wellsfargo', 'bofa']
        } # again, could be expanded. Only for demo
        
        detected = []
        
        try:
            # Check page content
            content = await page.content()
            content_lower = content.lower()
            title = await page.title()
            title_lower = title.lower()
            
            for brand, keywords in brands.items():
                for keyword in keywords:
                    if keyword in content_lower or keyword in title_lower:
                        detected.append(brand)
                        break
        except:
            pass
        
        return {
            'detected_brands': list(set(detected)),
            'has_brand_impersonation': len(detected) > 0
        }
    
    async def _take_screenshot(self, page: Page, url: str, suffix: str = None) -> Optional[str]:
        """Take screenshot of the page"""
        try:
            # Generate unique filename
            url_hash = hashlib.md5(url.encode()).hexdigest()
            timestamp = int(time.time())
            
            # Add suffix if provided
            if suffix:
                filename = f"screenshot_{url_hash}_{suffix}_{timestamp}.png"
            else:
                filename = f"screenshot_{url_hash}_{timestamp}.png"
                
            filepath = os.path.join(self.screenshots_dir, filename)
            
            # Take screenshot
            await page.screenshot(path=filepath, full_page=False)
            
            # Compress image
            with Image.open(filepath) as img:
                # Resize if too large
                if img.width > 1200:
                    ratio = 1200 / img.width
                    new_size = (1200, int(img.height * ratio))
                    img = img.resize(new_size, Image.Resampling.LANCZOS)
                
                # Save compressed
                img.save(filepath, 'PNG', optimize=True, quality=85)
            
            return filepath
            
        except Exception as e:
            print(f"Screenshot error: {e}")
            return None
