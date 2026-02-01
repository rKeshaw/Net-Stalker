import os
from groq import Groq
from dotenv import load_dotenv
import json

load_dotenv()

class GroqPhishingAnalyzer:
    def __init__(self):
        self.client = Groq(api_key=os.getenv('GROQ_API_KEY'))
        self.model = "openai/gpt-oss-20b"  # Example model name
        
    def analyze_features(self, features, analysis_type="url", external_context=None):
        """
        Send features to Groq for phishing assessment
        analysis_type: "url" or "email"
        external_context: Optional external API results
        """
        
        # Construct prompt based on type
        if analysis_type == "email":
            prompt = self._build_email_prompt(features)
        else:
            prompt = self._build_url_prompt(features, external_context)
        
        return self._query_llm(prompt)

    def analyze_text(self, text, features):
        """
        Analyze raw text for phishing indicators
        """
        prompt = self._build_text_prompt(text, features)
        return self._query_llm(prompt)

    def _query_llm(self, prompt):
        """Helper to send request to Groq and parse JSON"""
        try:
            response = self.client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": """You are a cybersecurity expert specializing in phishing detection. 
                        Analyze the provided features and determine if it's likely a phishing attempt.
                        
                        Respond ONLY with valid JSON in this exact format:
                        {
                            "verdict": "safe" | "suspicious" | "phishing",
                            "confidence": 0.0 to 1.0,
                            "risk_score": 0 to 100,
                            "reasoning": "brief explanation",
                            "indicators": ["indicator1", "indicator2", ...]
                        }"""
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                model=self.model,
                temperature=0.3,
                max_tokens=1000
            )
            
            # Parse response
            result_text = response.choices[0].message.content.strip()
            
            # Extract JSON from response
            if result_text.startswith('```json'):
                result_text = result_text[7:]
            if result_text.startswith('```'):
                result_text = result_text[3:]
            if result_text.endswith('```'):
                result_text = result_text[:-3]
            
            return json.loads(result_text.strip())
            
        except Exception as e:
            return {
                "verdict": "error",
                "confidence": 0.0,
                "risk_score": 0,
                "reasoning": f"Analysis failed: {str(e)}",
                "indicators": []
            }
    
    def _build_url_prompt(self, features, external_context=None):
        """Build analysis prompt for URL from features including behavioral data"""
        prompt = f"""Analyze this website for phishing indicators:

    URL: {features.get('url', 'N/A')}
    Domain: {features.get('domain', 'N/A')}

    TECHNICAL FEATURES:
    - Protocol: {features.get('protocol', 'N/A')}
    - SSL Valid: {features.get('ssl_valid', 'N/A')}
    - Domain Age (days): {features.get('domain_age_days', 'Unknown')}
    - Has IP in URL: {features.get('has_ip', 'N/A')}
    - URL Length: {features.get('url_length', 'N/A')}
    - Subdomain Count: {features.get('subdomain_count', 'N/A')}
    - Redirected: {features.get('redirected', 'N/A')}

    CONTENT FEATURES:
    - Form Count: {features.get('form_count', 0)}
    - Has Password Field: {features.get('has_password_field', False)}
    - External Links: {features.get('external_link_count', 0)}
    """

        # Add behavioral analysis if available
        if features.get('success') is not None:
            prompt += f"""
    BEHAVIORAL ANALYSIS (Headless Browser):
    - Analysis Success: {features.get('success', False)}
    - Load Time: {features.get('load_time', 'N/A')} seconds
    - Final URL: {features.get('final_url', 'N/A')}
    - Status Code: {features.get('status_code', 'N/A')}
    - Page Title: {features.get('title', 'N/A')}
    - Total Input Fields: {features.get('total_input_fields', 0)}
    - Has Password Field: {features.get('has_password_field', False)}
    - Has Email Field: {features.get('has_email_field', False)}

    NETWORK BEHAVIOR:
    """
            if features.get('network'):
                network = features['network']
                prompt += f"""- Total Requests: {network.get('total_requests', 0)}
    - Unique Domains Contacted: {network.get('unique_domains', 0)}
    - Third-Party Requests: {network.get('third_party_requests', 0)}
    - POST Requests: {network.get('post_requests', 0)}
    - POST to External Domains: {network.get('post_to_external', 0)}
    - Failed Requests: {network.get('failed_requests', 0)}
    - Redirect Count: {network.get('redirect_count', 0)}
    """

            # Forms analysis
            if features.get('forms'):
                prompt += f"\nFORMS DETECTED: {len(features['forms'])} form(s)\n"
                for i, form in enumerate(features['forms'][:3], 1):
                    prompt += f"""  Form {i}:
        - Action: {form.get('action', 'N/A')}
        - Method: {form.get('method', 'N/A')}
        - Has Password Input: {form.get('has_password', False)}
        - Has Email Input: {form.get('has_email', False)}
        - Input Count: {form.get('input_count', 0)}
    """

            # Behavioral anomalies
            if features.get('behavioral_indicators'):
                indicators = features['behavioral_indicators']
                if indicators:
                    prompt += f"\nBEHAVIORAL ANOMALIES DETECTED:\n"
                    for indicator in indicators:
                        prompt += f"  - {indicator}\n"

            # Brand impersonation
            if features.get('brand_indicators'):
                brand_info = features['brand_indicators']
                if brand_info.get('detected_brands'):
                    prompt += f"\nBRAND INDICATORS:\n"
                    prompt += f"  - Detected Brands: {', '.join(brand_info['detected_brands'])}\n"
                    prompt += f"  - Possible Impersonation: {brand_info.get('has_brand_impersonation', False)}\n"

            # Suspicious elements
            if features.get('iframe_count', 0) > 0:
                prompt += f"\nSUSPICIOUS ELEMENTS:\n"
                prompt += f"  - Iframes: {features.get('iframe_count', 0)}\n"
                if features.get('iframe_sources'):
                    prompt += f"  - Iframe Sources: {', '.join(features['iframe_sources'][:3])}\n"
            
            if features.get('external_scripts_count', 0) > 0:
                prompt += f"  - External Scripts: {features.get('external_scripts_count', 0)}\n"
            
            if features.get('console_errors', 0) > 0:
                prompt += f"  - Console Errors: {features.get('console_errors', 0)}\n"
            
            if features.get('honeypot_submission'):
                honeypot = features['honeypot_submission']
                prompt += f"\nHONEYPOT FORM SUBMISSION TEST:\n"
                prompt += f"- Forms Found: {honeypot.get('forms_found', 0)}\n"
                prompt += f"- Forms Submitted: {honeypot.get('forms_submitted', 0)}\n"
                
                if honeypot.get('credential_harvesting_detected'):
                    prompt += f"- ⚠️ CREDENTIAL HARVESTING DETECTED: YES\n"
                    prompt += f"- Severity: CRITICAL - Site is actively stealing credentials\n"
                    
                    if honeypot.get('exfiltration_evidence'):
                        prompt += f"\nEXFILTRATION EVIDENCE:\n"
                        for evidence in honeypot['exfiltration_evidence'][:5]:
                            prompt += f"  - [{evidence.get('severity', 'unknown').upper()}] {evidence.get('description', 'N/A')}\n"
                            if evidence.get('exfiltration_url'):
                                prompt += f"    Exfiltration URL: {evidence['exfiltration_url']}\n"
                else:
                    prompt += f"- Credential Harvesting: Not detected\n"
                
                # Add individual submission details
                if honeypot.get('submissions'):
                    for i, submission in enumerate(honeypot['submissions'][:3], 1):
                        if submission.get('submitted'):
                            prompt += f"\n  Submission {i}:\n"
                            prompt += f"    - Pre-submission URL: {submission.get('pre_submission_url', 'N/A')}\n"
                            prompt += f"    - Post-submission URL: {submission.get('post_submission_url', 'N/A')}\n"
                            if submission.get('harvesting_indicators'):
                                prompt += f"    - Harvesting Indicators: {len(submission['harvesting_indicators'])}\n"

        # Add external API results if available
        if external_context and external_context.get('results'):
            prompt += "\nEXTERNAL THREAT INTELLIGENCE:\n"
            prompt += f"- Aggregated Verdict: {external_context.get('aggregated_verdict', 'unknown')}\n"
            prompt += f"- Summary: {external_context.get('summary', 'N/A')}\n"
            
            for api_result in external_context.get('results', []):
                if 'error' not in api_result:
                    source = api_result.get('source', 'unknown')
                    verdict = api_result.get('verdict', 'unknown')
                    prompt += f"- {source.upper()}: {verdict}\n"

        prompt += f"\nPAGE TEXT SAMPLE:\n{features.get('page_text', features.get('body_text', 'No content available'))[:1500]}\n"
        prompt += "\nProvide a comprehensive phishing risk assessment considering all technical features, behavioral patterns, and external threat intelligence."
        
        return prompt
    
    def _build_email_prompt(self, features):
        """Build analysis prompt for email from features"""
        prompt = f"""Analyze this email for phishing indicators:

EMAIL HEADERS:
- From: {features.get('from', 'Unknown')}
- Sender Email: {features.get('sender_email', 'Unknown')}
- Sender Domain: {features.get('sender_domain', 'Unknown')}
- Reply-To: {features.get('reply_to', 'None')}
- Reply-To Mismatch: {features.get('reply_to_mismatch', False)}
- Subject: {features.get('subject', 'No Subject')}

AUTHENTICATION:
- SPF Result: {features.get('spf_result', 'Unknown')}
- Has DKIM: {features.get('has_dkim', False)}

SENDER ANALYSIS:
- Sender Has Numbers: {features.get('sender_has_numbers', False)}
- Sender Domain Has Subdomain: {features.get('sender_domain_has_subdomain', False)}

CONTENT ANALYSIS:
- Body Length: {features.get('body_length', 0)} characters
- Urgency Keywords Count: {features.get('urgency_keyword_count', 0)}
- Financial Keywords Count: {features.get('financial_keyword_count', 0)}
- Has Spelling Errors: {features.get('has_spelling_errors', False)}

LINKS:
- Link Count: {features.get('link_count', 0)}
- Has IP-based URL: {features.get('has_ip_based_url', False)}
- Has Shortened URL: {features.get('has_shortened_url', False)}
- Link Text Mismatch: {features.get('link_text_mismatch', False)}
- Links: {features.get('links', [])[:5]}

ATTACHMENTS:
- Attachment Count: {features.get('attachment_count', 0)}
- Has Suspicious Attachment: {features.get('has_suspicious_attachment', False)}
- Attachments: {features.get('attachments', [])}

EMAIL BODY SAMPLE:
{features.get('body_text', 'No content')[:1500]}

Provide a comprehensive phishing risk assessment for this email."""
        
        return prompt

    def _build_text_prompt(self, text, features):
        """Build analysis prompt for raw text"""
        return f"""Analyze this message/text for phishing indicators:

TEXT CONTENT:
{text[:1500]}

TEXT FEATURES:
- Length: {features.get('length', 0)} characters
- Urgency Keywords: {features.get('urgency_keywords', 0)}
- Financial Keywords: {features.get('financial_keywords', 0)}
- Contains Links: {features.get('has_links', False)}
- Link Count: {features.get('link_count', 0)}

Provide a phishing risk assessment."""