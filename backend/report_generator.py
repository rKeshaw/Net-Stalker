from logging_config import get_logger
logger = get_logger(__name__)

import os
import jinja2
import base64
from datetime import datetime
from playwright.async_api import async_playwright

class ForensicReportGenerator:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.template_str = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap');
                
                body { font-family: 'Inter', sans-serif; color: #1e293b; line-height: 1.5; margin: 0; padding: 40px; background: white; }
                
                /* Header */
                .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 30px; }
                .logo { font-size: 24px; font-weight: 800; color: #0f172a; display: flex; align-items: center; gap: 10px; }
                .logo span { color: #3b82f6; }
                .meta { text-align: right; font-size: 12px; color: #64748b; }
                
                /* Verdict Badge */
                .verdict-box { 
                    background: {{ '#fef2f2' if verdict == 'malicious' else '#ecfdf5' }};
                    border: 1px solid {{ '#ef4444' if verdict == 'malicious' else '#10b981' }};
                    border-radius: 12px;
                    padding: 24px;
                    text-align: center;
                    margin-bottom: 40px;
                    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
                }
                .verdict-label { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: #64748b; font-weight: 600; }
                .verdict-value { font-size: 42px; font-weight: 900; margin: 10px 0; color: {{ '#dc2626' if verdict == 'malicious' else '#059669' }}; }
                .risk-metrics { display: flex; justify-content: center; gap: 30px; margin-top: 15px; font-size: 14px; font-weight: 600; }
                
                /* Grid Layout */
                .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }
                
                /* Cards */
                .card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; background: #f8fafc; }
                .card-title { font-size: 12px; font-weight: 700; color: #64748b; text-transform: uppercase; margin-bottom: 10px; }
                .data-row { display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 13px; }
                .data-label { color: #64748b; }
                .data-value { font-weight: 600; color: #0f172a; }
                
                /* Visual Evidence */
                .evidence-img { width: 100%; border-radius: 8px; border: 1px solid #e2e8f0; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); margin-top: 10px; }
                
                /* Indicators List */
                .indicator { background: #fff; padding: 10px; border-left: 4px solid #ef4444; margin-bottom: 8px; font-size: 13px; border-radius: 0 4px 4px 0; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }
                
                /* Hop Chain */
                .hop-chain { display: flex; flex-direction: column; gap: 0; }
                .hop { display: flex; align-items: center; padding: 10px; border-bottom: 1px dashed #e2e8f0; }
                .hop-num { background: #3b82f6; color: white; width: 24px; height: 24px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: bold; margin-right: 15px; }
                .hop-details { flex-grow: 1; font-size: 13px; }
                .hop-loc { font-weight: 600; }
                .hop-ip { color: #64748b; font-size: 12px; }

                /* Footer */
                .footer { position: fixed; bottom: 20px; left: 0; right: 0; text-align: center; font-size: 10px; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 20px; margin: 0 40px; }
            </style>
        </head>
        <body>
            <div class="header">
                <div class="logo">🛡️ PHISH<span>DETECTOR</span></div>
                <div class="meta">
                    <strong>CASE ID:</strong> {{ task_id }}<br>
                    <strong>GENERATED:</strong> {{ timestamp }}
                </div>
            </div>

            <div class="verdict-box">
                <div class="verdict-label">Automated Threat Analysis</div>
                <div class="verdict-value">{{ verdict.upper() }}</div>
                <div class="risk-metrics">
                    <span>Risk Score: {{ risk_score }}/100</span>
                    <span style="color: #cbd5e1">|</span>
                    <span>Confidence: {{ confidence }}%</span>
                </div>
            </div>

            <div class="grid-2">
                <div class="card">
                    <div class="card-title">Target Intelligence</div>
                    <div class="data-row">
                        <span class="data-label">Target URL</span>
                        <span class="data-value">{{ url }}</span>
                    </div>
                    <div class="data-row">
                        <span class="data-label">Final Destination</span>
                        <span class="data-value">{{ final_url }}</span>
                    </div>
                    <div class="data-row">
                        <span class="data-label">Domain Age</span>
                        <span class="data-value">{{ domain_age }} days</span>
                    </div>
                </div>
                <div class="card">
                    <div class="card-title">Hosting Infrastructure</div>
                    <div class="data-row">
                        <span class="data-label">IP Address</span>
                        <span class="data-value">{{ ip }}</span>
                    </div>
                    <div class="data-row">
                        <span class="data-label">Location</span>
                        <span class="data-value">{{ city }}, {{ country }}</span>
                    </div>
                    <div class="data-row">
                        <span class="data-label">ISP / ASN</span>
                        <span class="data-value">{{ isp }}</span>
                    </div>
                </div>
            </div>

            {% if screenshot_b64 %}
            <div class="card" style="margin-bottom: 30px;">
                <div class="card-title">Visual Evidence Capture</div>
                <img src="data:image/png;base64,{{ screenshot_b64 }}" class="evidence-img">
            </div>
            {% endif %}

            <div class="grid-2">
                <div class="card">
                    <div class="card-title">Forensic Indicators</div>
                    {% for indicator in indicators %}
                        <div class="indicator">⚠️ {{ indicator }}</div>
                    {% else %}
                        <div style="color: #64748b; font-style: italic;">No critical anomalies detected.</div>
                    {% endfor %}
                </div>

                <div class="card">
                    <div class="card-title">Redirection Path (Trace)</div>
                    <div class="hop-chain">
                        {% for hop in hops %}
                        <div class="hop">
                            <div class="hop-num">{{ hop.hop }}</div>
                            <div class="hop-details">
                                <div class="hop-loc">{{ hop.city }}, {{ hop.country }}</div>
                                <div class="hop-ip">{{ hop.domain }} ({{ hop.ip }})</div>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </div>

            {% if honeypot %}
            <div class="card" style="margin-bottom: 50px; border-color: {{ '#ef4444' if honeypot.credential_harvesting_detected else '#e2e8f0' }};">
                <div class="card-title" style="color: {{ '#ef4444' if honeypot.credential_harvesting_detected else '#64748b' }};">
                    Active Defense: Honeypot Test
                </div>
                <div class="grid-2" style="margin-bottom: 0;">
                    <div class="data-row">
                        <span class="data-label">Status:</span>
                        <span class="data-value" style="color: {{ '#dc2626' if honeypot.credential_harvesting_detected else '#059669' }}">
                            {{ 'CREDENTIAL THEFT DETECTED' if honeypot.credential_harvesting_detected else 'NEGATIVE' }}
                        </span>
                    </div>
                    <div class="data-row">
                        <span class="data-label">Forms Tested:</span>
                        <span class="data-value">{{ honeypot.forms_submitted }}</span>
                    </div>
                </div>
            </div>
            {% endif %}

            {% if pcap_available %}
            <div class="card" style="margin-bottom: 30px;">
                <div class="card-title">Network Packet Forensics (PCAP)</div>
                <div class="grid-2" style="margin-bottom: 0;">
                    <div>
                        <div class="data-row">
                            <span class="data-label">Total Packets</span>
                            <span class="data-value">{{ packet_count }}</span>
                        </div>
                        <div class="data-row">
                            <span class="data-label">Capture Duration</span>
                            <span class="data-value">{{ duration }}s</span>
                        </div>
                    </div>
                    <div>
                        <div class="card-title" style="margin-top: 0;">Top Protocols</div>
                        {% for proto, count in top_protocols.items() %}
                        <div class="data-row">
                            <span class="data-label">{{ proto }}</span>
                            <span class="data-value">{{ count }}</span>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
            {% endif %}

            <div class="footer">
                CONFIDENTIAL FORENSIC REPORT | GENERATED AUTOMATICALLY BY PHISH DETECTOR AI | DO NOT DISTRIBUTE
            </div>
        </body>
        </html>
        """

    async def generate(self, task_id, data):
        """Render HTML and convert to PDF using Playwright"""
        try:
            features = data.get('features', {})
            behavioral = data.get('behavioral_analysis', {})
            llm = data.get('llm_analysis', {})
            geo = features.get('geo_location', {})
            
            screenshot_b64 = None
            screenshot_path = behavioral.get('screenshot_path') or features.get('screenshot_path')
            if screenshot_path and os.path.exists(screenshot_path):
                with open(screenshot_path, "rb") as img_file:
                    screenshot_b64 = base64.b64encode(img_file.read()).decode('utf-8')
            pcap_data = behavioral.get('pcap_analysis') or features.get('pcap_analysis', {})
            pcap_stats = pcap_data.get('statistics', {}) if pcap_data else {}
            
            context = {
                'task_id': task_id,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
                'url': features.get('url', 'N/A'),
                'final_url': features.get('final_url', 'N/A'),
                'verdict': llm.get('verdict', 'UNKNOWN'),
                'confidence': int(llm.get('confidence', 0) * 100),
                'risk_score': llm.get('risk_score', 0),
                'domain_age': features.get('domain_age_days', 'Unknown'),
                'ip': features.get('hosting_ip', 'Unknown'),
                'pcap_available': bool(pcap_data),
                'packet_count': pcap_stats.get('packet_count', 0),
                'duration': pcap_stats.get('duration_seconds', 0),
                'top_protocols': pcap_stats.get('top_protocols', {}),
                'city': geo.get('city', 'Unknown'),
                'country': geo.get('country', 'Unknown'),
                'isp': geo.get('isp', 'Unknown'),
                'screenshot_b64': screenshot_b64,
                'indicators': llm.get('indicators', []),
                'hops': features.get('geo_path', []),
                'honeypot': features.get('honeypot_submission', None)
            }

            template = jinja2.Template(self.template_str)
            html_content = template.render(context)
            
            output_filename = f"report_{task_id}.pdf"
            output_path = os.path.join(self.output_dir, output_filename)
            
            async with async_playwright() as p:
                ws_endpoint = os.getenv('PLAYWRIGHT_WS_ENDPOINT')
                browser = None
                
                if ws_endpoint:
                    try:
                        browser = await p.chromium.connect(ws_endpoint)
                        logger.info('Using remote Playwright browser for PDF generation')
                    except Exception:
                        logger.warning('Failed to connect remote Playwright endpoint, falling back to local browser')
                
                if browser is None:
                    browser = await p.chromium.launch(headless=True)

                page = await browser.new_page()
                await page.set_content(html_content, wait_until="networkidle")
                
                await page.pdf(
                    path=output_path,
                    format="A4",
                    print_background=True, 
                    margin={"top": "0px", "bottom": "0px", "left": "0px", "right": "0px"}
                )
                
                await browser.close()
                
            return output_path

        except Exception as e:
            logger.exception("Report Generation Failed")
            return None
