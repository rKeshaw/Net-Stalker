import os
import time
import hashlib
from abc import ABC, abstractmethod
from typing import Dict, Optional, Any
from cachetools import TTLCache
import aiohttp
import asyncio
from dotenv import load_dotenv

load_dotenv()

class ExternalAPIClient(ABC):
    """Abstract base class for external API clients"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.cache = TTLCache(maxsize=1000, ttl=3600)  # 1 hour cache
        self.last_request_time = 0
        self.min_request_interval = 0  # Seconds between requests
        
    @abstractmethod
    async def check_url(self, url: str) -> Dict[str, Any]:
        """Check if URL is malicious"""
        pass
    
    @abstractmethod
    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation"""
        pass
    
    def _get_cache_key(self, prefix: str, value: str) -> str:
        """Generate cache key"""
        return f"{prefix}:{hashlib.md5(value.encode()).hexdigest()}"
    
    def _rate_limit(self):
        """Enforce rate limiting"""
        if self.min_request_interval > 0:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.min_request_interval:
                time.sleep(self.min_request_interval - elapsed)
        self.last_request_time = time.time()
    
    def _check_cache(self, key: str) -> Optional[Dict]:
        """Check if result is cached"""
        return self.cache.get(key)
    
    def _set_cache(self, key: str, value: Dict):
        """Cache result"""
        self.cache[key] = value
    
    @property
    def is_available(self) -> bool:
        """Check if API key is configured"""
        return bool(self.api_key)


class VirusTotalClient(ExternalAPIClient):
    """VirusTotal API client with detailed results and polling"""
    
    def __init__(self):
        super().__init__(os.getenv('VIRUSTOTAL_API_KEY'))
        self.base_url = "https://www.virustotal.com/api/v3"
        self.min_request_interval = 15  # 4 requests/minute = 15 seconds between requests
        
    async def check_url(self, url: str, poll: bool = True) -> Dict[str, Any]:
        """Check URL reputation on VirusTotal with optional polling"""
        if not self.is_available:
            return {"error": "API key not configured", "available": False}
        
        cache_key = self._get_cache_key("vt_url", url)
        cached = self._check_cache(cache_key)
        if cached:
            return cached
        
        try:
            self._rate_limit()
            
            headers = {"x-apikey": self.api_key}
            
            async with aiohttp.ClientSession() as session:
                # Get URL ID
                import base64
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                
                # Try to get existing report
                async with session.get(
                    f"{self.base_url}/urls/{url_id}",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        result = self._parse_url_report(data)
                    elif response.status == 404:
                        # URL not scanned yet, submit for analysis
                        async with session.post(
                            f"{self.base_url}/urls",
                            headers={"x-apikey": self.api_key, "Content-Type": "application/x-www-form-urlencoded"},
                            data=f"url={url}"
                        ) as submit_response:
                            if submit_response.status == 200:
                                submit_data = await submit_response.json()
                                analysis_id = submit_data.get("data", {}).get("id")
                                
                                if poll and analysis_id:
                                    # Poll for results (max 3 attempts with 5 second delays)
                                    result = await self._poll_analysis(session, analysis_id, headers, max_attempts=3)
                                else:
                                    result = {
                                        "source": "virustotal",
                                        "verdict": "pending",
                                        "message": "URL submitted for analysis",
                                        "analysis_id": analysis_id,
                                        "available": True,
                                        "detailed": {}
                                    }
                            else:
                                result = {
                                    "source": "virustotal",
                                    "error": f"Failed to submit URL: {submit_response.status}",
                                    "available": True
                                }
                    else:
                        result = {
                            "source": "virustotal",
                            "error": f"API error: {response.status}",
                            "available": True
                        }
            
            self._set_cache(cache_key, result)
            return result
            
        except Exception as e:
            return {
                "source": "virustotal",
                "error": str(e),
                "available": True
            }
    
    async def _poll_analysis(self, session, analysis_id: str, headers: dict, max_attempts: int = 3) -> Dict[str, Any]:
        """Poll analysis results"""
        for attempt in range(max_attempts):
            await asyncio.sleep(5)  # Wait 5 seconds between polls
            
            async with session.get(
                f"{self.base_url}/analyses/{analysis_id}",
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    status = data.get("data", {}).get("attributes", {}).get("status")
                    
                    if status == "completed":
                        return self._parse_url_report(data)
        
        # If polling times out
        return {
            "source": "virustotal",
            "verdict": "pending",
            "message": "Analysis in progress, try again later",
            "available": True,
            "detailed": {}
        }
    
    def _parse_url_report(self, data: dict) -> Dict[str, Any]:
        """Parse detailed URL report from VirusTotal"""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        results = attributes.get("last_analysis_results", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        
        total_scans = malicious + suspicious + harmless + undetected
        
        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"
        
        # Extract detailed scanner results
        scanner_details = []
        for engine, result in results.items():
            if result.get("category") in ["malicious", "suspicious"]:
                scanner_details.append({
                    "engine": engine,
                    "category": result.get("category"),
                    "result": result.get("result", "N/A"),
                    "method": result.get("method", "N/A")
                })
        
        # Additional details
        detailed = {
            "stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total": total_scans
            },
            "url_info": {
                "final_url": attributes.get("url", "N/A"),
                "title": attributes.get("title", "N/A"),
                "last_analysis_date": attributes.get("last_analysis_date"),
                "reputation": attributes.get("reputation", 0),
                "times_submitted": attributes.get("times_submitted", 0)
            },
            "categories": attributes.get("categories", {}),
            "tags": attributes.get("tags", []),
            "threat_names": list(set([
                result.get("result", "") 
                for result in results.values() 
                if result.get("category") == "malicious" and result.get("result")
            ]))[:10],  # Top 10 threat names
            "detections": scanner_details[:15]  # Top 15 detections
        }
        
        return {
            "source": "virustotal",
            "verdict": verdict,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "undetected_count": undetected,
            "total_scans": total_scans,
            "available": True,
            "detailed": detailed
        }
    
    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation with detailed info"""
        if not self.is_available:
            return {"error": "API key not configured", "available": False}
        
        cache_key = self._get_cache_key("vt_domain", domain)
        cached = self._check_cache(cache_key)
        if cached:
            return cached
        
        try:
            self._rate_limit()
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/domains/{domain}",
                    headers={"x-apikey": self.api_key}
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        result = self._parse_domain_report(data)
                    else:
                        result = {
                            "source": "virustotal",
                            "error": f"API error: {response.status}",
                            "available": True
                        }
            
            self._set_cache(cache_key, result)
            return result
            
        except Exception as e:
            return {
                "source": "virustotal",
                "error": str(e),
                "available": True
            }
    
    def _parse_domain_report(self, data: dict) -> Dict[str, Any]:
        """Parse detailed domain report"""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        
        verdict = "malicious" if malicious > 0 else ("suspicious" if suspicious > 0 else "clean")
        
        detailed = {
            "stats": stats,
            "domain_info": {
                "creation_date": attributes.get("creation_date"),
                "last_update_date": attributes.get("last_update_date"),
                "reputation": attributes.get("reputation", 0),
                "popularity_ranks": attributes.get("popularity_ranks", {})
            },
            "categories": attributes.get("categories", {}),
            "tags": attributes.get("tags", []),
            "whois": attributes.get("whois", "")[:500] if attributes.get("whois") else "N/A"
        }
        
        return {
            "source": "virustotal",
            "verdict": verdict,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "reputation": attributes.get("reputation", 0),
            "available": True,
            "detailed": detailed
        }


class GoogleSafeBrowsingClient(ExternalAPIClient):
    """Google Safe Browsing API client with detailed threat info"""
    
    def __init__(self):
        super().__init__(os.getenv('GOOGLE_SAFE_BROWSING_API_KEY'))
        self.base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        
    async def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL against Safe Browsing database with details"""
        if not self.is_available:
            return {"error": "API key not configured", "available": False}
        
        cache_key = self._get_cache_key("gsb_url", url)
        cached = self._check_cache(cache_key)
        if cached:
            return cached
        
        try:
            payload = {
                "client": {
                    "clientId": "phishing-detector",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE", 
                        "SOCIAL_ENGINEERING", 
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM", "WINDOWS", "LINUX", "OSX"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}?key={self.api_key}",
                    json=payload
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        matches = data.get("matches", [])
                        
                        if matches:
                            threat_types = [match.get("threatType") for match in matches]
                            platforms = [match.get("platformType") for match in matches]
                            threat_entries = [match.get("threatEntryType") for match in matches]
                            
                            detailed = {
                                "threat_details": [
                                    {
                                        "threat_type": match.get("threatType"),
                                        "platform": match.get("platformType"),
                                        "threat_entry_type": match.get("threatEntryType"),
                                        "cache_duration": match.get("cacheDuration")
                                    }
                                    for match in matches
                                ],
                                "summary": {
                                    "total_matches": len(matches),
                                    "unique_threats": len(set(threat_types)),
                                    "platforms_affected": list(set(platforms))
                                }
                            }
                            
                            result = {
                                "source": "google_safe_browsing",
                                "verdict": "malicious",
                                "threat_types": threat_types,
                                "matches": len(matches),
                                "available": True,
                                "detailed": detailed
                            }
                        else:
                            result = {
                                "source": "google_safe_browsing",
                                "verdict": "clean",
                                "threat_types": [],
                                "matches": 0,
                                "available": True,
                                "detailed": {
                                    "message": "No threats found in Google Safe Browsing database"
                                }
                            }
                    else:
                        result = {
                            "source": "google_safe_browsing",
                            "error": f"API error: {response.status}",
                            "available": True
                        }
            
            self._set_cache(cache_key, result)
            return result
            
        except Exception as e:
            return {
                "source": "google_safe_browsing",
                "error": str(e),
                "available": True
            }
    
    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain (same as URL for Safe Browsing)"""
        return await self.check_url(f"http://{domain}")


class PhishTankClient(ExternalAPIClient):
    """PhishTank API client with detailed phishing info"""
    
    def __init__(self):
        super().__init__(os.getenv('PHISHTANK_API_KEY'))
        self.base_url = "https://checkurl.phishtank.com/checkurl/"
        self.min_request_interval = 1  
        
    async def check_url(self, url: str) -> Dict[str, Any]:
        """Check if URL is in PhishTank database with details"""
        if not self.is_available:
            return {"error": "API key not configured", "available": False}
        
        cache_key = self._get_cache_key("pt_url", url)
        cached = self._check_cache(cache_key)
        if cached:
            return cached
        
        try:
            import urllib.parse
            
            self._rate_limit()
            
            payload = {
                "url": urllib.parse.quote(url),
                "format": "json",
                "app_key": self.api_key
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.base_url,
                    data=payload
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        results = data.get("results", {})
                        
                        if results.get("in_database"):
                            is_valid = results.get("valid", False)
                            
                            detailed = {
                                "phish_id": results.get("phish_id"),
                                "phish_detail_url": results.get("phish_detail_page"),
                                "verified": results.get("verified", False),
                                "verified_at": results.get("verified_at"),
                                "submission_time": results.get("submission_time"),
                                "target": results.get("target", "Unknown")
                            }
                            
                            result = {
                                "source": "phishtank",
                                "verdict": "phishing" if is_valid else "suspicious",
                                "in_database": True,
                                "verified": results.get("verified", False),
                                "phish_id": results.get("phish_id"),
                                "available": True,
                                "detailed": detailed
                            }
                        else:
                            result = {
                                "source": "phishtank",
                                "verdict": "unknown",
                                "in_database": False,
                                "available": True,
                                "detailed": {
                                    "message": "URL not found in PhishTank database"
                                }
                            }
                    else:
                        result = {
                            "source": "phishtank",
                            "error": f"API error: {response.status}",
                            "available": True
                        }
            
            self._set_cache(cache_key, result)
            return result
            
        except Exception as e:
            return {
                "source": "phishtank",
                "error": str(e),
                "available": True
            }
    
    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """PhishTank works with URLs, not domains directly"""
        return await self.check_url(f"http://{domain}")

# Stub API Clients
class OPSWATClient(ExternalAPIClient):
    """OPSWAT MetaDefender API client (stub)"""
    
    def __init__(self):
        super().__init__(os.getenv('OPSWAT_API_KEY'))
    
    async def check_url(self, url: str) -> Dict[str, Any]:
        return {
            "source": "opswat",
            "error": "API not configured (premium service)",
            "available": False
        }
    
    async def check_domain(self, domain: str) -> Dict[str, Any]:
        return {
            "source": "opswat",
            "error": "API not configured (premium service)",
            "available": False
        }


class CiscoUmbrellaClient(ExternalAPIClient):
    """Cisco Umbrella Investigate API client (stub)"""
    
    def __init__(self):
        super().__init__(os.getenv('CISCO_UMBRELLA_KEY'))
    
    async def check_url(self, url: str) -> Dict[str, Any]:
        return {
            "source": "cisco_umbrella",
            "error": "API not configured (premium service)",
            "available": False
        }
    
    async def check_domain(self, domain: str) -> Dict[str, Any]:
        return {
            "source": "cisco_umbrella",
            "error": "API not configured (premium service)",
            "available": False
        }


class AlienVaultOTXClient(ExternalAPIClient):
    """AlienVault OTX API client"""
    
    def __init__(self):
        super().__init__(os.getenv('ALIENVAULT_OTX_KEY'))
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.min_request_interval = 1  
        
    async def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL reputation on AlienVault OTX"""
        if not self.is_available:
            return {"error": "API key not configured", "available": False}
        
        cache_key = self._get_cache_key("otx_url", url)
        cached = self._check_cache(cache_key)
        if cached:
            return cached
        
        try:
            self._rate_limit()
            
            # URL needs to be in a specific format for OTX
            import urllib.parse
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.netloc or parsed.path
            
            # Get general information about the URL
            headers = {"X-OTX-API-KEY": self.api_key}
            
            async with aiohttp.ClientSession() as session:
                # Check URL indicators
                async with session.get(
                    f"{self.base_url}/indicators/url/{urllib.parse.quote(url, safe='')}/general",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        result = await self._parse_url_report(data, url, session, headers)
                    elif response.status == 404:
                        # URL not found in OTX
                        result = {
                            "source": "alienvault_otx",
                            "verdict": "unknown",
                            "in_database": False,
                            "message": "URL not found in OTX database",
                            "available": True,
                            "detailed": {
                                "message": "No threat intelligence available for this URL"
                            }
                        }
                    else:
                        result = {
                            "source": "alienvault_otx",
                            "error": f"API error: {response.status}",
                            "available": True
                        }
            
            self._set_cache(cache_key, result)
            return result
            
        except Exception as e:
            return {
                "source": "alienvault_otx",
                "error": str(e),
                "available": True
            }
    
    async def _parse_url_report(self, data: dict, url: str, session, headers: dict) -> Dict[str, Any]:
        """Parse URL report from OTX with additional pulse data"""
        
        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        pulse_count = pulse_info.get("count", 0)
        
        # Determine verdict based on pulse data
        if pulse_count > 0:
            # Check pulse tags for malicious indicators
            malicious_tags = []
            for pulse in pulses[:10]:  # Check first 10 pulses
                tags = pulse.get("tags", [])
                malicious_keywords = ["malware", "phishing", "ransomware", "trojan", "botnet", "exploit"]
                for tag in tags:
                    if any(keyword in tag.lower() for keyword in malicious_keywords):
                        malicious_tags.append(tag)
            
            if malicious_tags:
                verdict = "malicious"
            else:
                verdict = "suspicious"
        else:
            verdict = "clean"
        
        # Get additional domain info if available
        try:
            import urllib.parse
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc
            
            if domain:
                # Get domain reputation
                async with session.get(
                    f"{self.base_url}/indicators/domain/{domain}/general",
                    headers=headers
                ) as domain_response:
                    if domain_response.status == 200:
                        domain_data = await domain_response.json()
                        domain_pulse_info = domain_data.get("pulse_info", {})
                        domain_pulse_count = domain_pulse_info.get("count", 0)
                        
                        # Combine URL and domain pulse counts
                        total_pulses = pulse_count + domain_pulse_count
                    else:
                        total_pulses = pulse_count
            else:
                total_pulses = pulse_count
                
        except:
            total_pulses = pulse_count
        
        # Extract detailed information
        detailed = {
            "pulse_count": pulse_count,
            "total_related_pulses": total_pulses,
            "pulses": []
        }
        
        # Add pulse details (top 10)
        for pulse in pulses[:10]:
            pulse_detail = {
                "name": pulse.get("name", "Unknown"),
                "description": pulse.get("description", "")[:200],  # Truncate long descriptions
                "created": pulse.get("created"),
                "modified": pulse.get("modified"),
                "tags": pulse.get("tags", []),
                "references": pulse.get("references", [])[:5],  # Top 5 references
                "adversary": pulse.get("adversary", "Unknown"),
                "targeted_countries": pulse.get("targeted_countries", []),
                "malware_families": pulse.get("malware_families", []),
                "attack_ids": pulse.get("attack_ids", [])
            }
            detailed["pulses"].append(pulse_detail)
        
        # Extract threat categories
        all_tags = []
        malware_families = []
        adversaries = []
        
        for pulse in pulses:
            all_tags.extend(pulse.get("tags", []))
            malware_families.extend(pulse.get("malware_families", []))
            adversary = pulse.get("adversary", "")
            if adversary:
                adversaries.append(adversary)
        
        detailed["summary"] = {
            "unique_tags": list(set(all_tags))[:20],  # Top 20 unique tags
            "malware_families": list(set(malware_families)),
            "adversaries": list(set(adversaries)),
            "countries_targeted": list(set([
                country 
                for pulse in pulses 
                for country in pulse.get("targeted_countries", [])
            ]))
        }
        
        return {
            "source": "alienvault_otx",
            "verdict": verdict,
            "in_database": pulse_count > 0,
            "pulse_count": pulse_count,
            "total_related_pulses": total_pulses,
            "available": True,
            "detailed": detailed
        }
    
    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation on AlienVault OTX"""
        if not self.is_available:
            return {"error": "API key not configured", "available": False}
        
        cache_key = self._get_cache_key("otx_domain", domain)
        cached = self._check_cache(cache_key)
        if cached:
            return cached
        
        try:
            self._rate_limit()
            
            headers = {"X-OTX-API-KEY": self.api_key}
            
            async with aiohttp.ClientSession() as session:
                # Get domain general info
                async with session.get(
                    f"{self.base_url}/indicators/domain/{domain}/general",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        result = await self._parse_domain_report(data, domain, session, headers)
                    elif response.status == 404:
                        result = {
                            "source": "alienvault_otx",
                            "verdict": "unknown",
                            "in_database": False,
                            "message": "Domain not found in OTX database",
                            "available": True,
                            "detailed": {}
                        }
                    else:
                        result = {
                            "source": "alienvault_otx",
                            "error": f"API error: {response.status}",
                            "available": True
                        }
            
            self._set_cache(cache_key, result)
            return result
            
        except Exception as e:
            return {
                "source": "alienvault_otx",
                "error": str(e),
                "available": True
            }
    
    async def _parse_domain_report(self, data: dict, domain: str, session, headers: dict) -> Dict[str, Any]:
        """Parse domain report from OTX"""
        
        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        pulse_count = pulse_info.get("count", 0)
        
        # Determine verdict
        if pulse_count > 0:
            malicious_indicators = sum(
                1 for pulse in pulses[:10]
                if any(
                    keyword in " ".join(pulse.get("tags", [])).lower()
                    for keyword in ["malware", "phishing", "ransomware", "trojan", "botnet"]
                )
            )
            
            if malicious_indicators >= 2:
                verdict = "malicious"
            elif malicious_indicators >= 1:
                verdict = "suspicious"
            else:
                verdict = "suspicious"
        else:
            verdict = "clean"
        
        # Get additional domain intelligence
        detailed = {
            "pulse_count": pulse_count,
            "domain_info": {},
            "pulses": []
        }
        
        # Try to get WHOIS and other domain data
        try:
            async with session.get(
                f"{self.base_url}/indicators/domain/{domain}/whois",
                headers=headers
            ) as whois_response:
                if whois_response.status == 200:
                    whois_data = await whois_response.json()
                    detailed["domain_info"]["whois"] = {
                        "registrar": whois_data.get("registrar", "Unknown"),
                        "creation_date": whois_data.get("creation_date"),
                        "expiration_date": whois_data.get("expiration_date"),
                        "updated_date": whois_data.get("updated_date")
                    }
        except:
            pass
        
        # Try to get malware samples
        try:
            async with session.get(
                f"{self.base_url}/indicators/domain/{domain}/malware",
                headers=headers
            ) as malware_response:
                if malware_response.status == 200:
                    malware_data = await malware_response.json()
                    samples = malware_data.get("data", [])
                    detailed["domain_info"]["malware_samples"] = len(samples)
        except:
            pass
        
        # Add pulse details
        for pulse in pulses[:10]:
            detailed["pulses"].append({
                "name": pulse.get("name", "Unknown"),
                "description": pulse.get("description", "")[:200],
                "created": pulse.get("created"),
                "tags": pulse.get("tags", []),
                "malware_families": pulse.get("malware_families", []),
                "adversary": pulse.get("adversary", "Unknown")
            })
        
        # Summary
        all_tags = []
        for pulse in pulses:
            all_tags.extend(pulse.get("tags", []))
        
        detailed["summary"] = {
            "unique_tags": list(set(all_tags))[:15],
            "malware_families": list(set([
                family
                for pulse in pulses
                for family in pulse.get("malware_families", [])
            ]))
        }
        
        return {
            "source": "alienvault_otx",
            "verdict": verdict,
            "in_database": pulse_count > 0,
            "pulse_count": pulse_count,
            "available": True,
            "detailed": detailed
        }


class ExternalAPIAggregator:
    """Aggregates results from multiple external APIs"""
    
    def __init__(self):
        self.clients = {
            'virustotal': VirusTotalClient(),
            'google_safe_browsing': GoogleSafeBrowsingClient(),
            'phishtank': PhishTankClient(),
            'opswat': OPSWATClient(),
            'cisco_umbrella': CiscoUmbrellaClient(),
            'alienvault_otx': AlienVaultOTXClient()
        }
    
    async def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL across all available APIs"""
        tasks = []
        
        for name, client in self.clients.items():
            if client.is_available:
                tasks.append(client.check_url(url))
        
        if not tasks:
            return {
                "results": [],
                "aggregated_verdict": "unknown",
                "message": "No external APIs configured"
            }
        
        # Run all API checks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = [r for r in results if isinstance(r, dict)]
        
        # Aggregate verdicts
        aggregated = self._aggregate_verdicts(valid_results)
        
        return {
            "results": valid_results,
            "aggregated_verdict": aggregated["verdict"],
            "confidence": aggregated["confidence"],
            "summary": aggregated["summary"]
        }
    
    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain across all available APIs"""
        tasks = []
        
        for name, client in self.clients.items():
            if client.is_available:
                tasks.append(client.check_domain(domain))
        
        if not tasks:
            return {
                "results": [],
                "aggregated_verdict": "unknown",
                "message": "No external APIs configured"
            }
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        valid_results = [r for r in results if isinstance(r, dict)]
        aggregated = self._aggregate_verdicts(valid_results)
        
        return {
            "results": valid_results,
            "aggregated_verdict": aggregated["verdict"],
            "confidence": aggregated["confidence"],
            "summary": aggregated["summary"]
        }
    
    def _aggregate_verdicts(self, results: list) -> Dict[str, Any]:
        """Aggregate verdicts from multiple sources"""
        if not results:
            return {
                "verdict": "unknown",
                "confidence": 0.0,
                "summary": "No results available"
            }
        
        # Count verdicts
        verdicts = {
            "malicious": 0,
            "phishing": 0,
            "suspicious": 0,
            "clean": 0,
            "unknown": 0
        }
        
        for result in results:
            if "error" in result:
                continue
            
            verdict = result.get("verdict", "unknown")
            if verdict in verdicts:
                verdicts[verdict] += 1
        
        total_checks = sum(verdicts.values())
        
        if total_checks == 0:
            return {
                "verdict": "unknown",
                "confidence": 0.0,
                "summary": "All API checks failed"
            }
        
        # Determine final verdict
        malicious_total = verdicts["malicious"] + verdicts["phishing"]
        
        if malicious_total > 0:
            final_verdict = "malicious"
            confidence = malicious_total / total_checks
        elif verdicts["suspicious"] > 0:
            final_verdict = "suspicious"
            confidence = verdicts["suspicious"] / total_checks
        elif verdicts["clean"] > total_checks * 0.5:
            final_verdict = "clean"
            confidence = verdicts["clean"] / total_checks
        else:
            final_verdict = "unknown"
            confidence = 0.5
        
        summary = f"{malicious_total} malicious, {verdicts['suspicious']} suspicious, {verdicts['clean']} clean out of {total_checks} checks"
        
        return {
            "verdict": final_verdict,
            "confidence": round(confidence, 2),
            "summary": summary
        }
    
    def get_available_apis(self) -> list:
        """Get list of configured and available APIs"""
        return [
            {
                "name": name,
                "available": client.is_available
            }
            for name, client in self.clients.items()
        ]
