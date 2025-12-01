"""
Web Intelligence Module - Real-time information gathering from the web

Features:
- Smart web scraper for CVE details, exploit info, security blogs
- External search API integration (Google, Shodan, etc.)
- Real-time vulnerability intelligence
- Technology fingerprint database updates
"""

import os
import re
import json
import logging
import hashlib
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
import threading

logger = logging.getLogger(__name__)


@dataclass
class WebIntelResult:
    """Result from web intelligence gathering"""
    source: str
    query: str
    results: List[Dict[str, Any]]
    timestamp: str
    cached: bool = False


class WebScraper:
    """Smart web scraper for security intelligence"""
    
    def __init__(self):
        self.session = None
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour cache
        self.rate_limits = {}  # Track rate limits per domain
        
        # User agents for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ]
        self._ua_index = 0
    
    def _get_user_agent(self) -> str:
        """Rotate user agents"""
        ua = self.user_agents[self._ua_index]
        self._ua_index = (self._ua_index + 1) % len(self.user_agents)
        return ua
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session
    
    async def fetch_url(self, url: str, use_cache: bool = True) -> Optional[str]:
        """Fetch URL content with caching and rate limiting"""
        # Check cache
        cache_key = hashlib.md5(url.encode()).hexdigest()
        if use_cache and cache_key in self.cache:
            cached = self.cache[cache_key]
            if datetime.now().timestamp() - cached['timestamp'] < self.cache_ttl:
                logger.debug(f"Cache hit for {url}")
                return cached['content']
        
        # Check rate limit
        domain = urlparse(url).netloc
        if domain in self.rate_limits:
            if datetime.now().timestamp() - self.rate_limits[domain] < 1:
                await asyncio.sleep(1)  # Rate limit: 1 request per second per domain
        
        try:
            session = await self._get_session()
            headers = {'User-Agent': self._get_user_agent()}
            
            async with session.get(url, headers=headers) as response:
                self.rate_limits[domain] = datetime.now().timestamp()
                
                if response.status == 200:
                    content = await response.text()
                    
                    # Update cache
                    self.cache[cache_key] = {
                        'content': content,
                        'timestamp': datetime.now().timestamp()
                    }
                    
                    return content
                else:
                    logger.warning(f"Failed to fetch {url}: HTTP {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            return None
    
    async def close(self):
        """Close the session"""
        if self.session and not self.session.closed:
            await self.session.close()


class CVEIntelligence:
    """CVE and vulnerability intelligence gathering"""
    
    def __init__(self):
        self.scraper = WebScraper()
        
        # CVE data sources
        self.sources = {
            'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'cvedetails': 'https://www.cvedetails.com',
            'exploit_db': 'https://www.exploit-db.com',
            'github_advisory': 'https://github.com/advisories',
        }
    
    async def search_cve(self, keyword: str, limit: int = 10) -> List[Dict]:
        """Search for CVEs related to a keyword"""
        results = []
        
        try:
            # Search NVD API
            nvd_url = f"{self.sources['nvd']}?keywordSearch={keyword}&resultsPerPage={limit}"
            content = await self.scraper.fetch_url(nvd_url)
            
            if content:
                try:
                    data = json.loads(content)
                    vulnerabilities = data.get('vulnerabilities', [])
                    
                    for vuln in vulnerabilities:
                        cve_data = vuln.get('cve', {})
                        
                        # Extract CVSS score
                        cvss_score = 0.0
                        metrics = cve_data.get('metrics', {})
                        if 'cvssMetricV31' in metrics:
                            cvss_score = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore', 0)
                        elif 'cvssMetricV2' in metrics:
                            cvss_score = metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore', 0)
                        
                        # Extract description
                        descriptions = cve_data.get('descriptions', [])
                        description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')
                        
                        results.append({
                            'cve_id': cve_data.get('id', ''),
                            'description': description[:500],
                            'cvss_score': cvss_score,
                            'published': cve_data.get('published', ''),
                            'source': 'nvd'
                        })
                        
                except json.JSONDecodeError:
                    logger.error("Failed to parse NVD response")
                    
        except Exception as e:
            logger.error(f"Error searching CVE: {e}")
        
        return results
    
    async def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """Get detailed information about a specific CVE"""
        try:
            nvd_url = f"{self.sources['nvd']}?cveId={cve_id}"
            content = await self.scraper.fetch_url(nvd_url)
            
            if content:
                data = json.loads(content)
                vulnerabilities = data.get('vulnerabilities', [])
                
                if vulnerabilities:
                    cve_data = vulnerabilities[0].get('cve', {})
                    
                    # Extract all relevant information
                    metrics = cve_data.get('metrics', {})
                    references = cve_data.get('references', [])
                    weaknesses = cve_data.get('weaknesses', [])
                    
                    return {
                        'cve_id': cve_id,
                        'description': next(
                            (d['value'] for d in cve_data.get('descriptions', []) if d['lang'] == 'en'),
                            ''
                        ),
                        'cvss_v3': metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}) if 'cvssMetricV31' in metrics else None,
                        'cvss_v2': metrics.get('cvssMetricV2', [{}])[0].get('cvssData', {}) if 'cvssMetricV2' in metrics else None,
                        'references': [{'url': ref.get('url'), 'source': ref.get('source')} for ref in references],
                        'weaknesses': [w.get('description', [{}])[0].get('value', '') for w in weaknesses],
                        'published': cve_data.get('published', ''),
                        'lastModified': cve_data.get('lastModified', '')
                    }
                    
        except Exception as e:
            logger.error(f"Error getting CVE details: {e}")
        
        return None
    
    async def search_exploits(self, cve_id: str) -> List[Dict]:
        """Search for public exploits for a CVE"""
        exploits = []
        
        # Search Exploit-DB (via Google dork simulation)
        # In production, you'd use the Exploit-DB API or searchsploit
        
        # Search GitHub for PoCs
        try:
            github_search = f"https://api.github.com/search/repositories?q={cve_id}+poc&sort=stars"
            content = await self.scraper.fetch_url(github_search)
            
            if content:
                data = json.loads(content)
                for repo in data.get('items', [])[:5]:
                    exploits.append({
                        'source': 'github',
                        'name': repo.get('full_name', ''),
                        'url': repo.get('html_url', ''),
                        'description': repo.get('description', ''),
                        'stars': repo.get('stargazers_count', 0),
                        'type': 'poc'
                    })
                    
        except Exception as e:
            logger.error(f"Error searching exploits: {e}")
        
        return exploits


class ExternalSearchManager:
    """Manager for external search APIs"""
    
    def __init__(self):
        self.scraper = WebScraper()
        
        # API keys (from environment)
        self.api_keys = {
            'shodan': os.getenv('SHODAN_API_KEY', ''),
            'censys': os.getenv('CENSYS_API_KEY', ''),
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY', ''),
            'hunter': os.getenv('HUNTER_API_KEY', ''),
            'securitytrails': os.getenv('SECURITYTRAILS_API_KEY', ''),
        }
    
    async def search_shodan(self, query: str) -> List[Dict]:
        """Search Shodan for target intelligence"""
        if not self.api_keys['shodan']:
            logger.warning("Shodan API key not configured")
            return []
        
        try:
            url = f"https://api.shodan.io/shodan/host/search?key={self.api_keys['shodan']}&query={query}"
            content = await self.scraper.fetch_url(url, use_cache=False)
            
            if content:
                data = json.loads(content)
                results = []
                
                for match in data.get('matches', []):
                    results.append({
                        'ip': match.get('ip_str', ''),
                        'port': match.get('port', 0),
                        'org': match.get('org', ''),
                        'hostnames': match.get('hostnames', []),
                        'os': match.get('os', ''),
                        'product': match.get('product', ''),
                        'version': match.get('version', ''),
                        'vulns': match.get('vulns', []),
                        'source': 'shodan'
                    })
                
                return results
                
        except Exception as e:
            logger.error(f"Shodan search error: {e}")
        
        return []
    
    async def search_censys(self, query: str) -> List[Dict]:
        """Search Censys for host information"""
        if not self.api_keys['censys']:
            logger.warning("Censys API key not configured")
            return []
        
        # Implement Censys API search
        # Similar to Shodan implementation
        return []
    
    async def check_virustotal(self, target: str, target_type: str = 'domain') -> Optional[Dict]:
        """Check VirusTotal for reputation"""
        if not self.api_keys['virustotal']:
            logger.warning("VirusTotal API key not configured")
            return None
        
        try:
            if target_type == 'domain':
                url = f"https://www.virustotal.com/api/v3/domains/{target}"
            elif target_type == 'ip':
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            else:
                return None
            
            session = await self.scraper._get_session()
            headers = {
                'x-apikey': self.api_keys['virustotal'],
                'User-Agent': self.scraper._get_user_agent()
            }
            
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    attributes = data.get('data', {}).get('attributes', {})
                    
                    return {
                        'target': target,
                        'type': target_type,
                        'reputation': attributes.get('reputation', 0),
                        'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                        'categories': attributes.get('categories', {}),
                        'source': 'virustotal'
                    }
                    
        except Exception as e:
            logger.error(f"VirusTotal check error: {e}")
        
        return None
    
    async def search_subdomains(self, domain: str) -> List[str]:
        """Search for subdomains using various sources"""
        subdomains = set()
        
        # SecurityTrails
        if self.api_keys['securitytrails']:
            try:
                url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
                session = await self.scraper._get_session()
                headers = {'APIKEY': self.api_keys['securitytrails']}
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        for sub in data.get('subdomains', []):
                            subdomains.add(f"{sub}.{domain}")
                            
            except Exception as e:
                logger.error(f"SecurityTrails error: {e}")
        
        # crt.sh (Certificate Transparency)
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            content = await self.scraper.fetch_url(url)
            
            if content:
                data = json.loads(content)
                for cert in data:
                    name = cert.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip()
                        if sub.endswith(domain) and '*' not in sub:
                            subdomains.add(sub)
                            
        except Exception as e:
            logger.error(f"crt.sh error: {e}")
        
        return list(subdomains)


class TechnologyFingerprinter:
    """Technology fingerprinting and vulnerability correlation"""
    
    def __init__(self):
        self.scraper = WebScraper()
        
        # Technology to vulnerability mapping
        self.tech_vuln_db = {}
        self._load_tech_vuln_db()
    
    def _load_tech_vuln_db(self):
        """Load technology vulnerability database"""
        # In production, this would load from a file or API
        self.tech_vuln_db = {
            'wordpress': {
                'common_vulns': ['CVE-2023-xxxxx', 'plugin vulnerabilities'],
                'default_creds': ['admin:admin', 'admin:password'],
                'attack_vectors': ['xmlrpc', 'wp-login.php', 'wp-admin'],
                'tools': ['wpscan', 'nuclei']
            },
            'apache': {
                'common_vulns': ['CVE-2021-41773', 'CVE-2021-42013'],
                'misconfigs': ['.htaccess', 'server-status'],
                'tools': ['nikto', 'nuclei']
            },
            'nginx': {
                'common_vulns': ['CVE-2021-23017'],
                'misconfigs': ['alias traversal', 'off-by-slash'],
                'tools': ['nikto', 'nuclei']
            },
            'php': {
                'common_vulns': ['type juggling', 'deserialization'],
                'attack_vectors': ['file inclusion', 'object injection'],
                'tools': ['commix', 'sqlmap']
            },
            'spring': {
                'common_vulns': ['CVE-2022-22965', 'CVE-2022-22963'],
                'attack_vectors': ['spring4shell', 'actuator endpoints'],
                'tools': ['nuclei', 'burpsuite']
            },
            'struts': {
                'common_vulns': ['CVE-2017-5638', 'CVE-2018-11776'],
                'attack_vectors': ['OGNL injection'],
                'tools': ['nuclei', 'metasploit']
            }
        }
    
    async def get_tech_vulnerabilities(self, technology: str, version: str = None) -> Dict:
        """Get known vulnerabilities for a technology"""
        tech_lower = technology.lower()
        
        result = {
            'technology': technology,
            'version': version,
            'known_vulns': [],
            'recommended_tools': [],
            'attack_vectors': []
        }
        
        # Check local database
        if tech_lower in self.tech_vuln_db:
            db_entry = self.tech_vuln_db[tech_lower]
            result['attack_vectors'] = db_entry.get('attack_vectors', [])
            result['recommended_tools'] = db_entry.get('tools', [])
        
        # Search CVE database for version-specific vulns
        if version:
            cve_intel = CVEIntelligence()
            cves = await cve_intel.search_cve(f"{technology} {version}", limit=10)
            result['known_vulns'] = cves
        
        return result


class WebIntelligenceEngine:
    """
    Main Web Intelligence Engine
    Coordinates all web intelligence gathering
    """
    
    def __init__(self):
        self.cve_intel = CVEIntelligence()
        self.search_manager = ExternalSearchManager()
        self.tech_fingerprinter = TechnologyFingerprinter()
        
        # Thread pool for synchronous callers
        self._executor = ThreadPoolExecutor(max_workers=4)
        self._loop = None
    
    def _get_event_loop(self):
        """Get or create event loop for async operations"""
        try:
            self._loop = asyncio.get_event_loop()
        except RuntimeError:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
        return self._loop
    
    def gather_target_intelligence(self, target: str) -> Dict[str, Any]:
        """
        Gather comprehensive intelligence about a target
        Synchronous wrapper for async method
        """
        loop = self._get_event_loop()
        return loop.run_until_complete(self._gather_target_intelligence_async(target))
    
    async def _gather_target_intelligence_async(self, target: str) -> Dict[str, Any]:
        """Async implementation of target intelligence gathering"""
        intel = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'shodan_data': [],
            'subdomains': [],
            'reputation': None,
            'technologies': [],
            'relevant_cves': [],
            'potential_exploits': []
        }
        
        # Determine target type
        is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target))
        domain = target if not is_ip else None
        
        # Gather intelligence concurrently
        tasks = []
        
        # Shodan search
        if is_ip:
            tasks.append(self._search_shodan_for_ip(target))
        else:
            tasks.append(self.search_manager.search_shodan(f"hostname:{target}"))
        
        # Subdomain enumeration (for domains)
        if domain:
            tasks.append(self.search_manager.search_subdomains(domain))
        else:
            tasks.append(asyncio.coroutine(lambda: [])())
        
        # VirusTotal reputation
        tasks.append(self.search_manager.check_virustotal(
            target, 'ip' if is_ip else 'domain'
        ))
        
        # Execute all tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        if not isinstance(results[0], Exception):
            intel['shodan_data'] = results[0]
            
            # Extract technologies from Shodan
            for item in intel['shodan_data']:
                if item.get('product'):
                    intel['technologies'].append({
                        'name': item['product'],
                        'version': item.get('version', ''),
                        'port': item.get('port', 0)
                    })
        
        if not isinstance(results[1], Exception):
            intel['subdomains'] = results[1]
        
        if not isinstance(results[2], Exception):
            intel['reputation'] = results[2]
        
        # Search for CVEs based on detected technologies
        for tech in intel['technologies'][:5]:  # Limit to avoid too many requests
            cves = await self.cve_intel.search_cve(
                f"{tech['name']} {tech.get('version', '')}", limit=5
            )
            intel['relevant_cves'].extend(cves)
        
        # Remove duplicates
        seen_cves = set()
        unique_cves = []
        for cve in intel['relevant_cves']:
            if cve['cve_id'] not in seen_cves:
                seen_cves.add(cve['cve_id'])
                unique_cves.append(cve)
        intel['relevant_cves'] = unique_cves
        
        return intel
    
    async def _search_shodan_for_ip(self, ip: str) -> List[Dict]:
        """Search Shodan for a specific IP"""
        return await self.search_manager.search_shodan(f"ip:{ip}")
    
    def search_vulnerability(self, keyword: str, limit: int = 10) -> List[Dict]:
        """Search for vulnerabilities by keyword"""
        loop = self._get_event_loop()
        return loop.run_until_complete(self.cve_intel.search_cve(keyword, limit))
    
    def get_exploit_info(self, cve_id: str) -> Dict:
        """Get exploit information for a CVE"""
        loop = self._get_event_loop()
        
        async def get_info():
            details = await self.cve_intel.get_cve_details(cve_id)
            exploits = await self.cve_intel.search_exploits(cve_id)
            return {
                'cve_details': details,
                'known_exploits': exploits
            }
        
        return loop.run_until_complete(get_info())
    
    def get_technology_intel(self, technology: str, version: str = None) -> Dict:
        """Get intelligence about a specific technology"""
        loop = self._get_event_loop()
        return loop.run_until_complete(
            self.tech_fingerprinter.get_tech_vulnerabilities(technology, version)
        )
    
    def close(self):
        """Cleanup resources"""
        if self._loop and not self._loop.is_closed():
            self._loop.run_until_complete(self.cve_intel.scraper.close())
            self._loop.run_until_complete(self.search_manager.scraper.close())


# Singleton instance
_web_intel_engine = None

def get_web_intelligence() -> WebIntelligenceEngine:
    """Get the singleton web intelligence engine"""
    global _web_intel_engine
    if _web_intel_engine is None:
        _web_intel_engine = WebIntelligenceEngine()
    return _web_intel_engine
