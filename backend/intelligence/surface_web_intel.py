"""
Surface Web Intelligence Collector
Sources: NVD, Exploit-DB, GitHub Advisories, CIRCL CVE
"""

import aiohttp
import asyncio
import json
import logging
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityInfo:
    """Structured vulnerability information"""
    cve_id: str
    description: str
    severity: float
    cvss_vector: str = ""
    published_date: str = ""
    references: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    exploits_available: bool = False
    exploit_urls: List[str] = field(default_factory=list)
    source: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IntelResult:
    """Intelligence query result"""
    query: str
    vulnerabilities: List[VulnerabilityInfo] = field(default_factory=list)
    exploits: List[Dict[str, Any]] = field(default_factory=list)
    total_results: int = 0
    sources_queried: List[str] = field(default_factory=list)
    query_time: float = 0.0
    cached: bool = False
    error: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['vulnerabilities'] = [
            v.to_dict() if isinstance(v, VulnerabilityInfo) else v 
            for v in self.vulnerabilities
        ]
        return result


class IntelCache:
    """Simple in-memory cache with TTL"""
    
    def __init__(self, default_ttl: int = 3600):
        self._cache: Dict[str, tuple] = {}
        self.default_ttl = default_ttl
    
    def _make_key(self, query: str, source: str) -> str:
        return hashlib.md5(f"{source}:{query}".encode()).hexdigest()
    
    def get(self, query: str, source: str) -> Optional[Any]:
        key = self._make_key(query, source)
        if key in self._cache:
            value, expiry = self._cache[key]
            if datetime.now().timestamp() < expiry:
                return value
            del self._cache[key]
        return None
    
    def set(self, query: str, source: str, value: Any, ttl: int = None):
        key = self._make_key(query, source)
        ttl = ttl or self.default_ttl
        expiry = datetime.now().timestamp() + ttl
        self._cache[key] = (value, expiry)
    
    def clear(self):
        self._cache.clear()


class SurfaceWebIntelligence:
    """
    Surface web intelligence collector.
    Queries NVD, CIRCL, GitHub, and Exploit-DB.
    """
    
    def __init__(self, nvd_api_key: str = None, cache_ttl: int = 3600, timeout: int = 30):
        self.nvd_api_key = nvd_api_key
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.cache = IntelCache(default_ttl=cache_ttl)
        
        self.endpoints = {
            'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'circl': 'https://cve.circl.lu/api/cve',
            'github': 'https://api.github.com/advisories'
        }
        
        self._last_request: Dict[str, float] = {}
        self._rate_limits = {'nvd': 0.6, 'circl': 0.5, 'github': 0.5}
        
        logger.info("[SurfaceIntel] Initialized")
    
    async def _rate_limit(self, source: str):
        """Apply rate limiting"""
        if source in self._last_request:
            elapsed = asyncio.get_event_loop().time() - self._last_request[source]
            min_interval = self._rate_limits.get(source, 1.0)
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
        self._last_request[source] = asyncio.get_event_loop().time()
    
    async def search_vulnerabilities(self, query: str, sources: List[str] = None) -> IntelResult:
        """Search for vulnerabilities across multiple sources"""
        start_time = asyncio.get_event_loop().time()
        sources = sources or ['nvd', 'circl', 'github']
        result = IntelResult(query=query, sources_queried=sources)
        
        tasks = []
        for source in sources:
            if source == 'nvd':
                tasks.append(self._search_nvd(query))
            elif source == 'circl':
                tasks.append(self._search_circl(query))
            elif source == 'github':
                tasks.append(self._search_github(query))
        
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            seen_cves: Set[str] = set()
            
            for source, res in zip(sources, results):
                if isinstance(res, Exception):
                    logger.warning(f"[SurfaceIntel] {source} failed: {res}")
                    continue
                for vuln in res:
                    if vuln.cve_id not in seen_cves:
                        seen_cves.add(vuln.cve_id)
                        result.vulnerabilities.append(vuln)
            
            result.total_results = len(result.vulnerabilities)
        except Exception as e:
            logger.error(f"[SurfaceIntel] Search failed: {e}")
            result.error = str(e)
        
        result.query_time = asyncio.get_event_loop().time() - start_time
        return result
    
    async def search_cve(self, cve_id: str) -> Optional[VulnerabilityInfo]:
        """Search for specific CVE"""
        cve_id = cve_id.upper()
        if not cve_id.startswith('CVE-'):
            return None
        
        # Check cache
        cached = self.cache.get(cve_id, 'cve')
        if cached:
            return cached
        
        # Try CIRCL first (faster)
        vuln = await self._get_cve_circl(cve_id)
        if vuln:
            self.cache.set(cve_id, 'cve', vuln)
            return vuln
        
        # Fallback to NVD
        result = await self._search_nvd(cve_id)
        if result:
            self.cache.set(cve_id, 'cve', result[0])
            return result[0]
        
        return None
    
    async def _search_nvd(self, query: str) -> List[VulnerabilityInfo]:
        """Search NVD"""
        cached = self.cache.get(query, 'nvd')
        if cached:
            return cached
        
        await self._rate_limit('nvd')
        vulns = []
        
        try:
            params = {'resultsPerPage': 50}
            if query.upper().startswith('CVE-'):
                params['cveId'] = query.upper()
            else:
                params['keywordSearch'] = query
            
            headers = {}
            if self.nvd_api_key:
                headers['apiKey'] = self.nvd_api_key
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(self.endpoints['nvd'], params=params, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get('vulnerabilities', []):
                            cve = item.get('cve', {})
                            vuln = self._parse_nvd_cve(cve)
                            if vuln:
                                vulns.append(vuln)
        except Exception as e:
            logger.error(f"[NVD] Error: {e}")
        
        self.cache.set(query, 'nvd', vulns)
        return vulns
    
    def _parse_nvd_cve(self, cve: Dict) -> Optional[VulnerabilityInfo]:
        """Parse NVD CVE entry"""
        try:
            cve_id = cve.get('id', '')
            descriptions = cve.get('descriptions', [])
            description = next((d['value'] for d in descriptions if d.get('lang') == 'en'), 
                              descriptions[0]['value'] if descriptions else '')
            
            # Get CVSS score
            metrics = cve.get('metrics', {})
            severity = 0.0
            cvss_vector = ""
            
            for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if version in metrics and metrics[version]:
                    cvss_data = metrics[version][0].get('cvssData', {})
                    severity = cvss_data.get('baseScore', 0.0)
                    cvss_vector = cvss_data.get('vectorString', '')
                    break
            
            references = [ref.get('url', '') for ref in cve.get('references', [])][:10]
            
            return VulnerabilityInfo(
                cve_id=cve_id,
                description=description[:1000],
                severity=severity,
                cvss_vector=cvss_vector,
                published_date=cve.get('published', ''),
                references=references,
                source='nvd'
            )
        except Exception as e:
            logger.warning(f"[NVD] Parse error: {e}")
            return None
    
    async def _search_circl(self, query: str) -> List[VulnerabilityInfo]:
        """Search CIRCL CVE database"""
        cached = self.cache.get(query, 'circl')
        if cached:
            return cached
        
        await self._rate_limit('circl')
        vulns = []
        
        try:
            # CIRCL only supports CVE ID lookup directly
            if query.upper().startswith('CVE-'):
                vuln = await self._get_cve_circl(query.upper())
                if vuln:
                    vulns.append(vuln)
        except Exception as e:
            logger.error(f"[CIRCL] Error: {e}")
        
        self.cache.set(query, 'circl', vulns)
        return vulns
    
    async def _get_cve_circl(self, cve_id: str) -> Optional[VulnerabilityInfo]:
        """Get specific CVE from CIRCL"""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(f"{self.endpoints['circl']}/{cve_id}") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return VulnerabilityInfo(
                            cve_id=data.get('id', cve_id),
                            description=data.get('summary', '')[:1000],
                            severity=float(data.get('cvss', 0) or 0),
                            cvss_vector=data.get('cvss-vector', ''),
                            published_date=data.get('Published', ''),
                            references=data.get('references', [])[:10],
                            source='circl'
                        )
        except Exception as e:
            logger.warning(f"[CIRCL] Error fetching {cve_id}: {e}")
        return None
    
    async def _search_github(self, query: str) -> List[VulnerabilityInfo]:
        """Search GitHub Security Advisories"""
        cached = self.cache.get(query, 'github')
        if cached:
            return cached
        
        await self._rate_limit('github')
        vulns = []
        
        try:
            headers = {'Accept': 'application/vnd.github+json'}
            params = {'per_page': 30}
            
            # GitHub requires specific search format
            if query.upper().startswith('CVE-'):
                params['cve_id'] = query.upper()
            else:
                params['ecosystem'] = 'pip'  # or npm, etc.
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(self.endpoints['github'], params=params, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data:
                            cve_id = item.get('cve_id', '') or item.get('ghsa_id', '')
                            severity_str = item.get('severity', 'medium').lower()
                            severity_map = {'critical': 9.5, 'high': 7.5, 'moderate': 5.0, 'low': 2.5}
                            
                            vuln = VulnerabilityInfo(
                                cve_id=cve_id,
                                description=item.get('summary', '')[:1000],
                                severity=severity_map.get(severity_str, 5.0),
                                published_date=item.get('published_at', ''),
                                references=[item.get('html_url', '')],
                                source='github'
                            )
                            vulns.append(vuln)
        except Exception as e:
            logger.error(f"[GitHub] Error: {e}")
        
        self.cache.set(query, 'github', vulns)
        return vulns
    
    async def get_exploits_for_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """Search for known exploits for a CVE"""
        # This is a placeholder - in production, you'd query Exploit-DB API
        exploits = []
        
        # Check if any cached vulnerability has exploit info
        cached = self.cache.get(cve_id, 'cve')
        if cached and cached.exploits_available:
            return [{'cve': cve_id, 'urls': cached.exploit_urls}]
        
        return exploits


# Singleton
_surface_intel = None

def get_surface_intel() -> SurfaceWebIntelligence:
    """Get singleton surface intelligence instance"""
    global _surface_intel
    if _surface_intel is None:
        try:
            from config import Config
            nvd_key = getattr(Config, 'NVD_API_KEY', None)
            _surface_intel = SurfaceWebIntelligence(nvd_api_key=nvd_key)
        except ImportError:
            _surface_intel = SurfaceWebIntelligence()
    return _surface_intel
