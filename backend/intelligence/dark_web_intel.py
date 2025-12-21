"""
Dark Web Intelligence Collector (Optional)
Monitors Tor hidden services for breach data and threat indicators

REQUIRES: Tor service running on localhost:9050
"""

import aiohttp
import asyncio
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
import hashlib
import re

logger = logging.getLogger(__name__)

# Try to import aiohttp_socks for Tor support
try:
    from aiohttp_socks import ProxyConnector
    TOR_AVAILABLE = True
except ImportError:
    TOR_AVAILABLE = False
    logger.warning("[DarkWebIntel] aiohttp_socks not installed - dark web features disabled")


@dataclass
class BreachInfo:
    """Breach/leak information"""
    source: str
    date_found: str
    data_types: List[str] = field(default_factory=list)
    affected_domain: str = ""
    record_count: int = 0
    description: str = ""
    confidence: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DarkWebResult:
    """Dark web query result"""
    query: str
    breaches: List[BreachInfo] = field(default_factory=list)
    mentions: List[Dict[str, Any]] = field(default_factory=list)
    threat_indicators: List[str] = field(default_factory=list)
    total_results: int = 0
    query_time: float = 0.0
    error: str = ""
    tor_connected: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['breaches'] = [b.to_dict() if isinstance(b, BreachInfo) else b 
                             for b in self.breaches]
        return result


class DarkWebIntelligence:
    """
    Dark web intelligence collector using Tor.
    
    Features:
    - Breach database monitoring
    - Paste site monitoring
    - Threat actor forum tracking (simulated)
    
    NOTE: This is a framework - actual dark web scraping requires
    specific onion addresses and careful implementation.
    """
    
    def __init__(
        self,
        tor_host: str = "127.0.0.1",
        tor_port: int = 9050,
        timeout: int = 60,
        enabled: bool = True
    ):
        self.tor_host = tor_host
        self.tor_port = tor_port
        self.timeout = timeout
        self.enabled = enabled and TOR_AVAILABLE
        self._tor_checked = False
        self._tor_working = False
        
        if not TOR_AVAILABLE:
            logger.warning("[DarkWebIntel] Tor support not available")
        
        logger.info(f"[DarkWebIntel] Initialized (enabled: {self.enabled})")
    
    async def check_tor_connection(self) -> bool:
        """Verify Tor connection is working"""
        if not self.enabled:
            return False
        
        if self._tor_checked:
            return self._tor_working
        
        try:
            connector = ProxyConnector.from_url(f'socks5://{self.tor_host}:{self.tor_port}')
            timeout = aiohttp.ClientTimeout(total=30)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get('https://check.torproject.org/api/ip') as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self._tor_working = data.get('IsTor', False)
                        logger.info(f"[DarkWebIntel] Tor connection: {self._tor_working}")
        except Exception as e:
            logger.warning(f"[DarkWebIntel] Tor check failed: {e}")
            self._tor_working = False
        
        self._tor_checked = True
        return self._tor_working
    
    async def search_breaches(self, domain: str) -> DarkWebResult:
        """
        Search for breach data related to a domain.
        
        Args:
            domain: Domain to search for
            
        Returns:
            DarkWebResult with findings
        """
        start_time = asyncio.get_event_loop().time()
        result = DarkWebResult(query=domain)
        
        if not self.enabled:
            result.error = "Dark web intelligence disabled"
            return result
        
        # Check Tor connection
        result.tor_connected = await self.check_tor_connection()
        
        if not result.tor_connected:
            result.error = "Tor connection not available"
            # Still return simulated/cached results
            result.breaches = self._get_simulated_breaches(domain)
            result.total_results = len(result.breaches)
            result.query_time = asyncio.get_event_loop().time() - start_time
            return result
        
        # In production, this would query actual dark web sources
        # For now, return simulated data
        result.breaches = self._get_simulated_breaches(domain)
        result.mentions = self._get_simulated_mentions(domain)
        result.threat_indicators = self._extract_threat_indicators(domain)
        
        result.total_results = len(result.breaches) + len(result.mentions)
        result.query_time = asyncio.get_event_loop().time() - start_time
        
        return result
    
    def _get_simulated_breaches(self, domain: str) -> List[BreachInfo]:
        """
        Return simulated breach data.
        In production, this would query breach databases.
        """
        # This is placeholder data - real implementation would use actual sources
        breaches = []
        
        # Check against known breach patterns (example)
        if domain:
            # Create a deterministic "breach" based on domain hash for demo
            domain_hash = hashlib.md5(domain.encode()).hexdigest()
            
            # Only "find" breaches for some domains (deterministic randomness)
            if int(domain_hash[0], 16) < 4:
                breaches.append(BreachInfo(
                    source="simulated_breach_db",
                    date_found=datetime.now().isoformat(),
                    data_types=["email", "password_hash"],
                    affected_domain=domain,
                    record_count=1000,
                    description=f"Potential credential exposure related to {domain}",
                    confidence=0.3  # Low confidence for simulated data
                ))
        
        return breaches
    
    def _get_simulated_mentions(self, domain: str) -> List[Dict[str, Any]]:
        """Return simulated dark web mentions"""
        return []  # Placeholder
    
    def _extract_threat_indicators(self, domain: str) -> List[str]:
        """Extract threat indicators from query"""
        indicators = []
        
        # Extract IP patterns
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        ips = re.findall(ip_pattern, domain)
        indicators.extend(ips)
        
        return indicators
    
    async def monitor_paste_sites(self, keywords: List[str]) -> List[Dict[str, Any]]:
        """
        Monitor paste sites for keywords.
        
        Args:
            keywords: Keywords to search for
            
        Returns:
            List of paste matches
        """
        if not self.enabled or not await self.check_tor_connection():
            return []
        
        # Placeholder - would query actual paste sites
        return []
    
    async def get_threat_actor_info(self, indicator: str) -> Dict[str, Any]:
        """
        Get threat actor information for an indicator.
        
        Args:
            indicator: IP, domain, or hash to look up
            
        Returns:
            Threat actor information
        """
        return {
            'indicator': indicator,
            'threat_actors': [],
            'campaigns': [],
            'confidence': 0.0
        }


# Singleton
_dark_web_intel = None

def get_dark_web_intel() -> DarkWebIntelligence:
    """Get singleton dark web intelligence instance"""
    global _dark_web_intel
    if _dark_web_intel is None:
        try:
            from config import Config
            enabled = getattr(Config, 'DARK_WEB_ENABLED', False)
            tor_host = getattr(Config, 'TOR_PROXY_HOST', '127.0.0.1')
            tor_port = getattr(Config, 'TOR_PROXY_PORT', 9050)
            _dark_web_intel = DarkWebIntelligence(
                tor_host=tor_host,
                tor_port=tor_port,
                enabled=enabled
            )
        except ImportError:
            _dark_web_intel = DarkWebIntelligence(enabled=False)
    return _dark_web_intel
