"""
Web Tool Research Engine
"""
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import json
import os

logger = logging.getLogger(__name__)

@dataclass
class ResearchDocument:
    """Document containing research about a tool"""
    tool_name: str
    description: str = ""
    github_url: str = ""
    basic_usage: str = ""
    common_flags: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    related_tools: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    confidence: float = 0.0
    last_updated: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

class WebToolResearch:
    """Research tools using web sources"""
    
    def __init__(self, cache_dir: str = "data/tool_research_cache"):
        self.cache_dir = cache_dir
        self._ensure_cache_dir()
    
    def _ensure_cache_dir(self):
        """Ensure cache directory exists"""
        os.makedirs(self.cache_dir, exist_ok=True)
    
    def research_tool(self, tool_name: str, force_refresh: bool = False) -> ResearchDocument:
        """
        Research a tool from web sources
        
        Args:
            tool_name: Name of the tool to research
            force_refresh: Whether to bypass cache
        """
        # Check cache first
        if not force_refresh:
            cached_doc = self._load_from_cache(tool_name)
            if cached_doc:
                return cached_doc
        
        # Perform research
        doc = self._perform_research(tool_name)
        
        # Save to cache
        self._save_to_cache(doc)
        
        return doc
    
    def _load_from_cache(self, tool_name: str) -> Optional[ResearchDocument]:
        """Load research document from cache"""
        cache_file = os.path.join(self.cache_dir, f"{tool_name}.json")
        
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                
                # Convert to ResearchDocument
                doc = ResearchDocument(
                    tool_name=data.get('tool_name', ''),
                    description=data.get('description', ''),
                    github_url=data.get('github_url', ''),
                    basic_usage=data.get('basic_usage', ''),
                    common_flags=data.get('common_flags', []),
                    examples=data.get('examples', []),
                    related_tools=data.get('related_tools', []),
                    sources=data.get('sources', []),
                    confidence=data.get('confidence', 0.0),
                    last_updated=data.get('last_updated', ''),
                    metadata=data.get('metadata', {})
                )
                
                return doc
            except Exception as e:
                logger.error(f"Error loading cache for {tool_name}: {e}")
        
        return None
    
    def _save_to_cache(self, doc: ResearchDocument):
        """Save research document to cache"""
        try:
            cache_file = os.path.join(self.cache_dir, f"{doc.tool_name}.json")
            
            # Convert to dict for JSON serialization
            data = {
                'tool_name': doc.tool_name,
                'description': doc.description,
                'github_url': doc.github_url,
                'basic_usage': doc.basic_usage,
                'common_flags': doc.common_flags,
                'examples': doc.examples,
                'related_tools': doc.related_tools,
                'sources': doc.sources,
                'confidence': doc.confidence,
                'last_updated': doc.last_updated,
                'metadata': doc.metadata
            }
            
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving cache for {doc.tool_name}: {e}")
    
    def _perform_research(self, tool_name: str) -> ResearchDocument:
        """Perform actual research (simplified implementation)"""
        # In a real implementation, this would:
        # 1. Search GitHub for the tool
        # 2. Search documentation sites
        # 3. Search security forums and blogs
        # 4. Aggregate information
        
        # For demonstration, return mock data based on tool name
        doc = ResearchDocument(tool_name=tool_name)
        
        if tool_name.lower() == "nmap":
            doc.description = "Network exploration tool and security scanner"
            doc.github_url = "https://github.com/nmap/nmap"
            doc.basic_usage = "nmap [options] target"
            doc.common_flags = ["-sS", "-sV", "-A", "-p-", "-O"]
            doc.examples = [
                "nmap 192.168.1.1",
                "nmap -sV -p 22,80,443 scanme.nmap.org",
                "nmap -A -p- 192.168.1.0/24"
            ]
            doc.related_tools = ["zenmap", "masscan", "rustscan"]
            doc.sources = ["github", "official_docs", "security_guides"]
            doc.confidence = 0.95
        elif tool_name.lower() == "sqlmap":
            doc.description = "Automatic SQL injection and database takeover tool"
            doc.github_url = "https://github.com/sqlmapproject/sqlmap"
            doc.basic_usage = "sqlmap -u URL [options]"
            doc.common_flags = ["-u", "--batch", "--level", "--risk", "-D", "-T"]
            doc.examples = [
                'sqlmap -u "http://example.com/page.php?id=1"',
                'sqlmap -u "http://example.com/page.php?id=1" --batch --level=3'
            ]
            doc.related_tools = ["sqlninja", "bbqsql", "nosqlmap"]
            doc.sources = ["github", "official_docs", "pentest_guides"]
            doc.confidence = 0.90
        else:
            # Generic research for unknown tools
            doc.description = f"Security tool: {tool_name}"
            doc.basic_usage = f"{tool_name} [options] target"
            doc.common_flags = ["-h", "--help"]
            doc.examples = [f"{tool_name} example.com"]
            doc.related_tools = ["nmap", "nikto"]
            doc.sources = ["generic_search"]
            doc.confidence = 0.50
        
        return doc
    
    def get_quick_reference(self, tool_name: str) -> str:
        """Get quick reference card for a tool"""
        doc = self.research_tool(tool_name)
        
        if not doc.description:
            return f"No quick reference available for {tool_name}"
        
        ref = f"# Quick Reference: {tool_name}\n\n"
        ref += f"**Description**: {doc.description}\n\n"
        ref += f"**Basic Usage**: {doc.basic_usage}\n\n"
        
        if doc.common_flags:
            ref += "**Common Flags**:\n"
            for flag in doc.common_flags:
                ref += f"  - {flag}\n"
            ref += "\n"
        
        if doc.examples:
            ref += "**Examples**:\n"
            for example in doc.examples:
                ref += f"  - {example}\n"
            ref += "\n"
        
        return ref
    
    def search_for_alternatives(self, tool_name: str, task: str = "penetration testing") -> List[str]:
        """Search for alternative tools for a given task"""
        # Simplified implementation - in reality this would search web sources
        
        # Common alternatives mapping
        alternatives_map = {
            "nmap": ["rustscan", "masscan", "zenmap", "netcat"],
            "sqlmap": ["sqlninja", "bbqsql", "nosqlmap", "jsql"],
            "nikto": ["nuclei", "gobuster", "dirb", "ffuf"],
            "hydra": ["medusa", "ncrack", "patator"],
            "metasploit": ["exploitdb", "searchsploit", "cobaltstrike"]
        }
        
        # Return alternatives if we have them
        if tool_name.lower() in alternatives_map:
            return alternatives_map[tool_name.lower()]
        
        # Generic alternatives based on task
        task_lower = task.lower()
        if "port scan" in task_lower:
            return ["nmap", "rustscan", "masscan"]
        elif "web" in task_lower:
            return ["nikto", "nuclei", "gobuster"]
        elif "sql" in task_lower:
            return ["sqlmap", "sqlninja", "bbqsql"]
        elif "password" in task_lower:
            return ["hydra", "medusa", "john"]
        
        # Default alternatives
        return ["nmap", "nikto", "sqlmap"]

# Convenience function
def create_research_engine(cache_dir: str = "data/tool_research_cache") -> WebToolResearch:
    """Create web research engine"""
    return WebToolResearch(cache_dir)