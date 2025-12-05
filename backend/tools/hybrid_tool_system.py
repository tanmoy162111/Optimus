"""
Main Hybrid Tool System Implementation
"""
import json
import logging
import os
import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class ToolSource(Enum):
    """Source of tool resolution"""
    KNOWLEDGE_BASE = "knowledge_base"
    MEMORY = "memory"
    DISCOVERED = "discovered"
    LLM_GENERATED = "llm_generated"
    WEB_RESEARCH = "web_research"
    UNKNOWN = "unknown"

class ResolutionStatus(Enum):
    """Status of tool resolution"""
    RESOLVED = "resolved"
    PARTIAL = "partial"
    FAILED = "failed"
    FALLBACK = "fallback"

class ToolCategory(Enum):
    """Categories of security tools"""
    SCANNER = "scanner"
    EXPLOITATION = "exploitation"
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY = "vulnerability"
    PASSWORD = "password"
    FORENSICS = "forensics"
    WIRELESS = "wireless"
    WEB = "web"
    MISC = "misc"

@dataclass
class ToolResolution:
    """Result of tool resolution"""
    tool_name: str
    source: ToolSource
    status: ResolutionStatus
    command: Optional[str] = None
    explanation: Optional[str] = None
    confidence: float = 0.0
    examples: Optional[List[str]] = None
    warnings: Optional[List[str]] = None
    alternatives: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class ExecutionPlan:
    """Plan for executing a tool"""
    pre_checks: List[str]
    post_checks: List[str]
    timeout: int
    requires_root: bool

class HybridToolSystem:
    """Main hybrid tool system"""
    
    _instance = None
    
    def __init__(self, ssh_client=None, llm_client=None, memory_system=None):
        self.ssh_client = ssh_client
        self.llm_client = llm_client
        self.memory_system = memory_system
        
        # Initialize subsystems
        self.knowledge_base = self._init_knowledge_base()
        self.tool_inventory = self._init_tool_inventory()
        self.tool_scanner = self._init_tool_scanner()
        self.command_generator = self._init_command_generator()
        self.research_engine = self._init_research_engine()
        
        # Statistics
        self.stats = {
            'tools_resolved': 0,
            'tools_failed': 0,
            'tools_generated': 0,
            'tools_researched': 0
        }
        
        # Reference to tool_manager for lazy SSH client access
        self.tool_manager_ref = None
    
    def update_ssh_client(self, ssh_client):
        """Update SSH client and recreate tool scanner"""
        self.ssh_client = ssh_client
        self.tool_scanner = self._init_tool_scanner()
        logger.info("Updated SSH client for hybrid tool system")
    
    def get_ssh_client(self):
        """Get SSH client, using tool_manager_ref if direct client not available"""
        if self.ssh_client:
            return self.ssh_client
        if self.tool_manager_ref and hasattr(self.tool_manager_ref, 'ssh_client'):
            return self.tool_manager_ref.ssh_client
        return None
    
    @classmethod
    def get_instance(cls, ssh_client=None, llm_client=None, memory_system=None):
        """Get singleton instance"""
        if cls._instance is None:
            cls._instance = cls(ssh_client, llm_client, memory_system)
        return cls._instance
    
    def _init_knowledge_base(self):
        """Initialize knowledge base"""
        return KnowledgeBase()
    
    def _init_tool_inventory(self):
        """Initialize tool inventory"""
        return ToolInventory()
    
    def _init_tool_scanner(self):
        """Initialize tool scanner"""
        return ToolScanner(self.ssh_client)
    
    def _init_command_generator(self):
        """Initialize command generator"""
        if self.llm_client:
            return LLMCommandGenerator(self.llm_client)
        return None
    
    def _init_research_engine(self):
        """Initialize research engine"""
        return WebToolResearch()
    
    def scan_for_tools(self) -> Dict[str, Any]:
        """Scan system for available tools"""
        if not self.tool_scanner:
            return {"tools_found": 0, "error": "Tool scanner not initialized"}
        
        try:
            tools = self.tool_scanner.scan_system()
            self.tool_inventory.update_inventory(tools)
            
            result = {
                "tools_found": len(tools),
                "new_tools": [t['name'] for t in tools],
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"Tool scan complete: {result}")
            return result
        except Exception as e:
            logger.error(f"Tool scan failed: {e}")
            return {"tools_found": 0, "error": str(e)}
    
    def get_available_tools(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get list of available tools"""
        tools = self.tool_inventory.get_all_tools()
        
        if category:
            tools = [t for t in tools if t.get('category') == category]
        
        return tools
    
    def resolve_tool(self, tool_name: str, task: str, target: str, 
                    context: Optional[Dict[str, Any]] = None) -> ToolResolution:
        """
        Resolve a tool through the hybrid system using priority chain:
        1. Knowledge Base
        2. Memory System
        3. Discovered Tools
        4. LLM Generation
        5. Web Research
        """
        context = context or {}
        
        # Priority 1: Knowledge Base
        resolution = self._resolve_from_knowledge_base(tool_name, task, target, context)
        if resolution and resolution.status == ResolutionStatus.RESOLVED:
            self.stats['tools_resolved'] += 1
            return resolution
        
        # Priority 2: Memory System
        if self.memory_system:
            resolution = self._resolve_from_memory(tool_name, task, target, context)
            if resolution and resolution.status == ResolutionStatus.RESOLVED:
                self.stats['tools_resolved'] += 1
                return resolution
        
        # Priority 3: Discovered Tools
        resolution = self._resolve_from_discovered(tool_name, task, target, context)
        if resolution and resolution.status == ResolutionStatus.RESOLVED:
            self.stats['tools_resolved'] += 1
            return resolution
        
        # Priority 4: LLM Generation
        if self.command_generator:
            resolution = self._resolve_from_llm(tool_name, task, target, context)
            if resolution and resolution.status in [ResolutionStatus.RESOLVED, ResolutionStatus.PARTIAL]:
                self.stats['tools_generated'] += 1
                return resolution
        
        # Priority 5: Web Research
        resolution = self._resolve_from_web(tool_name, task, target, context)
        if resolution and resolution.status in [ResolutionStatus.RESOLVED, ResolutionStatus.PARTIAL]:
            self.stats['tools_researched'] += 1
            return resolution
        
        # Failed to resolve
        self.stats['tools_failed'] += 1
        return ToolResolution(
            tool_name=tool_name,
            source=ToolSource.UNKNOWN,
            status=ResolutionStatus.FAILED,
            explanation=f"Could not resolve tool '{tool_name}' using any available method",
            confidence=0.0,
            alternatives=self._suggest_alternatives(tool_name, task)
        )
    
    def _resolve_from_knowledge_base(self, tool_name: str, task: str, target: str, 
                                   context: Dict[str, Any]) -> Optional[ToolResolution]:
        """Resolve tool from knowledge base"""
        tool_data = self.knowledge_base.get_tool(tool_name)
        if not tool_data:
            return None
        
        # Generate command from knowledge base
        command_template = self.knowledge_base.get_command_template(tool_name, task)
        if not command_template:
            # Use default template
            command_template = "{tool} {target}"
        
        command = command_template.format(tool=tool_name, target=target, **context)
        
        return ToolResolution(
            tool_name=tool_name,
            source=ToolSource.KNOWLEDGE_BASE,
            status=ResolutionStatus.RESOLVED,
            command=command,
            explanation=f"Resolved from knowledge base with confidence 95%",
            confidence=0.95,
            examples=tool_data.get("examples", []),
            metadata={
                "category": tool_data.get("category", "unknown"),
                "requires_root": tool_data.get("requires_root", False)
            }
        )
    
    def _resolve_from_memory(self, tool_name: str, task: str, target: str, 
                           context: Dict[str, Any]) -> Optional[ToolResolution]:
        """Resolve tool from memory system"""
        # This would integrate with a real memory system
        # For now, we'll simulate
        return None
    
    def _resolve_from_discovered(self, tool_name: str, task: str, target: str, 
                               context: Dict[str, Any]) -> Optional[ToolResolution]:
        """Resolve tool from discovered tools"""
        tool = self.tool_inventory.get_tool(tool_name)
        if not tool or not tool.get('is_available', False):
            return None
        
        # Try to generate command from help text
        help_text = tool.get('help_text', '')
        if help_text:
            command = self._generate_command_from_help(tool_name, help_text, task, target)
            if command:
                return ToolResolution(
                    tool_name=tool_name,
                    source=ToolSource.DISCOVERED,
                    status=ResolutionStatus.RESOLVED,
                    command=command,
                    explanation=f"Generated from tool help text with confidence 80%",
                    confidence=0.80,
                    metadata={
                        "category": tool.get("category", "unknown"),
                        "requires_root": tool.get("requires_root", False)
                    }
                )
        
        # Fallback to simple command
        return ToolResolution(
            tool_name=tool_name,
            source=ToolSource.DISCOVERED,
            status=ResolutionStatus.PARTIAL,
            command=f"{tool_name} {target}",
            explanation=f"Basic command generated - review recommended",
            confidence=0.60,
            warnings=["Command generated without help text - review recommended"]
        )
    
    def _resolve_from_llm(self, tool_name: str, task: str, target: str, 
                         context: Dict[str, Any]) -> Optional[ToolResolution]:
        """Resolve tool using LLM"""
        if not self.command_generator:
            return None
        
        # Get tool help if available
        tool = self.tool_inventory.get_tool(tool_name)
        help_text = tool.get('help_text', '') if tool else ''
        
        try:
            generated = self.command_generator.generate_command(
                tool_name=tool_name,
                task=task,
                target=target,
                help_text=help_text
            )
            
            return ToolResolution(
                tool_name=tool_name,
                source=ToolSource.LLM_GENERATED,
                status=ResolutionStatus.PARTIAL if generated.confidence < 0.7 else ResolutionStatus.RESOLVED,
                command=generated.command,
                explanation=generated.explanation,
                confidence=generated.confidence,
                warnings=generated.warnings,
                metadata={
                    "requires_root": generated.requires_root,
                    "safety_level": generated.safety_level.value
                }
            )
        except Exception as e:
            logger.error(f"LLM command generation failed: {e}")
            return None
    
    def _resolve_from_web(self, tool_name: str, task: str, target: str, 
                         context: Dict[str, Any]) -> Optional[ToolResolution]:
        """Resolve tool using web research"""
        try:
            doc = self.research_engine.research_tool(tool_name)
            if not doc or not doc.description:
                return None
            
            # Generate command from research
            command = self._generate_command_from_research(doc, task, target)
            
            return ToolResolution(
                tool_name=tool_name,
                source=ToolSource.WEB_RESEARCH,
                status=ResolutionStatus.PARTIAL,
                command=command,
                explanation=f"Command generated from web research: {doc.description[:100]}...",
                confidence=0.70,
                warnings=["Web-researched command - review before execution"],
                examples=doc.examples
            )
        except Exception as e:
            logger.error(f"Web research failed: {e}")
            return None
    
    def _generate_command_from_help(self, tool_name: str, help_text: str, 
                                  task: str, target: str) -> Optional[str]:
        """Generate command from tool help text"""
        # Simple heuristic-based generation
        # In a real implementation, this would be more sophisticated
        return f"{tool_name} {target}"
    
    def _generate_command_from_research(self, doc, task: str, target: str) -> str:
        """Generate command from research document"""
        # Simple generation from research
        return f"{doc.tool_name} {target}"
    
    def _suggest_alternatives(self, tool_name: str, task: str) -> List[str]:
        """Suggest alternative tools"""
        # Simple alternatives based on task type
        task_lower = task.lower()
        
        if 'port' in task_lower or 'scan' in task_lower:
            return ['nmap', 'rustscan', 'masscan']
        elif 'web' in task_lower:
            return ['nikto', 'burpsuite', 'zap']
        elif 'vulnerability' in task_lower:
            return ['nuclei', 'openvas', 'nessus']
        elif 'password' in task_lower:
            return ['hydra', 'john', 'hashcat']
        
        return ['nmap']  # Default suggestion
    
    def create_execution_plan(self, resolution: ToolResolution, 
                           context: Dict[str, Any]) -> ExecutionPlan:
        """Create execution plan for a resolved tool"""
        # Default execution plan
        return ExecutionPlan(
            pre_checks=[],
            post_checks=[],
            timeout=context.get('timeout', 300),
            requires_root=resolution.metadata.get('requires_root', False) if resolution.metadata else False
        )
    
    def record_execution_result(self, tool_name: str, command: str, 
                              success: bool, output: str, findings: List[Dict]):
        """Record result of tool execution for learning"""
        # In a real implementation, this would store results for future learning
        pass
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get tool system statistics"""
        return self.stats

# Singleton accessor
def get_hybrid_tool_system(ssh_client=None, llm_client=None, memory_system=None):
    """Get the hybrid tool system instance"""
    return HybridToolSystem.get_instance(ssh_client, llm_client, memory_system)

def get_tool_scanner(ssh_client=None):
    """Get the tool scanner instance"""
    return ToolScanner(ssh_client)

def get_research_engine():
    """Get the web research engine instance"""
    return WebToolResearch()

def get_tool_inventory():
    """Get the tool inventory instance"""
    return ToolInventory()

# Supporting classes (simplified implementations)
class KnowledgeBase:
    """Tool knowledge base"""
    
    def __init__(self):
        # Sample knowledge base data
        self.tools = {
            "nmap": {
                "description": "Network exploration tool and security scanner",
                "category": "scanner",
                "commands": {
                    "default": "{tool} {target}",
                    "stealth": "{tool} -sS {target}",
                    "comprehensive": "{tool} -sV -sC -A -p- {target}"
                },
                "examples": [
                    "nmap 192.168.1.1",
                    "nmap -sV -p 22,80,443 scanme.nmap.org"
                ],
                "requires_root": True
            },
            "nuclei": {
                "description": "Fast and customizable vulnerability scanner",
                "category": "vulnerability",
                "commands": {
                    "default": "{tool} -u {target}",
                    "tech_detect": "{tool} -u {target} -td",
                    "templates": "{tool} -u {target} -t cves/"
                },
                "examples": [
                    "nuclei -u https://example.com",
                    "nuclei -u https://example.com -t cves/"
                ],
                "requires_root": False
            }
        }
    
    def get_tool(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get tool information"""
        return self.tools.get(tool_name.lower())
    
    def get_command_template(self, tool_name: str, task: str) -> Optional[str]:
        """Get command template for tool and task"""
        tool_data = self.get_tool(tool_name)
        if not tool_data:
            return None
        
        commands = tool_data.get("commands", {})
        
        # Match task to command template
        task_lower = task.lower()
        if "stealth" in task_lower:
            return commands.get("stealth")
        elif "comprehensive" in task_lower or "full" in task_lower:
            return commands.get("comprehensive")
        elif "tech" in task_lower:
            return commands.get("tech_detect")
        elif "template" in task_lower:
            return commands.get("templates")
        
        return commands.get("default")

class ToolInventory:
    """Tool inventory management"""
    
    def __init__(self):
        self.tools = {}
        self.inventory_file = "data/tool_inventory.json"
    
    def update_inventory(self, tools: List[Dict[str, Any]]):
        """Update tool inventory"""
        for tool in tools:
            self.tools[tool['name']] = tool
    
    def get_tool(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get tool from inventory"""
        return self.tools.get(tool_name)
    
    def get_all_tools(self) -> List[Dict[str, Any]]:
        """Get all tools"""
        return list(self.tools.values())
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get inventory statistics"""
        return {
            "total_tools": len(self.tools),
            "categories": {}
        }

class ToolScanner:
    """Tool discovery and scanning"""
    
    def __init__(self, ssh_client=None):
        self.ssh_client = ssh_client
        # Import the real tool discovery implementation
        from .tool_discovery import ToolDiscovery
        self.discovery = ToolDiscovery(ssh_client)
    
    def scan_system(self) -> List[Dict[str, Any]]:
        """Scan system for available tools"""
        try:
            # Use the real tool discovery implementation
            tools = self.discovery.scan_for_tools()
            
            # Enrich tool information
            enriched_tools = []
            for tool in tools:
                enriched_tool = self.discovery.enrich_tool_info(tool)
                enriched_tools.append(enriched_tool)
            
            return enriched_tools
        except Exception as e:
            logger.error(f"Tool scanning failed: {e}")
            # Return empty list instead of simulated tools
            return []
    
    def verify_tool(self, tool_name: str) -> bool:
        """Verify a tool is available"""
        try:
            # Use the real tool discovery implementation
            return self.discovery.verify_tool(tool_name)
        except Exception as e:
            logger.error(f"Tool verification failed: {e}")
            return False

class LLMCommandGenerator:
    """LLM-powered command generation"""
    
    def __init__(self, llm_client):
        self.llm_client = llm_client
    
    def generate_command(self, tool_name: str, task: str, target: str, 
                        help_text: Optional[str] = None) -> Any:
        """Generate command using LLM"""
        # This is a simplified implementation
        # In a real system, this would use an actual LLM
        class GeneratedCommand:
            def __init__(self):
                self.command = f"{tool_name} {target}"
                self.explanation = f"Generated by LLM for task: {task}"
                self.safety_level = type('Enum', (), {'value': 'medium'})()
                self.confidence = 0.75
                self.requires_root = False
                self.warnings = ["LLM-generated command - review before execution"]
                self.alternatives = []
        
        return GeneratedCommand()

class WebToolResearch:
    """Web-based tool research"""
    
    def research_tool(self, tool_name: str, force_refresh: bool = False):
        """Research a tool from web sources"""
        # This is a simplified implementation
        # In a real system, this would search web sources
        class ResearchDocument:
            def __init__(self, tool_name):
                self.tool_name = tool_name
                self.description = f"Information about {tool_name} tool"
                self.github_url = f"https://github.com/search?q={tool_name}"
                self.basic_usage = f"{tool_name} [options] target"
                self.common_flags = ["-h", "-v"]
                self.examples = [f"{tool_name} example.com"]
                self.related_tools = []
                self.sources = ["github", "documentation"]
                self.confidence = 0.8
        
        return ResearchDocument(tool_name)
    
    def get_quick_reference(self, tool_name: str) -> str:
        """Get quick reference for a tool"""
        return f"Quick reference for {tool_name}"
    
    def search_for_alternatives(self, tool_name: str, task: str) -> List[str]:
        """Search for alternative tools"""
        return ["alternative1", "alternative2"]