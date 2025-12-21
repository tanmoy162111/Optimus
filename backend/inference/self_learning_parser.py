"""
Self-Learning Universal Parser
Combines multiple parsing strategies with learning capability

Strategy Order:
1. Learned patterns (from pattern DB) - fastest, most reliable for known outputs
2. Structured parsing (JSON/XML) - high confidence for structured outputs
3. Tool-specific parsers - medium confidence, handles known formats
4. LLM parsing (Ollama) - for complex/unknown outputs
5. Pattern-based extraction - regex fallback
6. Heuristic analysis - last resort
"""

import re
import json
import uuid
import logging
from typing import Dict, Any, Optional, List, Tuple
from enum import Enum
from datetime import datetime

# Import existing parser as fallback
from .enhanced_output_parser import EnhancedOutputParser
from .ollama_client import get_ollama_client, OllamaClient
from .parser_pattern_db import get_pattern_db, ParserPatternDB, ParsePattern

logger = logging.getLogger(__name__)


class ParseMethod(Enum):
    """Parsing method used"""
    LEARNED = "learned"           # From pattern database
    STRUCTURED = "structured"     # JSON/XML parsing
    TOOL_SPECIFIC = "tool_specific"  # Known tool parser
    LLM = "llm"                   # Ollama LLM parsing
    PATTERN = "pattern"           # Regex patterns
    HEURISTIC = "heuristic"       # Heuristic analysis
    FAILED = "failed"             # No parsing succeeded


class SelfLearningParser:
    """
    Universal parser that learns from successful parsing.
    
    Features:
    - Caches successful parsing patterns for reuse
    - Uses LLM for complex outputs that existing parsers can't handle
    - Learns from both automatic and human-verified parsing
    - Maintains statistics for monitoring
    - Full backward compatibility with existing parsers
    """
    
    def __init__(self, enable_llm: bool = True, enable_learning: bool = True):
        """
        Initialize the self-learning parser.
        
        Args:
            enable_llm: Whether to use Ollama LLM for complex parsing
            enable_learning: Whether to learn from successful parsing
        """
        # Initialize components
        self.base_parser = EnhancedOutputParser()
        self.pattern_db = get_pattern_db() if enable_learning else None
        self.ollama = get_ollama_client() if enable_llm else None
        
        self.enable_llm = enable_llm
        self.enable_learning = enable_learning
        
        # Confidence thresholds
        self.min_confidence_for_learning = 0.7
        self.min_pattern_success_count = 3
        
        # Statistics tracking
        self.stats = {
            'total': 0,
            'learned': 0,
            'structured': 0,
            'tool_specific': 0,
            'llm': 0,
            'pattern': 0,
            'heuristic': 0,
            'failed': 0,
            'learning_saves': 0  # Times learning avoided LLM call
        }
        
        logger.info(f"[SelfLearningParser] Initialized (LLM: {enable_llm}, Learning: {enable_learning})")
    
    def parse(self, tool_name: str, stdout: str, stderr: str = "",
              command: str = "", target: str = "") -> Dict[str, Any]:
        """
        Main parsing entry point with multi-strategy approach.
        
        Args:
            tool_name: Name of the tool that produced the output
            stdout: Standard output from the tool
            stderr: Standard error from the tool  
            command: The command that was executed
            target: The target that was scanned
            
        Returns:
            Parsed results dict with vulnerabilities, hosts, services
        """
        self.stats['total'] += 1
        
        context = {
            'tool': tool_name,
            'command': command,
            'target': target,
            'phase': self._infer_phase_from_tool(tool_name)
        }
        
        # Normalize tool name
        tool_lower = tool_name.lower().replace('.sh', '').replace('.py', '').strip()
        
        # Combine outputs for analysis
        combined_output = stdout
        if stderr and not stderr.isspace():
            combined_output += "\n" + stderr
        
        # Skip empty outputs
        if not combined_output or len(combined_output.strip()) < 5:
            return self._empty_result(stdout, ParseMethod.FAILED, "Empty output")
        
        # ===== STRATEGY 1: Check learned patterns first =====
        if self.pattern_db:
            pattern = self.pattern_db.find_pattern(tool_lower, combined_output)
            if pattern and pattern.success_count >= self.min_pattern_success_count:
                result = self._apply_learned_pattern(pattern, combined_output, context)
                if result and self._has_findings(result):
                    self.stats['learned'] += 1
                    self.stats['learning_saves'] += 1
                    result['parse_method'] = ParseMethod.LEARNED.value
                    result['parse_confidence'] = min(0.85 + pattern.confidence_boost, 0.95)
                    logger.debug(f"[SelfLearningParser] Used learned pattern for {tool_name}")
                    return result
        
        # ===== STRATEGY 2: Use base parser (structured, tool-specific, pattern, heuristic) =====
        try:
            # The EnhancedOutputParser has its own multi-strategy approach
            result = self.base_parser.parse(tool_lower, stdout, stderr, command, target)
            
            confidence = self._get_confidence_value(result.get('parse_confidence', 'low'))
            
            if self._has_findings(result) and confidence >= self.min_confidence_for_learning:
                # Good result from base parser - learn from it
                self._learn_from_success(tool_lower, combined_output, result)
                
                method = result.get('parse_method', 'tool_specific')
                if method in self.stats:
                    self.stats[method] += 1
                else:
                    self.stats['tool_specific'] += 1
                
                return result
            
            # If base parser found something but low confidence, still return it
            # but also try LLM to see if we can do better
            base_result = result if self._has_findings(result) else None
            
        except Exception as e:
            logger.warning(f"[SelfLearningParser] Base parser error: {e}")
            base_result = None
        
        # ===== STRATEGY 3: LLM parsing for complex/unknown outputs =====
        if self.enable_llm and self.ollama and self.ollama.is_available():
            try:
                llm_result = self.ollama.parse_tool_output(
                    tool_lower, combined_output, target, context
                )
                
                if llm_result and self._has_findings(llm_result):
                    self.stats['llm'] += 1
                    
                    # Normalize the result
                    normalized = self._normalize_llm_result(llm_result, tool_lower, context)
                    
                    # Learn from successful LLM parsing
                    self._learn_from_success(tool_lower, combined_output, normalized, llm_parsed=True)
                    
                    normalized['parse_method'] = ParseMethod.LLM.value
                    normalized['parse_confidence'] = 0.75
                    normalized['raw_output'] = stdout
                    
                    logger.debug(f"[SelfLearningParser] LLM parsed {len(normalized.get('vulnerabilities', []))} findings for {tool_name}")
                    return normalized
                    
            except Exception as e:
                logger.warning(f"[SelfLearningParser] LLM parsing error: {e}")
        
        # ===== STRATEGY 4: Return base parser result if we had one =====
        if base_result:
            method = base_result.get('parse_method', 'pattern')
            if method in self.stats:
                self.stats[method] += 1
            return base_result
        
        # ===== STRATEGY 5: Final fallback - return empty result =====
        self.stats['failed'] += 1
        
        # Record failure for learning
        if self.pattern_db:
            self.pattern_db.record_failure(tool_lower, combined_output)
        
        return self._empty_result(stdout, ParseMethod.FAILED, "No findings extracted")
    
    def parse_tool_output(self, tool_name: str, stdout: str, stderr: str = "") -> Dict[str, Any]:
        """
        Backward-compatible interface matching OutputParser.
        
        Args:
            tool_name: Name of the tool
            stdout: Standard output
            stderr: Standard error
            
        Returns:
            Parsed results
        """
        return self.parse(tool_name, stdout, stderr)
    
    def _apply_learned_pattern(self, pattern: ParsePattern, output: str, 
                                context: Dict) -> Optional[Dict]:
        """
        Apply a learned parsing pattern to extract findings.
        
        Args:
            pattern: The learned pattern to apply
            output: Raw output to parse
            context: Parsing context
            
        Returns:
            Parsed results or None
        """
        vulnerabilities = []
        seen = set()
        
        for regex in pattern.extraction_patterns:
            try:
                for match in re.finditer(regex, output, re.IGNORECASE | re.MULTILINE):
                    matched_text = match.group(0)
                    
                    # Deduplicate
                    match_hash = hash(matched_text[:100])
                    if match_hash in seen:
                        continue
                    seen.add(match_hash)
                    
                    # Build vulnerability from pattern
                    vuln = {
                        'id': str(uuid.uuid4()),
                        'type': pattern.field_mappings.get('type', 'finding'),
                        'name': self._extract_name_from_match(matched_text, pattern),
                        'severity': float(pattern.field_mappings.get('default_severity', 5.0)),
                        'confidence': 0.8 + pattern.confidence_boost,
                        'location': context.get('target', 'Unknown'),
                        'evidence': matched_text[:500],
                        'exploitable': pattern.field_mappings.get('exploitable', 'false').lower() == 'true',
                        'tool': context.get('tool', 'unknown')
                    }
                    vulnerabilities.append(vuln)
                    
            except re.error as e:
                logger.warning(f"[SelfLearningParser] Regex error in pattern: {e}")
                continue
        
        if vulnerabilities:
            return {
                'vulnerabilities': vulnerabilities,
                'hosts': [],
                'services': [],
                'raw_output': output
            }
        
        return None
    
    def _extract_name_from_match(self, matched_text: str, pattern: ParsePattern) -> str:
        """Extract a human-readable name from matched text"""
        # Clean up the matched text for use as a name
        name = matched_text[:150].strip()
        
        # Remove common prefixes
        prefixes_to_remove = ['[+]', '[!]', '[*]', '[-]', '|', '+', '-', '*']
        for prefix in prefixes_to_remove:
            if name.startswith(prefix):
                name = name[len(prefix):].strip()
        
        # Use pattern's type if name is too generic
        if len(name) < 10 or name.lower() in ['found', 'detected', 'vulnerable']:
            name = f"{pattern.field_mappings.get('type', 'Finding')}: {name}"
        
        return name[:200]
    
    def _learn_from_success(self, tool: str, output: str, 
                            result: Dict, llm_parsed: bool = False):
        """
        Learn from successful parsing by storing patterns.
        
        Args:
            tool: Tool name
            output: Raw output that was parsed
            result: Successful parsing result
            llm_parsed: Whether this was parsed by LLM (more valuable)
        """
        if not self.enable_learning or not self.pattern_db:
            return
        
        try:
            # Extract patterns from successful parse
            extraction_patterns = []
            field_mappings = {}
            
            vulns = result.get('vulnerabilities', [])
            if not vulns:
                return
            
            # Learn from evidence strings
            for vuln in vulns[:5]:  # Learn from first 5 findings
                evidence = vuln.get('evidence', '')
                if evidence and len(evidence) >= 15:
                    # Create a flexible pattern from evidence
                    pattern = self._create_pattern_from_evidence(evidence)
                    if pattern and pattern not in extraction_patterns:
                        extraction_patterns.append(pattern)
                
                # Capture field mappings from first finding
                if not field_mappings:
                    field_mappings = {
                        'type': vuln.get('type', 'finding'),
                        'default_severity': str(vuln.get('severity', 5.0)),
                        'exploitable': str(vuln.get('exploitable', False)).lower()
                    }
            
            # Store the pattern
            if extraction_patterns:
                self.pattern_db.store_pattern(
                    tool=tool,
                    output=output,
                    extraction_patterns=extraction_patterns[:5],
                    field_mappings=field_mappings,
                    human_verified=False
                )
                logger.debug(f"[SelfLearningParser] Learned {len(extraction_patterns)} patterns for {tool}")
                
        except Exception as e:
            logger.warning(f"[SelfLearningParser] Failed to learn pattern: {e}")
    
    def _create_pattern_from_evidence(self, evidence: str) -> Optional[str]:
        """Create a regex pattern from evidence string"""
        if len(evidence) < 15:
            return None
        
        try:
            # Take a representative portion
            sample = evidence[:80]
            
            # Escape special regex characters
            pattern = re.escape(sample)
            
            # Make it more flexible
            # Replace escaped whitespace with flexible whitespace
            pattern = re.sub(r'\\ +', r'\\s+', pattern)
            
            # Replace numbers with digit patterns
            pattern = re.sub(r'\\\d+', r'\\d+', pattern)
            
            # Replace common variable parts
            pattern = re.sub(r'\\\.\\d+\\\.\\d+\\\.\\d+', r'[\\d.]+', pattern)  # IP addresses
            
            # Verify it's a valid regex
            re.compile(pattern)
            
            return pattern
            
        except re.error:
            return None
    
    def _normalize_llm_result(self, llm_result: Dict, tool: str, context: Dict) -> Dict:
        """Normalize LLM parsing result to standard format"""
        vulnerabilities = []
        
        for vuln in llm_result.get('vulnerabilities', []):
            normalized = {
                'id': str(uuid.uuid4()),
                'type': str(vuln.get('type', 'unknown')).lower().replace(' ', '_'),
                'name': str(vuln.get('name', 'Unknown Finding'))[:200],
                'severity': self._normalize_severity(vuln.get('severity', 5.0)),
                'confidence': vuln.get('confidence', 0.75),
                'location': str(vuln.get('location', context.get('target', 'Unknown')))[:500],
                'evidence': str(vuln.get('evidence', ''))[:1000],
                'exploitable': bool(vuln.get('exploitable', False)),
                'tool': tool,
            }
            
            # Add CVE if present
            if vuln.get('cve'):
                normalized['cve'] = vuln['cve']
            
            vulnerabilities.append(normalized)
        
        return {
            'vulnerabilities': vulnerabilities,
            'hosts': llm_result.get('hosts', []),
            'services': llm_result.get('services', [])
        }
    
    def _normalize_severity(self, value: Any) -> float:
        """Normalize severity to 0-10 scale"""
        if isinstance(value, (int, float)):
            return max(0.0, min(10.0, float(value)))
        
        if isinstance(value, str):
            severity_map = {
                'critical': 9.5, 'high': 7.5, 'medium': 5.0,
                'moderate': 5.0, 'low': 2.5, 'info': 1.0
            }
            return severity_map.get(value.lower().strip(), 5.0)
        
        return 5.0
    
    def _get_confidence_value(self, confidence: Any) -> float:
        """Convert confidence to numeric value"""
        if isinstance(confidence, (int, float)):
            return float(confidence)
        
        if isinstance(confidence, str):
            confidence_map = {
                'high': 0.9, 'medium': 0.7, 'low': 0.5,
                'uncertain': 0.3, 'none': 0.0
            }
            return confidence_map.get(confidence.lower(), 0.5)
        
        return 0.5
    
    def _has_findings(self, result: Optional[Dict]) -> bool:
        """Check if result has any findings"""
        if not result:
            return False
        return bool(result.get('vulnerabilities') or 
                   result.get('hosts') or 
                   result.get('services'))
    
    def _empty_result(self, raw_output: str, method: ParseMethod, note: str = "") -> Dict:
        """Create empty result structure"""
        return {
            'vulnerabilities': [],
            'hosts': [],
            'services': [],
            'raw_output': raw_output,
            'parse_method': method.value,
            'parse_confidence': 0.0,
            'parse_note': note
        }
    
    def _infer_phase_from_tool(self, tool_name: str) -> str:
        """Infer pentesting phase from tool name"""
        tool_lower = tool_name.lower()
        
        recon_tools = ['sublist3r', 'amass', 'theharvester', 'fierce', 'dnsenum', 'whatweb']
        scan_tools = ['nmap', 'nikto', 'nuclei', 'gobuster', 'ffuf', 'masscan', 'sslscan']
        exploit_tools = ['sqlmap', 'dalfox', 'commix', 'hydra', 'metasploit', 'xsser']
        post_exploit = ['linpeas', 'winpeas', 'mimikatz', 'bloodhound']
        
        if any(t in tool_lower for t in recon_tools):
            return 'reconnaissance'
        elif any(t in tool_lower for t in scan_tools):
            return 'scanning'
        elif any(t in tool_lower for t in exploit_tools):
            return 'exploitation'
        elif any(t in tool_lower for t in post_exploit):
            return 'post_exploitation'
        
        return 'unknown'
    
    def verify_finding(self, tool: str, output: str, finding: Dict):
        """
        Mark a finding as human-verified to boost learning confidence.
        
        Args:
            tool: Tool name
            output: Raw output
            finding: The verified finding
        """
        if not self.pattern_db:
            return
        
        try:
            extraction_patterns = []
            evidence = finding.get('evidence', '')
            
            if evidence and len(evidence) >= 15:
                pattern = self._create_pattern_from_evidence(evidence)
                if pattern:
                    extraction_patterns.append(pattern)
            
            field_mappings = {
                'type': finding.get('type', 'finding'),
                'default_severity': str(finding.get('severity', 5.0)),
                'exploitable': str(finding.get('exploitable', False)).lower()
            }
            
            self.pattern_db.store_pattern(
                tool=tool.lower(),
                output=output,
                extraction_patterns=extraction_patterns,
                field_mappings=field_mappings,
                human_verified=True  # Higher confidence boost
            )
            
            logger.info(f"[SelfLearningParser] Verified finding for {tool}")
            
        except Exception as e:
            logger.warning(f"[SelfLearningParser] Failed to verify finding: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get parsing statistics"""
        total = max(self.stats['total'], 1)
        
        stats = {
            **self.stats,
            'success_rate': (total - self.stats['failed']) / total,
            'llm_usage_rate': self.stats['llm'] / total,
            'learned_rate': self.stats['learned'] / total,
            'learning_efficiency': self.stats['learning_saves'] / total if total > 0 else 0
        }
        
        # Add pattern DB stats if available
        if self.pattern_db:
            stats['pattern_db'] = self.pattern_db.get_statistics()
        
        return stats
    
    def cleanup(self):
        """Cleanup ineffective patterns"""
        if self.pattern_db:
            deleted = self.pattern_db.cleanup_ineffective_patterns()
            logger.info(f"[SelfLearningParser] Cleanup removed {deleted} patterns")
            return deleted
        return 0


# Factory function for easy instantiation
def get_self_learning_parser(enable_llm: bool = True, 
                             enable_learning: bool = True) -> SelfLearningParser:
    """
    Get a configured self-learning parser instance.
    
    Args:
        enable_llm: Whether to enable LLM parsing
        enable_learning: Whether to enable pattern learning
        
    Returns:
        Configured SelfLearningParser
    """
    return SelfLearningParser(enable_llm=enable_llm, enable_learning=enable_learning)
