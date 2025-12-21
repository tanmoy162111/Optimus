"""
Ollama LLM Client for Optimus
Handles communication with local Ollama instance for intelligent parsing
"""

import requests
import json
import re
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
import time

logger = logging.getLogger(__name__)


@dataclass
class OllamaConfig:
    """Configuration for Ollama client"""
    base_url: str = "http://localhost:11434"
    model: str = "codellama:7b-instruct"
    timeout: int = 120  # Increased for complex parsing
    temperature: float = 0.1  # Low temp for structured extraction
    max_tokens: int = 4096
    retry_attempts: int = 2
    retry_delay: float = 1.0


class OllamaClient:
    """
    Client for Ollama LLM API.
    
    Used for:
    - Parsing complex/unknown tool outputs
    - Extracting structured vulnerability data
    - Generating parsing patterns for learning
    """
    
    def __init__(self, config: OllamaConfig = None):
        self.config = config or OllamaConfig()
        self._available = None
        self._last_check = 0
        self._check_interval = 60  # Re-check availability every 60 seconds
        
        # Import config for environment overrides
        try:
            from config import Config
            if hasattr(Config, 'OLLAMA_BASE_URL'):
                self.config.base_url = Config.OLLAMA_BASE_URL
            if hasattr(Config, 'OLLAMA_MODEL'):
                self.config.model = Config.OLLAMA_MODEL
            if hasattr(Config, 'OLLAMA_TIMEOUT'):
                self.config.timeout = Config.OLLAMA_TIMEOUT
        except ImportError:
            pass
        
        logger.info(f"[OllamaClient] Initialized with model: {self.config.model}")
    
    def is_available(self) -> bool:
        """
        Check if Ollama is running and model is available.
        Caches result for performance.
        """
        current_time = time.time()
        
        # Use cached result if recent
        if self._available is not None and (current_time - self._last_check) < self._check_interval:
            return self._available
        
        self._last_check = current_time
        
        try:
            response = requests.get(
                f"{self.config.base_url}/api/tags",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                models = data.get('models', [])
                model_names = [m.get('name', '') for m in models]
                
                # Check if our model (or base model) is available
                model_base = self.config.model.split(':')[0]
                self._available = any(model_base in m for m in model_names)
                
                if self._available:
                    logger.info(f"[OllamaClient] Model {self.config.model} is available")
                else:
                    logger.warning(f"[OllamaClient] Model {self.config.model} not found. Available: {model_names}")
                    
                return self._available
            else:
                logger.warning(f"[OllamaClient] Ollama API returned status {response.status_code}")
                self._available = False
                
        except requests.exceptions.ConnectionError:
            logger.warning("[OllamaClient] Cannot connect to Ollama. Is it running?")
            self._available = False
        except Exception as e:
            logger.warning(f"[OllamaClient] Error checking Ollama: {e}")
            self._available = False
        
        return self._available
    
    def generate(self, prompt: str, system_prompt: str = None) -> Optional[str]:
        """
        Generate completion from Ollama.
        
        Args:
            prompt: The user prompt
            system_prompt: Optional system prompt for context
            
        Returns:
            Generated text or None if failed
        """
        if not self.is_available():
            return None
        
        for attempt in range(self.config.retry_attempts):
            try:
                payload = {
                    "model": self.config.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": self.config.temperature,
                        "num_predict": self.config.max_tokens,
                        "stop": ["```\n\n", "\n\n\n"]  # Stop tokens to prevent runaway generation
                    }
                }
                
                if system_prompt:
                    payload["system"] = system_prompt
                
                response = requests.post(
                    f"{self.config.base_url}/api/generate",
                    json=payload,
                    timeout=self.config.timeout
                )
                
                if response.status_code == 200:
                    result = response.json()
                    generated_text = result.get('response', '')
                    
                    if generated_text:
                        logger.debug(f"[OllamaClient] Generated {len(generated_text)} chars")
                        return generated_text.strip()
                    else:
                        logger.warning("[OllamaClient] Empty response from Ollama")
                else:
                    logger.error(f"[OllamaClient] Ollama API error: {response.status_code}")
                    
            except requests.exceptions.Timeout:
                logger.warning(f"[OllamaClient] Request timeout (attempt {attempt + 1}/{self.config.retry_attempts})")
                if attempt < self.config.retry_attempts - 1:
                    time.sleep(self.config.retry_delay)
            except Exception as e:
                logger.error(f"[OllamaClient] Generation failed: {e}")
                if attempt < self.config.retry_attempts - 1:
                    time.sleep(self.config.retry_delay)
        
        return None
    
    def parse_tool_output(self, tool_name: str, output: str, 
                          target: str = "", context: Dict = None) -> Optional[Dict]:
        """
        Use LLM to parse security tool output into structured data.
        
        Args:
            tool_name: Name of the tool (e.g., 'nmap', 'nikto')
            output: Raw tool output
            target: Target that was scanned
            context: Additional context (phase, command, etc.)
            
        Returns:
            Parsed results dict or None if parsing failed
        """
        if not output or len(output.strip()) < 10:
            return None
        
        # Truncate very long outputs to avoid token limits
        max_output_len = 6000
        truncated = output[:max_output_len] if len(output) > max_output_len else output
        if len(output) > max_output_len:
            truncated += f"\n\n[... truncated, {len(output) - max_output_len} more characters ...]"
        
        system_prompt = self._get_parsing_system_prompt()
        user_prompt = self._build_parsing_prompt(tool_name, truncated, target, context)
        
        response = self.generate(user_prompt, system_prompt)
        
        if response:
            parsed = self._extract_json_from_response(response)
            if parsed:
                # Validate and normalize the parsed result
                return self._normalize_parsed_result(parsed, tool_name)
        
        return None
    
    def _get_parsing_system_prompt(self) -> str:
        """Get the system prompt for parsing tasks"""
        return """You are a security tool output parser for a penetration testing platform.
Your job is to extract vulnerabilities, hosts, and services from tool outputs.

CRITICAL RULES:
1. ONLY output valid JSON - no explanations, no markdown, no extra text
2. Extract REAL findings from the output - do not make up data
3. If no vulnerabilities found, return empty arrays
4. Severity scale: 0-10 (Critical: 9-10, High: 7-8.9, Medium: 4-6.9, Low: 0-3.9)
5. Set exploitable=true only if the vulnerability can be directly exploited

OUTPUT FORMAT (JSON only):
{
    "vulnerabilities": [
        {
            "type": "vulnerability_type",
            "name": "Human readable finding name",
            "severity": 7.5,
            "location": "affected URL or host:port",
            "evidence": "exact text from output proving this finding",
            "exploitable": true,
            "cve": "CVE-XXXX-XXXXX or null"
        }
    ],
    "hosts": ["hostname or IP"],
    "services": [
        {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache 2.4.41"}
    ]
}"""

    def _build_parsing_prompt(self, tool_name: str, output: str, 
                               target: str, context: Dict = None) -> str:
        """Build the user prompt for parsing"""
        context = context or {}
        phase = context.get('phase', 'unknown')
        command = context.get('command', '')
        
        prompt = f"""Parse this {tool_name} output and extract all security findings.

Target: {target}
Phase: {phase}
Command: {command[:200] if command else 'N/A'}

=== TOOL OUTPUT START ===
{output}
=== TOOL OUTPUT END ===

Extract all vulnerabilities, discovered hosts, and services. Return ONLY valid JSON."""

        return prompt
    
    def _extract_json_from_response(self, response: str) -> Optional[Dict]:
        """Extract JSON from LLM response, handling common issues"""
        if not response:
            return None
        
        # Clean up response
        response = response.strip()
        
        # Try direct JSON parse first
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass
        
        # Try to find JSON object in response
        # Pattern matches outermost { ... }
        json_patterns = [
            r'```json\s*([\s\S]*?)\s*```',  # Markdown code block
            r'```\s*([\s\S]*?)\s*```',       # Generic code block
            r'(\{[\s\S]*\})',                 # Raw JSON object
        ]
        
        for pattern in json_patterns:
            match = re.search(pattern, response)
            if match:
                try:
                    json_str = match.group(1).strip()
                    return json.loads(json_str)
                except (json.JSONDecodeError, IndexError):
                    continue
        
        # Try to fix common JSON issues
        try:
            # Remove trailing commas
            fixed = re.sub(r',\s*}', '}', response)
            fixed = re.sub(r',\s*]', ']', fixed)
            return json.loads(fixed)
        except json.JSONDecodeError:
            pass
        
        logger.warning("[OllamaClient] Could not extract valid JSON from response")
        return None
    
    def _normalize_parsed_result(self, parsed: Dict, tool_name: str) -> Dict:
        """Normalize and validate parsed result"""
        result = {
            'vulnerabilities': [],
            'hosts': [],
            'services': []
        }
        
        # Process vulnerabilities
        for vuln in parsed.get('vulnerabilities', []):
            if not isinstance(vuln, dict):
                continue
            
            normalized_vuln = {
                'id': vuln.get('id', ''),  # Will be assigned by caller if empty
                'type': str(vuln.get('type', 'unknown')).lower().replace(' ', '_'),
                'name': str(vuln.get('name', 'Unknown Finding'))[:200],
                'severity': self._normalize_severity(vuln.get('severity', 5.0)),
                'confidence': 0.75,  # LLM parsing has medium-high confidence
                'location': str(vuln.get('location', 'Unknown'))[:500],
                'evidence': str(vuln.get('evidence', ''))[:1000],
                'exploitable': bool(vuln.get('exploitable', False)),
                'tool': tool_name,
                'cve': vuln.get('cve') if vuln.get('cve') and vuln.get('cve') != 'null' else None
            }
            result['vulnerabilities'].append(normalized_vuln)
        
        # Process hosts
        for host in parsed.get('hosts', []):
            if host and isinstance(host, str):
                result['hosts'].append(host)
        
        # Process services
        for svc in parsed.get('services', []):
            if isinstance(svc, dict) and svc.get('port'):
                result['services'].append({
                    'port': int(svc.get('port', 0)),
                    'protocol': str(svc.get('protocol', 'tcp')).lower(),
                    'service': str(svc.get('service', 'unknown')),
                    'version': str(svc.get('version', ''))
                })
        
        return result
    
    def _normalize_severity(self, value: Any) -> float:
        """Normalize severity to 0-10 scale"""
        if isinstance(value, (int, float)):
            return max(0.0, min(10.0, float(value)))
        
        if isinstance(value, str):
            value_lower = value.lower().strip()
            severity_map = {
                'critical': 9.5,
                'high': 7.5,
                'medium': 5.0,
                'moderate': 5.0,
                'low': 2.5,
                'info': 1.0,
                'informational': 1.0,
                'none': 0.0
            }
            return severity_map.get(value_lower, 5.0)
        
        return 5.0  # Default medium


# Singleton instance
_ollama_client = None


def get_ollama_client() -> OllamaClient:
    """Get or create singleton Ollama client"""
    global _ollama_client
    if _ollama_client is None:
        _ollama_client = OllamaClient()
    return _ollama_client
