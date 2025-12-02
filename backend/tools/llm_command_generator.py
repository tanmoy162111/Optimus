"""
LLM Command Generator
"""
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List

logger = logging.getLogger(__name__)

class SafetyLevel(Enum):
    """Safety level of generated commands"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNSAFE = "unsafe"

@dataclass
class GeneratedCommand:
    """Result of command generation"""
    command: str
    explanation: str
    safety_level: SafetyLevel
    confidence: float
    requires_root: bool
    warnings: List[str]
    alternatives: List[str]

class LLMCommandGenerator:
    """Generate tool commands using LLM"""
    
    def __init__(self, llm_client):
        self.llm_client = llm_client
    
    def generate_command(self, tool_name: str, task: str, target: str, 
                       help_text: Optional[str] = None) -> GeneratedCommand:
        """
        Generate a command for a tool based on the task
        
        Args:
            tool_name: Name of the tool
            task: Description of what to accomplish
            target: Target to run the tool against
            help_text: Help text for the tool (optional)
        """
        # Create prompt for LLM
        prompt = self._create_prompt(tool_name, task, target, help_text)
        
        try:
            # Generate response from LLM
            response = self._call_llm(prompt)
            
            # Parse response
            return self._parse_response(response, tool_name, task, target)
        except Exception as e:
            logger.error(f"LLM command generation failed: {e}")
            # Return fallback command
            return self._create_fallback_command(tool_name, task, target)
    
    def _create_prompt(self, tool_name: str, task: str, target: str, 
                      help_text: Optional[str]) -> str:
        """Create prompt for LLM"""
        prompt = f"""
Generate a command line for the security tool '{tool_name}' to accomplish the following task:
Task: {task}
Target: {target}

"""
        
        if help_text:
            prompt += f"""
Tool help text:
{help_text[:1000]}  # Limit help text size

"""
        
        prompt += """
Requirements:
1. Generate ONLY the command line, nothing else
2. Do not include explanations in the command itself
3. Make sure the command is syntactically correct
4. Consider safety - avoid destructive commands
5. If the task is unclear, make reasonable assumptions

Response format:
COMMAND: <command line>
EXPLANATION: <brief explanation of what the command does>
SAFETY: <high|medium|low|unsafe>
CONFIDENCE: <0.0-1.0>
REQUIRES_ROOT: <true|false>
WARNINGS: <comma-separated warnings or "none">
ALTERNATIVES: <comma-separated alternative tools or "none">

Example response:
COMMAND: nmap -sV -p 22,80,443 192.168.1.1
EXPLANATION: Scan specific ports with service detection
SAFETY: high
CONFIDENCE: 0.9
REQUIRES_ROOT: true
WARNINGS: none
ALTERNATIVES: rustscan,masscan
"""
        
        return prompt
    
    def _call_llm(self, prompt: str) -> str:
        """Call LLM with prompt"""
        # This is a simplified implementation
        # In a real system, this would call an actual LLM API
        
        # For demonstration purposes, return a mock response
        if "nmap" in prompt.lower():
            return """COMMAND: nmap -sV -p- 192.168.1.1
EXPLANATION: Perform a full port scan with service detection
SAFETY: high
CONFIDENCE: 0.95
REQUIRES_ROOT: true
WARNINGS: Full port scan may take a long time
ALTERNATIVES: rustscan, masscan"""
        
        elif "sqlmap" in prompt.lower():
            return """COMMAND: sqlmap -u "http://example.com/page.php?id=1" --batch --level=3
EXPLANATION: Test for SQL injection on the specified URL
SAFETY: medium
CONFIDENCE: 0.9
REQUIRES_ROOT: false
WARNINGS: Automated SQL injection testing - ensure authorization
ALTERNATIVES: sqlninja, bbqsql"""
        
        else:
            # Generic fallback
            return f"""COMMAND: {prompt.split()[0]} {prompt.split()[-1]}
EXPLANATION: Basic command for the specified task
SAFETY: medium
CONFIDENCE: 0.7
REQUIRES_ROOT: false
WARNINGS: Generic command - review before execution
ALTERNATIVES: nmap, nikto"""
    
    def _parse_response(self, response: str, tool_name: str, task: str, 
                       target: str) -> GeneratedCommand:
        """Parse LLM response"""
        lines = response.strip().split('\n')
        
        command = ""
        explanation = ""
        safety_level = SafetyLevel.MEDIUM
        confidence = 0.7
        requires_root = False
        warnings = []
        alternatives = []
        
        for line in lines:
            if line.startswith("COMMAND:"):
                command = line[8:].strip()
            elif line.startswith("EXPLANATION:"):
                explanation = line[12:].strip()
            elif line.startswith("SAFETY:"):
                safety_str = line[7:].strip().lower()
                try:
                    safety_level = SafetyLevel(safety_str)
                except ValueError:
                    safety_level = SafetyLevel.MEDIUM
            elif line.startswith("CONFIDENCE:"):
                try:
                    confidence = float(line[11:].strip())
                except ValueError:
                    confidence = 0.7
            elif line.startswith("REQUIRES_ROOT:"):
                requires_root = line[15:].strip().lower() == "true"
            elif line.startswith("WARNINGS:"):
                warnings_str = line[9:].strip()
                if warnings_str.lower() != "none":
                    warnings = [w.strip() for w in warnings_str.split(",")]
            elif line.startswith("ALTERNATIVES:"):
                alternatives_str = line[13:].strip()
                if alternatives_str.lower() != "none":
                    alternatives = [a.strip() for a in alternatives_str.split(",")]
        
        # Ensure we have a command
        if not command:
            command = f"{tool_name} {target}"
            if not explanation:
                explanation = f"Basic command for {tool_name}"
        
        return GeneratedCommand(
            command=command,
            explanation=explanation,
            safety_level=safety_level,
            confidence=confidence,
            requires_root=requires_root,
            warnings=warnings,
            alternatives=alternatives
        )
    
    def _create_fallback_command(self, tool_name: str, task: str, target: str) -> GeneratedCommand:
        """Create fallback command when LLM fails"""
        return GeneratedCommand(
            command=f"{tool_name} {target}",
            explanation=f"Fallback command for {tool_name} - LLM generation failed",
            safety_level=SafetyLevel.LOW,
            confidence=0.3,
            requires_root=False,
            warnings=["LLM generation failed - using fallback command"],
            alternatives=[]
        )

# Convenience function
def create_command_generator(llm_client) -> Optional[LLMCommandGenerator]:
    """Create LLM command generator if LLM client is available"""
    if llm_client:
        return LLMCommandGenerator(llm_client)
    return None