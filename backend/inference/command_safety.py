"""
Command Safety and Correctness Engine
Enforces strict separation between LLM suggestions and real command execution.
"""
import logging
import subprocess
import re
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum
import validators
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


class CommandType(Enum):
    """Enumeration of supported command types"""
    SCAN = "scan"
    EXPLOIT = "exploit"
    ENUMERATION = "enumeration"
    RECON = "recon"
    WEB = "web"


@dataclass
class Command:
    """Structured command schema"""
    tool: str
    arguments: List[str]
    target: str
    command_type: Optional[CommandType] = None
    timeout: int = 300  # 5 minutes default timeout
    
    def to_command_line(self) -> str:
        """Convert structured command to command line string"""
        args_str = " ".join(self.arguments)
        return f"{self.tool} {args_str} {self.target}"


class CommandValidator:
    """Validates commands before execution"""
    
    def __init__(self, ssh_client=None):
        self.ssh_client = ssh_client
        self.known_targets = set()  # This would be populated from a whitelist
        
    def _get_known_tools(self) -> set:
        """Get a list of known tools that are available on the system"""
        # Common security tools that should be available
        common_tools = {
            'nmap', 'nikto', 'sqlmap', 'dirb', 'gobuster', 'whatweb', 'wpscan',
            'hydra', 'medusa', 'enum4linux', 'smbclient', 'nessus', 'openvas',
            'metasploit', 'msfconsole', 'msfvenom', 'aircrack-ng', 'ettercap',
            'wireshark', 'tcpdump', 'netcat', 'nc', 'curl', 'wget', 'amass',
            'subfinder', 'gau', 'httpx', 'naabu', 'subjack', 'nuclei', 'zap',
            'burp', 'sqlninja', 'davtest', 'ike-scan', 'ikecrack', 'onesixtyone',
            'oscanner', 'sipvicious', 'sslscan', 'sslyze', 'testssl', 'tnscmd10g',
            'zmap', 'masscan', 'rustscan', 'zap-cli', 'nikto', 'dirbuster',
            'ffuf', 'wfuzz', 'dirsearch', 'arachni', 'w3af', 'skipfish', 'zap',
            'nikto', 'nessus', 'openvas', 'qualys', 'tenable', 'nessusd', 'nessus-service'
        }
        
        # Add tools that are actually available on the system
        available_tools = set()
        for tool in common_tools:
            if self._is_tool_available(tool):
                available_tools.add(tool)
        
        # Add common system tools
        system_tools = {'bash', 'sh', 'python', 'python3', 'perl', 'ruby', 'php', 'node', 'npm'}
        for tool in system_tools:
            if self._is_tool_available(tool):
                available_tools.add(tool)
        
        return available_tools
    
    def _is_tool_available(self, tool: str) -> bool:
        """Check if a tool is available on the system (local or remote via SSH)"""
        # Use the proper tool availability checking with SSH support
        from .tool_availability import is_tool_available
        return is_tool_available(tool, ssh_client=self.ssh_client)
    
    def validate_command(self, command: Command) -> tuple[bool, str]:
        """
        Validate a command according to security rules
        Returns (is_valid, reason_for_rejection)
        """
        # Check if tool exists
        if not command.tool:
            return False, "Tool name is required"
        
        if not self._is_tool_available(command.tool):
            return False, f"Tool '{command.tool}' is not available or not in known tools list"
        
        # Check if target is present and valid
        if not command.target:
            return False, "Target is required"
        
        # Validate target format
        if not self._is_valid_target(command.target):
            return False, f"Invalid target format: {command.target}"
        
        # Validate arguments don't contain dangerous patterns
        for arg in command.arguments:
            if self._has_dangerous_pattern(arg):
                return False, f"Dangerous pattern detected in argument: {arg}"
        
        # Additional validation based on command type
        if command.command_type == CommandType.WEB:
            if not self._is_valid_web_target(command.target):
                return False, f"Invalid web target format: {command.target}"
        
        return True, "Command is valid"
    
    def _is_valid_target(self, target: str) -> bool:
        """Validate target format"""
        # Check if it's a valid IP address
        if validators.ipv4(target) or validators.ipv6(target):
            return True
        
        # Check if it's a valid hostname or URL
        if validators.domain(target):
            return True
        
        # Check if it's a URL with protocol
        try:
            parsed = urlparse(target)
            if parsed.scheme and (validators.domain(parsed.hostname) or 
                                  validators.ipv4(parsed.hostname) or 
                                  validators.ipv6(parsed.hostname)):
                return True
        except:
            pass
        
        # Check for CIDR notation
        if '/' in target:
            parts = target.split('/')
            if len(parts) == 2:
                ip_part, cidr_part = parts
                try:
                    if (validators.ipv4(ip_part) or validators.ipv6(ip_part)) and \
                       0 <= int(cidr_part) <= 32:
                        return True
                except ValueError:
                    pass
        
        # Check for port specification (e.g., host:port)
        if ':' in target and not target.startswith('http'):
            host, port = target.rsplit(':', 1)
            try:
                port_num = int(port)
                if 1 <= port_num <= 65535:
                    return validators.domain(host) or validators.ipv4(host)
            except ValueError:
                pass
        
        return False
    
    def _is_valid_web_target(self, target: str) -> bool:
        """Validate web-specific target format"""
        if validators.url(target):
            return True
        
        # Check for http/https prefix
        if not target.startswith(('http://', 'https://')):
            target = f'http://{target}'
        
        return validators.url(target)
    
    def _has_dangerous_pattern(self, arg: str) -> bool:
        """Check if argument contains dangerous patterns"""
        dangerous_patterns = [
            r';',           # Command chaining
            r'&&',          # Command chaining
            r'\|\|',        # Command chaining
            r'\|',          # Pipe
            r'\$\(.*\)',    # Command substitution
            r'`.*`',        # Backtick command substitution
            r'>',           # Output redirection
            r'<',           # Input redirection
            r'>>',          # Append redirection
            r'2>',          # Error redirection
            r'\$\(',        # Environment variable expansion
            r'eval',        # Eval function
            r'exec',        # Exec function
            r'bash',        # Bash execution
            r'sh',          # Shell execution
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, arg, re.IGNORECASE):
                return True
        
        return False


class CommandLogger:
    """Logs command execution and rejections"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def log_rejected_command(self, command: Command, reason: str):
        """Log rejected commands"""
        self.logger.warning(
            f"Command rejected: {command.to_command_line()} | Reason: {reason}"
        )
    
    def log_validated_command(self, command: Command):
        """Log validated commands"""
        self.logger.info(f"Command validated: {command.to_command_line()}")
    
    def log_executed_command(self, command: Command, result: subprocess.CompletedProcess):
        """Log executed commands"""
        self.logger.info(
            f"Command executed: {command.to_command_line()} | "
            f"Exit code: {result.returncode}"
        )


class SafeCommandExecutor:
    """Executes only validated commands"""
    
    def __init__(self, ssh_client=None):
        self.validator = CommandValidator(ssh_client=ssh_client)
        self.logger = CommandLogger()
    
    def execute_command(self, command: Command) -> Optional[subprocess.CompletedProcess]:
        """
        Execute a command after validation
        Returns the subprocess result or None if validation fails
        """
        is_valid, reason = self.validator.validate_command(command)
        
        if not is_valid:
            self.logger.log_rejected_command(command, reason)
            return None
        
        self.logger.log_validated_command(command)
        
        try:
            cmd_line = command.to_command_line()
            
            # Execute via SSH if client is available, otherwise locally
            if self.validator.ssh_client:
                # Execute command via SSH
                stdin, stdout, stderr = self.validator.ssh_client.exec_command(cmd_line, timeout=command.timeout)
                
                # Get the output
                stdout_content = stdout.read().decode('utf-8')
                stderr_content = stderr.read().decode('utf-8')
                exit_status = stdout.channel.recv_exit_status()
                
                # Create a mock subprocess.CompletedProcess-like object
                class SSHCompletedProcess:
                    def __init__(self, args, returncode, stdout, stderr):
                        self.args = args
                        self.returncode = returncode
                        self.stdout = stdout
                        self.stderr = stderr
                        
                result = SSHCompletedProcess(cmd_line, exit_status, stdout_content, stderr_content)
            else:
                # Execute locally if no SSH client
                result = subprocess.run(
                    cmd_line,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=command.timeout
                )
            
            self.logger.log_executed_command(command, result)
            return result
        except Exception as e:
            self.logger.logger.error(f"Command execution error: {str(e)}")
            return None
    
    def execute_command_safe(self, tool: str, arguments: List[str], target: str) -> Optional[subprocess.CompletedProcess]:
        """
        Convenience method to create and execute a command safely
        """
        command = Command(tool=tool, arguments=arguments, target=target)
        return self.execute_command(command)


# Global instance for use throughout the application
# NOTE: This is deprecated. Use SafeCommandExecutor(ssh_client=ssh_client) with proper SSH client instead
# safe_executor = SafeCommandExecutor()