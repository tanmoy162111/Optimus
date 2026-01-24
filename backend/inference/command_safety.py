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
        """Convert structured command to command line string
        
        Detects whether the target already exists in the command to prevent double injection.
        Also ensures proper timeout parameters for network tools.
        """
        args_str = " ".join(self.arguments)
        base_command = f"{self.tool} {args_str}"
        
        # Add timeout parameters for nmap if not already present (critical for external targets)
        if self.tool == 'nmap':
            base_command = self._add_nmap_timeout_params(base_command)
        
        # Check if target is already present in the base command to avoid double injection
        # Use more robust detection by checking if target appears as a separate argument
        # Split the command into tokens and check if target is one of them
        tokens = re.split(r'\s+', base_command.strip())
        if self.target in tokens:
            # Target is already in the command, don't add it again
            return base_command
        else:
            # Target is not in the command, append it
            return f"{base_command} {self.target}"
    
    def _add_nmap_timeout_params(self, command: str) -> str:
        """Add timeout parameters to nmap command to prevent retransmission issues"""
        # Check if target is external (not local network)
        is_external = not any(x in self.target for x in ['192.168.', '10.', '172.', '127.', 'localhost'])
        
        # For external targets, use conservative settings to prevent retransmission cap issues
        if is_external:
            # Lower max-retries to avoid hitting retransmission cap (default is 10)
            if '--max-retries' not in command:
                command += ' --max-retries 2'  # Very low to prevent cap hit
            if '--host-timeout' not in command:
                command += ' --host-timeout 15m'
            if '--initial-rtt-timeout' not in command:
                command += ' --initial-rtt-timeout 500ms'  # Higher initial RTT for external
            if '--max-rtt-timeout' not in command:
                command += ' --max-rtt-timeout 3s'  # Higher max RTT for external
            # Use slower timing template
            if '-T' not in command:
                command += ' -T3'
        else:
            # For internal targets, use faster settings
            if '--max-retries' not in command:
                command += ' --max-retries 5'
            if '--host-timeout' not in command:
                command += ' --host-timeout 30m'
        
        # Common parameters for stability
        if '--min-rate' not in command:
            command += ' --min-rate 100'
        if '--defeat-rst-ratelimit' not in command:
            command += ' --defeat-rst-ratelimit'
        
        return command


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
        try:
            from .tool_availability import is_tool_available
        except (ImportError, ValueError):
            try:
                from tool_availability import is_tool_available
            except ImportError:
                import sys
                from pathlib import Path
                backend_path = str(Path(__file__).parent.parent)
                if backend_path not in sys.path:
                    sys.path.insert(0, backend_path)
                from inference.tool_availability import is_tool_available
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
        """Check if argument contains dangerous patterns
        
        NOTE: Patterns must use word boundaries (\b) where appropriate to avoid
        false positives with URLs (e.g., 'sh' matching '.shop' domains).
        """
        dangerous_patterns = [
            r';',           # Command chaining
            r'&&',          # Command chaining
            r'\|\|',        # Command chaining
            r'(?<!https?:)(?<!http:)\|(?!\w)',  # Pipe (but not in URLs)
            r'\$\(.*\)',    # Command substitution
            r'`.*`',        # Backtick command substitution
            r'(?<![a-zA-Z0-9])>(?![a-zA-Z])',   # Output redirection (not in HTML/XML-like content)
            r'(?<![a-zA-Z0-9])<(?![a-zA-Z])',   # Input redirection (not in HTML/XML-like content)
            r'>>',          # Append redirection
            r'2>',          # Error redirection
            r'\$\{',        # Environment variable expansion (use \$\{ instead of \$\()
            r'\beval\b',    # Eval function (word boundary)
            r'\bexec\b',    # Exec function (word boundary)
            r'(?<![a-zA-Z0-9/.-])bash(?![a-zA-Z0-9])',  # Bash execution (word boundary, not in paths)
            r'(?<![a-zA-Z0-9/.-])sh(?![a-zA-Z0-9])',    # Shell execution (word boundary, not in .shop, etc.)
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, arg, re.IGNORECASE):
                return True
        
        return False


class CommandLogger:
    """Logs command execution and rejections"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def log_rejected_command(self, command: Command, reason: str, phase: str = 'unknown', scan_id: str = 'unknown'):
        """Log rejected commands with detailed information"""
        self.logger.warning(
            f"Command rejected: tool='{command.tool}', target='{command.target}', phase='{phase}', scan_id='{scan_id}' | Reason: {reason}"
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
    
    def execute_command(self, command: Command, phase: str = 'unknown', scan_id: str = 'unknown') -> Optional[subprocess.CompletedProcess]:
        """
        Execute a command after validation
        Returns the subprocess result or None if validation fails
        """
        is_valid, reason = self.validator.validate_command(command)
        
        if not is_valid:
            self.logger.log_rejected_command(command, reason, phase, scan_id)
            return None
        
        self.logger.log_validated_command(command)
        
        try:
            cmd_line = command.to_command_line()
            
            # Execute via SSH if client is available, otherwise locally
            if self.validator.ssh_client:
                # Execute command via SSH
                try:
                    stdin, stdout, stderr = self.validator.ssh_client.exec_command(cmd_line, timeout=command.timeout)
                    
                    # Get the output
                    stdout_content = stdout.read().decode('utf-8', errors='replace')
                    stderr_content = stderr.read().decode('utf-8', errors='replace')
                    exit_status = stdout.channel.recv_exit_status()
                except Exception as e:
                    self.logger.logger.error(f"SSH command execution failed: {str(e)} | Tool: {command.tool}, Target: {command.target}, Phase: {phase}, Scan ID: {scan_id}")
                    return None
                
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
                try:
                    result = subprocess.run(
                        cmd_line,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=command.timeout
                    )
                except subprocess.TimeoutExpired:
                    self.logger.logger.error(f"Local command execution timed out: {cmd_line} | Tool: {command.tool}, Target: {command.target}, Phase: {phase}, Scan ID: {scan_id}")
                    return None
                except Exception as e:
                    self.logger.logger.error(f"Local command execution failed: {str(e)} | Tool: {command.tool}, Target: {command.target}, Phase: {phase}, Scan ID: {scan_id}")
                    return None
            
            self.logger.log_executed_command(command, result)
            return result
        except Exception as e:
            self.logger.logger.error(f"Command execution error: {str(e)} | Tool: {command.tool}, Target: {command.target}, Phase: {phase}, Scan ID: {scan_id}")
            return None
    
    def execute_command_safe(self, tool: str, arguments: List[str], target: str, phase: str = 'unknown', scan_id: str = 'unknown') -> Optional[subprocess.CompletedProcess]:
        """
        Convenience method to create and execute a command safely
        """
        command = Command(tool=tool, arguments=arguments, target=target)
        return self.execute_command(command, phase, scan_id)


# Global instance for use throughout the application
# NOTE: This is deprecated. Use SafeCommandExecutor(ssh_client=ssh_client) with proper SSH client instead
# safe_executor = SafeCommandExecutor()