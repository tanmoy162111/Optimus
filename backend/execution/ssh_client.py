"""
SSH Client for Remote Tool Execution on Kali VM
"""
import paramiko
import time
import logging
from typing import Dict, Any, Callable, Optional
from config import Config

logger = logging.getLogger(__name__)

class KaliSSHClient:
    """SSH client for executing pentesting tools on Kali VM"""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize SSH client with Kali VM config
        Args:
            config: Dict with host, port, username, password, key_path
        """
        self.config = config or Config.KALI_VM
        self.client = None
        self.connected = False
        
    def connect(self) -> bool:
        """
        Establish SSH connection to Kali VM
        Returns:
            True if connected successfully
        """
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            retries = int(self.config.get('connect_retries', 3))
            timeout = int(self.config.get('connect_timeout', 30))
            last_err = None

            for attempt in range(1, retries + 1):
                try:
                    # Try key-based auth first, then password
                    if self.config.get('key_path'):
                        logger.info(f"Connecting to {self.config['host']} (attempt {attempt}/{retries}) with SSH key...")
                        self.client.connect(
                            hostname=self.config['host'],
                            port=self.config['port'],
                            username=self.config['username'],
                            key_filename=self.config['key_path'],
                            timeout=timeout,
                            allow_agent=True,
                            look_for_keys=True
                        )
                    else:
                        logger.info(f"Connecting to {self.config['host']} (attempt {attempt}/{retries}) with password...")
                        self.client.connect(
                            hostname=self.config['host'],
                            port=self.config['port'],
                            username=self.config['username'],
                            password=self.config['password'],
                            timeout=timeout,
                            allow_agent=False,
                            look_for_keys=False
                        )

                    # Enable server keepalive to maintain session
                    transport = self.client.get_transport()
                    if transport:
                        keepalive = int(self.config.get('keepalive_seconds', 30))
                        transport.set_keepalive(keepalive)

                    self.connected = True
                    logger.info(f"Successfully connected to Kali VM at {self.config['host']} (timeout={timeout}s)")
                    return True
                except Exception as e:
                    last_err = e
                    logger.warning(f"SSH connect attempt {attempt}/{retries} failed: {e}")
                    time.sleep(2 * attempt)

            logger.error(f"Failed to connect to Kali VM after {retries} attempts: {last_err}")
            self.connected = False
            return False
        except Exception as e:
            logger.error(f"Failed to initialize SSH client: {e}")
            self.connected = False
            return False
    
    def disconnect(self):
        """Close SSH connection"""
        if self.client:
            self.client.close()
            self.connected = False
            logger.info("Disconnected from Kali VM")
    
    def execute_command(
        self, 
        command: str, 
        timeout: int = 300,
        output_callback: Optional[Callable[[str], None]] = None
    ) -> Dict[str, Any]:
        """
        Execute command on Kali VM and stream output
        Args:
            command: Command to execute
            timeout: Max execution time in seconds
            output_callback: Function to call with each output line
        Returns:
            Dict with stdout, stderr, exit_code, execution_time
        """
        if not self.connected:
            if not self.connect():
                return {
                    'success': False,
                    'error': 'Not connected to Kali VM',
                    'stdout': '',
                    'stderr': '',
                    'exit_code': -1
                }
        
        try:
            logger.info(f"Executing command: {command}")
            start_time = time.time()
            
            # Execute command
            stdin, stdout, stderr = self.client.exec_command(
                command,
                timeout=timeout,
                get_pty=True  # Needed for interactive commands
            )
            
            # Stream output
            stdout_lines = []
            stderr_lines = []
            
            # Read stdout in real-time
            while not stdout.channel.exit_status_ready():
                if stdout.channel.recv_ready():
                    line = stdout.channel.recv(1024).decode('utf-8', errors='ignore')
                    if line:
                        stdout_lines.append(line)
                        if output_callback:
                            output_callback(line)
                time.sleep(0.1)
            
            # Get remaining output
            remaining_stdout = stdout.read().decode('utf-8', errors='ignore')
            if remaining_stdout:
                stdout_lines.append(remaining_stdout)
                if output_callback:
                    output_callback(remaining_stdout)
            
            # Get stderr
            stderr_output = stderr.read().decode('utf-8', errors='ignore')
            if stderr_output:
                stderr_lines.append(stderr_output)
            
            exit_code = stdout.channel.recv_exit_status()
            execution_time = time.time() - start_time
            
            result = {
                'success': exit_code == 0,
                'stdout': ''.join(stdout_lines),
                'stderr': ''.join(stderr_lines),
                'exit_code': exit_code,
                'execution_time': execution_time,
                'command': command
            }
            
            logger.info(f"Command completed with exit code {exit_code} in {execution_time:.2f}s")
            return result
            
        except Exception as e:
            logger.error(f"Error executing command: {e}")
            return {
                'success': False,
                'error': str(e),
                'stdout': '',
                'stderr': str(e),
                'exit_code': -1,
                'command': command
            }
    
    def execute_tool(
        self,
        tool_name: str,
        target: str,
        options: Dict[str, Any] = None,
        output_callback: Optional[Callable[[str], None]] = None
    ) -> Dict[str, Any]:
        """
        Execute pentesting tool with standard options
        Args:
            tool_name: Tool to execute (nmap, sqlmap, etc.)
            target: Target URL/IP
            options: Additional tool-specific options
            output_callback: Function for streaming output
        Returns:
            Execution result dict
        """
        options = options or {}
        
        # Build command based on tool
        command = self._build_tool_command(tool_name, target, options)
        
        if not command:
            return {
                'success': False,
                'error': f'Unknown tool: {tool_name}',
                'stdout': '',
                'stderr': f'Tool {tool_name} not supported',
                'exit_code': -1
            }
        
        # Execute with timeout based on tool type
        timeout = options.get('timeout', 300)
        return self.execute_command(command, timeout=timeout, output_callback=output_callback)
    
    def _build_tool_command(self, tool: str, target: str, options: Dict[str, Any]) -> str:
        """Build command string for specific tool"""
        
        commands = {
            # Network scanning
            'nmap': f"nmap -T4 -A {target}",
            'masscan': f"masscan {target} -p1-65535",
            
            # Web scanning
            'nikto': f"nikto -h {target}",
            'nuclei': f"nuclei -u {target}",
            'whatweb': f"whatweb {target}",
            
            # Web exploitation
            'sqlmap': f"sqlmap -u {target} --batch --level=1 --risk=1",
            'dalfox': f"dalfox url {target}",
            'commix': f"commix --url={target} --batch",
            
            # Directory brute-forcing
            'dirb': f"dirb {target}",
            'gobuster': f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt",
            
            # Reconnaissance
            'sublist3r': f"sublist3r -d {target}",
            'dnsenum': f"dnsenum {target}",
            
            # Exploitation frameworks
            'metasploit': f"msfconsole -q -x 'search {target}; exit'",
            
            # Password attacks
            'hydra': f"hydra {target}",
            
            # CMS scanners
            'wpscan': f"wpscan --url {target} --enumerate vp,vt,u",
        }
        
        base_cmd = commands.get(tool)
        if not base_cmd:
            return ""
        
        # Add custom options if provided
        if options.get('extra_args'):
            base_cmd += f" {options['extra_args']}"
        
        return base_cmd
    
    def test_connection(self) -> Dict[str, Any]:
        """
        Test connection to Kali VM
        Returns:
            Dict with connection status and info
        """
        try:
            if not self.connect():
                return {
                    'connected': False,
                    'error': 'Failed to establish connection'
                }
            
            # Run simple test command
            result = self.execute_command('uname -a && whoami')
            
            return {
                'connected': True,
                'host': self.config['host'],
                'username': self.config['username'],
                'system_info': result.get('stdout', '').strip(),
                'response_time': result.get('execution_time', 0)
            }
            
        except Exception as e:
            return {
                'connected': False,
                'error': str(e)
            }
    
    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()
