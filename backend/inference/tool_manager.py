"""Robust SSH-based tool execution manager with PTY support
Handles: sudo, interactive commands, real-time streaming, error recovery
"""
import paramiko
import select
import threading
import time
import re
import socket
import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional, Callable, List
from config import Config

# Add import for the new tool knowledge base
from inference.tool_knowledge_base import ToolKnowledgeBase

logger = logging.getLogger(__name__)


class ToolManager:
    def __init__(self, socketio):
        self.socketio = socketio
        self.ssh_client = None
        self.current_execution = None
        self.output_buffer = []
        self.connection_retries = 5
        self.connection_timeout = 60  # Increased from 30
        self.keepalive_interval = 30
        # Initialize the tool knowledge base
        self.tool_kb = ToolKnowledgeBase()
        logger.info("[ToolManager] Initialized with dynamic command generation")
    
    def connect_ssh(self) -> paramiko.SSHClient:
        """
        Establish SSH connection with robust retry logic and keepalive
        
        Returns:
            paramiko.SSHClient: Connected SSH client
        """
        # If already connected and alive, reuse it
        if self.ssh_client is not None:
            try:
                transport = self.ssh_client.get_transport()
                if transport is not None and transport.is_active():
                    # Test with a simple command
                    stdin, stdout, stderr = self.ssh_client.exec_command('echo test', timeout=5)
                    if stdout.read().decode().strip() == 'test':
                        print(f"✅ Reusing existing SSH connection")
                        return self.ssh_client
            except Exception as e:
                print(f"⚠️ Existing connection dead, reconnecting: {e}")
                self.cleanup()
        
        # Create new connection with retry logic
        for attempt in range(1, self.connection_retries + 1):
            try:
                print(f"\n[SSH] Connection attempt {attempt}/{self.connection_retries}")
                print(f"[SSH] Target: {Config.KALI_HOST}:{Config.KALI_PORT}")
                print(f"[SSH] User: {Config.KALI_USER}")
                
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # Connection parameters with increased timeouts
                connect_params = {
                    'hostname': Config.KALI_HOST,
                    'port': Config.KALI_PORT,
                    'username': Config.KALI_USER,
                    'timeout': self.connection_timeout,
                    'banner_timeout': 60,
                    'auth_timeout': 60,
                    'look_for_keys': False,
                    'allow_agent': False
                }
                
                # Use password or key
                if Config.KALI_KEY_PATH:
                    connect_params['key_filename'] = Config.KALI_KEY_PATH
                    print(f"[SSH] Using SSH key: {Config.KALI_KEY_PATH}")
                else:
                    connect_params['password'] = Config.KALI_PASSWORD
                    print(f"[SSH] Using password authentication")
                
                # Attempt connection
                print(f"[SSH] Connecting...")
                client.connect(**connect_params)
                
                # Configure keepalive to prevent timeouts
                transport = client.get_transport()
                if transport:
                    transport.set_keepalive(self.keepalive_interval)
                    # Set TCP keepalive options
                    transport.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    # Windows-specific TCP keepalive
                    if hasattr(socket, 'SIO_KEEPALIVE_VALS'):
                        transport.sock.ioctl(
                            socket.SIO_KEEPALIVE_VALS,
                            (1, 10000, 3000)  # Enable, 10s idle, 3s interval
                        )
                    print(f"[SSH] Keepalive configured: {self.keepalive_interval}s")
                
                # Test connection
                stdin, stdout, stderr = client.exec_command('echo "SSH connection test"', timeout=10)
                test_output = stdout.read().decode().strip()
                
                if "SSH connection test" not in test_output:
                    raise Exception("SSH connection test failed")
                
                print(f"✅ SSH connected successfully to {Config.KALI_HOST}")
                self.ssh_client = client
                return client
                
            except paramiko.AuthenticationException as e:
                print(f"❌ SSH authentication failed: {e}")
                print(f"   Check KALI_USER and KALI_PASSWORD in .env file")
                raise
                
            except socket.timeout as e:
                print(f"⚠️ SSH connection timeout (attempt {attempt}/{self.connection_retries})")
                if attempt < self.connection_retries:
                    wait_time = 5 * attempt
                    print(f"   Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    print(f"❌ SSH connection failed after {self.connection_retries} attempts")
                    raise Exception(f"SSH connection timeout: {e}")
                    
            except Exception as e:
                print(f"❌ SSH connection error (attempt {attempt}/{self.connection_retries}): {e}")
                if attempt < self.connection_retries:
                    wait_time = 5 * attempt
                    print(f"   Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    raise
        
        raise Exception("Failed to establish SSH connection after all retries")
    
    def execute_tool(self, tool_name: str, target: str, parameters: Dict[str, Any],
                  scan_id: str, phase: str) -> Dict[str, Any]:
        """
        Execute pentesting tool with real-time output streaming
        """
        start_time = datetime.now()
        
        # Check API requirements
        has_reqs, missing = self.check_tool_requirements(tool_name)
        
        if not has_reqs:
            logger.warning(f"[API] Cannot run {tool_name}: missing {missing}")
            
            # Try fallback tool
            fallback = self.get_fallback_tool(tool_name)
            if fallback:
                logger.info(f"[API] Using fallback tool: {fallback}")
                tool_name = fallback
            else:
                # Return graceful failure
                return {
                    'tool_name': tool_name,
                    'target': target,
                    'phase': phase,
                    'success': False,
                    'exit_code': -2,
                    'stdout': '',
                    'stderr': f'Tool requires API keys: {missing}. Keys not configured.',
                    'execution_time': 0,
                    'start_time': start_time.isoformat(),
                    'end_time': datetime.now().isoformat(),
                    'parsed_results': {'vulnerabilities': []},
                    'error': f'Missing required API keys: {missing}'
                }
        
        try:
            # Ensure SSH connection with retry logic
            max_connection_retries = 3
            for connection_attempt in range(1, max_connection_retries + 1):
                try:
                    # Connect SSH if not already connected
                    if not self.ssh_client or not self.ssh_client.get_transport().is_active():
                        print(f"[DEBUG] Establishing SSH connection (attempt {connection_attempt}/{max_connection_retries})")
                        self.ssh_client = self.connect_ssh()
                    break  # Success, exit retry loop
                    
                except Exception as conn_error:
                    print(f"❌ SSH connection failed (attempt {connection_attempt}/{max_connection_retries}): {conn_error}")
                    if connection_attempt < max_connection_retries:
                        wait_time = 5 * connection_attempt
                        print(f"   Retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                    else:
                        # Final failure
                        raise Exception(f"Failed to connect to Kali VM after {max_connection_retries} attempts: {conn_error}")
            
            # Build command
            command = self.build_command(tool_name, target, parameters)
            
            # Notify frontend
            self.socketio.emit('tool_execution_start', {
                'scan_id': scan_id,
                'tool': tool_name,
                'phase': phase,
                'command': command[:200],  # Truncate for safety
                'timestamp': start_time.isoformat()
            })
            
            # Execute with streaming
            exit_code, stdout, stderr = self.execute_with_streaming(
                command, 
                scan_id, 
                tool_name,
                timeout=parameters.get('timeout', 300)
            )
            
            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()
            
            # Parse output
            from inference.output_parser import OutputParser
            parser = OutputParser()
            parsed_results = parser.parse_tool_output(tool_name, stdout, stderr)
            
            result = {
                'tool_name': tool_name,
                'target': target,
                'phase': phase,
                'command': command,
                'exit_code': exit_code,
                'stdout': stdout,
                'stderr': stderr,
                'execution_time': execution_time,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'success': exit_code == 0,
                'parsed_results': parsed_results
            }
            
            # Learn from execution
            if result.get('success'):
                findings_count = len(result.get('parsed_results', {}).get('vulnerabilities', []))
                execution_time_val = result.get('execution_time', 0)
                self.tool_kb.learn_from_execution(
                    tool_name, 
                    command, 
                    findings_count, 
                    execution_time_val
                )
            
            # Notify completion
            self.socketio.emit('tool_execution_complete', {
                'scan_id': scan_id,
                'tool': tool_name,
                'success': result['success'],
                'execution_time': execution_time,
                'findings_count': len(parsed_results.get('vulnerabilities', []))
            })
            
            return result
            
        except Exception as e:
            print(f"❌ Tool execution error: {e}")
            self.socketio.emit('tool_execution_error', {
                'scan_id': scan_id,
                'tool': tool_name,
                'error': str(e)
            })
            raise
    
    def execute_with_streaming(self, command: str, scan_id: str,
                            tool_name: str, timeout: int = 300) -> tuple:
        """
        Execute command with real-time output streaming using PTY
        
        Args:
            command: Shell command to execute
            scan_id: Unique scan identifier
            tool_name: Name of the tool being executed
            timeout: Maximum execution time in seconds (default: 300)
        Returns:
            tuple: (exit_code, stdout, stderr)
        """
        print(f"\n[DEBUG] === Tool Execution Start ===")
        print(f"[DEBUG] Tool: {tool_name}")
        print(f"[DEBUG] Scan ID: {scan_id}")
        print(f"[DEBUG] Command: {command[:200]}...")  # Truncate long commands
        print(f"[DEBUG] Timeout: {timeout}s")
        
        try:
            # Ensure we have a valid connection
            if self.ssh_client is None:
                print(f"[DEBUG] No SSH client, connecting...")
                self.connect_ssh()
            
            # Verify connection is alive
            transport = self.ssh_client.get_transport()
            if transport is None or not transport.is_active():
                print(f"[DEBUG] Transport dead, reconnecting...")
                self.cleanup()
                self.connect_ssh()
                transport = self.ssh_client.get_transport()
            
            print(f"[DEBUG] SSH transport active: {transport.is_active()}")
            
            # Open session with retry
            channel = None
            for retry in range(3):
                try:
                    channel = transport.open_session()
                    print(f"[DEBUG] Channel opened successfully")
                    break
                except Exception as e:
                    print(f"[DEBUG] Failed to open channel (attempt {retry+1}/3): {e}")
                    if retry < 2:
                        time.sleep(2)
                        # Try reconnecting
                        self.cleanup()
                        self.connect_ssh()
                        transport = self.ssh_client.get_transport()
                    else:
                        raise
            
            if channel is None:
                raise Exception("Failed to open SSH channel after retries")
            
            # Request PTY (pseudo-terminal) - CRITICAL for interactive commands
            channel.get_pty(term='xterm', width=200, height=50)
            
            # Set timeout on channel
            channel.settimeout(timeout)
            
            # Execute command
            print(f"[DEBUG] Executing command...")
            channel.exec_command(command)
            
            stdout_data = []
            stderr_data = []
            
            # Non-blocking I/O
            channel.setblocking(0)
            
            start_time = time.time()
            last_data_time = time.time()
            data_timeout = 120  # 2 minutes without any data = timeout
            
            while True:
                # Check for overall timeout
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    print(f"[DEBUG] Command timeout reached ({timeout}s)")
                    channel.close()
                    break
                
                # Check if channel is closed
                if channel.exit_status_ready():
                    print(f"[DEBUG] Command completed")
                    break
                
                # Check for data timeout (no output for 2 minutes)
                if time.time() - last_data_time > data_timeout:
                    print(f"[DEBUG] No data received for {data_timeout}s, assuming stalled")
                    channel.close()
                    break
                
                # Read stdout
                if channel.recv_ready():
                    chunk = channel.recv(4096).decode('utf-8', errors='ignore')
                    if chunk:
                        stdout_data.append(chunk)
                        last_data_time = time.time()
                        
                        # Stream to frontend
                        self.socketio.emit('tool_output', {
                            'scan_id': scan_id,
                            'tool': tool_name,
                            'output': chunk,
                            'timestamp': datetime.now().isoformat()
                        })
                        
                        # Print to console (truncated)
                        print(chunk[:200], end='', flush=True)
                
                # Read stderr
                if channel.recv_stderr_ready():
                    chunk = channel.recv_stderr(4096).decode('utf-8', errors='ignore')
                    if chunk:
                        stderr_data.append(chunk)
                        last_data_time = time.time()
                        
                        # Stream errors
                        self.socketio.emit('tool_error_output', {
                            'scan_id': scan_id,
                            'tool': tool_name,
                            'error': chunk
                        })
                
                # Small delay to prevent CPU spinning
                time.sleep(0.1)
            
            # Get remaining data after command completes
            while channel.recv_ready():
                chunk = channel.recv(4096).decode('utf-8', errors='ignore')
                if chunk:
                    stdout_data.append(chunk)
                    self.socketio.emit('tool_output', {
                        'scan_id': scan_id,
                        'tool': tool_name,
                        'output': chunk
                    })
            
            while channel.recv_stderr_ready():
                chunk = channel.recv_stderr(4096).decode('utf-8', errors='ignore')
                if chunk:
                    stderr_data.append(chunk)
            
            # Get exit code
            exit_code = channel.recv_exit_status()
            channel.close()
            
            stdout_str = ''.join(stdout_data)
            stderr_str = ''.join(stderr_data)
            
            print(f"\n[DEBUG] Exit code: {exit_code}")
            print(f"[DEBUG] Stdout length: {len(stdout_str)} chars")
            print(f"[DEBUG] Stderr length: {len(stderr_str)} chars")
            print(f"[DEBUG] === Tool Execution End ===\n")
            
            return exit_code, stdout_str, stderr_str
            
        except socket.timeout as e:
            print(f"❌ Socket timeout during command execution: {e}")
            return -1, '', f'Socket timeout: {e}'
            
        except Exception as e:
            print(f"❌ Error during command execution: {e}")
            import traceback
            traceback.print_exc()
            return -1, '', f'Execution error: {e}'
    
    def build_command(self, tool_name: str, target: str,
                  parameters: Dict[str, Any]) -> str:
        """Build tool-specific commands using Knowledge Base - DYNAMIC"""
        
        # Normalize target URL
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        # Extract hostname/IP for tools that need it
        import re
        hostname_match = re.search(r'(?:https?://)?([^:/]+)', target)
        hostname = hostname_match.group(1) if hostname_match else target
        
        # Build context for command generation
        context = {
            'phase': parameters.get('phase', 'reconnaissance'),
            'target_type': parameters.get('target_type', 'web'),
            'findings': parameters.get('findings', []),
            'tools_executed': parameters.get('tools_executed', []),
            'time_remaining': parameters.get('time_remaining', 1.0),
            'waf_detected': parameters.get('waf_detected', False),
            'stealth_required': parameters.get('stealth_required', False),
            'technologies_detected': parameters.get('technologies_detected', []),
        }
        
        # Use Knowledge Base to generate optimal command
        try:
            command = self.tool_kb.build_command(tool_name, target, context)
            logger.info(f"[ToolManager] Dynamic command: {command[:150]}")
        except Exception as e:
            logger.error(f"[ToolManager] KB command generation failed: {e}, using fallback")
            # Fallback to simple command
            command = self._fallback_command(tool_name, target)
        
        # Add timeout wrapper
        timeout = parameters.get('timeout', 300)
        command = f"timeout {timeout} {command}"
        
        return command

    def _fallback_command(self, tool_name: str, target: str) -> str:
        """Fallback commands if Knowledge Base fails"""
        fallback_commands = {
            'nmap': f"nmap -sV -T4 {target}",
            'nikto': f"nikto -h {target}",
            'sqlmap': f"sqlmap -u '{target}' --batch",
            'sublist3r': f"sublist3r -d {target} -n",
            'whatweb': f"whatweb {target}",
            'nuclei': f"nuclei -u {target} -severity critical,high",
            'dalfox': f"dalfox url {target}",
            'commix': f"commix --url='{target}' --batch",
        }
        return fallback_commands.get(tool_name, f"{tool_name} {target}")

    def _build_sqlmap_for_juiceshop(self, target: str, parameters: Dict[str, Any]) -> str:
        """
        Build SQLMap command specifically targeting OWASP Juice Shop vulnerabilities
        
        Juice Shop has SQL injection in:
        - /rest/products/search?q=
        - /rest/user/login (POST)
        - /api/Users/
        """
        # Ensure target has proper format
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"

        # Remove trailing slash
        target = target.rstrip('/')

        # Primary vulnerable endpoint in Juice Shop
        vuln_url = f"{target}/rest/products/search?q=test"

        # Build aggressive SQLMap command
        # Level 3: Tests all parameters and HTTP headers
        # Risk 3: Includes OR-based and heavy query tests
        # Technique BEUSTQ: All injection techniques
        command = (
            f"sqlmap -u '{vuln_url}' "
            f"--batch "
            f"--level=3 "
            f"--risk=3 "
            f"--technique=BEUSTQ "
            f"--dbs "
            f"--random-agent "
            f"--threads=2 "
            f"--tamper=space2comment "
            f"--timeout=30 "
            f"--retries=2"
        )

        return command

    def _build_nmap_command(self, target: str, params: Dict) -> str:
        """Build nmap command with parameters"""
        base = f"nmap {target}"
        
        if params.get('aggressive'):
            base += " -A"
        if params.get('version_detection'):
            base += " -sV"
        if params.get('os_detection'):
            base += " -O"
        if params.get('port_range'):
            base += f" -p {params['port_range']}"
        else:
            base += " -p-"  # All ports
        
        base += " -oX /tmp/nmap_output.xml"
        return base

    def _build_sqlmap_command(self, target: str, params: Dict) -> str:
        """Build sqlmap command"""
        base = f"sqlmap -u \"{target}\" --batch --random-agent"
        
        if params.get('dbs'):
            base += " --dbs"
        if params.get('dump'):
            base += " --dump"
        if params.get('level'):
            base += f" --level={params['level']}"
        if params.get('risk'):
            base += f" --risk={params['risk']}"
        
        return base

    def check_tool_requirements(self, tool_name: str) -> tuple[bool, List[str]]:
        """
        Check if tool has all required API keys

        Returns:
            (has_requirements, missing_keys)
        """
        import os
        
        # Tools that require API keys
        api_requirements = {
            'theHarvester': {
                'optional': ['SHODAN_API_KEY', 'CENSYS_API_KEY', 'HUNTER_API_KEY'],
                'required': []  # Can work without APIs, just limited
            },
            'subfinder': {
                'optional': ['CHAOS_KEY', 'SHODAN_API_KEY'],
                'required': []
            },
            'nuclei': {
                'optional': ['GITHUB_TOKEN'],  # For template updates
                'required': []
            },
            'shodan': {
                'required': ['SHODAN_API_KEY'],
                'optional': []
            },
            'netlas': {
                'required': ['NETLAS_API_KEY'],
                'optional': []
            },
            'onyphe': {
                'required': ['ONYPHE_API_KEY'],
                'optional': []
            },
        }
        
        if tool_name not in api_requirements:
            # Tool doesn't need API keys
            return True, []
        
        reqs = api_requirements[tool_name]
        missing_required = [k for k in reqs.get('required', []) if not os.getenv(k)]
        
        if missing_required:
            logger.warning(f"[API] {tool_name} missing REQUIRED keys: {missing_required}")
            return False, missing_required
        
        missing_optional = [k for k in reqs.get('optional', []) if not os.getenv(k)]
        if missing_optional:
            logger.info(f"[API] {tool_name} missing optional keys: {missing_optional} (tool will work with reduced functionality)")
        
        return True, []

    def get_fallback_tool(self, tool_name: str) -> Optional[str]:
        """Get alternative tool when primary tool is unavailable"""
        fallbacks = {
            'shodan': 'nmap',
            'netlas': 'nmap',
            'onyphe': 'nmap',
            'theHarvester': 'sublist3r',
            'censys': 'nmap',
        }
        return fallbacks.get(tool_name)

    def cleanup(self):
        """Close SSH connection"""
        if self.ssh_client:
            self.ssh_client.close()
            print("✅ SSH connection closed")