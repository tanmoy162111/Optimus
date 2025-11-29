"""Robust SSH-based tool execution manager with PTY support
Handles: sudo, interactive commands, real-time streaming, error recovery"""
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
        # Tool execution history for dynamic timeout adjustment
        self.tool_execution_history = {}
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
                if self.ssh_client.get_transport().is_active():
                    print("[DEBUG] Reusing existing SSH connection")
                    return self.ssh_client
            except:
                print("[DEBUG] Existing SSH connection is dead, reconnecting...")
                self.ssh_client = None
        
        # Create new connection
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Retry connection
        for attempt in range(1, self.connection_retries + 1):
            try:
                print(f"[DEBUG] SSH connection attempt {attempt}/{self.connection_retries}")
                self.ssh_client.connect(
                    hostname=Config.KALI_HOST,
                    port=Config.KALI_PORT,
                    username=Config.KALI_USER,
                    password=Config.KALI_PASSWORD,
                    key_filename=Config.KALI_KEY_PATH if Config.KALI_KEY_PATH else None,
                    timeout=self.connection_timeout,
                    look_for_keys=False,  # Disable to prevent hanging
                    allow_agent=False,    # Disable to prevent hanging
                )
                
                # Enable keepalive
                transport = self.ssh_client.get_transport()
                transport.set_keepalive(self.keepalive_interval)
                
                print("✅ SSH connection established successfully")
                return self.ssh_client
                
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
    
    def _get_tool_execution_history(self, tool_name: str) -> List[float]:
        """
        Get execution history for a tool to inform dynamic timeout adjustments
        
        Args:
            tool_name: Name of the tool
            

        Returns:
            List of execution times in seconds
        """
        return self.tool_execution_history.get(tool_name, [])
    
    def execute_tool(self, tool_name: str, target: str, parameters: Dict[str, Any],
                  scan_id: str, phase: str) -> Dict[str, Any]:
        """
        Execute pentesting tool with real-time output streaming
        """
        start_time = datetime.now()
        
        # Special handling for linpeas - should only run in post-exploitation with active session
        # But allow it to run if specifically requested in post-exploitation phase
        if tool_name in ['linpeas', 'linpeas.sh'] and phase != 'post_exploitation':
            logger.warning(f"[ToolManager] linpeas should only run in post-exploitation phase, not {phase}")
            # Check if this is a legitimate post-exploitation scenario
            # Look for indicators that we have an active session
            if 'session_id' in parameters or 'active_session' in parameters:
                logger.info("[ToolManager] linpeas execution authorized with active session")
            else:
                return {
                    'tool_name': tool_name,
                    'target': target,
                    'phase': phase,
                    'error': 'linpeas should only run in post-exploitation phase with active session',
                    'success': False
                }
        
        # Check API requirements
        has_requirements, missing_keys = self.check_tool_requirements(tool_name)
        if not has_requirements:
            logger.warning(f"[ToolManager] {tool_name} missing required API keys: {missing_keys}")
            # Try fallback tool if available
            fallback_tool = self.get_fallback_tool(tool_name)
            if fallback_tool:
                logger.info(f"[ToolManager] Using fallback tool: {fallback_tool}")
                tool_name = fallback_tool
            else:
                return {
                    'tool_name': tool_name,
                    'target': target,
                    'phase': phase,
                    'error': f'Missing required API keys: {missing_keys}',
                    'success': False
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
            if self.socketio:
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
            
            # Record execution time for dynamic timeout adjustment
            if tool_name not in self.tool_execution_history:
                self.tool_execution_history[tool_name] = []
            self.tool_execution_history[tool_name].append(execution_time)
            
            # Keep only last 10 executions to prevent memory bloat
            if len(self.tool_execution_history[tool_name]) > 10:
                self.tool_execution_history[tool_name] = self.tool_execution_history[tool_name][-10:]
            
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
            if self.socketio:
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
            if self.socketio:
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
            if not transport or not transport.is_active():
                print(f"[DEBUG] SSH connection dead, reconnecting...")
                self.connect_ssh()
                transport = self.ssh_client.get_transport()
            
            # Open channel with PTY
            channel = transport.open_session()
            
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
            
            # Set data timeout based on tool type and overall timeout
            # Some tools like nmap can legitimately have long periods between output
            # Calculate adaptive data timeout based on overall timeout
            adaptive_factor = min(3.0, max(1.0, timeout / 300.0))  # Scale factor based on overall timeout
            
            if tool_name in ['nmap', 'masscan', 'ike-scan']:
                # Network scanners can take longer between outputs
                base_data_timeout = 300  # 5 minutes base
                data_timeout = int(base_data_timeout * adaptive_factor)
                # Cap at 30 minutes for network scanners
                data_timeout = min(data_timeout, 1800)
            elif tool_name in ['linpeas', 'winpeas']:
                # Privilege escalation tools
                base_data_timeout = 180  # 3 minutes base
                data_timeout = int(base_data_timeout * adaptive_factor)
                # Cap at 15 minutes for privilege escalation tools
                data_timeout = min(data_timeout, 900)
            elif tool_name in ['nikto', 'nuclei']:
                # Web scanners can take longer between outputs
                base_data_timeout = 240  # 4 minutes base
                data_timeout = int(base_data_timeout * adaptive_factor)
                # Cap at 25 minutes for web scanners
                data_timeout = min(data_timeout, 1500)
            else:
                # Other tools
                base_data_timeout = 120  # 2 minutes base
                data_timeout = int(base_data_timeout * adaptive_factor)
                # Cap at 10 minutes for other tools
                data_timeout = min(data_timeout, 600)
            
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
                        if self.socketio:
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
                        if self.socketio:
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
                    if self.socketio:
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
        
        # Enhanced dynamic timeout calculation with learning-based adjustments
        base_timeout = parameters.get('timeout', 300)
        
        # Define timeout multipliers for different tool categories with more granularity
        timeout_multipliers = {
            # Long-running enumeration tools
            'long_enumeration': {
                'tools': ['linpeas', 'linpeas.sh', 'winpeas', 'gobuster', 'ffuf', 'cewl', 'crunch'],
                'multiplier': 3.0,  # 3x base timeout (up to 45 minutes)
                'progressive_extension': True  # Allow progressive timeout extension
            },
            # Exploitation frameworks that can take significant time
            'exploitation_frameworks': {
                'tools': ['metasploit', 'burpsuite'],
                'multiplier': 5.0,  # 5x base timeout (up to 75 minutes) - increased for Metasploit
                'progressive_extension': True
            },
            # Network scanning tools
            'network_scanners': {
                'tools': ['nmap', 'masscan', 'ike-scan'],
                'multiplier': 3.0,  # 3x base timeout (up to 45 minutes) - increased for nMap
                'progressive_extension': True
            },
            # Web application scanners
            'web_scanners': {
                'tools': ['nikto', 'nuclei', 'wpscan', 'sqlmap'],
                'multiplier': 3.5,  # 3.5x base timeout (up to 52.5 minutes) - increased for Nikto
                'progressive_extension': True
            },
            # Brute force tools
            'brute_force': {
                'tools': ['hydra', 'medusa', 'john', 'hashcat'],
                'multiplier': 4.0,  # 4x base timeout (up to 60 minutes)
                'progressive_extension': True
            }
        }
        
        # Determine appropriate timeout multiplier based on tool category
        multiplier = 1.0
        tool_category = None
        progressive_extension = False
        
        for category, config in timeout_multipliers.items():
            if tool_name in config['tools']:
                tool_category = category
                multiplier = config['multiplier']
                progressive_extension = config.get('progressive_extension', False)
                break
        
        # Adjust timeout based on scan context
        context_adjustment = 1.0
        if parameters.get('aggressive', False):
            context_adjustment = 1.5  # Increase timeout for aggressive scans
        if parameters.get('stealth_required', False):
            context_adjustment = 2.0  # Double timeout for stealth mode
        if parameters.get('phase') == 'post_exploitation':
            context_adjustment = 1.5  # Increase timeout for post-exploitation
        
        # Progressive timeout extension for tools that may need more time
        if progressive_extension:
            # Check if this tool has been executed before and how long it took
            execution_history = self._get_tool_execution_history(tool_name)
            if execution_history:
                avg_execution_time = sum(execution_history) / len(execution_history)
                # If average execution time is close to current timeout, increase it
                if avg_execution_time > (base_timeout * multiplier * context_adjustment * 0.8):
                    context_adjustment *= 1.5  # Increase by 50%
        
        # Additional context-based adjustments
        time_remaining = context.get('time_remaining', 1.0)
        coverage = context.get('coverage', 0.0)
        
        # If we're running low on time, give more time to tools likely to find vulnerabilities
        if time_remaining < 0.3 and coverage < 0.7:  # Less than 30% time remaining and low coverage
            if tool_category in ['exploitation_frameworks', 'web_scanners']:
                context_adjustment *= 1.3  # Give more time to exploitation tools
        
        # If we have high coverage, reduce timeout for exploratory tools
        if coverage > 0.8:
            if tool_category in ['long_enumeration', 'network_scanners']:
                context_adjustment *= 0.7  # Reduce time for exploratory tools when we have enough coverage
        
        # Calculate final timeout
        calculated_timeout = int(base_timeout * multiplier * context_adjustment)
        
        # Ensure reasonable bounds (minimum 5 minutes, maximum 180 minutes for long-running tools)
        max_timeout = 10800 if progressive_extension else 7200  # 180 mins vs 120 mins
        final_timeout = max(300, min(calculated_timeout, max_timeout))
        
        # Update parameters with calculated timeout
        parameters['timeout'] = final_timeout
        
        if multiplier > 1.0 or context_adjustment > 1.0:
            print(f"[DEBUG] Dynamic timeout for {tool_name} ({tool_category}): {final_timeout}s (base: {base_timeout}s, mult: {multiplier}x, context: {context_adjustment}x, progressive: {progressive_extension})")
        
        # Use Knowledge Base for adaptive command generation
        try:
            command_target = hostname if tool_name in ['nmap', 'nikto', 'fierce', 'enum4linux', 'sslscan'] else target
            
            # NEW: Use adaptive command building
            findings = parameters.get('findings', [])
            command = self.tool_kb.build_adaptive_command(
                tool_name, 
                command_target, 
                context,
                findings
            )
            
            logger.info(f"[ToolManager] Adaptive command: {command[:150]}")
        except Exception as e:
            logger.error(f"[ToolManager] Command generation failed: {e}, using fallback")
            command = self._fallback_command(tool_name, target)
        
        # TEMPORARILY DISABLE timeout wrapper for debugging
        # Add timeout wrapper for non-linpeas tools
        # if tool_name != 'linpeas':  # linpeas handles its own timeout internally
        #     timeout = parameters.get('timeout', 300)
        #     command = f"timeout {timeout} {command}"
        
        return command

    def _fallback_command(self, tool_name: str, target: str) -> str:
        """Fallback commands if Knowledge Base fails"""
        # Map tool names to available tools on Kali VM
        tool_mapping = {
            'sublist3r': 'amass',  # Use amass instead of sublist3r
            'theHarvester': 'dnsenum',  # Use dnsenum as alternative
            'linpeas.sh': 'linpeas',  # Normalize name
        }
        
        # Use the mapped tool if available
        actual_tool = tool_mapping.get(tool_name, tool_name)
        
        fallback_commands = {
            'nmap': f"nmap -sV -T4 {target}",
            'nikto': f"nikto -h {target}",
            'sqlmap': f"sqlmap -u '{target}' --batch",
            'amass': f"amass enum -d {target}",  # Updated for amass
            'dnsenum': f"dnsenum {target}",  # Updated for dnsenum
            'whatweb': f"whatweb {target}",
            'nuclei': f"nuclei -u {target} -severity critical,high",
            'dalfox': f"dalfox url {target}",
            'commix': f"commix --url='{target}' --batch",
            'gobuster': f"gobuster dir -u {target} -w /usr/share/dirb/wordlists/common.txt",
            'ffuf': f"ffuf -u {target}/FUZZ -w /usr/share/dirb/wordlists/common.txt:FUZZ",
            'fierce': f"fierce --domain {target}",
            'wpscan': f"wpscan --url {target}",
            'hydra': f"hydra {target}",
            'linpeas': f"/usr/share/peass/linpeas/linpeas.sh",  # Full path for linpeas
            'winpeas': f"/usr/share/peass/winpeas/winpeas.exe",  # Full path for winpeas
            'metasploit': f"msfconsole -q -x \"use auxiliary/scanner/portscan/tcp; set RHOSTS {target}; run; exit\"",
            'enum4linux': f"enum4linux {target}",
            'sslscan': f"sslscan {target}",
            'cewl': f"cewl {target}",
        }
        
        # Special handling for linpeas - it's a local tool, not a remote scanner
        if actual_tool in ['linpeas', 'linpeas.sh']:
            logger.warning(f"[ToolManager] linpeas is a LOCAL privilege escalation tool and should only be run on COMPROMISED targets, not {target}")
            logger.warning("[ToolManager] linpeas should be executed AFTER gaining access to a target system")
            
        return fallback_commands.get(actual_tool, f"{actual_tool} {target}")

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
        
        # Add timeout parameters to prevent hanging and handle retransmissions
        base += " --host-timeout 45m"     # Increased host timeout
        base += " --max-retries 5"        # Increased retries to handle retransmissions
        base += " --min-rate 150"         # Reduced minimum packet rate for stability
        base += " --max-rate 3000"        # Reduced maximum packet rate to avoid overwhelming
        base += " --scan-delay 100ms"     # Increased scan delay to avoid network congestion
        base += " --max-scan-delay 1s"    # Maximum scan delay
        base += " --defeat-rst-ratelimit" # Defeat reset rate limiting
        base += " --disable-arp-ping"     # Disable ARP ping for remote targets
        
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
            'wpscan': {
                'optional': ['WPVULNDB_API_KEY'],  # For better vulnerability detection
                'required': []
            }
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
            'theHarvester': 'dnsenum',  # Updated to dnsenum
            'sublist3r': 'amass',  # Updated to amass
            'censys': 'nmap',
            'linpeas.sh': 'linpeas',  # Normalize name
        }
        return fallbacks.get(tool_name)

    def cleanup(self):
        """Close SSH connection"""
        if self.ssh_client:
            self.ssh_client.close()
            print("✅ SSH connection closed")