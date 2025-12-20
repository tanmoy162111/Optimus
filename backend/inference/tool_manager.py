"""Enhanced Tool Manager with Hybrid Intelligence and Real-time Streaming
Supports 50+ pentesting tools with dynamic command generation
"""

import logging
import re
import time
import paramiko
import socket
from datetime import datetime
from typing import Dict, Any, List, Optional
import subprocess

# Set up logger first
logger = logging.getLogger(__name__)

# Import the output parser
# Try enhanced parser first, fall back to basic
try:
    from .enhanced_output_parser import EnhancedOutputParser
    logger.info("[ToolManager] Using EnhancedOutputParser")
except ImportError:
    from .output_parser import OutputParser
    logger.info("[ToolManager] Using basic OutputParser")

from .tool_knowledge_base import ToolKnowledgeBase
# Import Config from the backend root
from config import Config

# Try to import hybrid tool system - FIXED IMPORT PATH
HYBRID_SYSTEM_AVAILABLE = False
ResolutionStatus = None  # Will be set if import succeeds
ToolSource = None  # Will be set if import succeeds
try:
    from tools.hybrid_tool_system import (
        get_hybrid_tool_system,
        ResolutionStatus as _ResolutionStatus,
        ToolSource as _ToolSource
    )
    ResolutionStatus = _ResolutionStatus
    ToolSource = _ToolSource
    HYBRID_SYSTEM_AVAILABLE = True
    print(" Hybrid tool system available")
except ImportError as e:
    print(f" Warning: Hybrid tool system not available: {e}")


class ToolManager:
    def __init__(self, socketio):
        self.socketio = socketio
        self.ssh_client = None
        self.current_execution = None
        self.output_buffer = []
        self.connection_retries = Config.KALI_CONNECT_RETRIES  # Updated to use config
        self.connection_timeout = Config.KALI_CONNECT_TIMEOUT   # Updated to use config
        self.keepalive_interval = Config.KALI_KEEPALIVE_SECONDS  # Updated to use config
        # Initialize the tool knowledge base
        self.tool_kb = ToolKnowledgeBase()
        # Tool execution history for dynamic timeout adjustment
        self.tool_execution_history = {}
        # Initialize the output parser
        # Try enhanced parser first, fall back to basic
        try:
            from .enhanced_output_parser import EnhancedOutputParser
            self.output_parser = EnhancedOutputParser(llm_client=None)
            logger.info("[ToolManager] Using EnhancedOutputParser")
        except ImportError:
            from .output_parser import OutputParser
            self.output_parser = OutputParser()
            logger.info("[ToolManager] Using basic OutputParser")
        
        # Try to initialize hybrid tool system
        self.hybrid_system = None
        if HYBRID_SYSTEM_AVAILABLE:
            try:
                self.hybrid_system = get_hybrid_tool_system()
                logger.info("[ToolManager] Hybrid tool system initialized")
            except Exception as e:
                logger.warning(f"[ToolManager] Failed to initialize hybrid tool system: {e}")
        
        logger.info("[ToolManager] Initialized with dynamic command generation")
    
    def connect_ssh(self) -> paramiko.SSHClient:
        """
        Establish SSH connection with robust retry logic and keepalive
        
        Returns:
            paramiko.SSHClient: Connected SSH client
        """
        print(f"\n{'='*60}")
        print(f"[SSH] Connecting to Kali VM: {Config.KALI_HOST}:{Config.KALI_PORT}")
        print(f"[SSH] User: {Config.KALI_USER}, Timeout: {self.connection_timeout}s, Retries: {self.connection_retries}")
        print(f"{'='*60}")
        
        # If already connected and alive, reuse it
        if self.ssh_client is not None:
            try:
                # Check if transport exists and is active
                transport = self.ssh_client.get_transport()
                if transport is not None and transport.is_active():
                    print("[SSH] Reusing existing SSH connection")
                    return self.ssh_client
            except Exception as e:
                print(f"[SSH] Error checking existing SSH connection: {e}")
                print("[SSH] Existing SSH connection is dead, reconnecting...")
                self.ssh_client = None
        
        # Create new connection
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Retry connection
        for attempt in range(1, self.connection_retries + 1):
            try:
                print(f"[SSH] Connection attempt {attempt}/{self.connection_retries}...")
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
                if transport is not None:
                    transport.set_keepalive(self.keepalive_interval)
                
                print(f"[SSH]  Connection established successfully!")
                
                # Update hybrid tool system with the new SSH client if available
                if self.hybrid_system:
                    try:
                        self.hybrid_system.update_ssh_client(self.ssh_client)
                        print("[SSH] Updated hybrid tool system with new SSH client")
                    except Exception as e:
                        print(f"[SSH] Warning: Failed to update hybrid tool system with SSH client: {e}")
                
                return self.ssh_client
                
            except socket.timeout as e:
                print(f"[SSH]  Connection TIMEOUT (attempt {attempt}/{self.connection_retries})")
                if attempt < self.connection_retries:
                    wait_time = 2 * attempt  # Reduced wait time
                    print(f"[SSH] Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    print(f"[SSH]  Connection FAILED after {self.connection_retries} attempts")
                    raise Exception(f"SSH connection timeout: {e}")
                    
            except Exception as e:
                print(f"[SSH]  Connection ERROR (attempt {attempt}/{self.connection_retries}): {e}")
                if attempt < self.connection_retries:
                    wait_time = 2 * attempt  # Reduced wait time
                    print(f"[SSH] Retrying in {wait_time} seconds...")
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
        
        # CRITICAL SAFETY: linpeas/winpeas are LOCAL privilege escalation tools
        # They should ONLY run on COMPROMISED REMOTE targets, NEVER on the scanning system
        post_exploitation_tools = ['linpeas', 'linpeas.sh', 'winpeas', 'winpeas.exe', 'mimikatz', 'lazagne']
        
        if tool_name in post_exploitation_tools:
            # Block execution unless we have verified remote access
            has_active_session = parameters.get('session_id') or parameters.get('active_session')
            shells_obtained = parameters.get('shells_obtained', 0)
            
            if phase != 'post_exploitation':
                logger.error(f"[ToolManager] BLOCKED: {tool_name} requires post_exploitation phase, not {phase}")
                return {
                    'tool_name': tool_name,
                    'target': target,
                    'phase': phase,
                    'error': f'{tool_name} blocked - requires post_exploitation phase with active shell',
                    'success': False
                }
            
            if not has_active_session and shells_obtained == 0:
                logger.error(f"[ToolManager] BLOCKED: {tool_name} requires active session on remote target")
                logger.error(f"[ToolManager] These tools run on COMPROMISED systems, not the scanner!")
                return {
                    'tool_name': tool_name,
                    'target': target,
                    'phase': phase,
                    'error': f'{tool_name} blocked - requires confirmed shell access to remote target',
                    'success': False
                }
            
            # Also check target is not local
            local_indicators = ['127.0.0.1', 'localhost', '0.0.0.0', '::1']
            if any(ind in target.lower() for ind in local_indicators):
                logger.error(f"[ToolManager] BLOCKED: Cannot run {tool_name} on local system!")
                return {
                    'tool_name': tool_name,
                    'target': target,
                    'phase': phase,
                    'error': f'{tool_name} blocked - cannot run on local/scanning system',
                    'success': False
                }
            
            logger.info(f"[ToolManager] {tool_name} authorized for remote target with active session")
        
        # Try to resolve tool using hybrid system first
        resolved_command = None
        if self.hybrid_system:
            try:
                task_description = f"Execute {tool_name} during {phase} phase"
                resolution = self.hybrid_system.resolve_tool(
                    tool_name=tool_name,
                    task=task_description,
                    target=target,
                    context={
                        'phase': phase,
                        'parameters': parameters,
                        'scan_id': scan_id
                    }
                )
                
                # If resolution was successful, use the generated command
                # Check both enum and string values for compatibility
                status_resolved = (
                    (ResolutionStatus and resolution.status in [ResolutionStatus.RESOLVED, ResolutionStatus.PARTIAL]) or
                    (hasattr(resolution.status, 'value') and resolution.status.value in ['resolved', 'partial']) or
                    (str(resolution.status).lower() in ['resolved', 'partial', 'resolutionstatus.resolved', 'resolutionstatus.partial'])
                )
                if status_resolved:
                    resolved_command = resolution.command
                    logger.info(f"Using hybrid system resolved command for {tool_name}: {resolved_command}")
                    
                    # Stream resolution info to frontend
                    if self.socketio:
                        self.socketio.emit('tool_resolution', {
                            'scan_id': scan_id,
                            'tool': tool_name,
                            'source': resolution.source.value if hasattr(resolution.source, 'value') else str(resolution.source),
                            'confidence': resolution.confidence,
                            'status': resolution.status.value if hasattr(resolution.status, 'value') else str(resolution.status),
                            'explanation': resolution.explanation
                        })
                else:
                    logger.warning(f"Hybrid system failed to resolve {tool_name}, falling back to original")
            except Exception as e:
                logger.error(f"Hybrid system resolution failed: {e}")
        
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
                    transport_active = False
                    if self.ssh_client is not None:
                        try:
                            transport = self.ssh_client.get_transport()
                            if transport is not None:
                                transport_active = transport.is_active()
                        except Exception as e:
                            print(f"[DEBUG] Error checking transport status: {e}")
                            transport_active = False
                    
                    if not self.ssh_client or not transport_active:
                        print(f"[DEBUG] Establishing SSH connection (attempt {connection_attempt}/{max_connection_retries})")
                        self.ssh_client = self.connect_ssh()
                    break  # Success, exit retry loop
                    
                except Exception as conn_error:
                    print(f" SSH connection failed (attempt {connection_attempt}/{max_connection_retries}): {conn_error}")
                    if connection_attempt < max_connection_retries:
                        wait_time = 5 * connection_attempt
                        print(f"   Retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                    else:
                        # Final failure
                        raise Exception(f"Failed to connect to Kali VM after {max_connection_retries} attempts: {conn_error}")
            
            # Build command - use resolved command if available
            if resolved_command:
                command = resolved_command
            else:
                command = self.build_command(tool_name, target, parameters)
            
            # Notify frontend
            if self.socketio:
                self.socketio.emit('tool_execution_start', {
                    'scan_id': scan_id,
                    'tool': tool_name,
                    'phase': phase,
                    'command': command[:200],  # Truncate for safety
                    'timestamp': start_time.isoformat()
                }, room=f'scan_{scan_id}')
            
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
            
            # Parse output
            parsed_results = self.output_parser.parse_tool_output(tool_name, stdout, stderr)
            
            # DEBUG: Log raw output for analysis
            print(f"\n{'='*60}")
            print(f"[DEBUG] TOOL OUTPUT ANALYSIS FOR: {tool_name}")
            print(f"{'='*60}")
            print(f"[DEBUG] Exit Code: {exit_code}")
            print(f"[DEBUG] STDOUT Length: {len(stdout)} chars")
            print(f"[DEBUG] STDERR Length: {len(stderr)} chars")
            
            if stdout:
                print(f"[DEBUG] STDOUT (first 2000 chars):")
                print(stdout[:2000])
            else:
                print(f"[DEBUG] STDOUT: EMPTY!")
                
            if stderr:
                print(f"[DEBUG] STDERR (first 1000 chars):")
                print(stderr[:1000])
            
            print(f"[DEBUG] Parsed Results: {parsed_results}")
            print(f"[DEBUG] Vulnerabilities Found: {len(parsed_results.get('vulnerabilities', []))}")
            print(f"{'='*60}\n")
            
            # Count findings
            findings_count = len(parsed_results.get('vulnerabilities', []))
            
            # Record execution result for learning (if hybrid system available)
            if self.hybrid_system:
                try:
                    self.hybrid_system.record_execution_result(
                        tool_name=tool_name,
                        command=command,
                        success=(exit_code == 0 or findings_count > 0),  # FIX: Use corrected success logic
                        output=stdout,
                        findings=parsed_results.get('vulnerabilities', [])
                    )
                except Exception as e:
                    logger.warning(f"Failed to record execution result: {e}")
            
            # Notify completion
            if self.socketio:
                self.socketio.emit('tool_execution_complete', {
                    'scan_id': scan_id,
                    'tool': tool_name,
                    'phase': phase,
                    'exit_code': exit_code,
                    'findings_count': findings_count,
                    'execution_time': execution_time,
                    'success': (exit_code == 0 or findings_count > 0)  # FIX #1: Success if found findings
                }, room=f'scan_{scan_id}')
            
            return {
                'tool_name': tool_name,
                'target': target,
                'phase': phase,
                'command': command,
                'exit_code': exit_code,
                'stdout': stdout,
                'stderr': stderr,
                'parsed_results': parsed_results,
                'findings_count': findings_count,
                'execution_time': execution_time,
                'success': (exit_code == 0 or findings_count > 0)  # FIX #1: Success if found findings
            }
            
        except Exception as e:
            logger.error(f"Tool execution failed: {e}")
            import traceback
            traceback.print_exc()
            
            # Notify error
            if self.socketio:
                self.socketio.emit('tool_execution_error', {
                    'scan_id': scan_id,
                    'tool': tool_name,
                    'phase': phase,
                    'error': str(e)
                }, room=f'scan_{scan_id}')
            
            return {
                'tool_name': tool_name,
                'target': target,
                'phase': phase,
                'error': str(e),
                'success': False
            }
    
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
            
            # Check if command requires sudo and modify it to auto-provide password
            if command.strip().startswith('sudo ') or ' sudo ' in command:
                # Modify command to automatically provide password using expect
                wrapped_command = f"python3 -c \"import pty; import subprocess; import sys; pty.spawn(['bash', '-c', 'echo kali | sudo -S {command.replace('\"', '\\\"')}'])\""
                print(f"[DEBUG] Wrapped sudo command: {wrapped_command[:200]}...")
                command = wrapped_command
            
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
                            }, room=f'scan_{scan_id}')
                        
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
                            }, room=f'scan_{scan_id}')
                
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
            print(f" Socket timeout during command execution: {e}")
            return -1, '', f'Socket timeout: {e}'
            
        except Exception as e:
            print(f" Error during command execution: {e}")
            import traceback
            traceback.print_exc()
            return -1, '', f'Execution error: {e}'
    
    def build_command(self, tool_name: str, target: str,
                  parameters: Dict[str, Any]) -> str:
        """
        Build tool command using multiple resolution strategies.
        
        Priority:
        1. HybridToolSystem (LLM + memory + discovery)
        2. ToolKnowledgeBase (expert rules)
        3. Default fallback commands
        """
        # Normalize target
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        import re
        hostname_match = re.search(r'(?:https?://)?([^:/]+)', target)
        hostname = hostname_match.group(1) if hostname_match else target
        
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
        
        command = None
        resolution_source = 'unknown'
        
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
        
        # TIER 1: Try HybridToolSystem
        if self.hybrid_system:
            try:
                resolution = self.hybrid_system.resolve_tool(tool_name, target, context)
                if resolution and resolution.status.value == 'resolved':
                    command = resolution.command
                    resolution_source = f'hybrid_{resolution.source.value}'
                    logger.info(f"[ToolManager] Hybrid resolution: {resolution_source}")
            except Exception as e:
                logger.warning(f"Hybrid tool resolution failed: {e}")
        
        # TIER 2: Try ToolKnowledgeBase
        if not command:
            try:
                command_target = hostname if tool_name in ['nmap', 'nikto', 'fierce', 'enum4linux', 'sslscan'] else target
                command = self.tool_kb.build_command(tool_name, command_target, context)
                if command:
                    resolution_source = 'knowledge_base'
                    logger.info(f"[ToolManager] KB resolution for {tool_name}")
            except Exception as e:
                logger.warning(f"KB command generation failed: {e}")
        
        # TIER 3: Default fallback
        if not command:
            command = self._build_default_command(tool_name, target, parameters)
            resolution_source = 'default_fallback'
        
        # Record resolution for learning
        if self.hybrid_system:
            try:
                self.hybrid_system.record_resolution(tool_name, resolution_source, command)
            except:
                pass
        
        # At the end, before returning, substitute all parameters
        if command:
            command = self._substitute_parameters(command, target, parameters)
        
        print(f"[ToolManager] Command ({resolution_source}): {command[:100]}...")
        return command
    def _build_default_command(self, tool_name: str, target: str,
                             parameters: Dict[str, Any]) -> str:
        """Fallback command building with IMPROVED commands for web app testing"""
        import re
        
        # Map tool names to available tools on Kali VM
        tool_mapping = {
            'sublist3r': 'amass',
            'theHarvester': 'dnsenum',
            'linpeas.sh': 'linpeas',
        }
        
        # Use the mapped tool if available
        actual_tool = tool_mapping.get(tool_name, tool_name)
        
        # Extract hostname/port from target
        hostname_match = re.search(r'(?:https?://)?([^:/]+)(?::(\d+))?', target)
        hostname = hostname_match.group(1) if hostname_match else target
        port = hostname_match.group(2) if hostname_match and hostname_match.group(2) else '80'
        
        # Ensure target has proper format
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        # Tool paths
        tool_paths = {
            'nmap': 'nmap',
            'nikto': 'nikto',
            'sqlmap': 'sqlmap',
            'amass': 'amass',
            'dnsenum': 'dnsenum',
            'whatweb': 'whatweb',
            'nuclei': 'nuclei',
            'dalfox': '/home/kali/go/bin/dalfox',
            'commix': 'commix',
            'gobuster': 'gobuster',
            'ffuf': 'ffuf',
            'fierce': 'fierce',
            'wpscan': 'wpscan',
            'hydra': 'hydra',
        }
        
        tool_path = tool_paths.get(actual_tool, actual_tool)
        
        # IMPROVED commands optimized for web application testing
        fallback_commands = {
            # Nmap: More thorough scan for web apps
            'nmap': f"{tool_path} -sV -sC -T4 -p 80,443,3000,8080,8443 --script=http-enum,http-headers,http-methods,http-title {hostname}",
            
            # Nikto: Comprehensive web scanner
            'nikto': f"{tool_path} -h {target} -C all -Tuning 123bde -timeout 10",
            
            # SQLMap: Need to specify testable endpoints
            # For Juice Shop, test the login endpoint
            'sqlmap': f"{tool_path} -u '{target}/rest/products/search?q=test' --batch --level=2 --risk=2 --forms --crawl=2 --timeout=30",
            
            # Nuclei: Comprehensive templates
            'nuclei': f"{tool_path} -u {target} -t cves/ -t vulnerabilities/ -t exposures/ -t misconfiguration/ -severity critical,high,medium -timeout 30",
            
            # Dalfox: XSS scanner with crawling
            'dalfox': f"{tool_path} url {target} --deep-domxss --mining-dict --skip-bav",
            
            # Commix: Command injection with form testing
            'commix': f"{tool_path} --url='{target}' --batch --level=2 --crawl=2",
            
            # Gobuster: Directory enumeration with more extensions
            'gobuster': f"{tool_path} dir -u {target} -w /usr/share/wordlists/dirb/common.txt -x js,json,php,html,txt,bak -t 50 -q",
            
            # FFUF: Fuzzing with better wordlist
            'ffuf': f"{tool_path} -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,401,403 -t 50",
            
            # Whatweb: Technology detection
            'whatweb': f"{tool_path} -a 3 {target}",
            
            # Amass: Subdomain enumeration (for domain targets)
            'amass': f"{tool_path} enum -passive -d {hostname}",
            
            # DNSenum
            'dnsenum': f"{tool_path} {hostname}",
            
            # Fierce
            'fierce': f"{tool_path} --domain {hostname}",
            
            # WPScan (if WordPress detected)
            'wpscan': f"{tool_path} --url {target} --enumerate vp,vt,u --api-token $WPSCAN_API_TOKEN",
            
            # SSLScan
            'sslscan': f"{tool_path} {hostname}:{port}",
        }
        
        command = fallback_commands.get(actual_tool, f"{tool_path} {target}")
        
        print(f"[DEBUG] Generated command for {actual_tool}: {command}")
        return command

    def _fallback_command(self, tool_name: str, target: str) -> str:
        """Fallback commands if Knowledge Base fails"""
        # Map tool names to available tools on Kali VM
        tool_mapping = {
            'sublist3r': 'amass',  # Use amass instead of sublist3r
            'theHarvester': 'dnsenum',  # Use dnsenum as alternative
            'linpeas.sh': 'linpeas',  # Normalize name
            # Map missing tools to available alternatives
            'nuclei': 'nikto',  # Use nikto as alternative to nuclei
            'gospider': 'whatweb',  # Use whatweb as alternative to gospider
            'katana': 'whatweb',  # Use whatweb as alternative to katana
            'httprobe': 'whatweb',  # Use whatweb as alternative to httprobe
            'netlas': 'nmap',  # Use nmap as alternative to netlas
            'onyphe': 'nmap',  # Use nmap as alternative to onyphe
            'xsser': 'dalfox',  # Use dalfox as alternative to xsser
        }
        
        # Use the mapped tool if available
        actual_tool = tool_mapping.get(tool_name, tool_name)
        
        # Check if tool exists in standard locations or Go bin directories
        tool_paths = {
            'nmap': 'nmap',
            'nikto': 'nikto',
            'sqlmap': 'sqlmap',
            'amass': 'amass',
            'dnsenum': 'dnsenum',
            'whatweb': 'whatweb',
            'nuclei': 'nuclei',
            'dalfox': '/home/kali/go/bin/dalfox',  # Explicitly use Go bin path
            'commix': 'commix',
            'gobuster': 'gobuster',
            'ffuf': 'ffuf',
            'fierce': 'fierce',
            'wpscan': 'wpscan',
            'hydra': 'hydra',
            'linpeas': '/usr/share/peass/linpeas/linpeas.sh',
            'winpeas': '/usr/share/peass/winpeas/winpeas.exe',
            'metasploit': 'msfconsole',
            'enum4linux': 'enum4linux',
            'sslscan': 'sslscan',
            'cewl': 'cewl',
            'subfinder': '/home/kali/go/bin/subfinder',  # Explicitly use Go bin path
            'gospider': 'whatweb',  # Use whatweb as fallback
            'katana': 'whatweb',  # Use whatweb as fallback
            'arjun': '/home/kali/.local/bin/arjun',  # Explicitly use local bin path
            'httprobe': 'whatweb',  # Use whatweb as fallback
            'netlas': 'nmap',  # Use nmap as fallback
            'onyphe': 'nmap',  # Use nmap as fallback
            'xsser': 'dalfox',  # Use dalfox as fallback
        }
        
        # Get the appropriate path for the tool
        tool_path = tool_paths.get(actual_tool, actual_tool)
        
        fallback_commands = {
            'nmap': f"{tool_path} -sV -T4 {target}",
            'nikto': f"{tool_path} -h {target}",
            'sqlmap': f"{tool_path} -u '{target}' --batch",
            'amass': f"{tool_path} enum -d {target}",
            'dnsenum': f"{tool_path} {target}",
            'whatweb': f"{tool_path} {target}",
            'nuclei': f"{tool_path} -u {target} -severity critical,high",
            'dalfox': f"{tool_path} url {target}",
            'commix': f"{tool_path} --url='{target}' --batch",
            'gobuster': f"{tool_path} dir -u {target} -w /usr/share/dirb/wordlists/common.txt",
            'ffuf': f"{tool_path} -u {target}/FUZZ -w /usr/share/dirb/wordlists/common.txt:FUZZ",
            'fierce': f"{tool_path} --domain {target}",
            'wpscan': f"{tool_path} --url {target}",
            'hydra': f"{tool_path} {target}",
            'linpeas': f"{tool_path}",
            'winpeas': f"{tool_path}",
            'metasploit': f"{tool_path} -q -x \"use auxiliary/scanner/portscan/tcp; set RHOSTS {target}; run; exit\"",
            'enum4linux': f"{tool_path} {target}",
            'sslscan': f"{tool_path} {target}",
            'cewl': f"{tool_path} {target}",
        }
        
        # Special handling for linpeas - it's a local tool, not a remote scanner
        if actual_tool in ['linpeas', 'linpeas.sh']:
            logger.warning(f"[ToolManager] linpeas is a LOCAL privilege escalation tool and should only be run on COMPROMISED targets, not {target}")
            logger.warning("[ToolManager] linpeas should be executed AFTER gaining access to a target system")
        
        # Get the command, fallback to just the tool path and target
        command = fallback_commands.get(actual_tool, f"{tool_path} {target}")
        return command

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
            # Additional fallbacks for missing tools
            'nuclei': 'nikto',
            'gospider': 'whatweb',
            'katana': 'whatweb',
            'httprobe': 'whatweb',
            'xsser': 'dalfox',
        }
        return fallbacks.get(tool_name)

    def _substitute_parameters(self, command: str, target: str, parameters: Dict[str, Any]) -> str:
        """
        Substitute all placeholders in a command with actual values.
        Handles: {target}, {host}, {domain}, {url}, {port}, {ip}, etc.
        """
        import re
        
        # Normalize target
        if not target.startswith(('http://', 'https://')):
            url_target = f"http://{target}"
        else:
            url_target = target
        
        # Extract components from target
        hostname_match = re.search(r'(?:https?://)?([^:/]+)', target)
        hostname = hostname_match.group(1) if hostname_match else target
        
        # Extract port if present
        port_match = re.search(r':(\d+)', target)
        port = port_match.group(1) if port_match else '80'
        
        # Extract domain (for DNS tools)
        domain = hostname
        
        # Extract IP if target is an IP
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        is_ip = re.match(ip_pattern, hostname)
        ip = hostname if is_ip else hostname  # Use hostname as fallback
        
        # Define all substitutions
        substitutions = {
            '{target}': target,
            '{TARGET}': target,
            '{host}': hostname,
            '{HOST}': hostname,
            '{hostname}': hostname,
            '{HOSTNAME}': hostname,
            '{domain}': domain,
            '{DOMAIN}': domain,
            '{url}': url_target,
            '{URL}': url_target,
            '{port}': port,
            '{PORT}': port,
            '{ip}': ip,
            '{IP}': ip,
            '{RHOSTS}': hostname,
            '{RHOST}': hostname,
            '{specific_port}': parameters.get('port', port),
        }
        
        # Apply substitutions
        result = command
        for placeholder, value in substitutions.items():
            result = result.replace(placeholder, str(value))
        
        # Handle any remaining placeholders with a warning
        remaining = re.findall(r'\{[^}]+\}', result)
        if remaining:
            logger.warning(f"[ToolManager] Unsubstituted placeholders in command: {remaining}")
            # Replace remaining placeholders with empty string or sensible default
            for placeholder in remaining:
                result = result.replace(placeholder, '')
        
        return result.strip()

    def cleanup(self):
        """Close SSH connection"""
        if self.ssh_client:
            self.ssh_client.close()
            print(" SSH connection closed")