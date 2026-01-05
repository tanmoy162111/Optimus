"""
Fixed SSH Client with proper timeout handling for long-running tools
"""
import paramiko
import time
import logging
from typing import Dict, Any, Callable, Optional
from ..config import Config

logger = logging.getLogger(__name__)

class KaliSSHClient:
    """SSH client for executing pentesting tools on Kali VM"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or Config.KALI_VM
        self.client = None
        self.connected = False
        
    def connect(self) -> bool:
        """Establish SSH connection to Kali VM"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            retries = int(self.config.get('connect_retries', 3))
            timeout = int(self.config.get('connect_timeout', 60))  # INCREASED
            last_err = None

            for attempt in range(1, retries + 1):
                try:
                    logger.info(f"Connecting to {self.config['host']} (attempt {attempt}/{retries})...")
                    
                    if self.config.get('key_path'):
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
                        self.client.connect(
                            hostname=self.config['host'],
                            port=self.config['port'],
                            username=self.config['username'],
                            password=self.config['password'],
                            timeout=timeout,
                            allow_agent=False,
                            look_for_keys=False
                        )

                    # Enable keepalive
                    transport = self.client.get_transport()
                    if transport:
                        keepalive = int(self.config.get('keepalive_seconds', 30))
                        transport.set_keepalive(keepalive)

                    self.connected = True
                    logger.info(f"Successfully connected to Kali VM")
                    return True
                    
                except Exception as e:
                    last_err = e
                    logger.warning(f"SSH connect attempt {attempt}/{retries} failed: {e}")
                    if attempt < retries:
                        time.sleep(2 * attempt)

            logger.error(f"Failed to connect after {retries} attempts: {last_err}")
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
        timeout: int = 600,  # INCREASED DEFAULT to 10 minutes
        output_callback: Optional[Callable[[str], None]] = None
    ) -> Dict[str, Any]:
        """
        Execute command with PROPER timeout for long-running scans
        
        CRITICAL: Many pentesting tools take 5-15 minutes to complete
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
            logger.info(f"Executing: {command[:100]}...")
            start_time = time.time()
            
            # Execute command with PTY
            stdin, stdout, stderr = self.client.exec_command(
                command,
                timeout=timeout,
                get_pty=True
            )
            
            # Stream output
            stdout_lines = []
            stderr_lines = []
            
            # FIXED: Better non-blocking I/O with longer data timeout
            stdout.channel.setblocking(0)
            stderr.channel.setblocking(0)
            
            last_data_time = time.time()
            data_timeout = 300  # 5 minutes without data = timeout
            
            while True:
                # Check overall timeout
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    logger.warning(f"⏰ Command timeout after {timeout}s")
                    break
                
                # Check if command finished
                if stdout.channel.exit_status_ready():
                    break
                
                # Check data timeout (no output for 5 minutes = stalled)
                if time.time() - last_data_time > data_timeout:
                    logger.warning(f"⏰ No data for {data_timeout}s, assuming stalled")
                    break
                
                # Read stdout
                if stdout.channel.recv_ready():
                    chunk = stdout.channel.recv(4096).decode('utf-8', errors='ignore')
                    if chunk:
                        stdout_lines.append(chunk)
                        last_data_time = time.time()
                        
                        if output_callback:
                            output_callback(chunk)
                        
                        # Print progress indicator
                        if len(stdout_lines) % 10 == 0:
                            logger.info(f"📊 Received {len(stdout_lines)} output chunks...")
                
                # Read stderr
                if stderr.channel.recv_ready():
                    chunk = stderr.channel.recv(4096).decode('utf-8', errors='ignore')
                    if chunk:
                        stderr_lines.append(chunk)
                        last_data_time = time.time()
                
                time.sleep(0.5)  # Increased from 0.1 to reduce CPU usage
            
            # Get remaining output
            while stdout.channel.recv_ready():
                chunk = stdout.channel.recv(4096).decode('utf-8', errors='ignore')
                if chunk:
                    stdout_lines.append(chunk)
            
            while stderr.channel.recv_ready():
                chunk = stderr.channel.recv(4096).decode('utf-8', errors='ignore')
                if chunk:
                    stderr_lines.append(chunk)
            
            exit_code = stdout.channel.recv_exit_status()
            execution_time = time.time() - start_time
            
            stdout_str = ''.join(stdout_lines)
            stderr_str = ''.join(stderr_lines)
            
            logger.info(f"Command completed: exit={exit_code}, time={execution_time:.1f}s, "
                       f"stdout={len(stdout_str)} chars")
            
            return {
                'success': exit_code == 0,
                'stdout': stdout_str,
                'stderr': stderr_str,
                'exit_code': exit_code,
                'execution_time': execution_time,
                'command': command
            }
            
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return {
                'success': False,
                'error': str(e),
                'stdout': '',
                'stderr': str(e),
                'exit_code': -1,
                'command': command
            }
    
    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()