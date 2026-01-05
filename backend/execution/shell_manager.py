"""
Shell Manager - Handles proper PATH and shell initialization for interactive and non-interactive shells
"""
import os
import logging
import subprocess
from typing import Dict, Optional, List
import platform

logger = logging.getLogger(__name__)


class ShellManager:
    """
    Manages shell environments to ensure tools are accessible in both
    interactive and non-interactive contexts.
    """
    
    def __init__(self):
        self._shell_configured = False
        self._cached_environment = None
        
    def setup_environment(self) -> bool:
        """
        Setup proper environment for both interactive and non-interactive shells.
        This ensures that tools are accessible regardless of shell type.
        """
        try:
            # Determine OS and set appropriate paths
            system = platform.system().lower()
            
            if system == "linux" or system == "darwin":  # Linux or macOS
                self._setup_linux_environment()
            elif system == "windows":
                self._setup_windows_environment()
            else:
                logger.warning(f"Unsupported platform: {system}")
                return False
            
            self._shell_configured = True
            logger.info("[ShellManager] Environment setup completed")
            return True
            
        except Exception as e:
            logger.error(f"[ShellManager] Environment setup failed: {e}")
            return False
    
    def _setup_linux_environment(self):
        """Setup environment for Linux systems"""
        # Define common security tool paths
        security_paths = [
            "/usr/bin",
            "/bin", 
            "/usr/local/bin",
            "/sbin",
            "/usr/sbin",
            "/usr/local/sbin",
            "/opt/bin",
            "/opt/metasploit-framework/bin",
            "/home/kali/go/bin",
            "/root/go/bin",
            "/home/kali/.local/bin",
            "/root/.local/bin",
            "/usr/share/metasploit-framework/tools/exploit",
            "/usr/share/metasploit-framework/tools/payloads"
        ]
        
        # Get current PATH
        current_path = os.environ.get("PATH", "")
        
        # Add security paths to PATH if not already present
        path_parts = current_path.split(os.pathsep)
        for path in security_paths:
            if os.path.exists(path) and path not in path_parts:
                path_parts.append(path)
        
        # Set the updated PATH
        new_path = os.pathsep.join(path_parts)
        os.environ["PATH"] = new_path
        
        # Set other important environment variables
        os.environ["SHELL"] = "/bin/bash"
        
        # Set up bash environment for non-interactive shells
        self._setup_bash_environment()
    
    def _setup_windows_environment(self):
        """Setup environment for Windows systems"""
        # On Windows, we'll primarily rely on the existing PATH
        # but we can add common security tool locations
        security_paths = [
            r"C:\Program Files\Metasploit\bin",
            r"C:\Program Files\Nmap",
            r"C:\Program Files\OpenSSL\bin",
            r"C:\msys64\usr\bin",  # For MSYS2 installations
            r"C:\tools"  # Common tools directory
        ]
        
        # Get current PATH
        current_path = os.environ.get("PATH", "")
        
        # Add security paths to PATH if not already present
        path_parts = current_path.split(os.pathsep)
        for path in security_paths:
            if os.path.exists(path) and path not in path_parts:
                path_parts.append(path)
        
        # Set the updated PATH
        new_path = os.pathsep.join(path_parts)
        os.environ["PATH"] = new_path
    
    def _setup_bash_environment(self):
        """Setup bash-specific environment for non-interactive shells"""
        # For non-interactive shells, we need to source the profile/bashrc
        # This ensures that all the PATH modifications from those files are available
        
        # Create a minimal bash environment that sources the necessary files
        bashrc_content = self._get_bashrc_content()
        profile_content = self._get_profile_content()
        
        # Cache the environment for reuse
        self._cached_environment = {
            'PATH': os.environ.get('PATH', ''),
            'SHELL': os.environ.get('SHELL', '/bin/bash'),
            'BASH_ENV': os.environ.get('BASH_ENV', ''),
        }
        
        # Ensure BASH_ENV points to a file that sets up the environment
        bash_env_file = self._create_bash_env_file(bashrc_content, profile_content)
        if bash_env_file:
            os.environ['BASH_ENV'] = bash_env_file
    
    def _get_bashrc_content(self) -> str:
        """Get content of .bashrc file"""
        bashrc_paths = [
            os.path.expanduser("~/.bashrc"),
            "/etc/bash.bashrc",
            "/etc/bashrc"
        ]
        
        for bashrc_path in bashrc_paths:
            if os.path.exists(bashrc_path):
                try:
                    with open(bashrc_path, 'r') as f:
                        return f.read()
                except Exception:
                    continue
        return ""
    
    def _get_profile_content(self) -> str:
        """Get content of profile file"""
        profile_paths = [
            os.path.expanduser("~/.profile"),
            os.path.expanduser("~/.bash_profile"),
            "/etc/profile"
        ]
        
        for profile_path in profile_paths:
            if os.path.exists(profile_path):
                try:
                    with open(profile_path, 'r') as f:
                        return f.read()
                except Exception:
                    continue
        return ""
    
    def _create_bash_env_file(self, bashrc_content: str, profile_content: str) -> Optional[str]:
        """Create a temporary bash environment file"""
        import tempfile
        
        try:
            # Create a temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.bash_env', delete=False) as f:
                # Add profile content first
                if profile_content:
                    f.write("# Profile content\n")
                    f.write(profile_content)
                    f.write("\n")
                
                # Add bashrc content
                if bashrc_content:
                    f.write("# Bashrc content\n")
                    f.write(bashrc_content)
                    f.write("\n")
                
                # Add security tool paths
                f.write("# Security tool paths\n")
                security_paths = [
                    "/home/kali/go/bin",
                    "/root/go/bin",
                    "/opt/metasploit-framework/bin",
                    "/usr/share/metasploit-framework/tools/exploit",
                    "/usr/share/metasploit-framework/tools/payloads"
                ]
                
                for path in security_paths:
                    if os.path.exists(path):
                        f.write(f'export PATH="$PATH:{path}"\n')
                
                f.flush()
                return f.name
        except Exception as e:
            logger.error(f"[ShellManager] Failed to create bash env file: {e}")
            return None
    
    def get_shell_command(self, command: str, interactive: bool = False) -> List[str]:
        """
        Get the appropriate shell command for execution.
        This ensures that the command runs in an environment where all tools are available.
        """
        if not self._shell_configured:
            self.setup_environment()
        
        if platform.system().lower() in ["linux", "darwin"]:
            if interactive:
                return ["/bin/bash", "-i", "-c", command]
            else:
                # For non-interactive shells, ensure we have the proper environment
                return ["/bin/bash", "--norc", "--noprofile", "-c", command]
        else:
            # For Windows, use cmd or PowerShell
            return ["cmd", "/c", command]
    
    def execute_command_with_path(self, command: str, timeout: int = 60) -> Dict[str, any]:
        """
        Execute a command ensuring it has access to the proper PATH.
        This method is especially important for non-interactive shells.
        """
        if not self._shell_configured:
            self.setup_environment()
        
        try:
            # Use the shell command that ensures proper environment
            shell_cmd = self.get_shell_command(command, interactive=False)
            
            # Execute with the current environment (which has been properly set up)
            result = subprocess.run(
                shell_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=os.environ.copy()  # Use the modified environment
            )
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'exit_code': result.returncode,
                'command': command
            }
        except subprocess.TimeoutExpired:
            logger.warning(f"[ShellManager] Command timed out: {command[:50]}...")
            return {
                'success': False,
                'stdout': '',
                'stderr': 'Command timed out',
                'exit_code': -1,
                'command': command
            }
        except Exception as e:
            logger.error(f"[ShellManager] Command execution failed: {e}")
            return {
                'success': False,
                'stdout': '',
                'stderr': str(e),
                'exit_code': -1,
                'command': command
            }
    
    def validate_tool_path(self, tool_name: str) -> bool:
        """
        Validate that a tool is accessible in the current environment.
        This works for both interactive and non-interactive shells.
        """
        if not self._shell_configured:
            self.setup_environment()
        
        try:
            # Try to find the tool using which command
            if platform.system().lower() in ["linux", "darwin"]:
                result = self.execute_command_with_path(f"which {tool_name}", timeout=10)
                return result['success'] and result.get('stdout', '').strip() != ''
            else:
                # On Windows, use where command
                result = self.execute_command_with_path(f"where {tool_name}", timeout=10)
                return result['success']
        except Exception:
            return False


# Global instance
_shell_manager: Optional[ShellManager] = None


def get_shell_manager() -> ShellManager:
    """Get or create singleton shell manager instance"""
    global _shell_manager
    if _shell_manager is None:
        _shell_manager = ShellManager()
        _shell_manager.setup_environment()
    return _shell_manager


def setup_shell_environment() -> bool:
    """Convenience function to setup shell environment"""
    manager = get_shell_manager()
    return manager.setup_environment()


def execute_with_proper_path(command: str, timeout: int = 60) -> Dict[str, any]:
    """Convenience function to execute command with proper PATH"""
    manager = get_shell_manager()
    return manager.execute_command_with_path(command, timeout)


def validate_tool_in_path(tool_name: str) -> bool:
    """Convenience function to validate tool availability"""
    manager = get_shell_manager()
    return manager.validate_tool_path(tool_name)