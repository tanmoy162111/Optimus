"""
Evolving Command Generation System

This module provides self-evolving command generation that learns from:

1. TOOL DISCOVERY:
   - Automatically discovers tool paths on the system
   - Learns alternative paths for tools
   - Tracks which paths work on which systems

2. COMMAND TEMPLATE EVOLUTION:
   - Learns from successful command executions
   - Adapts commands based on error feedback
   - Tracks success rates per command template

3. ERROR ADAPTATION:
   - Learns from "command not found" errors
   - Adapts to permission issues
   - Handles timeout-based adjustments

4. CONTEXT-AWARE GENERATION:
   - Different commands for different target types
   - Phase-specific command optimization
   - Technology-aware command selection

Integration:
    Works alongside existing tool_manager.py
    Uses hybrid_tool_system.py infrastructure
    Stores learned data in data/command_evolution.db
"""

import re
import json
import hashlib
import sqlite3
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple, Set
from datetime import datetime
from dataclasses import dataclass, field, asdict
from contextlib import contextmanager
from enum import Enum

logger = logging.getLogger(__name__)


class CommandStatus(Enum):
    """Status of command execution"""
    SUCCESS = "success"
    TOOL_NOT_FOUND = "tool_not_found"
    PERMISSION_DENIED = "permission_denied"
    TIMEOUT = "timeout"
    SYNTAX_ERROR = "syntax_error"
    TARGET_ERROR = "target_error"
    UNKNOWN_ERROR = "unknown_error"


@dataclass
class ToolPath:
    """Represents a discovered tool path"""
    tool: str
    path: str
    verified: bool = False
    success_count: int = 0
    failure_count: int = 0
    last_used: str = ""
    os_type: str = "linux"  # linux, windows, macos
    version: str = ""
    

@dataclass 
class CommandTemplate:
    """Represents a command template"""
    tool: str
    template: str  # Command template with placeholders
    context_type: str  # web, network, host, etc.
    phase: str  # reconnaissance, scanning, exploitation, etc.
    success_count: int = 0
    failure_count: int = 0
    avg_findings: float = 0.0
    avg_execution_time: float = 0.0
    last_used: str = ""
    generated_by: str = "manual"  # manual, llm, evolved
    notes: str = ""


@dataclass
class CommandError:
    """Represents a command error for learning"""
    tool: str
    command: str
    error_type: str
    error_message: str
    suggested_fix: str = ""
    fixed: bool = False
    timestamp: str = ""


class CommandEvolutionDB:
    """
    SQLite database for storing evolved commands, tool paths, and errors.
    """
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = Path(__file__).parent.parent / 'data' / 'command_evolution.db'
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        logger.info(f"[CommandEvolutionDB] Initialized at {self.db_path}")
    
    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def _init_db(self):
        """Initialize database schema"""
        with self._get_connection() as conn:
            # Tool paths table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS tool_paths (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool TEXT NOT NULL,
                    path TEXT NOT NULL,
                    verified INTEGER DEFAULT 0,
                    success_count INTEGER DEFAULT 0,
                    failure_count INTEGER DEFAULT 0,
                    last_used TEXT,
                    os_type TEXT DEFAULT 'linux',
                    version TEXT,
                    created_at TEXT,
                    UNIQUE(tool, path)
                )
            ''')
            
            # Command templates table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS command_templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool TEXT NOT NULL,
                    template TEXT NOT NULL,
                    context_type TEXT DEFAULT 'general',
                    phase TEXT DEFAULT 'scanning',
                    success_count INTEGER DEFAULT 0,
                    failure_count INTEGER DEFAULT 0,
                    avg_findings REAL DEFAULT 0.0,
                    avg_execution_time REAL DEFAULT 0.0,
                    last_used TEXT,
                    generated_by TEXT DEFAULT 'manual',
                    notes TEXT,
                    created_at TEXT,
                    UNIQUE(tool, template, context_type, phase)
                )
            ''')
            
            # Command errors table (for learning)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS command_errors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool TEXT NOT NULL,
                    command TEXT NOT NULL,
                    error_type TEXT NOT NULL,
                    error_message TEXT,
                    suggested_fix TEXT,
                    fixed INTEGER DEFAULT 0,
                    timestamp TEXT
                )
            ''')
            
            # Tool alternatives mapping
            conn.execute('''
                CREATE TABLE IF NOT EXISTS tool_alternatives (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool TEXT NOT NULL,
                    alternative TEXT NOT NULL,
                    priority INTEGER DEFAULT 1,
                    notes TEXT,
                    UNIQUE(tool, alternative)
                )
            ''')
            
            # Execution history for learning
            conn.execute('''
                CREATE TABLE IF NOT EXISTS execution_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool TEXT NOT NULL,
                    command TEXT NOT NULL,
                    target TEXT,
                    exit_code INTEGER,
                    findings_count INTEGER DEFAULT 0,
                    execution_time REAL,
                    status TEXT,
                    timestamp TEXT
                )
            ''')
            
            # Indexes
            conn.execute('CREATE INDEX IF NOT EXISTS idx_paths_tool ON tool_paths(tool)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_templates_tool ON command_templates(tool)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_errors_tool ON command_errors(tool)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_history_tool ON execution_history(tool)')
            
            # Initialize default tool paths
            self._init_default_paths(conn)
            
            # Initialize default templates
            self._init_default_templates(conn)
            
            # Initialize tool alternatives
            self._init_tool_alternatives(conn)
    
    def _init_default_paths(self, conn):
        """Initialize default tool paths"""
        default_paths = [
            # Standard tools
            ('nmap', '/usr/bin/nmap', 'linux'),
            ('nikto', '/usr/bin/nikto', 'linux'),
            ('sqlmap', '/usr/bin/sqlmap', 'linux'),
            ('gobuster', '/usr/bin/gobuster', 'linux'),
            ('whatweb', '/usr/bin/whatweb', 'linux'),
            ('wpscan', '/usr/bin/wpscan', 'linux'),
            ('hydra', '/usr/bin/hydra', 'linux'),
            ('john', '/usr/bin/john', 'linux'),
            ('hashcat', '/usr/bin/hashcat', 'linux'),
            ('metasploit', '/usr/bin/msfconsole', 'linux'),
            ('curl', '/usr/bin/curl', 'linux'),
            ('wget', '/usr/bin/wget', 'linux'),
            ('dig', '/usr/bin/dig', 'linux'),
            ('host', '/usr/bin/host', 'linux'),
            ('whois', '/usr/bin/whois', 'linux'),
            
            # Go tools (common locations)
            ('nuclei', '/usr/bin/nuclei', 'linux'),
            ('nuclei', '/home/kali/go/bin/nuclei', 'linux'),
            ('nuclei', '/root/go/bin/nuclei', 'linux'),
            ('ffuf', '/usr/bin/ffuf', 'linux'),
            ('ffuf', '/home/kali/go/bin/ffuf', 'linux'),
            ('dalfox', '/home/kali/go/bin/dalfox', 'linux'),
            ('dalfox', '/usr/local/bin/dalfox', 'linux'),
            ('amass', '/usr/bin/amass', 'linux'),
            ('amass', '/home/kali/go/bin/amass', 'linux'),
            
            # Python tools
            ('commix', '/usr/bin/commix', 'linux'),
            ('commix', '/usr/share/commix/commix.py', 'linux'),
            
            # Kali specific
            ('fierce', '/usr/bin/fierce', 'linux'),
            ('dnsenum', '/usr/bin/dnsenum', 'linux'),
            ('enum4linux', '/usr/bin/enum4linux', 'linux'),
            ('smbclient', '/usr/bin/smbclient', 'linux'),
            ('sslscan', '/usr/bin/sslscan', 'linux'),
        ]
        
        now = datetime.now().isoformat()
        for tool, path, os_type in default_paths:
            try:
                conn.execute('''
                    INSERT OR IGNORE INTO tool_paths (tool, path, os_type, created_at)
                    VALUES (?, ?, ?, ?)
                ''', (tool, path, os_type, now))
            except:
                pass
    
    def _init_default_templates(self, conn):
        """Initialize default command templates"""
        templates = [
            # Nmap templates
            ('nmap', 'nmap -sV -sC -T4 {target}', 'network', 'scanning', 'manual'),
            ('nmap', 'nmap -sV -sC -T4 -p 80,443,8080,8443,3000 {target}', 'web', 'scanning', 'manual'),
            ('nmap', 'nmap -sV -sC -T4 -p- {target}', 'network', 'scanning', 'manual'),
            ('nmap', 'nmap -sU -sV --top-ports 100 {target}', 'network', 'scanning', 'manual'),
            ('nmap', 'nmap --script vuln {target}', 'network', 'exploitation', 'manual'),
            
            # Nikto templates
            ('nikto', 'nikto -h {target}', 'web', 'scanning', 'manual'),
            ('nikto', 'nikto -h {target} -C all -Tuning 123bde', 'web', 'scanning', 'manual'),
            
            # SQLMap templates
            ('sqlmap', "sqlmap -u '{target}' --batch --level=2 --risk=2", 'web', 'exploitation', 'manual'),
            ('sqlmap', "sqlmap -u '{target}' --batch --forms --crawl=2", 'web', 'exploitation', 'manual'),
            ('sqlmap', "sqlmap -u '{target}' --batch --dbs", 'web', 'exploitation', 'manual'),
            
            # Directory enumeration
            ('gobuster', 'gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -t 50', 'web', 'reconnaissance', 'manual'),
            ('ffuf', 'ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403', 'web', 'reconnaissance', 'manual'),
            
            # Nuclei templates
            ('nuclei', 'nuclei -u {target} -severity critical,high,medium', 'web', 'scanning', 'manual'),
            ('nuclei', 'nuclei -u {target} -as', 'web', 'scanning', 'manual'),
            
            # XSS scanning
            ('dalfox', "dalfox url '{target}' --skip-bav", 'web', 'exploitation', 'manual'),
            
            # Command injection
            ('commix', "commix --url='{target}' --batch", 'web', 'exploitation', 'manual'),
            
            # Technology detection
            ('whatweb', 'whatweb -a 3 {target}', 'web', 'reconnaissance', 'manual'),
            
            # DNS enumeration
            ('fierce', 'fierce --domain {hostname}', 'network', 'reconnaissance', 'manual'),
            ('dnsenum', 'dnsenum {hostname}', 'network', 'reconnaissance', 'manual'),
            ('amass', 'amass enum -passive -d {hostname}', 'network', 'reconnaissance', 'manual'),
            
            # WordPress
            ('wpscan', 'wpscan --url {target} --enumerate vp,vt,u', 'web', 'scanning', 'manual'),
            
            # SSL
            ('sslscan', 'sslscan {hostname}:{port}', 'web', 'scanning', 'manual'),
            
            # Basic tools (always available)
            ('curl', 'curl -s -I {target}', 'web', 'reconnaissance', 'manual'),
            ('curl', 'curl -s -X GET {target}', 'web', 'reconnaissance', 'manual'),
            ('wget', 'wget -q --spider --server-response {target} 2>&1 | head -20', 'web', 'reconnaissance', 'manual'),
        ]
        
        now = datetime.now().isoformat()
        for tool, template, context, phase, generated_by in templates:
            try:
                conn.execute('''
                    INSERT OR IGNORE INTO command_templates 
                    (tool, template, context_type, phase, generated_by, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (tool, template, context, phase, generated_by, now))
            except:
                pass
    
    def _init_tool_alternatives(self, conn):
        """Initialize tool alternatives"""
        alternatives = [
            ('sublist3r', 'amass', 1),
            ('theHarvester', 'dnsenum', 1),
            ('dirb', 'gobuster', 1),
            ('dirsearch', 'gobuster', 1),
            ('dirsearch', 'ffuf', 2),
            ('wfuzz', 'ffuf', 1),
            ('masscan', 'nmap', 2),
            ('xsser', 'dalfox', 1),
        ]
        
        for tool, alt, priority in alternatives:
            try:
                conn.execute('''
                    INSERT OR IGNORE INTO tool_alternatives (tool, alternative, priority)
                    VALUES (?, ?, ?)
                ''', (tool, alt, priority))
            except:
                pass
    
    # ============ Tool Path Methods ============
    
    def get_tool_paths(self, tool: str) -> List[ToolPath]:
        """Get all known paths for a tool, ordered by success rate"""
        with self._get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM tool_paths 
                WHERE tool = ? 
                ORDER BY 
                    verified DESC,
                    (success_count * 1.0 / (success_count + failure_count + 1)) DESC,
                    success_count DESC
            ''', (tool,))
            
            return [
                ToolPath(
                    tool=row['tool'],
                    path=row['path'],
                    verified=bool(row['verified']),
                    success_count=row['success_count'],
                    failure_count=row['failure_count'],
                    last_used=row['last_used'] or '',
                    os_type=row['os_type'] or 'linux',
                    version=row['version'] or ''
                )
                for row in cursor
            ]
    
    def get_best_tool_path(self, tool: str) -> Optional[str]:
        """Get the best known path for a tool"""
        paths = self.get_tool_paths(tool)
        if paths:
            # Return verified path if available, otherwise best success rate
            for p in paths:
                if p.verified:
                    return p.path
            return paths[0].path if paths else None
        return None
    
    def add_tool_path(self, tool: str, path: str, verified: bool = False, 
                      os_type: str = 'linux', version: str = ''):
        """Add or update a tool path"""
        now = datetime.now().isoformat()
        
        with self._get_connection() as conn:
            try:
                conn.execute('''
                    INSERT INTO tool_paths (tool, path, verified, os_type, version, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (tool, path, 1 if verified else 0, os_type, version, now))
            except sqlite3.IntegrityError:
                conn.execute('''
                    UPDATE tool_paths 
                    SET verified = MAX(verified, ?), version = COALESCE(NULLIF(?, ''), version)
                    WHERE tool = ? AND path = ?
                ''', (1 if verified else 0, version, tool, path))
    
    def update_path_stats(self, tool: str, path: str, success: bool):
        """Update path success/failure stats"""
        now = datetime.now().isoformat()
        
        with self._get_connection() as conn:
            if success:
                conn.execute('''
                    UPDATE tool_paths 
                    SET success_count = success_count + 1, 
                        last_used = ?,
                        verified = 1
                    WHERE tool = ? AND path = ?
                ''', (now, tool, path))
            else:
                conn.execute('''
                    UPDATE tool_paths 
                    SET failure_count = failure_count + 1, last_used = ?
                    WHERE tool = ? AND path = ?
                ''', (now, tool, path))
    
    # ============ Command Template Methods ============
    
    def get_templates(self, tool: str, context_type: str = None, 
                      phase: str = None) -> List[CommandTemplate]:
        """Get command templates for a tool"""
        with self._get_connection() as conn:
            query = 'SELECT * FROM command_templates WHERE tool = ?'
            params = [tool]
            
            if context_type:
                query += ' AND context_type = ?'
                params.append(context_type)
            if phase:
                query += ' AND phase = ?'
                params.append(phase)
            
            query += ' ORDER BY success_count DESC, avg_findings DESC'
            
            cursor = conn.execute(query, params)
            
            return [
                CommandTemplate(
                    tool=row['tool'],
                    template=row['template'],
                    context_type=row['context_type'],
                    phase=row['phase'],
                    success_count=row['success_count'],
                    failure_count=row['failure_count'],
                    avg_findings=row['avg_findings'],
                    avg_execution_time=row['avg_execution_time'],
                    last_used=row['last_used'] or '',
                    generated_by=row['generated_by'] or 'manual',
                    notes=row['notes'] or ''
                )
                for row in cursor
            ]
    
    def get_best_template(self, tool: str, context_type: str = None,
                          phase: str = None) -> Optional[CommandTemplate]:
        """Get the best template for a tool/context/phase"""
        templates = self.get_templates(tool, context_type, phase)
        
        if not templates and context_type:
            # Fallback to general context
            templates = self.get_templates(tool, 'general', phase)
        
        if not templates and phase:
            # Fallback to any phase
            templates = self.get_templates(tool, context_type)
        
        return templates[0] if templates else None
    
    def add_template(self, template: CommandTemplate) -> bool:
        """Add a new command template"""
        now = datetime.now().isoformat()
        
        try:
            with self._get_connection() as conn:
                conn.execute('''
                    INSERT INTO command_templates 
                    (tool, template, context_type, phase, generated_by, notes, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    template.tool, template.template, template.context_type,
                    template.phase, template.generated_by, template.notes, now
                ))
            return True
        except sqlite3.IntegrityError:
            return False
    
    def update_template_stats(self, tool: str, template: str, 
                              success: bool, findings_count: int = 0,
                              execution_time: float = 0):
        """Update template statistics"""
        now = datetime.now().isoformat()
        
        with self._get_connection() as conn:
            if success:
                # Update with running average
                conn.execute('''
                    UPDATE command_templates 
                    SET success_count = success_count + 1,
                        avg_findings = (avg_findings * success_count + ?) / (success_count + 1),
                        avg_execution_time = (avg_execution_time * success_count + ?) / (success_count + 1),
                        last_used = ?
                    WHERE tool = ? AND template = ?
                ''', (findings_count, execution_time, now, tool, template))
            else:
                conn.execute('''
                    UPDATE command_templates 
                    SET failure_count = failure_count + 1, last_used = ?
                    WHERE tool = ? AND template = ?
                ''', (now, tool, template))
    
    # ============ Error Learning Methods ============
    
    def record_error(self, tool: str, command: str, error_type: str, 
                     error_message: str, suggested_fix: str = ''):
        """Record a command error for learning"""
        now = datetime.now().isoformat()
        
        with self._get_connection() as conn:
            conn.execute('''
                INSERT INTO command_errors 
                (tool, command, error_type, error_message, suggested_fix, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (tool, command, error_type, error_message, suggested_fix, now))
    
    def get_recent_errors(self, tool: str = None, limit: int = 10) -> List[CommandError]:
        """Get recent errors for learning"""
        with self._get_connection() as conn:
            if tool:
                cursor = conn.execute('''
                    SELECT * FROM command_errors 
                    WHERE tool = ? AND fixed = 0
                    ORDER BY timestamp DESC LIMIT ?
                ''', (tool, limit))
            else:
                cursor = conn.execute('''
                    SELECT * FROM command_errors 
                    WHERE fixed = 0
                    ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
            
            return [
                CommandError(
                    tool=row['tool'],
                    command=row['command'],
                    error_type=row['error_type'],
                    error_message=row['error_message'],
                    suggested_fix=row['suggested_fix'] or '',
                    fixed=bool(row['fixed']),
                    timestamp=row['timestamp'] or ''
                )
                for row in cursor
            ]
    
    def mark_error_fixed(self, tool: str, error_type: str):
        """Mark errors as fixed after learning"""
        with self._get_connection() as conn:
            conn.execute('''
                UPDATE command_errors SET fixed = 1
                WHERE tool = ? AND error_type = ?
            ''', (tool, error_type))
    
    # ============ Tool Alternatives ============
    
    def get_alternative(self, tool: str) -> Optional[str]:
        """Get best alternative for a tool"""
        with self._get_connection() as conn:
            row = conn.execute('''
                SELECT alternative FROM tool_alternatives
                WHERE tool = ? ORDER BY priority ASC LIMIT 1
            ''', (tool,)).fetchone()
            return row['alternative'] if row else None
    
    # ============ Execution History ============
    
    def record_execution(self, tool: str, command: str, target: str,
                        exit_code: int, findings_count: int,
                        execution_time: float, status: str):
        """Record command execution for learning"""
        now = datetime.now().isoformat()
        
        with self._get_connection() as conn:
            conn.execute('''
                INSERT INTO execution_history 
                (tool, command, target, exit_code, findings_count, execution_time, status, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (tool, command, target, exit_code, findings_count, execution_time, status, now))
    
    # ============ Statistics ============
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get evolution statistics"""
        with self._get_connection() as conn:
            paths = conn.execute('SELECT COUNT(*) FROM tool_paths').fetchone()[0]
            verified = conn.execute('SELECT COUNT(*) FROM tool_paths WHERE verified = 1').fetchone()[0]
            templates = conn.execute('SELECT COUNT(*) FROM command_templates').fetchone()[0]
            errors = conn.execute('SELECT COUNT(*) FROM command_errors').fetchone()[0]
            fixed = conn.execute('SELECT COUNT(*) FROM command_errors WHERE fixed = 1').fetchone()[0]
            executions = conn.execute('SELECT COUNT(*) FROM execution_history').fetchone()[0]
            
            return {
                'tool_paths': paths,
                'verified_paths': verified,
                'command_templates': templates,
                'recorded_errors': errors,
                'fixed_errors': fixed,
                'total_executions': executions
            }


class EvolvingCommandGenerator:
    """
    Self-evolving command generator that learns from execution results.
    """
    
    def __init__(self, ssh_client=None, llm_client=None):
        self.ssh_client = ssh_client
        self.llm_client = llm_client
        self.db = CommandEvolutionDB()
        
        # Error pattern detection
        self.error_patterns = {
            'command_not_found': [
                r'command not found',
                r'not found',
                r'No such file or directory',
            ],
            'permission_denied': [
                r'Permission denied',
                r'Operation not permitted',
                r'Access denied',
            ],
            'timeout': [
                r'Connection timed out',
                r'timeout',
                r'Timed out',
            ],
            'connection_refused': [
                r'Connection refused',
                r'Unable to connect',
            ],
            'syntax_error': [
                r'Invalid option',
                r'Unknown option',
                r'unrecognized option',
                r'illegal option',
            ],
        }
        
        # Compile patterns
        self._compiled_errors = {}
        for error_type, patterns in self.error_patterns.items():
            self._compiled_errors[error_type] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]
        
        # Statistics
        self.stats = {
            'commands_generated': 0,
            'paths_discovered': 0,
            'templates_evolved': 0,
            'errors_adapted': 0,
        }
        
        logger.info("[EvolvingCommandGenerator] Initialized")
    
    def generate_command(self, tool: str, target: str, 
                        context: Dict[str, Any] = None) -> Tuple[str, str]:
        """
        Generate the best command for a tool.
        
        Returns:
            Tuple of (command, source) where source indicates how it was generated
        """
        context = context or {}
        self.stats['commands_generated'] += 1
        
        # Extract context
        phase = context.get('phase', 'scanning')
        target_type = context.get('target_type', 'web')
        
        # Normalize target
        target, hostname, port = self._normalize_target(target)
        
        # Get best tool path
        tool_path = self.db.get_best_tool_path(tool)
        if not tool_path:
            tool_path = tool  # Fallback to tool name
        
        # Get best template
        template_obj = self.db.get_best_template(tool, target_type, phase)
        
        if template_obj:
            # Substitute variables in template
            command = self._substitute_template(
                template_obj.template, tool_path, target, hostname, port, context
            )
            return command, f'evolved_template:{template_obj.generated_by}'
        
        # Fallback to basic command
        command = f"{tool_path} {target}"
        return command, 'basic_fallback'
    
    def _normalize_target(self, target: str) -> Tuple[str, str, str]:
        """Normalize target and extract hostname/port"""
        # Ensure protocol
        if not target.startswith(('http://', 'https://')):
            target = f'http://{target}'
        
        # Extract hostname and port
        match = re.search(r'(?:https?://)?([^:/]+)(?::(\d+))?', target)
        hostname = match.group(1) if match else target
        port = match.group(2) if match and match.group(2) else '80'
        
        return target, hostname, port
    
    def _substitute_template(self, template: str, tool_path: str,
                            target: str, hostname: str, port: str,
                            context: Dict[str, Any]) -> str:
        """Substitute variables in command template"""
        # Replace common placeholders
        command = template
        
        # Check if template starts with tool name placeholder
        if '{tool}' in command or command.startswith(tool_path.split('/')[-1]):
            # Template uses tool placeholder
            command = command.replace('{tool}', tool_path)
        else:
            # Template starts with bare tool name, replace it with full path
            tool_name = tool_path.split('/')[-1]
            if command.startswith(tool_name):
                command = tool_path + command[len(tool_name):]
        
        # Standard substitutions
        command = command.replace('{target}', target)
        command = command.replace('{hostname}', hostname)
        command = command.replace('{host}', hostname)
        command = command.replace('{port}', port)
        command = command.replace('{url}', target)
        
        # Context substitutions
        command = command.replace('{lhost}', context.get('lhost', '10.10.14.1'))
        command = command.replace('{lport}', str(context.get('lport', 4444)))
        
        return command
    
    def learn_from_execution(self, tool: str, command: str, target: str,
                            exit_code: int, stdout: str, stderr: str,
                            findings_count: int, execution_time: float):
        """
        Learn from command execution results.
        
        This is the key evolution mechanism.
        """
        # Detect error type
        error_type = self._detect_error_type(stdout, stderr, exit_code)
        
        # Record execution
        status = 'success' if error_type is None else error_type
        self.db.record_execution(tool, command, target, exit_code, 
                                findings_count, execution_time, status)
        
        if error_type:
            # Handle error - adapt
            self._adapt_from_error(tool, command, error_type, stderr or stdout)
        else:
            # Success - reinforce
            self._reinforce_success(tool, command, findings_count, execution_time)
    
    def _detect_error_type(self, stdout: str, stderr: str, 
                          exit_code: int) -> Optional[str]:
        """Detect error type from output"""
        combined = f"{stdout}\n{stderr}".lower()
        
        for error_type, patterns in self._compiled_errors.items():
            for pattern in patterns:
                if pattern.search(combined):
                    return error_type
        
        # Check exit code
        if exit_code != 0 and not stdout.strip():
            return 'unknown_error'
        
        return None
    
    def _adapt_from_error(self, tool: str, command: str, 
                         error_type: str, error_output: str):
        """Adapt from an error - try to fix it"""
        self.stats['errors_adapted'] += 1
        
        # Record the error
        suggested_fix = self._suggest_fix(tool, error_type, error_output)
        self.db.record_error(tool, command, error_type, error_output[:500], suggested_fix)
        
        # Extract the path used
        path_match = re.match(r'^(\S+)', command)
        if path_match:
            path = path_match.group(1)
            self.db.update_path_stats(tool, path, success=False)
        
        # Update template stats
        template = self._extract_template(command)
        if template:
            self.db.update_template_stats(tool, template, success=False)
        
        # Handle specific errors
        if error_type == 'command_not_found':
            self._handle_tool_not_found(tool, command)
        elif error_type == 'permission_denied':
            self._handle_permission_denied(tool, command)
    
    def _suggest_fix(self, tool: str, error_type: str, error_output: str) -> str:
        """Suggest a fix for an error"""
        suggestions = {
            'command_not_found': f"Try alternative path or install {tool}",
            'permission_denied': f"Try with sudo or check file permissions",
            'timeout': f"Increase timeout or check network connectivity",
            'connection_refused': f"Check if target is accessible",
            'syntax_error': f"Check command syntax and options",
        }
        return suggestions.get(error_type, "Review error and adjust command")
    
    def _handle_tool_not_found(self, tool: str, command: str):
        """Handle tool not found error - try to find alternative paths"""
        logger.info(f"[EvolvingCommandGenerator] Tool not found: {tool}, searching alternatives")
        
        # Try to discover the tool
        if self.ssh_client:
            discovered_path = self._discover_tool_path(tool)
            if discovered_path:
                self.db.add_tool_path(tool, discovered_path, verified=True)
                self.stats['paths_discovered'] += 1
                logger.info(f"[EvolvingCommandGenerator] Discovered {tool} at {discovered_path}")
                return
        
        # Try alternative tool
        alternative = self.db.get_alternative(tool)
        if alternative:
            logger.info(f"[EvolvingCommandGenerator] Suggesting alternative: {alternative}")
    
    def _handle_permission_denied(self, tool: str, command: str):
        """Handle permission denied - try sudo or different approach"""
        # Create a sudo version of the template
        if not command.startswith('sudo '):
            sudo_template = CommandTemplate(
                tool=tool,
                template=f"sudo {command}",
                context_type='general',
                phase='scanning',
                generated_by='error_adaptation',
                notes='Auto-generated sudo version due to permission error'
            )
            self.db.add_template(sudo_template)
    
    def _discover_tool_path(self, tool: str) -> Optional[str]:
        """Discover tool path on the system via SSH and register it in the ground-truth registry"""
        if not self.ssh_client:
            return None
        
        try:
            # First, check if tool is already registered in our ground-truth registry
            from .tool_registry import get_tool_registry
            registry = get_tool_registry()
            registered_path = registry.get_tool_path(tool)
            if registered_path:
                return registered_path
            
            # Try command which or whereis
            result = self.ssh_client.execute_command(f"command -v {tool} || which {tool}")
            if result['success'] and result.get('stdout', '').strip():
                path = result.get('stdout', '').strip()
                # Register this discovered tool in the registry
                registry.register_tool(
                    name=tool,
                    path=path,
                    version=self._get_remote_tool_version(tool),
                    category=self._categorize_tool(tool)
                )
                return path
            
            # Try common locations
            common_paths = [
                f"/usr/bin/{tool}",
                f"/usr/local/bin/{tool}",
                f"/home/kali/go/bin/{tool}",
                f"/root/go/bin/{tool}",
                f"/opt/{tool}/{tool}",
            ]
            
            for path in common_paths:
                result = self.ssh_client.execute_command(f"test -x {path} && echo 'exists'")
                if 'exists' in result.get('stdout', ''):
                    # Register this discovered tool in the registry
                    registry.register_tool(
                        name=tool,
                        path=path,
                        version=self._get_remote_tool_version(tool),
                        category=self._categorize_tool(tool)
                    )
                    return path
            
            # Try locate
            result = self.ssh_client.execute_command(f"locate -l 1 'bin/{tool}' 2>/dev/null")
            if result['success'] and result.get('stdout', '').strip():
                path = result.get('stdout', '').strip().split('\n')[0]
                # Register this discovered tool in the registry
                registry.register_tool(
                    name=tool,
                    path=path,
                    version=self._get_remote_tool_version(tool),
                    category=self._categorize_tool(tool)
                )
                return path
                
        except Exception as e:
            logger.debug(f"[EvolvingCommandGenerator] Discovery failed: {e}")
        
        return None
    
    def _get_remote_tool_version(self, tool: str) -> str:
        """Get version of a remote tool"""
        try:
            result = self.ssh_client.execute_command(f"{tool} --version")
            if result['success']:
                output = result.get('stdout', '').split('\n')[0]
                import re
                version_match = re.search(r'(\d+\.\d+(\.\d+)?(\.\d+)?)|([\w\d\.\-]+)', output)
                if version_match:
                    return version_match.group(0)
                return output.strip()[:100]
        except:
            pass
        return "Unknown"
    
    def _categorize_tool(self, tool: str) -> str:
        """Categorize a tool based on its name"""
        tool_lower = tool.lower()
        
        # Scanner category
        if any(scanner in tool_lower for scanner in ["nmap", "nikto", "nuclei", "wpscan", "gobuster", "ffuf", "dirb", "scan"]):
            return "scanner"
        
        # Password category
        if any(password in tool_lower for password in ["john", "hashcat", "hydra", "password"]):
            return "password"
        
        # Exploitation category
        if any(exploit in tool_lower for exploit in ["metasploit", "msf", "exploit", "sqlmap"]):
            return "exploitation"
        
        # Network category
        if any(network in tool_lower for network in ["netcat", "nc", "tcpdump", "wireshark", "network"]):
            return "network"
        
        # Wireless category
        if any(wireless in tool_lower for wireless in ["aircrack", "kismet", "wireless"]):
            return "wireless"
        
        # Forensics category
        if any(forensics in tool_lower for forensics in ["volatility", "autopsy", "forensic"]):
            return "forensics"
        
        # Web category
        if any(web in tool_lower for web in ["curl", "wget", "burp", "zap", "web"]):
            return "web"
        
        return "misc"
    
    def _reinforce_success(self, tool: str, command: str, 
                          findings_count: int, execution_time: float):
        """Reinforce successful command execution"""
        # Update path stats
        path_match = re.match(r'^(\S+)', command)
        if path_match:
            path = path_match.group(1)
            self.db.update_path_stats(tool, path, success=True)
        
        # Update template stats
        template = self._extract_template(command)
        if template:
            self.db.update_template_stats(tool, template, success=True,
                                         findings_count=findings_count,
                                         execution_time=execution_time)
    
    def _extract_template(self, command: str) -> Optional[str]:
        """Extract template pattern from a command"""
        # Replace target-specific parts with placeholders
        template = command
        
        # Replace URLs
        template = re.sub(r'https?://[^\s]+', '{target}', template)
        
        # Replace IPs
        template = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '{hostname}', template)
        
        # Replace ports
        template = re.sub(r':(\d{2,5})\b', ':{port}', template)
        
        return template if template != command else None
    
    def evolve_template_with_llm(self, tool: str, target_type: str,
                                 phase: str, error_info: str = None) -> Optional[CommandTemplate]:
        """
        Use LLM to evolve a new template.
        
        OPTIMIZED FOR MISTRAL/CODELLAMA 7B:
        - Simple, direct prompts
        - Single command output expected
        - Robust response cleaning
        """
        if not self.llm_client:
            return None
        
        try:
            # Simple prompt that works well with 7B models
            prompt = f"""Write a {tool} command for {phase} on a {target_type} target.
Use {{target}} as the target placeholder.
Only output the command, nothing else.

Command:"""
            
            response = self.llm_client.generate(prompt, temperature=0.1, max_tokens=150)
            if not response:
                return None
            
            # Robust response cleaning
            command = response.strip()
            
            # Take only first line
            if '\n' in command:
                command = command.split('\n')[0]
            
            # Remove markdown code blocks
            command = re.sub(r'^```\w*\s*', '', command)
            command = re.sub(r'\s*```$', '', command)
            
            # Remove common prefixes LLMs add
            command = re.sub(r'^(Command:|Here\'s|The command is:?|Sure,?)\s*', '', command, flags=re.IGNORECASE)
            
            command = command.strip()
            
            # Validate command
            if not command or len(command) < 5:
                return None
            
            # Must contain the tool name
            if tool.lower() not in command.lower():
                return None
            
            # Create template
            template = CommandTemplate(
                tool=tool,
                template=command,
                context_type=target_type,
                phase=phase,
                generated_by='llm_evolved',
                notes=f'LLM generated{" (after error)" if error_info else ""}'
            )
            
            if self.db.add_template(template):
                self.stats['templates_evolved'] += 1
                logger.info(f"[EvolvingCommandGenerator] Evolved template for {tool}: {command[:50]}...")
                return template
                
        except Exception as e:
            logger.debug(f"[EvolvingCommandGenerator] LLM evolution failed: {e}")
        
        return None
        
        return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get generator statistics"""
        return {
            **self.stats,
            'db': self.db.get_statistics()
        }


# Singleton instance
_command_generator: Optional[EvolvingCommandGenerator] = None


def get_evolving_command_generator(ssh_client=None, 
                                   llm_client=None) -> EvolvingCommandGenerator:
    """Get or create singleton command generator"""
    global _command_generator
    if _command_generator is None:
        _command_generator = EvolvingCommandGenerator(ssh_client, llm_client)
    elif ssh_client:
        _command_generator.ssh_client = ssh_client
    elif llm_client:
        _command_generator.llm_client = llm_client
    return _command_generator
