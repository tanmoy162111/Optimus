"""Tool Knowledge Base - Dynamic Command Generation
Generates optimal tool commands based on scan context"""

import logging
from typing import Dict, Any, List, Optional
import re

logger = logging.getLogger(__name__)

class ToolKnowledgeBase:
    """Generates context-aware tool commands"""

    def __init__(self):
        self.command_templates = self._initialize_templates()
        self.parameter_effectiveness = {}  # Learning from past executions

    def _initialize_templates(self) -> Dict[str, Dict]:
        """Initialize tool command templates with parameter options"""
        return {
            'nmap': {
                'base': 'nmap {target}',
                'parameters': {
                    'reconnaissance': {
                        'scan_type': ['-sn', '-sV'],  # Ping scan or version detection
                        'timing': ['-T2', '-T3'],  # Slower for stealth
                        'ports': ['-p 80,443', '-p 1-1000'],
                    },
                    'scanning': {
                        'scan_type': ['-sV', '-sS -sV'],  # Version + service detection
                        'timing': ['-T4'],
                        'ports': ['-p 1-65535', '-p-'],  # All ports
                        'scripts': ['--script=vuln', '--script=default,vuln'],
                    },
                    'exploitation': {
                        'scan_type': ['-sV -sC'],
                        'timing': ['-T4'],
                        'ports': ['-p {specific_port}'],  # Target specific port
                    }
                },
                'conditions': {
                    'waf_detected': {
                        'timing': '-T2',  # Slower
                        'scan_type': '-sS',  # Stealth SYN scan
                    },
                    'time_critical': {
                        'timing': '-T5',
                        'ports': '--top-ports 100',
                    }
                }
            },

            'sqlmap': {
                'base': 'sqlmap -u "{target}" --batch',
                'parameters': {
                    'reconnaissance': {
                        'level': ['1'],
                        'risk': ['1'],
                        'options': ['--forms'],
                    },
                    'scanning': {
                        'level': ['2'],
                        'risk': ['2'],
                        'options': ['--forms', '--crawl=2'],
                    },
                    'exploitation': {
                        'level': ['3', '4', '5'],
                        'risk': ['2', '3'],
                        'options': ['--forms', '--dbs', '--technique=BEUSTQ'],
                    }
                },
                'conditions': {
                    'sql_injection_confirmed': {
                        'level': '5',
                        'risk': '3',
                        'options': '--dbs --dump',
                    },
                    'waf_detected': {
                        'options': '--tamper=space2comment --random-agent',
                    },
                    'time_critical': {
                        'level': '2',
                        'risk': '2',
                        'options': '--threads=3',
                    }
                }
            },

            'nikto': {
                'base': 'nikto -h {target}',
                'parameters': {
                    'reconnaissance': {
                        'tuning': ['1'],  # Interesting files
                        'options': ['-nossl'],
                    },
                    'scanning': {
                        'tuning': ['123456789'],  # All tests
                        'options': ['-ssl'],
                    }
                },
                'conditions': {
                    'wordpress_detected': {
                        'plugins': '-Plugins wordpress',
                    },
                    'time_critical': {
                        'tuning': '1234',  # Reduced tests
                    }
                }
            },

            'nuclei': {
                'base': 'nuclei -u {target}',
                'parameters': {
                    'scanning': {
                        'severity': ['-severity critical,high', '-severity critical,high,medium'],
                        'options': ['-silent'],
                    },
                    'exploitation': {
                        'severity': ['-severity critical'],
                        'templates': ['-t cves/', '-t vulnerabilities/'],
                    }
                },
                'conditions': {
                    'wordpress_detected': {
                        'templates': '-t wordpress/',
                    },
                    'cms_detected': {
                        'templates': '-t technologies/{cms}/',
                    }
                }
            },

            'amass': {
                'base': 'amass enum -d {domain}',
                'parameters': {
                    'reconnaissance': {
                        'options': ['-passive'],  # Passive enumeration
                    }
                },
                'conditions': {
                    'aggressive_mode': {
                        'options': '-active',  # Active enumeration
                    }
                }
            },

            'dnsenum': {
                'base': 'dnsenum {domain}',
                'parameters': {
                    'reconnaissance': {
                        'options': ['--enum'],  # Enumerate everything
                    }
                },
                'conditions': {
                    'time_critical': {
                        'options': '--threads 5',  # Faster with fewer threads
                    }
                }
            },

            'whatweb': {
                'base': 'whatweb {target}',
                'parameters': {
                    'reconnaissance': {
                        'aggression': ['-a 1', '-a 2'],  # Stealthy to polite
                    },
                    'scanning': {
                        'aggression': ['-a 3'],  # Aggressive
                    }
                },
                'conditions': {
                    'stealth_required': {
                        'aggression': '-a 1',
                    }
                }
            },

            'dalfox': {
                'base': 'dalfox url {target}',
                'parameters': {
                    'exploitation': {
                        'options': ['--silence', '--skip-bav'],
                    }
                },
                'conditions': {
                    'xss_confirmed': {
                        'options': '--deep-domxss --mining-dict',
                    }
                }
            },

            'commix': {
                'base': 'commix --url="{target}" --batch',
                'parameters': {
                    'exploitation': {
                        'level': ['--level=2', '--level=3'],
                        'risk': ['--risk=2'],
                    }
                },
                'conditions': {
                    'command_injection_confirmed': {
                        'level': '--level=3',
                        'risk': '--risk=3',
                    }
                }
            },

            'gobuster': {
                'base': 'gobuster dir -u {target}',
                'parameters': {
                    'scanning': {
                        'wordlist': ['-w /usr/share/dirb/wordlists/common.txt'],
                        'options': ['-q', '-z'],  # Quiet mode
                    },
                    'exploitation': {
                        'wordlist': ['-w /usr/share/dirb/wordlists/big.txt'],
                        'options': ['-q', '-z', '-k'],  # Skip TLS verification
                    }
                },
                'conditions': {
                    'time_critical': {
                        'wordlist': '-w /usr/share/dirb/wordlists/small.txt',
                    }
                }
            },

            'ffuf': {
                'base': 'ffuf -u {target}/FUZZ',
                'parameters': {
                    'scanning': {
                        'wordlist': ['-w /usr/share/dirb/wordlists/common.txt'],
                        'options': ['-s', '-v'],  # Silent mode
                    },
                    'exploitation': {
                        'wordlist': ['-w /usr/share/dirb/wordlists/big.txt:FUZZ'],
                        'options': ['-s', '-v', '-recursion'],
                    }
                },
                'conditions': {
                    'time_critical': {
                        'wordlist': '-w /usr/share/dirb/wordlists/small.txt:FUZZ',
                    }
                }
            },

            'fierce': {
                'base': 'fierce --domain {domain}',
                'parameters': {
                    'reconnaissance': {
                        'options': ['--dnsserver'],  # Use custom DNS server
                    }
                },
                'conditions': {
                    'aggressive_mode': {
                        'options': '--threads 10',
                    }
                }
            },

            'wpscan': {
                'base': 'wpscan --url {target}',
                'parameters': {
                    'scanning': {
                        'options': ['--enumerate vp'],  # Vulnerable plugins
                    },
                    'exploitation': {
                        'options': ['--enumerate u,vp', '--api-token YOUR_API_TOKEN'],  # Users and vulnerable plugins
                    }
                },
                'conditions': {
                    'wordpress_detected': {
                        'options': '--enumerate ap,at,cb,dbe,u,m',  # All enumeration
                    }
                }
            },

            'hydra': {
                'base': 'hydra {target}',
                'parameters': {
                    'exploitation': {
                        'service': ['ssh', 'ftp', 'telnet'],
                        'options': ['-L /usr/share/seclists/Usernames/top-usernames-shortlist.txt'],
                    }
                },
                'conditions': {
                    'specific_service': {
                        'service': '{service}',
                        'options': '-P /usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt',
                    }
                }
            },

            'linpeas': {
                'base': '/usr/share/peass/linpeas/linpeas.sh',
                'parameters': {
                    'post_exploitation': {
                        'options': [''],  # Basic execution
                    }
                },
                'conditions': {
                    'time_critical': {
                        'options': '-s',  # Skip some time-consuming checks
                    }
                }
            },

            'winpeas': {
                'base': '/usr/share/peass/winpeas/winpeas.exe',
                'parameters': {
                    'post_exploitation': {
                        'options': [''],  # Basic execution
                    }
                },
                'conditions': {
                    'time_critical': {
                        'options': 'basic',  # Basic checks only
                    }
                }
            },

            'metasploit': {
                'base': 'msfconsole -q -x "use auxiliary/scanner/portscan/tcp; set RHOSTS {target}; run; exit"',
                'parameters': {
                    'scanning': {
                        'options': [''],  # Basic port scan
                    },
                    'exploitation': {
                        'options': [''],  # Placeholder for specific modules
                    }
                },
                'conditions': {
                    'specific_exploit': {
                        'options': 'use {exploit_module}; set RHOSTS {target}; run; exit',
                    }
                }
            },

            'enum4linux': {
                'base': 'enum4linux {target}',
                'parameters': {
                    'reconnaissance': {
                        'options': ['-a'],  # Do all simple enumeration
                    }
                },
                'conditions': {
                    'smb_detected': {
                        'options': '-S -U -P',  # Share, user, and password policy enumeration
                    }
                }
            },

            'sslscan': {
                'base': 'sslscan {target}',
                'parameters': {
                    'scanning': {
                        'options': ['--no-colour'],  # No color output
                    }
                },
                'conditions': {
                    'tls_issues': {
                        'options': '--xml=/tmp/sslscan.xml',  # XML output
                    }
                }
            },

            'cewl': {
                'base': 'cewl {target}',
                'parameters': {
                    'reconnaissance': {
                        'options': ['-w /tmp/cewl_wordlist.txt'],  # Output to file
                    }
                },
                'conditions': {
                    'custom_wordlist': {
                        'options': '-d 2 -m 5',  # Depth 2, minimum word length 5
                    }
                }
            },
            
            'john': {
                'base': 'john {hash_file}',
                'parameters': {
                    'exploitation': {
                        'mode': ['--wordlist={wordlist}', '--incremental'],
                        'options': ['--format=Raw-SHA256'],
                    }
                },
                'conditions': {
                    'hash_cracking': {
                        'options': '--show',
                    }
                }
            },
            
            'medusa': {
                'base': 'medusa -h {target}',
                'parameters': {
                    'exploitation': {
                        'service': ['-M ssh', '-M ftp', '-M telnet'],
                        'users': ['-U /usr/share/seclists/Usernames/top-usernames-shortlist.txt'],
                        'passwords': ['-P /usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt'],
                    }
                },
                'conditions': {
                    'specific_service': {
                        'service': '-M {service}',
                    }
                }
            },
            
            'crunch': {
                'base': 'crunch {min_length} {max_length}',
                'parameters': {
                    'reconnaissance': {
                        'charset': ['abcdefghijklmnopqrstuvwxyz'],
                        'output': ['-o /tmp/crunch_wordlist.txt'],
                    }
                },
                'conditions': {
                    'custom_charset': {
                        'charset': '{charset}',
                    }
                }
            },
            
            'hashcat': {
                'base': 'hashcat -m {hash_type} {hash_file}',
                'parameters': {
                    'exploitation': {
                        'attack_mode': ['-a 0', '-a 1', '-a 3'],
                        'wordlist': ['/usr/share/seclists/Passwords/Common-Credentials/rockyou.txt'],
                    }
                },
                'conditions': {
                    'specific_hash': {
                        'options': '-O --force',
                    }
                }
            },
            
            'ike-scan': {
                'base': 'ike-scan {target}',
                'parameters': {
                    'scanning': {
                        'options': ['-A'],  # Aggressive mode
                    }
                },
                'conditions': {
                    'vpn_detected': {
                        'options': '--id=group1',
                    }
                }
            },
            
            'arjun': {
                'base': 'arjun -u {target}',
                'parameters': {
                    'reconnaissance': {
                        'options': ['--headers'],  # Find hidden parameters
                    }
                },
                'conditions': {
                    'api_target': {
                        'options': '--json',  # JSON output
                    }
                }
            },
            
            'dirb': {
                'base': 'dirb {target}',
                'parameters': {
                    'scanning': {
                        'wordlist': ['/usr/share/dirb/wordlists/common.txt'],
                        'options': ['-r'],  # Don't recursively scan
                    }
                },
                'conditions': {
                    'time_critical': {
                        'wordlist': '/usr/share/dirb/wordlists/small.txt',
                    }
                }
            },
            
            'nosqlmap': {
                'base': 'nosqlmap -t {target}',
                'parameters': {
                    'exploitation': {
                        'options': ['--attack'],  # Attack mode
                    }
                },
                'conditions': {
                    'nosql_detected': {
                        'options': '--scan',  # Scan mode
                    }
                }
            },
            
            'tplmap': {
                'base': 'tplmap -u "{target}"',
                'parameters': {
                    'exploitation': {
                        'options': ['--level=5'],  # Maximum level
                    }
                },
                'conditions': {
                    'template_injection_confirmed': {
                        'options': '--force-level=10',
                    }
                }
            },
            
            'jwt_tool': {
                'base': 'jwt_tool {jwt_token}',
                'parameters': {
                    'exploitation': {
                        'options': ['--mode=5'],  # Brute force mode
                    }
                },
                'conditions': {
                    'jwt_found': {
                        'options': '--sig-only',  # Signature only
                    }
                }
            },
            
            'shodan': {
                'base': 'shodan search hostname:{domain}',
                'parameters': {
                    'reconnaissance': {
                        'options': ['--fields=ip_str,port,hostnames'],
                    }
                },
                'conditions': {
                    'api_key_available': {
                        'options': '--limit 100',
                    }
                }
            },
            
            'bloodhound-python': {
                'base': 'bloodhound-python -d {domain}',
                'parameters': {
                    'post_exploitation': {
                        'options': ['-c ALL'],  # Collect all data
                    }
                },
                'conditions': {
                    'domain_joined': {
                        'options': '--username {username} --password {password}',
                    }
                }
            },
            
            'burpsuite': {
                'base': 'burpsuite',
                'parameters': {
                    'exploitation': {
                        'options': ['--project-file=/tmp/burp-project.burp'],
                    }
                },
                'conditions': {
                    'web_app_target': {
                        'options': '--config-file=/tmp/burp-config.json',
                    }
                }
            },
            
            'mimikatz': {
                'base': 'mimikatz',
                'parameters': {
                    'post_exploitation': {
                        'options': ['"privilege::debug" "sekurlsa::logonPasswords" exit'],
                    }
                },
                'conditions': {
                    'windows_target': {
                        'options': '"lsadump::sam" exit',
                    }
                }
            },
            
            'weevely': {
                'base': 'weevely generate {password} /tmp/weevely.php',
                'parameters': {
                    'exploitation': {
                        'options': [''],
                    }
                },
                'conditions': {
                    'webshell_needed': {
                        'options': 'weevely {target}/weevely.php {password}',
                    }
                }
            }
        }

    def build_command(self, tool: str, target: str, context: Dict[str, Any]) -> str:
        """
        Build optimal command based on scan context

        Args:
            tool: Tool name (e.g., 'nmap')
            target: Target URL/IP/domain
            context: Full scan context including phase, findings, etc.

        Returns:
            Optimized command string
        """
        # Map tool names to available tools on Kali VM
        tool_mapping = {
            'sublist3r': 'amass',  # Use amass instead of sublist3r
            'theHarvester': 'dnsenum',  # Use dnsenum as alternative
            'linpeas.sh': 'linpeas',  # Normalize name
        }
        
        # Use the mapped tool if available
        actual_tool = tool_mapping.get(tool, tool)
        
        if actual_tool not in self.command_templates:
            logger.warning(f"[ToolKB] No template for {actual_tool}, using default")
            return f"{actual_tool} {target}"

        template = self.command_templates[actual_tool]
        phase = context.get('phase', 'reconnaissance')

        # Start with base command
        # Create format dictionary with target, domain, and all context variables
        format_dict = {'target': target, 'domain': self._extract_domain(target)}
        format_dict.update(context)  # Add all context variables
        command = template['base'].format(**format_dict)

        # Add phase-specific parameters
        if phase in template.get('parameters', {}):
            phase_params = template['parameters'][phase]
            command = self._add_parameters(command, phase_params, context)

        # Apply conditional parameters based on context
        if 'conditions' in template:
            command = self._apply_conditions(command, template['conditions'], context)

        # Apply learned parameters
        command = self._apply_learned_parameters(command, actual_tool, context)

        logger.info(f"[ToolKB] Generated command for {actual_tool}: {command[:100]}...")

        return command

    def _extract_domain(self, target: str) -> str:
        """Extract domain from URL"""
        # Remove protocol
        domain = re.sub(r'https?://', '', target)
        # Remove path
        domain = domain.split('/')[0]
        # Remove port
        domain = domain.split(':')[0]
        return domain

    def _add_parameters(self, command: str, params: Dict, context: Dict) -> str:
        """Add phase-specific parameters to command"""
        for param_type, options in params.items():
            # Choose best option based on context
            if isinstance(options, list) and options:
                # For now, use most aggressive option in exploitation phase
                # Use most conservative in reconnaissance
                phase = context.get('phase')
                if phase == 'exploitation':
                    chosen = options[-1]  # Most aggressive
                elif phase == 'reconnaissance':
                    chosen = options[0]  # Most conservative
                else:
                    chosen = options[len(options)//2]  # Middle ground

                # Special handling for nmap - avoid combining -sn with port specs
                if 'nmap' in command and param_type == 'scan_type' and chosen == '-sn':
                    # Check if ports parameter will be added
                    if 'ports' in params:
                        # Skip -sn and use -sV instead for reconnaissance
                        chosen = '-sV'
                
                # Special handling for linpeas - don't add empty options
                if chosen.strip():  # Only add non-empty options
                    command += f" {chosen}"
        return command

    def _apply_conditions(self, command: str, conditions: Dict, context: Dict) -> str:
        """Apply conditional parameters based on scan context"""
        findings = context.get('findings', [])

        # Check for specific vulnerabilities
        vuln_types = [f.get('type') for f in findings]

        if 'sql_injection' in vuln_types and 'sql_injection_confirmed' in conditions:
            for param, value in conditions['sql_injection_confirmed'].items():
                command += f" {value}"

        if 'xss' in vuln_types and 'xss_confirmed' in conditions:
            for param, value in conditions['xss_confirmed'].items():
                command += f" {value}"

        # Check for WAF
        if context.get('waf_detected') and 'waf_detected' in conditions:
            for param, value in conditions['waf_detected'].items():
                command += f" {value}"

        # Check for time constraints
        time_remaining = context.get('time_remaining', 1.0)
        if time_remaining < 0.3 and 'time_critical' in conditions:
            for param, value in conditions['time_critical'].items():
                command += f" {value}"

        # Check for stealth requirements
        if context.get('stealth_required') and 'stealth_required' in conditions:
            for param, value in conditions['stealth_required'].items():
                command += f" {value}"

        # Check for specific technologies
        technologies = context.get('technologies_detected', [])
        if 'wordpress' in technologies and 'wordpress_detected' in conditions:
            for param, value in conditions['wordpress_detected'].items():
                command += f" {value}"

        return command

    def _apply_learned_parameters(self, command: str, tool: str, context: Dict) -> str:
        """Apply parameters learned from previous successful executions"""
        if tool not in self.parameter_effectiveness:
            return command

        # Get best performing parameters for this tool
        tool_history = self.parameter_effectiveness[tool]

        # Find parameters that led to most findings
        best_params = max(tool_history.items(),
                          key=lambda x: x[1].get('findings', 0),
                         default=(None, {}))[0]

        if best_params and best_params not in command:
            command += f" {best_params}"
            logger.info(f"[ToolKB] Applied learned parameter for {tool}: {best_params}")

        return command

    def learn_from_execution(self, tool: str, command: str,
                           findings_count: int, execution_time: float):
        """
        Learn from tool execution results

        Args:
            tool: Tool name
            command: Full command that was executed
            findings_count: Number of vulnerabilities found
            execution_time: Time taken in seconds
        """
        # Map tool names to available tools on Kali VM
        tool_mapping = {
            'sublist3r': 'amass',  # Use amass instead of sublist3r
            'theHarvester': 'dnsenum',  # Use dnsenum as alternative
            'linpeas.sh': 'linpeas',  # Normalize name
        }
        
        # Use the mapped tool for learning
        actual_tool = tool_mapping.get(tool, tool)
        
        if actual_tool not in self.parameter_effectiveness:
            self.parameter_effectiveness[actual_tool] = {}

        # Extract parameters from command
        params = self._extract_parameters(command, actual_tool)

        # Calculate effectiveness score
        # Higher score = more findings in less time
        if execution_time > 0:
            effectiveness = findings_count / (execution_time / 60.0)  # Findings per minute
        else:
            effectiveness = findings_count

        # Store or update effectiveness
        if params not in self.parameter_effectiveness[actual_tool]:
            self.parameter_effectiveness[actual_tool][params] = {
                'uses': 0,
                'findings': 0,
                'avg_time': 0,
                'effectiveness': 0
            }

        stats = self.parameter_effectiveness[actual_tool][params]
        stats['uses'] += 1
        stats['findings'] += findings_count
        stats['avg_time'] = (stats['avg_time'] * (stats['uses'] - 1) + execution_time) / stats['uses']
        stats['effectiveness'] = stats['findings'] / (stats['avg_time'] / 60.0) if stats['avg_time'] > 0 else stats['findings']

        logger.info(f"[ToolKB] Learning: {actual_tool} {params} -> {findings_count} findings in {execution_time:.1f}s (effectiveness: {effectiveness:.2f})")

    def _extract_parameters(self, command: str, tool: str) -> str:
        """Extract parameter string from full command"""
        # Remove base command and target
        parts = command.split()
        if len(parts) <= 2:
            return ""

        # Return everything after tool name and target
        return ' '.join(parts[2:])

    def get_effectiveness_report(self, tool: str) -> Dict:
        """Get effectiveness statistics for a tool"""
        # Map tool names to available tools on Kali VM
        tool_mapping = {
            'sublist3r': 'amass',  # Use amass instead of sublist3r
            'theHarvester': 'dnsenum',  # Use dnsenum as alternative
            'linpeas.sh': 'linpeas',  # Normalize name
        }
        
        # Use the mapped tool for reporting
        actual_tool = tool_mapping.get(tool, tool)
        
        if actual_tool not in self.parameter_effectiveness:
            return {'message': 'No data available'}

        return self.parameter_effectiveness[actual_tool]