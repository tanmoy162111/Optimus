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
                        'options': ['--max-retries 3', '--host-timeout 10m'],
                    },
                    'scanning': {
                        'scan_type': ['-sV', '-sS -sV'],  # Version + service detection
                        'timing': ['-T4'],
                        'ports': ['-p 1-65535', '-p-'],  # All ports
                        'scripts': ['--script=vuln', '--script=default,vuln'],
                        'options': ['--max-retries 5', '--host-timeout 30m', '--defeat-rst-ratelimit'],
                    },
                    'exploitation': {
                        'scan_type': ['-sV -sC'],
                        'timing': ['-T4'],
                        'ports': ['-p {specific_port}'],  # Target specific port
                        'options': ['--max-retries 4', '--host-timeout 20m'],
                    }
                },
                'conditions': {
                    'waf_detected': {
                        'timing': '-T2',  # Slower
                        'scan_type': '-sS',  # Stealth SYN scan
                        'options': '--defeat-rst-ratelimit',
                    },
                    'time_critical': {
                        'timing': '-T5',
                        'ports': '--top-ports 100',
                        'options': '--max-retries 2',
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
                },
                'notes': 'linpeas is a LOCAL privilege escalation checker that should only be run on compromised targets, not as a remote scanner'
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
                },
                'notes': 'winpeas is a LOCAL privilege escalation checker for Windows that should only be run on compromised targets, not as a remote scanner'
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
            
            'subfinder': {
                'base': 'subfinder -d {domain}',
                'parameters': {
                    'reconnaissance': {
                        'options': ['-silent'],  # Silent mode
                    }
                },
                'conditions': {
                    'aggressive_mode': {
                        'options': '-recursive',  # Recursive enumeration
                    }
                }
            },
            
            'gospider': {
                'base': 'gospider -s {target}',
                'parameters': {
                    'scanning': {
                        'options': ['-q', '-w'],  # Quiet mode with sitemap
                    }
                },
                'conditions': {
                    'deep_crawl': {
                        'options': '-d 3',  # Depth 3 crawling
                    }
                }
            },
            
            'katana': {
                'base': 'katana -u {target}',
                'parameters': {
                    'scanning': {
                        'options': ['-silent', '-jc'],  # Silent mode with js crawler
                    }
                },
                'conditions': {
                    'deep_crawl': {
                        'options': '-d 5',  # Depth 5 crawling
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
            
            'httprobe': {
                'base': 'httprobe',
                'parameters': {
                    'reconnaissance': {
                        'options': [''],  # Basic execution
                    }
                },
                'conditions': {
                    'fast_check': {
                        'options': '-c 50',  # 50 concurrent connections
                    }
                }
            },
            
            'netlas': {
                'base': 'netlas query "domain:{domain}"',
                'parameters': {
                    'reconnaissance': {
                        'options': [''],  # Basic query
                    }
                },
                'conditions': {
                    'detailed_scan': {
                        'options': '-f json',  # JSON output
                    }
                }
            },
            
            'onyphe': {
                'base': 'onyphe -s {target}',
                'parameters': {
                    'reconnaissance': {
                        'options': [''],  # Basic scan
                    }
                },
                'conditions': {
                    'full_scan': {
                        'options': '-a',  # All modules
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
            },
            
            # ADD THESE MISSING TOOLS:
            'sublist3r': {
                'base': 'sublist3r -d {domain}',
                'parameters': {
                    'reconnaissance': {
                        'options': ['-o /tmp/sublist3r_output.txt'],
                    }
                }
            },
            
            'theHarvester': {
                'base': 'theHarvester -d {domain} -b all',
                'parameters': {
                    'reconnaissance': {
                        'options': ['-l 500'],
                    }
                }
            },
            
            'fierce': {
                'base': 'fierce --domain {domain}',
                'parameters': {
                    'reconnaissance': {
                        'options': ['--subdomains'],
                    }
                }
            },
            
            'enum4linux': {
                'base': 'enum4linux -a {target}',
                'parameters': {
                    'reconnaissance': {
                        'options': [],
                    },
                    'scanning': {
                        'options': ['-U', '-S', '-P'],
                    }
                }
            },
            
            'sslscan': {
                'base': 'sslscan {target}',
                'parameters': {
                    'scanning': {
                        'options': ['--no-colour'],
                    }
                }
            },
            
            'wpscan': {
                'base': 'wpscan --url {target}',
                'parameters': {
                    'scanning': {
                        'options': ['--enumerate vp,vt,u', '--random-user-agent'],
                    }
                }
            },
            
            'hydra': {
                'base': 'hydra -L /usr/share/wordlists/metasploit/http_default_users.txt -P /usr/share/wordlists/metasploit/http_default_pass.txt {target}',
                'parameters': {
                    'exploitation': {
                        'options': ['-t 4', '-f'],
                    }
                }
            },
            
            'metasploit': {
                'base': 'msfconsole -q -x "{commands}"',
                'parameters': {
                    'exploitation': {
                        'commands': ['use auxiliary/scanner/portscan/tcp', 'set RHOSTS {target}', 'run', 'exit'],
                    }
                }
            },
            
            'xsser': {
                'base': 'xsser -u {target}',
                'parameters': {
                    'exploitation': {
                        'options': ['--auto', '--reverse-check'],
                    }
                }
            },
            
            'dirb': {
                'base': 'dirb {target}',
                'parameters': {
                    'scanning': {
                        'options': ['/usr/share/dirb/wordlists/common.txt'],
                    }
                }
            },
            
            'masscan': {
                'base': 'masscan {target}',
                'parameters': {
                    'scanning': {
                        'options': ['-p1-65535', '--rate=1000'],
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
            # Add mappings for missing tools to alternatives that are available
            'dalfox': 'xsser',  # Use xsser as alternative to dalfox
            'nuclei': 'nikto',  # Use nikto as alternative to nuclei
            'subfinder': 'amass',  # Use amass as alternative to subfinder
            'gospider': 'whatweb',  # Use whatweb as alternative to gospider
            'katana': 'whatweb',  # Use whatweb as alternative to katana
            'arjun': 'whatweb',  # Use whatweb as alternative to arjun
            'httprobe': 'whatweb',  # Use whatweb as alternative to httprobe
            'netlas': 'nmap',  # Use nmap as alternative to netlas
            'onyphe': 'nmap',  # Use nmap as alternative to onyphe
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

    def build_adaptive_command(self, tool: str, target: str, context: Dict[str, Any],
                           findings: List[Dict] = None) -> str:
        """
        Build command that adapts based on findings

        Args:
            tool: Tool name
            target: Target URL/IP
            context: Scan context
            findings: Current findings (vulnerabilities discovered)

        Returns:
            Optimized command string
        """
        findings = findings or []

        # Get base command
        command = self.build_command(tool, target, context)

        # Enhance based on findings
        if findings:
            command = self._enhance_with_findings(command, tool, findings)

        # Enhance based on failed attempts
        tools_executed = context.get('tools_executed', [])
        if tools_executed:
            command = self._enhance_with_history(command, tool, tools_executed)

        return command

    def _enhance_with_findings(self, command: str, tool: str, findings: List[Dict]) -> str:
        """Enhance command based on discovered findings"""

        # Get vulnerability types
        vuln_types = [f.get('type') for f in findings]
        locations = [f.get('location') for f in findings if f.get('location')]

        # Tool-specific enhancements
        if tool == 'sqlmap' and 'sql_injection' in vuln_types:
            # Target specific vulnerable parameter if known
            for finding in findings:
                if finding.get('type') == 'sql_injection':
                    param = finding.get('parameter')
                    if param:
                        # Update sqlmap to target specific parameter
                        if '-p' not in command:
                            command += f' -p {param}'

                        # Increase aggression since we know there's SQL injection
                        if '--level' not in command:
                            command += ' --level=5'
                        if '--risk' not in command:
                            command += ' --risk=3'
                    break

        elif tool == 'nikto' and locations:
            # Target specific paths where vulnerabilities found
            first_location = locations[0]
            if first_location and '/' in first_location:
                path = first_location.split('?')[0]  # Remove query string
                if ' -h ' in command:
                    # Add path targeting
                    pass  # Nikto doesn't need path targeting in the same way

        elif tool == 'nuclei':
            # Use templates matching found vulnerability types
            templates = []
            if 'sql_injection' in vuln_types:
                templates.append('sqli')
            if 'xss' in vuln_types:
                templates.append('xss')
            if 'command_injection' in vuln_types:
                templates.append('rce')

            if templates:
                template_str = ','.join(templates)
                if '-tags' in command:
                    command = re.sub(r'-tags \S+', f'-tags {template_str}', command)
                else:
                    command += f' -tags {template_str}'

        return command

    def _enhance_with_history(self, command: str, tool: str, history: List) -> str:
        """Enhance command based on execution history"""

        # Count how many times this tool has been used
        tool_uses = sum(1 for t in history if
                       (isinstance(t, dict) and t.get('tool') == tool) or t == tool)

        # Increase aggression on repeated use
        if tool_uses > 1:
            if tool == 'nmap':
                # More aggressive port scanning
                if '-T' in command:
                    command = re.sub(r'-T\d', '-T5', command)
                else:
                    command += ' -T5'

                # Expand port range
                if '-p' in command and not '-p-' in command:
                    command = re.sub(r'-p \S+', '-p-', command)
                
                # Add host timeout to prevent hanging
                if '--host-timeout' not in command:
                    command += ' --host-timeout 30m'
                
                # Add additional timeout parameters to handle retransmissions
                if '--max-retries' not in command:
                    command += ' --max-retries 5'  # Increased retries to handle retransmissions
                if '--min-rate' not in command:
                    command += ' --min-rate 100'   # Lower minimum rate for stability
                if '--max-rate' not in command:
                    command += ' --max-rate 2000'  # Maximum packet rate
                if '--scan-delay' not in command:
                    command += ' --scan-delay 50ms'  # Scan delay
                if '--defeat-rst-ratelimit' not in command:
                    command += ' --defeat-rst-ratelimit'  # Defeat reset rate limiting

            elif tool == 'nikto':
                # Enable all tests
                if '-Tuning' not in command:
                    command += ' -Tuning 123456789'

            elif tool in ['gobuster', 'ffuf']:
                # Use larger wordlist
                if tool_uses == 2:
                    command = command.replace('common.txt', 'big.txt')
                elif tool_uses >= 3:
                    command = command.replace('big.txt', 'directory-list-2.3-medium.txt')

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