# Tool Command Templates Summary

## Overview
The Tool Knowledge Base contains command templates for 35 tools, while the Dynamic Tool Database has 22 tools. 12 tools have templates but are not in the database, and 10 tools in the database don't have templates.

## Tools with Command Templates (35)

### Network Scanning
- **nmap**: Port scanning with phase-specific parameters
  - Reconnaissance: `-sn`, `-sV`, `-T2`, `-T3`, ports `80,443` or `1-1000`
  - Scanning: `-sV`, `-sS -sV`, `-T4`, all ports, vulnerability scripts
  - Exploitation: `-sV -sC`, specific ports
  - Conditions: WAF detection, time-critical scenarios

- **masscan**: High-speed port scanning (in database but no template)
- **ike-scan**: VPN/IPsec scanning

### Web Application Scanning
- **nikto**: Web server scanner
  - Reconnaissance: Tuning level 1, `-nossl`
  - Scanning: All tests, `-ssl`
  - Conditions: WordPress detection, time-critical scenarios

- **nuclei**: Template-based vulnerability scanner
  - Scanning: Critical/high severity, silent mode
  - Exploitation: Critical severity, CVE/vulnerability templates
  - Conditions: WordPress/CMS detection

- **sqlmap**: SQL injection testing
  - Reconnaissance: Level 1, risk 1, form scanning
  - Scanning: Level 2, risk 2, crawling
  - Exploitation: Levels 3-5, risk 2-3, all techniques
  - Conditions: Confirmed SQLi, WAF detection, time-critical

- **dalfox**: XSS scanning
  - Exploitation: Silent mode, skip BAV
  - Conditions: Confirmed XSS

- **commix**: Command injection testing
  - Exploitation: Level 2-3, risk 2
  - Conditions: Confirmed command injection

### Directory/Content Discovery
- **gobuster**: Directory brute-forcing
  - Scanning: Common wordlists, quiet mode
  - Exploitation: Big wordlists, TLS skip
  - Conditions: Time-critical (small wordlists)

- **ffuf**: Fuzzing tool
  - Scanning: Common wordlists, silent mode
  - Exploitation: Big wordlists, recursion
  - Conditions: Time-critical (small wordlists)

- **dirb**: Web content scanner
  - Scanning: Common wordlists, no recursion
  - Conditions: Time-critical (small wordlists)

- **wfuzz**: Web fuzzer (in database but no template)

### Subdomain Enumeration
- **amass**: Subdomain enumeration
  - Reconnaissance: Passive enumeration
  - Conditions: Aggressive mode

- **sublist3r**: Subdomain finder (in database but no template, mapped to amass)
- **subfinder**: Subdomain enumeration (in database but no template)
- **theHarvester**: Email/employee discovery (in database but no template, mapped to dnsenum)
- **fierce**: DNS enumeration
- **dnsenum**: DNS enumeration (used as alternative for theHarvester)

### CMS Scanning
- **wpscan**: WordPress security scanner
  - Scanning: Vulnerable plugin enumeration
  - Exploitation: User and plugin enumeration, API token
  - Conditions: WordPress detection (full enumeration)

### Authentication Testing
- **hydra**: Login brute-forcing
  - Exploitation: SSH/FTP/telnet, username/password lists
  - Conditions: Specific service targeting

- **medusa**: Login brute-forcing
  - Exploitation: Service-specific, user/password lists
  - Conditions: Specific service targeting

- **john**: Password cracker
  - Exploitation: Wordlist or incremental mode, Raw-SHA256
  - Conditions: Hash cracking (show mode)

- **hashcat**: Password cracker
  - Exploitation: Various attack modes, rockyou wordlist
  - Conditions: Specific hash types

### Privilege Escalation
- **linpeas**: Linux privilege escalation checker
  - Post-exploitation: Basic execution
  - Conditions: Time-critical (skip checks)

- **winpeas**: Windows privilege escalation checker
  - Post-exploitation: Basic execution
  - Conditions: Time-critical (basic checks only)

- **bloodhound-python**: Active Directory visualization
  - Post-exploitation: All data collection
  - Conditions: Domain-joined systems

### Frameworks/Platforms
- **metasploit**: Exploitation framework
  - Scanning: Port scan modules
  - Exploitation: Placeholder for specific modules
  - Conditions: Specific exploit targeting

- **burpsuite**: Web application security testing
  - Exploitation: Project file configuration
  - Conditions: Web application targets

### System Enumeration
- **enum4linux**: SMB/Windows enumeration
  - Reconnaissance: All simple enumeration
  - Conditions: SMB detection (specific enumeration)

- **whatweb**: Web technology detection
  - Reconnaissance: Stealthy to polite scanning
  - Scanning: Aggressive scanning
  - Conditions: Stealth requirements

- **sslscan**: SSL/TLS scanning
  - Scanning: No color output
  - Conditions: TLS issues (XML output)

### Wordlist Generation
- **cewl**: Custom wordlist generator
  - Reconnaissance: Output to file
  - Conditions: Custom wordlist parameters

- **crunch**: Wordlist generator
  - Reconnaissance: Character set, output file
  - Conditions: Custom character sets

### Specialized Tools
- **arjun**: Hidden parameter discovery
  - Reconnaissance: Header analysis
  - Conditions: API targets (JSON output)

- **nosqlmap**: NoSQL database exploitation
  - Exploitation: Attack mode
  - Conditions: NoSQL detection (scan mode)

- **tplmap**: Template injection testing
  - Exploitation: Maximum level
  - Conditions: Confirmed template injection

- **jwt_tool**: JWT token analysis
  - Exploitation: Brute force mode
  - Conditions: JWT found (signature only)

- **shodan**: Internet device search
  - Reconnaissance: Hostname search, specific fields
  - Conditions: API key available (increased limit)

- **mimikatz**: Windows credential extraction
  - Post-exploitation: Debug privilege, logon passwords
  - Conditions: Windows targets (SAM dump)

- **weevely**: Web shell generator
  - Exploitation: Generate PHP shell
  - Conditions: Web shell needed (execute shell)

## Tools in Database Without Templates (10)
1. **masscan** - High-speed port scanner
2. **sublist3r** - Subdomain enumeration (mapped to amass)
3. **subfinder** - Subdomain enumeration
4. **theHarvester** - Email/employee discovery (mapped to dnsenum)
5. **gospider** - Web crawler
6. **katana** - Web crawler
7. **wfuzz** - Web fuzzer
8. **httprobe** - HTTP endpoint verification
9. **netlas** - Network scanner
10. **onyphe** - Network scanner

## Tools with Templates Not in Database (12)
1. **dnsenum** - DNS enumeration (alternative for theHarvester)
2. **gobuster** - Directory brute-forcing
3. **fierce** - DNS enumeration
4. **hydra** - Login brute-forcing
5. **winpeas** - Windows privilege escalation
6. **metasploit** - Exploitation framework
7. **enum4linux** - SMB/Windows enumeration
8. **sslscan** - SSL/TLS scanning
9. **cewl** - Custom wordlist generator
10. **john** - Password cracker
11. **medusa** - Login brute-forcing
12. **crunch** - Wordlist generator
13. **hashcat** - Password cracker
14. **dirb** - Web content scanner
15. **nosqlmap** - NoSQL exploitation
16. **tplmap** - Template injection
17. **jwt_tool** - JWT analysis
18. **bloodhound-python** - AD visualization
19. **burpsuite** - Web application testing
20. **mimikatz** - Windows credential extraction
21. **weevely** - Web shell generator

## Template Features

### Phase-Based Parameters
Templates adapt based on scan phase:
- **Reconnaissance**: Stealthy, limited scope
- **Scanning**: Comprehensive, thorough
- **Exploitation**: Aggressive, targeted
- **Post-Exploitation**: Local checks only

### Contextual Conditions
Templates adjust based on:
- Vulnerability findings (SQLi, XSS, etc.)
- WAF detection
- Time constraints
- Stealth requirements
- Technology detection (WordPress, CMS, etc.)

### Learning Integration
Templates incorporate learned effectiveness data to optimize future executions.