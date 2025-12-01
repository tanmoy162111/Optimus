# Kali VM Tool Configuration Summary

## Tools Found on Kali VM

### In [/home/kali/go/bin](file:///home/kali/go/bin):
- dalfox
- gau
- gowitness
- subfinder
- waybackurls

### In [/home/kali/.local/share/pipx/venvs](file:///home/kali/.local/share/pipx/venvs):
- arjun

### Standard Kali Tools:
- nmap: /usr/bin/nmap
- nikto: /usr/bin/nikto
- sqlmap: /usr/bin/sqlmap
- amass: /usr/bin/amass
- dnsenum: /usr/bin/dnsenum
- whatweb: /usr/bin/whatweb
- commix: /usr/bin/commix
- gobuster: /usr/bin/gobuster
- ffuf: /usr/bin/ffuf
- wpscan: /usr/bin/wpscan

## Missing Tools:
- nuclei
- gospider
- httprobe
- katana
- netlas
- onyphe
- xsser

## Agent Configuration Updates

### Tool Path Configuration
Updated the [ToolManager](file:///d:/Work/Ai%20Engineering/Git/Optimus/backend/inference/tool_manager.py#L21-L839) in `backend/inference/tool_manager.py` to use the correct paths for installed tools:
- dalfox: [/home/kali/go/bin/dalfox](file:///home/kali/go/bin/dalfox)
- subfinder: [/home/kali/go/bin/subfinder](file:///home/kali/go/bin/subfinder)
- arjun: [/home/kali/.local/share/pipx/venvs/arjun/bin/arjun](file:///home/kali/.local/share/pipx/venvs/arjun/bin/arjun)

### Fallback Tool Mapping
Added fallback mappings for missing tools:
- nuclei → nikto
- gospider → whatweb
- katana → whatweb
- httprobe → whatweb
- netlas → nmap
- onyphe → nmap
- xsser → dalfox

### Tool Command Templates
Updated command templates to work with the available tools:
- nuclei commands now use nikto syntax
- All tools use their correct installation paths

## Verification
The agent can now:
1. Access all installed tools using their correct paths
2. Fall back to alternative tools when primary tools are missing
3. Generate appropriate commands for all tool types
4. Work with the 16 tools currently installed on the Kali VM

## Next Steps
To fully utilize all 23 tools the agent knows about, install the 7 missing tools:
```bash
# Install missing tools
sudo apt install nuclei xsser
# Install Go tools
go install github.com/projectdiscovery/gospider@latest
go install github.com/tomnomnom/httprobe@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
# Install using pip
pip3 install netlas onyphe
```