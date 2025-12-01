# Kali VM Tool Installation and Configuration Summary

## Current Status

### Tools Installed and Accessible
- ✅ **dalfox**: Installed in `/home/kali/go/bin/dalfox` (executable)
- ✅ **subfinder**: Installed in `/home/kali/go/bin/subfinder` (executable)
- ✅ **nmap**: Standard Kali tool
- ✅ **nikto**: Standard Kali tool
- ✅ **sqlmap**: Standard Kali tool
- ✅ **commix**: Standard Kali tool
- ✅ **amass**: Standard Kali tool
- ✅ **dnsenum**: Standard Kali tool
- ✅ **whatweb**: Standard Kali tool
- ✅ **gobuster**: Standard Kali tool
- ✅ **ffuf**: Standard Kali tool
- ✅ **fierce**: Standard Kali tool
- ✅ **wpscan**: Standard Kali tool
- ✅ **hydra**: Standard Kali tool
- ✅ **metasploit**: Standard Kali tool
- ✅ **enum4linux**: Standard Kali tool
- ✅ **sslscan**: Standard Kali tool
- ✅ **cewl**: Standard Kali tool

### Tools Still Missing
- ❌ **arjun**
- ❌ **gospider**
- ❌ **httprobe**
- ❌ **katana**
- ❌ **netlas**
- ❌ **nuclei**
- ❌ **onyphe**
- ❌ **xsser**

## Changes Made

### 1. Updated ToolManager to Support Go Bin Directory
Modified the [ToolManager](file:///d:/Work/Ai%20Engineering/Git/Optimus/backend/inference/tool_manager.py#L21-L839) class in `backend/inference/tool_manager.py` to:
- Explicitly check for tools in `/home/kali/go/bin` directory
- Updated both [_build_default_command](file:///d:/Work/Ai%20Engineering/Git/Optimus/backend/inference/tool_manager.py#L597-L639) and [_fallback_command](file:///d:/Work/Ai%20Engineering/Git/Optimus/backend/inference/tool_manager.py#L640-L680) methods
- Added specific paths for Go tools like subfinder, gospider, katana, etc.

### 2. Updated PATH Configuration
- Added `/home/kali/go/bin` and `/root/go/bin` to the PATH in `.bashrc`
- This allows tools to be found when running new terminal sessions

## Next Steps

### 1. Install Missing Tools
To fully utilize the agent's capabilities, install the remaining 8 tools:

```bash
# Install missing tools using Go
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/httprobe@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/gospider@latest
go install github.com/projectdiscovery/netlas@latest
go install github.com/projectdiscovery/onyphe@latest
go install github.com/hahwul/dalfox/v2@latest
go install https://github.com/PortSwigger/xsser@latest
go install https://github.com/s0md3v/Arjun@latest
```

### 2. Verify Installation
After installing the tools, verify they are accessible:
```bash
# Check if tools are in PATH
which arjun gospider httprobe katana netlas nuclei onyphe xsser
```

### 3. Restart Kali VM or Source .bashrc
To make PATH changes effective:
```bash
# Either restart the Kali VM or source .bashrc
source ~/.bashrc
```

## Agent Capabilities

With these changes, the agent can now:
1. Access tools installed in standard Kali locations
2. Access tools installed in Go bin directories
3. Dynamically generate commands based on scan context
4. Fall back to alternative tools when primary tools are missing
5. Handle API key requirements for tools that need them

## Testing

To verify the changes work correctly:
1. Run the pentest agent in autonomous mode
2. Check that tools in Go bin directories are properly executed
3. Verify that command generation works for all tool types
4. Confirm that fallback mechanisms work when tools are missing