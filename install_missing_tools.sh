#!/bin/bash
# Script to install missing pentest tools on Kali VM

echo "🔐 Installing missing pentest tools on Kali VM..."

# Update package list
echo "🔄 Updating package list..."
sudo apt update

# Install Go if not already installed
if ! command -v go &> /dev/null; then
    echo "📥 Installing Go..."
    sudo apt install -y golang
else
    echo "✅ Go is already installed"
fi

# Ensure GOPATH is set
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Create Go bin directory if it doesn't exist
mkdir -p $GOPATH/bin

# Install missing tools using Go
echo "📥 Installing missing tools using Go..."

# Nuclei
echo "📥 Installing nuclei..."
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Httpx
echo "📥 Installing httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Httprobe
echo "📥 Installing httprobe..."
go install -v github.com/tomnomnom/httprobe@latest

# Katana
echo "📥 Installing katana..."
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Gospider
echo "📥 Installing gospider..."
go install -v github.com/projectdiscovery/gospider@latest

# Arjun
echo "📥 Installing arjun..."
go install -v github.com/s0md3v/Arjun@latest

# Netlas
echo "📥 Installing netlas..."
# Note: Netlas might not be available via Go install, try pip as alternative
pip3 install netlas || echo "⚠️ Failed to install netlas via pip"

# Onyphe
echo "📥 Installing onyphe..."
# Note: Onyphe might not be available via Go install, try pip as alternative
pip3 install onyphe || echo "⚠️ Failed to install onyphe via pip"

# XSSer
echo "📥 Installing xsser..."
# XSSer is not typically installed via Go, try apt as alternative
sudo apt install -y xsser || echo "⚠️ Failed to install xsser via apt"

# Verify installations
echo "✅ Verifying installations..."
echo "=================================="

TOOLS_TO_CHECK=("nuclei" "httpx" "httprobe" "katana" "gospider" "arjun" "netlas" "onyphe" "xsser")
for tool in "${TOOLS_TO_CHECK[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo "✅ $tool: $(which $tool)"
    else
        echo "❌ $tool: Not found"
    fi
done

# Add Go bin to PATH permanently
echo "📝 Adding Go bin to PATH..."
echo "export GOPATH=\$HOME/go" >> ~/.bashrc
echo "export PATH=\$PATH:\$GOPATH/bin" >> ~/.bashrc

echo "✅ Installation complete!"
echo ""
echo "📝 To make the PATH changes effective, either:"
echo "   1. Restart your terminal session, or"
echo "   2. Run: source ~/.bashrc"
echo ""
echo "🧪 To verify all tools are accessible, run:"
echo "   which nuclei httpx httprobe katana gospider arjun netlas onyphe xsser"