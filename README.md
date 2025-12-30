# Optimus - AI-Powered Security Testing Platform

Optimus is an advanced AI-powered security testing platform that combines autonomous scanning, intelligent vulnerability detection, and automated exploitation capabilities.

## Features

- **Autonomous Scanning**: Full automated penetration testing with AI-driven decision making
- **Multi-Phase Approach**: Reconnaissance, scanning, exploitation, and post-exploitation phases
- **Intelligent Tool Selection**: AI-powered tool selection and execution based on target characteristics
- **Real-time Monitoring**: WebSocket-based progress tracking and reporting
- **Vulnerability Chaining**: Advanced exploitation techniques that chain vulnerabilities
- **Self-Learning Parser**: Adaptive output parsing that improves over time
- **LLM Integration**: Uses local LLMs for intelligent analysis and exploit generation

## Architecture

- **Frontend**: React-based dashboard with real-time scan monitoring
- **Backend**: Python Flask API with WebSocket support
- **AI Engine**: Integration with local Ollama models for intelligent analysis
- **Tool Integration**: Supports various security tools (nmap, nmap, sqlmap, nikto, nuclei, etc.)
- **Exploitation Engine**: Automated exploit generation and execution

## Prerequisites

- Python 3.10+
- Node.js 16+
- Ollama (for local LLM integration)
- Kali Linux VM with SSH access
- Git

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/Optimus.git
   cd Optimus
   ```

2. Set up the backend:
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Set up the frontend:
   ```bash
   cd ../frontend
   npm install
   ```

4. Configure environment variables:
   ```bash
   cd ../backend
   cp .env.example .env
   # Edit .env with your configuration
   ```

## Configuration

Key configuration points:

- **Kali VM**: Configure SSH access in `.env`
- **Ollama**: Set up local LLM model (e.g., codellama:7b-instruct)
- **MSF-RPC**: Configure Metasploit RPC if needed

## Usage

1. Start the backend:
   ```bash
   cd backend
   python app.py
   ```

2. Start the frontend:
   ```bash
   cd frontend
   npm run dev
   ```

3. Access the dashboard at `http://localhost:5173`

## Security Considerations

- This tool is designed for authorized penetration testing and security research
- Always ensure you have explicit permission before testing on any system
- Use responsibly and in accordance with local laws and regulations

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License.