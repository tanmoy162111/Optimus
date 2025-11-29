# Optimus AI Agent

An autonomous penetration testing system that intelligently selects and executes security tools based on context and learned knowledge.

## Overview

The Optimus AI Agent is designed to automate the penetration testing process by dynamically adapting its approach based on findings and environmental factors. Unlike traditional scanners with fixed tool lists, the AI agent learns from execution results to improve future decisions.

## Key Features

- **Autonomous Scanning**: Automatically selects and executes appropriate security tools
- **Dynamic Tool Selection**: Chooses tools based on current scan state and findings
- **Continuous Learning**: Improves decision-making through machine learning
- **Adaptive Strategy**: Adjusts approach based on environmental feedback
- **Comprehensive Reporting**: Generates detailed security reports with remediation guidance

## Architecture

The system consists of several core components:

1. **Autonomous Pentest Agent** - Main orchestrator that drives the penetration testing process
2. **Dynamic Tool Database** - Central repository of all penetration testing tools with metadata
3. **Knowledge Base** - Persistent storage of security knowledge and vulnerability patterns
4. **Decision Engine** - AI-powered component that makes strategic choices
5. **Continuous Learning Module** - Records and analyzes execution results to improve future decisions

## Training System

The agent includes a comprehensive training system that enables it to learn from live execution results on practice VMs:

- **Training Session Manager** - Orchestrates complete training sessions
- **Real-time Learning Module** - Learns from tool execution results with context awareness
- **Strategy Selector** - Adapts scanning strategies based on performance metrics
- **Data Collection** - Gathers comprehensive execution metrics for analysis

See [Training System Documentation](docs/TRAINING_SYSTEM.md) for detailed information.

## Getting Started

### Prerequisites

- Python 3.8+
- Kali Linux VM for tool execution
- Practice VMs for training (OWASP Juice Shop, DVWA, etc.)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd optimus-ai-agent

# Install dependencies
pip install -r backend/requirements.txt
```

### Configuration

1. Set up the `.env` file with your configuration
2. Configure SSH access to your Kali Linux VM
3. Ensure practice VMs are accessible

### Running the Agent

```bash
# Start the backend service
./start-backend.sh

# Run a scan
python backend/run_scan.py --target http://example.com

# Train the agent
python backend/training_environment/train_agent_on_vms.py --targets http://practice-vm.local --episodes 50
```

## Documentation

- [Agent Architecture](docs/AGENT_ARCHITECTURE.md) - Detailed system architecture
- [Training System](docs/TRAINING_SYSTEM.md) - Training system documentation
- [User Guide](docs/USER_GUIDE_REPORTS.md) - User guide and report examples

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.