# Autonomous Pentest Agent Training System

## Overview

The training system enables the autonomous penetration testing agent to learn from live execution results on practice VMs. It consists of several key components:

1. **Training Session Manager** - Orchestrates complete training sessions
2. **Real-time Learning Module** - Learns from tool execution results
3. **Strategy Selector** - Adapts scanning strategies based on performance
4. **Data Collection** - Gathers comprehensive execution metrics

## Directory Structure

```
backend/training_environment/
├── __init__.py
├── session_manager.py          # Training session orchestration
├── train_agent_on_vms.py       # Main training script
├── test_training.py            # Simple training test
├── test_training_components.py # Unit tests
└── demo_training.py            # Training system demonstration
```

## Key Components

### 1. Training Session Manager

Manages end-to-end training sessions for the autonomous agent:

- Executes scans against practice VMs
- Collects execution data (tool outputs, timings, findings)
- Feeds results back to learning modules
- Updates models based on performance
- Generates training reports

### 2. Real-time Learning Module

Enhanced with live execution feedback:

- Context-aware effectiveness tracking
- Performance-based recommendations
- Alternative tool suggestions
- Best tool selection for specific contexts

### 3. Strategy Selector

Adaptive strategy selection based on learned performance:

- Performance tracking for all strategies
- Context-aware strategy selection
- Performance-based recommendations
- Strategy effectiveness reporting

## Usage

### Running Training Sessions

To train the agent on practice VMs:

```bash
python backend/training_environment/train_agent_on_vms.py \
    --targets http://192.168.131.128 https://landscape.canonical.com \
    --episodes 50 \
    --learning-mode mixed \
    --output-dir training_results/20251129_120000
```

### Parameters

- `--targets`: List of target VM URLs/IPs
- `--episodes`: Number of training episodes (default: 50)
- `--learning-mode`: Learning mode ('exploration', 'exploitation', 'mixed')
- `--output-dir`: Output directory for results

### Testing Components

Run unit tests:

```bash
python -m pytest backend/training_environment/test_training_components.py -v
```

Run demonstration:

```bash
python backend/training_environment/demo_training.py
```

## Training Phases

1. **Exploration Phase**: Agent tries different tools and strategies
2. **Model Update Phase**: Models are updated based on exploration data
3. **Exploitation Phase**: Agent uses learned best practices
4. **Mixed Training Phase**: Balance exploration and exploitation
5. **Final Model Update**: Comprehensive model retraining

## Data Collection

The system collects comprehensive data from each tool execution:

- Tool name and parameters used
- Execution time and success/failure status
- Vulnerabilities found and parse quality
- Resource usage metrics

## Learning Feedback Loop

1. Tool execution results are fed to the learning module
2. Strategy selector updates performance metrics
3. Agent adapts tool selection based on learned effectiveness
4. Models are periodically retrained with new data

## Output Files

Training results are saved to the specified output directory:

- `training_results_*.json`: Comprehensive training session results
- `training_checkpoint.json`: Progress checkpoints for resume capability
- Strategy performance reports
- Episode execution histories

## Best Practices

1. Start with fewer episodes for initial testing
2. Use exploration mode to discover effective tool combinations
3. Monitor training progress through checkpoint files
4. Review strategy reports to understand agent performance
5. Use mixed mode for balanced learning and exploitation