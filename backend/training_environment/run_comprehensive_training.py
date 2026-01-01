#!/usr/bin/env python3
"""
Optimus Training Launcher

Easy-to-use launcher for comprehensive training sessions.

Usage:
    python run_comprehensive_training.py                    # Use default config
    python run_comprehensive_training.py --juice-shop       # Train on Juice Shop only
    python run_comprehensive_training.py --vms              # Train on VMs only
    python run_comprehensive_training.py --all              # Train on all targets
    python run_comprehensive_training.py --quick            # Quick training (2 episodes each)
    python run_comprehensive_training.py --intensive        # Intensive training (10 episodes each)
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def print_banner():
    """Print training banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║     ██████╗ ██████╗ ████████╗██╗███╗   ███╗██╗   ██╗███████╗     ║
    ║    ██╔═══██╗██╔══██╗╚══██╔══╝██║████╗ ████║██║   ██║██╔════╝     ║
    ║    ██║   ██║██████╔╝   ██║   ██║██╔████╔██║██║   ██║███████╗     ║
    ║    ██║   ██║██╔═══╝    ██║   ██║██║╚██╔╝██║██║   ██║╚════██║     ║
    ║    ╚██████╔╝██║        ██║   ██║██║ ╚═╝ ██║╚██████╔╝███████║     ║
    ║     ╚═════╝ ╚═╝        ╚═╝   ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝     ║
    ║                                                                   ║
    ║              COMPREHENSIVE TRAINING SESSION v2                    ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def check_target_availability(targets):
    """Check if targets are reachable"""
    import socket
    
    print("\n[Pre-flight] Checking target availability...")
    available = []
    
    for target in targets:
        url = target.get('url') or target.get('ip')
        name = target.get('name', url)
        
        # Parse host and port
        if url.startswith('http'):
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        else:
            host = url.split(':')[0]
            port = int(url.split(':')[1]) if ':' in url else 22
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                print(f"  ✓ {name} ({host}:{port}) - AVAILABLE")
                available.append(target)
            else:
                print(f"  ✗ {name} ({host}:{port}) - NOT REACHABLE")
        except Exception as e:
            print(f"  ✗ {name} ({host}:{port}) - ERROR: {e}")
    
    return available


def get_preset_targets():
    """Get preset target configurations"""
    return {
        'juice_shop': {
            'name': 'OWASP_Juice_Shop',
            'url': 'http://192.168.56.101:3000',
            'type': 'web_application',
        },
        'vm1': {
            'name': 'Vulnerable_VM_1',
            'ip': '192.168.56.102',
            'type': 'linux_server',
        },
        'vm2': {
            'name': 'Vulnerable_VM_2',
            'ip': '192.168.56.103',
            'type': 'linux_server',
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description='Optimus Comprehensive Training Launcher',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_comprehensive_training.py --juice-shop
  python run_comprehensive_training.py --vms --episodes 3
  python run_comprehensive_training.py --all --intensive
  python run_comprehensive_training.py --target http://10.10.10.5 --name HTB_Box
        """
    )
    
    # Target selection
    target_group = parser.add_argument_group('Target Selection')
    target_group.add_argument('--juice-shop', action='store_true', help='Train on OWASP Juice Shop')
    target_group.add_argument('--vms', action='store_true', help='Train on vulnerable VMs')
    target_group.add_argument('--all', action='store_true', help='Train on all targets')
    target_group.add_argument('--target', type=str, help='Custom target URL or IP')
    target_group.add_argument('--name', type=str, default='Custom_Target', help='Name for custom target')
    
    # Training intensity
    intensity_group = parser.add_argument_group('Training Intensity')
    intensity_group.add_argument('--quick', action='store_true', help='Quick training (2 episodes)')
    intensity_group.add_argument('--standard', action='store_true', help='Standard training (5 episodes)')
    intensity_group.add_argument('--intensive', action='store_true', help='Intensive training (10 episodes)')
    intensity_group.add_argument('--episodes', type=int, help='Custom number of episodes per target')
    
    # Feature toggles
    feature_group = parser.add_argument_group('Features')
    feature_group.add_argument('--no-chains', action='store_true', help='Disable chain attack training')
    feature_group.add_argument('--no-evolution', action='store_true', help='Disable parser/command evolution')
    feature_group.add_argument('--no-discovery', action='store_true', help='Disable new tool discovery')
    feature_group.add_argument('--exploration', type=float, default=0.3, help='Exploration rate (0-1)')
    
    # Output
    output_group = parser.add_argument_group('Output')
    output_group.add_argument('--output', type=str, help='Output directory')
    output_group.add_argument('--verbose', action='store_true', help='Verbose logging')
    
    # Advanced
    advanced_group = parser.add_argument_group('Advanced')
    advanced_group.add_argument('--config', type=str, help='Load config from JSON file')
    advanced_group.add_argument('--max-time', type=int, default=1800, help='Max time per episode (seconds)')
    advanced_group.add_argument('--skip-check', action='store_true', help='Skip target availability check')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Build target list
    presets = get_preset_targets()
    targets = []
    
    if args.config:
        # Load from config file
        with open(args.config) as f:
            config = json.load(f)
            targets = config.get('targets', [])
            print(f"[Config] Loaded {len(targets)} targets from {args.config}")
    elif args.target:
        # Custom target
        targets = [{'url': args.target, 'name': args.name, 'type': 'unknown'}]
    elif args.all:
        targets = list(presets.values())
    elif args.juice_shop:
        targets = [presets['juice_shop']]
    elif args.vms:
        targets = [presets['vm1'], presets['vm2']]
    else:
        # Default: all targets
        targets = list(presets.values())
    
    if not targets:
        print("[Error] No targets specified!")
        parser.print_help()
        sys.exit(1)
    
    # Check target availability
    if not args.skip_check:
        targets = check_target_availability(targets)
        if not targets:
            print("\n[Error] No targets available! Please ensure VMs are running.")
            sys.exit(1)
    
    # Determine episodes
    if args.episodes:
        episodes = args.episodes
    elif args.quick:
        episodes = 2
    elif args.intensive:
        episodes = 10
    else:
        episodes = 5  # Standard
    
    # Build training config
    config = {
        'targets': targets,
        'episodes_per_target': episodes,
        'max_time_per_episode': args.max_time,
        'exploration_rate': args.exploration,
        'enable_chain_attacks': not args.no_chains,
        'enable_parser_evolution': not args.no_evolution,
        'enable_command_evolution': not args.no_evolution,
        'enable_web_intel': True,
        'enable_new_tool_discovery': not args.no_discovery,
        'output_dir': args.output or f'training_output/session_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
    }
    
    # Print training plan
    print("\n" + "="*60)
    print("TRAINING PLAN")
    print("="*60)
    print(f"Targets: {len(targets)}")
    for t in targets:
        print(f"  - {t.get('name')}: {t.get('url') or t.get('ip')}")
    print(f"Episodes per target: {episodes}")
    print(f"Total episodes: {len(targets) * episodes}")
    print(f"Estimated time: {len(targets) * episodes * 15}-{len(targets) * episodes * 30} minutes")
    print(f"Features:")
    print(f"  - Chain attacks: {'✓' if config['enable_chain_attacks'] else '✗'}")
    print(f"  - Parser evolution: {'✓' if config['enable_parser_evolution'] else '✗'}")
    print(f"  - Tool discovery: {'✓' if config['enable_new_tool_discovery'] else '✗'}")
    print(f"  - Exploration rate: {config['exploration_rate']:.0%}")
    print(f"Output: {config['output_dir']}")
    print("="*60)
    
    # Confirm
    try:
        response = input("\nProceed with training? [Y/n]: ").strip().lower()
        if response and response != 'y':
            print("Training cancelled.")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\nTraining cancelled.")
        sys.exit(0)
    
    # Import and run training
    print("\n[Starting] Initializing training session...")
    
    try:
        from training_environment.comprehensive_training_v2 import (
            ComprehensiveTrainer, TrainingConfig
        )
        
        training_config = TrainingConfig(**config)
        trainer = ComprehensiveTrainer(training_config)
        
        if not trainer.initialize():
            print("[Error] Failed to initialize trainer!")
            sys.exit(1)
        
        summary = trainer.run_training()
        
        print("\n" + "="*60)
        print("TRAINING COMPLETE!")
        print("="*60)
        print(f"Results saved to: {config['output_dir']}")
        print(f"Total reward: {summary['total_reward']:.2f}")
        print(f"Findings: {summary['metrics']['total_findings']}")
        print(f"Chains successful: {summary['metrics']['chains_successful']}/{summary['metrics']['chains_attempted']}")
        
    except KeyboardInterrupt:
        print("\n[Interrupted] Training stopped by user.")
        print("Checkpoint saved. You can resume later.")
    except Exception as e:
        print(f"\n[Error] Training failed: {e}")
        raise


if __name__ == '__main__':
    main()
