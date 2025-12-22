#!/usr/bin/env python3
"""
Quick Start Script for Deep RL Training
Run this to start training the RL agent

Usage:
    python run_rl_training.py --target1-ip 192.168.1.100 --target2-ip 192.168.1.101
    python run_rl_training.py --config my_config.json
    python run_rl_training.py --resume checkpoint.pt
"""

import sys
import os
import argparse
import logging

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from training.rl_training_config import RLTrainingConfig, TrainingTarget
from training.deep_rl_trainer import DeepRLTrainer


def setup_logging(verbose: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    
    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    formatter = logging.Formatter('[%(levelname)s] %(message)s')
    console.setFormatter(formatter)
    
    # File handler
    os.makedirs("logs", exist_ok=True)
    file_handler = logging.FileHandler("logs/rl_training.log", encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    
    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(console)
    root_logger.addHandler(file_handler)


def create_config_from_args(args) -> RLTrainingConfig:
    """Create training config from command line arguments"""
    config = RLTrainingConfig()
    
    # Clear default targets
    config.targets = []
    
    # Add target 1 (Juice Shop)
    if args.target1_ip:
        config.targets.append(TrainingTarget(
            name=args.target1_name or "Target 1 (Juice Shop)",
            host=args.target1_ip,
            port=args.target1_port or 3000,
            target_type="web",
            difficulty="medium",
            known_vulns=["sql_injection", "xss", "broken_auth"],
            enabled=True
        ))
    
    # Add target 2 (DVWA)
    if args.target2_ip:
        config.targets.append(TrainingTarget(
            name=args.target2_name or "Target 2 (DVWA)",
            host=args.target2_ip,
            port=args.target2_port or 80,
            target_type="web",
            difficulty="easy",
            known_vulns=["sql_injection", "xss", "command_injection"],
            enabled=True
        ))
    
    # Override episodes if specified
    if args.episodes:
        config.episodes_per_target = args.episodes
    
    # Override max time if specified
    if args.max_time:
        config.max_time_per_episode = args.max_time
    
    return config


def main():
    parser = argparse.ArgumentParser(
        description="Train Deep RL Agent for Optimus",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Train on two VMs
  python run_rl_training.py --target1-ip 192.168.1.100 --target2-ip 192.168.1.101
  
  # Train with custom settings
  python run_rl_training.py --target1-ip 192.168.1.100 --episodes 100 --max-time 3600
  
  # Resume from checkpoint
  python run_rl_training.py --resume backend/data/models/deep_rl/checkpoint.pt
  
  # Use config file
  python run_rl_training.py --config training_config.json
        """
    )
    
    # Target 1 arguments
    parser.add_argument("--target1-ip", help="IP address of first training target (e.g., Juice Shop)")
    parser.add_argument("--target1-port", type=int, default=3000, help="Port for target 1 (default: 3000)")
    parser.add_argument("--target1-name", default="OWASP Juice Shop", help="Name for target 1")
    
    # Target 2 arguments
    parser.add_argument("--target2-ip", help="IP address of second training target (e.g., DVWA)")
    parser.add_argument("--target2-port", type=int, default=80, help="Port for target 2 (default: 80)")
    parser.add_argument("--target2-name", default="DVWA", help="Name for target 2")
    
    # Training arguments
    parser.add_argument("--episodes", type=int, default=50, help="Episodes per target (default: 50)")
    parser.add_argument("--max-time", type=int, default=1800, help="Max seconds per episode (default: 1800)")
    parser.add_argument("--config", help="Path to JSON config file")
    parser.add_argument("--resume", help="Path to checkpoint to resume from")
    
    # Other arguments
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--dry-run", action="store_true", help="Show config without training")
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    # Create or load config
    if args.config:
        from training.rl_training_config import load_training_config
        config = load_training_config(args.config)
    elif args.target1_ip or args.target2_ip:
        # CLI arguments provided
        config = create_config_from_args(args)
    else:
        # Use default config with preset targets
        from training.rl_training_config import DEFAULT_TRAINING_CONFIG
        config = DEFAULT_TRAINING_CONFIG
    
    # Validate targets
    if not config.get_enabled_targets():
        print("ERROR: No training targets specified!")
        print("Use --target1-ip and optionally --target2-ip to specify targets")
        print("Example: python run_rl_training.py --target1-ip 192.168.1.100")
        sys.exit(1)
    
    # Show config
    print("\n" + "="*60)
    print("DEEP RL TRAINING CONFIGURATION")
    print("="*60)
    print(f"Targets:")
    for t in config.get_enabled_targets():
        print(f"  - {t.name}: {t.url}")
    print(f"Episodes per target: {config.episodes_per_target}")
    print(f"Max time per episode: {config.max_time_per_episode}s")
    print(f"Total estimated time: {len(config.get_enabled_targets()) * config.episodes_per_target * config.max_time_per_episode / 3600:.1f} hours (max)")
    print("="*60 + "\n")
    
    if args.dry_run:
        print("Dry run - exiting without training")
        return
    
    # Confirm
    try:
        input("Press Enter to start training (Ctrl+C to cancel)...")
    except KeyboardInterrupt:
        print("\nCancelled")
        return
    
    # Create trainer and run
    trainer = DeepRLTrainer(config)
    
    print("\n[*] Starting Deep RL Training...")
    print("[*] This may take several hours. Progress will be logged.")
    print("[*] Press Ctrl+C to stop and save checkpoint.\n")
    
    summary = trainer.train(resume_from=args.resume)
    
    # Print summary
    print("\n" + "="*60)
    print("TRAINING COMPLETE")
    print("="*60)
    print(f"Total Episodes: {summary['total_episodes']}")
    print(f"Total Steps: {summary['total_steps']}")
    print(f"Best Average Reward: {summary['best_avg_reward']:.2f}")
    print(f"Final Average Reward: {summary['final_avg_reward']:.2f}")
    print(f"Final Average Findings: {summary['final_avg_findings']:.2f}")
    print(f"Training Time: {summary['training_time_seconds']/3600:.2f} hours")
    print("="*60)
    print("\nModel saved to: backend/data/models/deep_rl/")
    print("Experiences saved to: backend/data/training_experiences/")


if __name__ == "__main__":
    main()
