#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║              ELITE OPERATOR TRAINING - QUICK START RUNNER                     ║
╚═══════════════════════════════════════════════════════════════════════════════╝

Easy launcher for advanced elite operator training.

Usage:
    python run_elite_training.py                    # Full 24-hour training
    python run_elite_training.py --phase red_team   # Specific phase only
    python run_elite_training.py --quick            # 8-hour condensed
    python run_elite_training.py --resume           # Resume from checkpoint
    python run_elite_training.py --cert-only        # Final certification only
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime, timedelta

# Fix Windows console encoding
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def print_banner():
    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     ███████╗██╗     ██╗████████╗███████╗                                     ║
║     ██╔════╝██║     ██║╚══██╔══╝██╔════╝                                     ║
║     █████╗  ██║     ██║   ██║   █████╗                                       ║
║     ██╔══╝  ██║     ██║   ██║   ██╔══╝                                       ║
║     ███████╗███████╗██║   ██║   ███████╗                                     ║
║     ╚══════╝╚══════╝╚═╝   ╚═╝   ╚══════╝                                     ║
║                                                                               ║
║              🎯 ELITE OPERATOR TRAINING SYSTEM 🎯                            ║
║                                                                               ║
║     Advanced training for master penetration testers                         ║
║     Prerequisites: Completed Newbie to Pro training                          ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """)


def check_prerequisites():
    """Check if prerequisites are met"""
    print("\n[Checking Prerequisites]")
    
    # Check for base training completion
    base_training_dir = Path('training_output/newbie_to_pro')
    if not base_training_dir.exists():
        print("  ✗ Newbie to Pro training not found")
        print("  → Please complete base training first")
        return False
    
    # Look for completion indicators
    checkpoints = list(base_training_dir.glob('checkpoint_*.json'))
    if not checkpoints:
        print("  ✗ No training checkpoints found")
        return False
    
    # Load latest checkpoint
    latest = max(checkpoints, key=lambda p: p.stat().st_mtime)
    with open(latest) as f:
        checkpoint = json.load(f)
    
    agent = checkpoint.get('agent', {})
    current_level = agent.get('current_level', 'NEWBIE')
    
    print(f"  ✓ Base training found")
    print(f"  ✓ Current level: {current_level}")
    
    # Check minimum skill level
    skills = agent.get('skills', {})
    if skills:
        avg_skill = sum(s.get('level', 0) for s in skills.values()) / len(skills)
        print(f"  ✓ Average skill level: {avg_skill:.1f}")
        
        if avg_skill < 60:
            print(f"  ⚠  Warning: Recommended minimum skill level is 60")
            print(f"     You may want to complete more base training")
            response = input("  Continue anyway? [y/N]: ").strip().lower()
            if response != 'y':
                return False
    
    print("  ✓ Prerequisites met!")
    return True


def print_training_overview():
    print("""
┌───────────────────────────────────────────────────────────────────────────────┐
│                      ADVANCED TRAINING CURRICULUM                             │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  PHASE 1: RED TEAM OPERATIONS (4 hours)                                      │
│  • Advanced OSINT & Reconnaissance                                           │
│  • Active Directory Exploitation                                             │
│  • Network Pivoting & Tunneling                                              │
│  • C2 Infrastructure & Persistence                                           │
│                                                                               │
│  PHASE 2: EXPLOIT DEVELOPMENT (4 hours)                                      │
│  • Binary Exploitation Fundamentals                                          │
│  • Buffer Overflow & ROP Chains                                              │
│  • Heap Exploitation Techniques                                              │
│  • Custom Exploit Development                                                │
│                                                                               │
│  PHASE 3: ADVERSARIAL SCENARIOS (4 hours)                                    │
│  • Blue Team Evasion Tactics                                                 │
│  • WAF & IDS Bypass Mastery                                                  │
│  • Time-Limited Breach Challenges                                            │
│  • Multi-Target Coordinated Attacks                                          │
│                                                                               │
│  PHASE 4: ZERO-DAY HUNTING (4 hours)                                         │
│  • Fuzzing & Vulnerability Discovery                                         │
│  • Static Code Analysis                                                      │
│  • Logic Flaw Identification                                                 │
│  • Novel Attack Vector Research                                              │
│                                                                               │
│  PHASE 5: APT SIMULATION (4 hours)                                           │
│  • Enterprise Network Compromise                                             │
│  • Long-Term Persistence Mechanisms                                          │
│  • Covert Data Exfiltration                                                  │
│  • Anti-Forensics & Cleanup                                                  │
│                                                                               │
│  PHASE 6: FINAL CERTIFICATION (4 hours)                                      │
│  • Comprehensive Skills Assessment                                           │
│  • Full APT Campaign Simulation                                              │
│  • Professional Report Generation                                            │
│  • Elite Operator Certification                                              │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
    """)


def main():
    parser = argparse.ArgumentParser(description='Elite Operator Advanced Training')
    
    # Training options
    parser.add_argument('--phase', type=str, 
                       choices=['red_team', 'exploit_dev', 'adversarial', 'zero_day', 'apt', 'cert'],
                       help='Run specific phase only')
    parser.add_argument('--quick', action='store_true', 
                       help='Quick 8-hour condensed training')
    parser.add_argument('--cert-only', action='store_true',
                       help='Final certification exam only')
    
    # Environment
    parser.add_argument('--config', type=str, 
                       default='training_environment/elite_operator_config.json',
                       help='Config file path')
    parser.add_argument('--output', type=str, 
                       default='training_output/elite_operator',
                       help='Output directory')
    
    # Control
    parser.add_argument('--resume', action='store_true', 
                       help='Resume from last checkpoint')
    parser.add_argument('--skip-prereq', action='store_true',
                       help='Skip prerequisite check')
    parser.add_argument('--show-curriculum', action='store_true',
                       help='Show curriculum and exit')
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.show_curriculum:
        print_training_overview()
        sys.exit(0)
    
    # Check prerequisites
    if not args.skip_prereq:
        if not check_prerequisites():
            print("\n❌ Prerequisites not met. Use --skip-prereq to bypass.")
            sys.exit(1)
    
    # Load config
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"\n❌ Config file not found: {config_path}")
        print("   Creating default config...")
        
        # Create default config
        config_path.parent.mkdir(parents=True, exist_ok=True)
        default_config = {
            "training_name": "Elite Operator Training",
            "total_hours": 24,
            "targets": [
                {"name": "Demo_Target", "url": "https://demo.owasp-juice.shop"}
            ],
            "output_dir": args.output
        }
        with open(config_path, 'w') as f:
            json.dump(default_config, f, indent=2)
        print(f"   ✓ Created: {config_path}")
    
    with open(config_path) as f:
        config = json.load(f)
    
    # Determine training duration
    if args.cert_only:
        hours = 4
        print("\n📋 Running CERTIFICATION EXAM ONLY (4 hours)")
    elif args.quick:
        hours = 8
        print("\n⚡ Running QUICK TRAINING (8 hours condensed)")
    elif args.phase:
        hours = 4
        print(f"\n🎯 Running PHASE: {args.phase.upper()} (4 hours)")
    else:
        hours = config.get('total_hours', 24)
        print(f"\n🎓 Running FULL ELITE TRAINING ({hours} hours)")
    
    # Show training plan
    end_time = datetime.now() + timedelta(hours=hours)
    print(f"""
┌───────────────────────────────────────────────────────────────────────────────┐
│                            TRAINING PLAN                                      │
├───────────────────────────────────────────────────────────────────────────────┤
│  Mode: {'Certification' if args.cert_only else 'Quick' if args.quick else 'Full Training'}
│  Duration: {hours} hours                                                      
│  Est. Completion: {end_time.strftime('%Y-%m-%d %H:%M')}                       
│  Output: {args.output}                                                        
│                                                                               │
│  TARGET SKILLS:                                                               │
│    • Advanced Red Team Operations                                            │
│    • Binary Exploitation & ROP                                               │
│    • Stealth & Evasion Mastery                                               │
│    • Zero-Day Discovery                                                      │
│    • APT-Level Operations                                                    │
└───────────────────────────────────────────────────────────────────────────────┘
    """)
    
    # Confirm
    try:
        response = input(f"\n⚠️  This is ADVANCED training ({hours} hours). Ready? [Y/n]: ").strip().lower()
        if response and response != 'y':
            print("Cancelled.")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(0)
    
    print("\n" + "="*70)
    print("INITIALIZING ELITE TRAINING...")
    print("="*70 + "\n")
    
    # Import and run training
    try:
        # Import the elite training module
        try:
            from training_environment.elite_operator_training import EliteOperatorTrainer
            print("[INFO] Using EliteOperatorTrainer")
            use_elite_trainer = True
        except ImportError:
            # Fallback to base trainer if elite module not available
            from training_environment.newbie_to_pro_training import NewbieToProTrainer
            print("[WARN] EliteOperatorTrainer not found, using NewbieToProTrainer as fallback")
            use_elite_trainer = False
        
        # Modify config for elite training
        config['output_dir'] = args.output
        config['total_hours'] = hours
        
        if use_elite_trainer:
            trainer = EliteOperatorTrainer(config)
        else:
            trainer = NewbieToProTrainer(config)
        
        if not trainer.initialize():
            print("\n❌ Failed to initialize training!")
            sys.exit(1)
        
        print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║                          🚀 TRAINING STARTED 🚀                               ║
║                                                                               ║
║  Note: This is ADVANCED training. Expect challenging scenarios that          ║
║  require expert-level skills in evasion, exploitation, and operations.       ║
║                                                                               ║
║  Stay focused. Document everything. Good luck, operator. 🎯                  ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
        """)
        
        report = trainer.run_training()
        
        # Check if elite certification achieved
        final_score = report.get('metrics', {}).get('skills_learned', 0)
        certification = "ELITE OPERATOR" if final_score >= 85 else "ADVANCED"
        
        print(f"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                       🎉 TRAINING COMPLETE! 🎉                                ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  Certification: {certification:<20}                                          ║
║  Final Score: {final_score:<10}                                               ║
║  Results: {args.output:<50}                                                   ║
║                                                                               ║
║  {('✅ ELITE OPERATOR STATUS ACHIEVED!' if certification == 'ELITE OPERATOR' else '⚠️  Continue training for Elite certification'):<75}║
╚═══════════════════════════════════════════════════════════════════════════════╝
        """)
        
    except KeyboardInterrupt:
        print("\n\nTraining interrupted. Progress saved.")
        print("Resume with: python run_elite_training.py --resume")
    except Exception as e:
        print(f"\n❌ Training error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()