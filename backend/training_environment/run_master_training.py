#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     ███╗   ███╗ █████╗ ███████╗████████╗███████╗██████╗                      ║
║     ████╗ ████║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗                     ║
║     ██╔████╔██║███████║███████╗   ██║   █████╗  ██████╔╝                     ║
║     ██║╚██╔╝██║██╔══██║╚════██║   ██║   ██╔══╝  ██╔══██╗                     ║
║     ██║ ╚═╝ ██║██║  ██║███████║   ██║   ███████╗██║  ██║                     ║
║     ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝                     ║
║                                                                               ║
║                 MASTER OPERATOR TRAINING SYSTEM                               ║
║              Nation-State Level - 40+ Hour Curriculum                         ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

The ultimate training for operators who will work at the highest levels.

Prerequisites:
  • Elite Operator certification
  • Minimum skill level: 85+
  • 100+ findings documented
  • 20+ successful exploits
  • Stealth operations score: 0.8+

Usage:
    python run_master_training.py                    # Full 40-hour training
    python run_master_training.py --module 1         # Specific module only
    python run_master_training.py --cert-only        # Final certification
    python run_master_training.py --resume           # Resume from checkpoint
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
║     ███╗   ███╗ █████╗ ███████╗████████╗███████╗██████╗                      ║
║     ████╗ ████║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗                     ║
║     ██╔████╔██║███████║███████╗   ██║   █████╗  ██████╔╝                     ║
║     ██║╚██╔╝██║██╔══██║╚════██║   ██║   ██╔══╝  ██╔══██╗                     ║
║     ██║ ╚═╝ ██║██║  ██║███████║   ██║   ███████╗██║  ██║                     ║
║     ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝                     ║
║                                                                               ║
║                 🎖️  MASTER OPERATOR TRAINING 🎖️                             ║
║                                                                               ║
║           Nation-State Level Offensive Security Training                     ║
║              For Elite Operators Only - 40+ Hours                            ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """)


def check_prerequisites():
    """Verify master-level prerequisites"""
    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║          MASTER LEVEL PREREQUISITES VERIFICATION            ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")
    
    all_passed = True
    
    # Check Elite Operator training
    elite_dir = Path('training_output/elite_operator')
    if not elite_dir.exists():
        print("  ✗ Elite Operator training not found")
        print("  → Complete Elite training first")
        return False
    
    print("  ✓ Elite Operator training directory found")
    
    # Check for elite certification
    checkpoints = list(elite_dir.glob('checkpoint_*.json'))
    if not checkpoints:
        print("  ✗ No Elite training checkpoints found")
        return False
    
    latest = max(checkpoints, key=lambda p: p.stat().st_mtime)
    with open(latest) as f:
        checkpoint = json.load(f)
    
    agent = checkpoint.get('agent', {})
    metrics = checkpoint.get('metrics', {})
    
    # Check skill level
    skills = agent.get('skills', {})
    if skills:
        avg_skill = sum(s.get('level', 0) for s in skills.values()) / len(skills)
        print(f"  ✓ Average skill level: {avg_skill:.1f}")
        
        if avg_skill < 85:
            print(f"  ✗ Minimum skill level: 85 (current: {avg_skill:.1f})")
            print("  → Complete more Elite training")
            all_passed = False
    
    # Check findings
    total_findings = metrics.get('total_findings', 0)
    print(f"  {'✓' if total_findings >= 100 else '✗'} Total findings: {total_findings} (required: 100+)")
    if total_findings < 100:
        all_passed = False
    
    # Check shells/exploits
    total_shells = metrics.get('total_shells', 0)
    print(f"  {'✓' if total_shells >= 20 else '✗'} Successful exploits: {total_shells} (required: 20+)")
    if total_shells < 20:
        all_passed = False
    
    # Check certifications
    achievements = agent.get('achievements', [])
    has_elite = any('elite' in str(a).lower() for a in achievements)
    print(f"  {'✓' if has_elite else '✗'} Elite Operator certification")
    
    if not all_passed:
        print("\n  ⚠️  Prerequisites not fully met")
        response = input("  Continue anyway? [y/N]: ").strip().lower()
        return response == 'y'
    
    print("\n  ✅ All prerequisites met!")
    print("\n  🎖️  You are qualified for MASTER OPERATOR training")
    return True


def print_curriculum():
    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                      MASTER OPERATOR CURRICULUM                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  MODULE 1: ADVANCED OPERATIONAL TRADECRAFT (6 hours)                         ║
║  ├── Counter-Intelligence Operations                                         ║
║  ├── Advanced OPSEC & Attribution Avoidance                                  ║
║  ├── Infrastructure Compartmentalization                                     ║
║  ├── Covert Channel Mastery                                                  ║
║  └── Long-Term Deep Cover Operations                                         ║
║                                                                               ║
║  MODULE 2: ADVANCED RESEARCH & 0-DAY DEVELOPMENT (6 hours)                   ║
║  ├── Advanced Fuzzing & Symbolic Execution                                   ║
║  ├── Kernel Exploitation                                                     ║
║  ├── Browser Exploitation                                                    ║
║  ├── Hypervisor Escapes                                                      ║
║  ├── Mobile Platform Exploitation (iOS/Android)                              ║
║  └── Blockchain & Smart Contract Exploitation                                ║
║                                                                               ║
║  MODULE 3: APT CAMPAIGN MANAGEMENT (8 hours)                                 ║
║  ├── Full Campaign Planning & Execution                                      ║
║  ├── Living Off The Land (LOTL) Mastery                                      ║
║  ├── Domain Dominance Techniques                                             ║
║  ├── Cloud Infrastructure Exploitation (Azure/AWS/GCP)                       ║
║  ├── Supply Chain Attacks                                                    ║
║  └── Firmware & BIOS Rootkits                                                ║
║                                                                               ║
║  MODULE 4: SPECIALIZED TARGET EXPLOITATION (6 hours)                         ║
║  ├── ICS/SCADA Security & Exploitation                                       ║
║  ├── Industrial Protocol Analysis (Modbus, DNP3, OPC-UA)                     ║
║  ├── PLC Programming & Exploitation                                          ║
║  ├── Air-Gap Bridging Techniques                                             ║
║  ├── Hardware Hacking & Physical Access                                      ║
║  └── RF Exploitation & Side-Channel Analysis                                 ║
║                                                                               ║
║  MODULE 5: ADVERSARIAL AI/ML & NEXT-GEN EVASION (6 hours)                    ║
║  ├── Adversarial Machine Learning                                            ║
║  ├── ML-Based Defense Evasion (EDR, SIEM, NDR)                               ║
║  ├── Malware Mutation & Polymorphism                                         ║
║  ├── Neural Network Backdoors                                                ║
║  ├── LLM Exploitation & Prompt Injection                                     ║
║  └── Model Extraction, Inversion & Poisoning                                 ║
║                                                                               ║
║  MODULE 6: SECURITY RESEARCH & PUBLICATION (4 hours)                         ║
║  ├── Research Methodology                                                    ║
║  ├── Novel Technique Development                                             ║
║  ├── Responsible Disclosure Process                                          ║
║  ├── CVE Coordination                                                        ║
║  ├── Conference Paper Writing                                                ║
║  └── Tool Development & Open Source                                          ║
║                                                                               ║
║  MODULE 7: MASTER CERTIFICATION EXAM (4 hours + 48-hour practical)           ║
║  ├── 48-Hour Red Team Operation                                              ║
║  ├── Multi-Domain Enterprise Breach                                          ║
║  ├── Live Blue Team Opposition                                               ║
║  ├── Complete Operational Cleanup                                            ║
║  ├── Executive & Technical Reporting                                         ║
║  └── Oral Defense & Board Presentation                                       ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """)


def print_warnings():
    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                         ⚠️  CRITICAL WARNINGS ⚠️                             ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  1. LEGAL COMPLIANCE                                                          ║
║     • Only use on authorized targets you own or have explicit permission     ║
║     • Unauthorized access is a serious crime in all jurisdictions            ║
║     • Critical infrastructure testing requires special authorization         ║
║                                                                               ║
║  2. SAFETY CRITICAL SYSTEMS                                                   ║
║     • ICS/SCADA testing must NEVER impact safety systems                     ║
║     • Always have safety cutoffs and kill switches                           ║
║     • Physical safety takes absolute priority                                ║
║                                                                               ║
║  3. RESPONSIBLE DISCLOSURE                                                    ║
║     • All vulnerabilities must be responsibly disclosed                      ║
║     • Follow industry-standard disclosure timelines                          ║
║     • Coordinate with vendors and security teams                             ║
║                                                                               ║
║  4. OPERATIONAL SECURITY                                                      ║
║     • Your actions will be monitored and logged                              ║
║     • Maintain strict OPSEC at all times                                     ║
║     • Attribution to real identity can have severe consequences              ║
║                                                                               ║
║  5. ETHICAL CONSIDERATIONS                                                    ║
║     • These skills are for defensive improvement                             ║
║     • Never use for malicious purposes                                       ║
║     • Consider the impact of your actions                                    ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """)


def main():
    parser = argparse.ArgumentParser(description='Master Operator Training')
    
    # Training options
    parser.add_argument('--module', type=int, choices=[1,2,3,4,5,6,7],
                       help='Run specific module only (1-7)')
    parser.add_argument('--cert-only', action='store_true',
                       help='Final certification exam only (48 hours)')
    parser.add_argument('--research-only', action='store_true',
                       help='Research & publication module only')
    
    # Environment
    parser.add_argument('--config', type=str,
                       default='training_environment/master_operator_config.json',
                       help='Config file path')
    parser.add_argument('--output', type=str,
                       default='training_output/master_operator',
                       help='Output directory')
    
    # Control
    parser.add_argument('--resume', action='store_true',
                       help='Resume from checkpoint')
    parser.add_argument('--skip-prereq', action='store_true',
                       help='Skip prerequisite check (NOT RECOMMENDED)')
    parser.add_argument('--show-curriculum', action='store_true',
                       help='Show full curriculum')
    parser.add_argument('--accept-warnings', action='store_true',
                       help='Accept all warnings (for automation)')
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.show_curriculum:
        print_curriculum()
        sys.exit(0)
    
    # Show critical warnings
    if not args.accept_warnings:
        print_warnings()
        try:
            response = input("\n⚠️  I understand and accept these warnings [type 'I ACCEPT']: ").strip()
            if response != 'I ACCEPT':
                print("\nYou must accept the warnings to continue.")
                sys.exit(0)
        except KeyboardInterrupt:
            print("\nCancelled.")
            sys.exit(0)
    
    # Check prerequisites
    if not args.skip_prereq:
        if not check_prerequisites():
            print("\n❌ Prerequisites not met. Complete Elite training first.")
            sys.exit(1)
    
    # Load config
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"\n❌ Config not found: {config_path}")
        print("   Use: python run_elite_training.py to complete prerequisites")
        sys.exit(1)
    
    with open(config_path) as f:
        config = json.load(f)
    
    # Determine training mode
    if args.cert_only:
        hours = 52  # 4 hours prep + 48 hours practical
        mode = "CERTIFICATION EXAM"
    elif args.module:
        hours = 6  # Average module length
        mode = f"MODULE {args.module}"
    elif args.research_only:
        hours = 4
        mode = "RESEARCH & PUBLICATION"
    else:
        hours = config.get('total_hours', 40)
        mode = "FULL MASTER TRAINING"
    
    end_time = datetime.now() + timedelta(hours=hours)
    
    print(f"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                         TRAINING CONFIGURATION                                ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  Mode: {mode:<70} ║
║  Duration: {hours} hours{' '*60}║
║  Est. Completion: {end_time.strftime('%Y-%m-%d %H:%M')}{' '*44}║
║  Output: {args.output}{' '*(65-len(args.output))}║
║                                                                               ║
║  OBJECTIVES:                                                                  ║
║  • Master nation-state level techniques                                      ║
║  • Develop 0-day vulnerabilities                                             ║
║  • Execute full APT campaigns                                                ║
║  • Evade advanced ML-based defenses                                          ║
║  • Exploit specialized targets (ICS/SCADA)                                   ║
║  • Publish original security research                                        ║
║  • Achieve MASTER OPERATOR certification                                     ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Final confirmation
    if not args.accept_warnings:
        try:
            response = input(f"\n🎖️  Begin {mode}? This is the ultimate challenge. [Y/n]: ").strip().lower()
            if response and response != 'y':
                print("Cancelled.")
                sys.exit(0)
        except KeyboardInterrupt:
            print("\nCancelled.")
            sys.exit(0)
    
    print("\n" + "="*80)
    print("INITIALIZING MASTER OPERATOR TRAINING...")
    print("="*80 + "\n")
    
    # Run training
    try:
        # Import the master training module
        try:
            from training_environment.master_operator_training import MasterOperatorTrainer
            print("[INFO] Using MasterOperatorTrainer")
            use_master_trainer = True
        except ImportError:
            # Fallback to base trainer if master module not available
            from training_environment.newbie_to_pro_training import NewbieToProTrainer
            print("[WARN] MasterOperatorTrainer not found, using NewbieToProTrainer as fallback")
            use_master_trainer = False
        
        config['output_dir'] = args.output
        config['total_hours'] = hours
        
        if use_master_trainer:
            trainer = MasterOperatorTrainer(config)
        else:
            trainer = NewbieToProTrainer(config)
        
        if not trainer.initialize():
            print("\n❌ Initialization failed!")
            sys.exit(1)
        
        print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║                     🎖️  MASTER TRAINING INITIATED 🎖️                        ║
║                                                                               ║
║  You are now entering the highest level of offensive security training.      ║
║  What you learn here represents the cutting edge of the field.               ║
║                                                                               ║
║  This training simulates nation-state level operations. The challenges       ║
║  are designed to push you to your absolute limits.                           ║
║                                                                               ║
║  Document everything. Think strategically. Operate with precision.           ║
║                                                                               ║
║  Good luck, Master Operator. 🎯                                              ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
        """)
        
        report = trainer.run_training()
        
        # Evaluate for master certification
        final_score = report.get('metrics', {}).get('skills_learned', 0)
        certification = "MASTER OPERATOR" if final_score >= 90 else "ADVANCED ELITE"
        
        print(f"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    🎖️  TRAINING COMPLETE 🎖️                                 ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  Certification: {certification:<62} ║
║  Final Score: {final_score}/100{' '*59}║
║  Output: {args.output}{' '*(69-len(args.output))}║
║                                                                               ║
║  {('🏆 MASTER OPERATOR STATUS ACHIEVED! 🏆' if certification == 'MASTER OPERATOR' else '⚠️  Continue training for Master certification'):<77}║
║                                                                               ║
║  {'You now possess nation-state level capabilities.' if certification == 'MASTER OPERATOR' else 'You are close. Push to the final level.':^77}║
╚═══════════════════════════════════════════════════════════════════════════════╝
        """)
        
        if certification == "MASTER OPERATOR":
            print("\n🎖️  Congratulations, Master Operator.")
            print("   You have completed the highest level of training.")
            print("   Use these skills wisely and ethically.\n")
        
    except KeyboardInterrupt:
        print("\n\nTraining interrupted. Progress saved.")
        print(f"Resume: python run_master_training.py --resume")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()