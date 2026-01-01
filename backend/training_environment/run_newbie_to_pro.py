#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                 OPTIMUS NEWBIE TO PRO TRAINING LAUNCHER                       ║
╚═══════════════════════════════════════════════════════════════════════════════╝

Easy launcher for the comprehensive 10-12 hour training program.

Usage:
    python run_newbie_to_pro.py                    # Full 12-hour training
    python run_newbie_to_pro.py --hours 6          # 6-hour condensed training
    python run_newbie_to_pro.py --quick            # Quick 2-hour overview
    python run_newbie_to_pro.py --resume           # Resume from last checkpoint
"""

import os
import sys
import json
import socket
import argparse
from pathlib import Path
from datetime import datetime, timedelta

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def print_banner():
    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     ██████╗ ██████╗ ████████╗██╗███╗   ███╗██╗   ██╗███████╗                 ║
║    ██╔═══██╗██╔══██╗╚══██╔══╝██║████╗ ████║██║   ██║██╔════╝                 ║
║    ██║   ██║██████╔╝   ██║   ██║██╔████╔██║██║   ██║███████╗                 ║
║    ██║   ██║██╔═══╝    ██║   ██║██║╚██╔╝██║██║   ██║╚════██║                 ║
║    ╚██████╔╝██║        ██║   ██║██║ ╚═╝ ██║╚██████╔╝███████║                 ║
║     ╚═════╝ ╚═╝        ╚═╝   ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝                 ║
║                                                                               ║
║                    🎓 NEWBIE TO PRO TRAINING SYSTEM 🎓                        ║
║                                                                               ║
║     Transform your AI agent from beginner to expert penetration tester       ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """)


def print_curriculum():
    print("""
┌───────────────────────────────────────────────────────────────────────────────┐
│                           TRAINING CURRICULUM                                 │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  LEVEL 1: FUNDAMENTALS (Hours 1-2)                                           │
│  ├── Network Reconnaissance Basics (nmap, host discovery)                    │
│  ├── Web Application Fingerprinting (whatweb, wafw00f)                       │
│  ├── Directory & File Discovery (gobuster, ffuf)                             │
│  └── Basic Vulnerability Scanning (nikto, nuclei)                            │
│                                                                               │
│  LEVEL 2: INTERMEDIATE (Hours 3-4)                                           │
│  ├── Advanced Enumeration (API discovery, parameter fuzzing)                 │
│  ├── SQL Injection Detection & Exploitation (sqlmap)                         │
│  ├── XSS Detection & Exploitation (dalfox, xsstrike)                         │
│  └── Authentication Testing (hydra, brute force)                             │
│                                                                               │
│  LEVEL 3: ADVANCED (Hours 5-7)                                               │
│  ├── Chain Attack: SQLi to Shell                                             │
│  ├── Chain Attack: LFI/RFI to RCE                                            │
│  ├── Command Injection Mastery                                               │
│  ├── SSRF and XXE Exploitation                                               │
│  └── Privilege Escalation Fundamentals                                       │
│                                                                               │
│  LEVEL 4: EXPERT (Hours 8-10)                                                │
│  ├── Multi-Stage Attack Orchestration                                        │
│  ├── Custom Exploit Development                                              │
│  ├── Evasion and Anti-Detection                                              │
│  └── Credential Harvesting & Lateral Movement                                │
│                                                                               │
│  LEVEL 5: MASTERY (Hours 11-12)                                              │
│  ├── Full Autonomous Operation                                               │
│  └── Final Evaluation & Certification                                        │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
    """)


def check_targets(targets):
    """Check target availability"""
    print("\n[Pre-flight Check] Verifying targets...")
    available = []
    
    for target in targets:
        url = target.get('url') or target.get('ip')
        name = target.get('name', url)
        
        if url.startswith('http'):
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port or 80
        else:
            host = url.split(':')[0]
            port = int(url.split(':')[1]) if ':' in url else 22
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                print(f"  ✓ {name} ({host}:{port}) - ONLINE")
                available.append(target)
            else:
                print(f"  ✗ {name} ({host}:{port}) - OFFLINE")
        except Exception as e:
            print(f"  ✗ {name} - ERROR: {e}")
    
    return available


def get_default_targets():
    return [
        {'name': 'OWASP_Juice_Shop', 'url': 'http://192.168.56.101:3000', 'type': 'web'},
        {'name': 'Vulnerable_VM_1', 'ip': '192.168.56.102', 'type': 'linux'},
        {'name': 'Vulnerable_VM_2', 'ip': '192.168.56.103', 'type': 'linux'}
    ]


def find_latest_checkpoint(output_dir):
    checkpoints = list(Path(output_dir).glob('checkpoint_*.json'))
    return max(checkpoints, key=lambda p: p.stat().st_mtime) if checkpoints else None


def estimate_completion_time(hours):
    return (datetime.now() + timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M')


def main():
    parser = argparse.ArgumentParser(description='Optimus Newbie to Pro Training')
    
    # Duration
    parser.add_argument('--hours', type=int, default=12, help='Training hours (default: 12)')
    parser.add_argument('--quick', action='store_true', help='Quick 2-hour overview')
    parser.add_argument('--condensed', action='store_true', help='Condensed 6-hour training')
    
    # Targets
    parser.add_argument('--targets', type=str, help='Comma-separated target URLs/IPs')
    parser.add_argument('--juice-shop', type=str, help='OWASP Juice Shop URL')
    parser.add_argument('--vm1', type=str, help='VM 1 IP')
    parser.add_argument('--vm2', type=str, help='VM 2 IP')
    
    # Other
    parser.add_argument('--config', type=str, help='Config JSON file')
    parser.add_argument('--output', type=str, default='training_output/newbie_to_pro')
    parser.add_argument('--resume', action='store_true', help='Resume from checkpoint')
    parser.add_argument('--skip-check', action='store_true', help='Skip target check')
    parser.add_argument('--show-curriculum', action='store_true', help='Show curriculum')
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.show_curriculum:
        print_curriculum()
        sys.exit(0)
    
    # Determine hours
    hours = 2 if args.quick else (6 if args.condensed else args.hours)
    
    # Build targets
    if args.config:
        with open(args.config) as f:
            config = json.load(f)
        targets = config.get('targets', [])
    elif args.targets:
        targets = [{'url': t.strip(), 'name': f'target_{i}'} 
                  for i, t in enumerate(args.targets.split(','))]
    else:
        targets = get_default_targets()
        if args.juice_shop:
            targets[0]['url'] = args.juice_shop
        if args.vm1:
            targets[1]['ip'] = args.vm1
        if args.vm2:
            targets[2]['ip'] = args.vm2
    
    # Check targets
    if not args.skip_check:
        targets = check_targets(targets)
        if not targets:
            print("\n⚠️  No targets available! Use --skip-check to bypass.")
            sys.exit(1)
    
    # Check resume
    if args.resume:
        checkpoint = find_latest_checkpoint(args.output)
        if checkpoint:
            print(f"\n📂 Resuming from: {checkpoint}")
    
    # Print plan
    target_names = ', '.join(t.get('name', 'Unknown')[:12] for t in targets[:3])
    print(f"""
┌───────────────────────────────────────────────────────────────────────────────┐
│                            TRAINING PLAN                                      │
├───────────────────────────────────────────────────────────────────────────────┤
│  Duration: {hours} hours                                                       │
│  Targets: {len(targets)} ({target_names})
│  Output: {args.output}
│  Est. End: {estimate_completion_time(hours)}
│                                                                               │
│  PHASES:                                                                      │
│    ✓ Fundamentals (Hrs 1-2)  - Recon, scanning, basic tools                  │
│    ✓ Intermediate (Hrs 3-4)  - SQLi, XSS, auth testing                       │
│    ✓ Advanced     (Hrs 5-7)  - Chain attacks, privesc                        │
│    ✓ Expert       (Hrs 8-10) - Multi-stage, evasion                          │
│    ✓ Mastery      (Hrs 11-12)- Full autonomous operation                     │
└───────────────────────────────────────────────────────────────────────────────┘
    """)
    
    # Confirm
    try:
        response = input(f"\n⚠️  Training will take ~{hours} hours. Start? [Y/n]: ").strip().lower()
        if response and response != 'y':
            print("Cancelled.")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(0)
    
    # Run training
    config = {'targets': targets, 'total_hours': hours, 'output_dir': args.output}
    
    print("\n" + "="*70)
    print("INITIALIZING TRAINING...")
    print("="*70 + "\n")
    
    try:
        from training_environment.newbie_to_pro_training import NewbieToProTrainer
        
        trainer = NewbieToProTrainer(config)
        
        if not trainer.initialize():
            print("\n❌ Failed to initialize!")
            sys.exit(1)
        
        report = trainer.run_training()
        
        print(f"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                         🎉 TRAINING COMPLETE! 🎉                              ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  Final Level: {report['agent_profile']['final_level']:<15}                                         ║
║  Total Reward: {int(report['total_reward']):<14}                                         ║
║  Lessons: {report['curriculum_completion']['lessons_completed']:<5} | Challenges: {report['challenges_completion']['challenges_completed']:<5}                              ║
║  Results: {args.output:<50}   ║
╚═══════════════════════════════════════════════════════════════════════════════╝
        """)
        
    except KeyboardInterrupt:
        print("\n\nTraining interrupted. Resume with: python run_newbie_to_pro.py --resume")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
