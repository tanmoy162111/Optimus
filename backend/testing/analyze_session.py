"""
Analyze training session results
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import json

def analyze_training_session(session_num):
    """Analyze training session results"""
    
    results_dir = 'testing/data'
    session_files = [f for f in os.listdir(results_dir) 
                     if f.startswith(f'session{session_num}_') and not f.endswith('_error.json')]
    
    print(f"\n{'='*80}")
    print(f"Training Session {session_num} Analysis")
    print(f"{'='*80}\n")
    
    for file in session_files:
        with open(os.path.join(results_dir, file)) as f:
            result = json.load(f)
        
        target = file.replace(f'session{session_num}_', '').replace('.json', '')
        
        print(f"\n{target}")
        print(f"{'-'*40}")
        
        # Tool diversity
        tools = [t['tool'] if isinstance(t, dict) else t 
                 for t in result.get('tools_executed', [])]
        unique_tools = len(set(tools))
        total_tools = len(tools)
        
        if total_tools > 0:
            print(f"Tool Diversity: {unique_tools} unique / {total_tools} total")
            print(f"Repetition rate: {(1 - unique_tools/total_tools)*100:.1f}%")
        else:
            print("Tool Diversity: No tools executed")
        
        # Findings
        findings = result.get('findings', [])
        print(f"\nFindings: {len(findings)}")
        
        if findings:
            by_severity = {}
            for f in findings:
                sev = f.get('severity', 0)
                if sev >= 9.0:
                    by_severity['critical'] = by_severity.get('critical', 0) + 1
                elif sev >= 7.0:
                    by_severity['high'] = by_severity.get('high', 0) + 1
                elif sev >= 4.0:
                    by_severity['medium'] = by_severity.get('medium', 0) + 1
                else:
                    by_severity['low'] = by_severity.get('low', 0) + 1
            
            for severity, count in sorted(by_severity.items()):
                print(f"  {severity}: {count}")
        
        # Phase progression
        print(f"\nPhase reached: {result.get('phase', 'unknown')}")
        print(f"Coverage: {result.get('coverage', 0):.1%}")
        
        # Issues detected
        issues = []
        if total_tools > 0 and unique_tools < total_tools * 0.6:
            issues.append("⚠️  High tool repetition")
        if len(findings) == 0:
            issues.append("⚠️  No findings discovered")
        if result.get('coverage', 0) < 0.5:
            issues.append("⚠️  Low coverage")
        
        if issues:
            print("\nIssues:")
            for issue in issues:
                print(f"  {issue}")
        else:
            print("\n✅ Session performance good")

if __name__ == '__main__':
    analyze_training_session(1)