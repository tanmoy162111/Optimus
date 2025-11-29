#!/usr/bin/env python3
"""
Training Progress Monitor

This script monitors the training progress and displays updates
"""
import time
import os
import json
from pathlib import Path

def monitor_training_progress(output_dir, timeout=300):
    """Monitor training progress by checking output directory"""
    output_path = Path(output_dir)
    
    print(f"🔍 Monitoring training progress in {output_dir}")
    print("=" * 60)
    
    # Wait for training to start
    print("⏳ Waiting for training to start...")
    
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        # Check for any files in output directory
        files = list(output_path.glob("*"))
        
        if files:
            print(f"📁 Files found: {[f.name for f in files]}")
            
            # Check for results file
            results_files = list(output_path.glob("training_results_*.json"))
            if results_files:
                print(f"✅ Training completed! Results file: {results_files[0].name}")
                try:
                    with open(results_files[0], 'r') as f:
                        data = json.load(f)
                    print(f"📊 Training ID: {data.get('training_id', 'Unknown')}")
                    print(f"⏱️  Duration: {data.get('duration_seconds', 0):.1f} seconds")
                    print(f"📈 Episodes: {data.get('total_episodes', 0)}")
                    successful_episodes = len([e for e in data.get('episode_history', []) if e.get('success')])
                    print(f"✅ Successful Episodes: {successful_episodes}")
                    break
                except Exception as e:
                    print(f"⚠️  Could not read results: {e}")
        
        time.sleep(10)  # Check every 10 seconds
    
    print("\n🏁 Monitoring complete")

if __name__ == "__main__":
    monitor_training_progress("training_output/comprehensive_training")