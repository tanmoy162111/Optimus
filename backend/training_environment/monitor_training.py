#!/usr/bin/env python3
"""
Training Progress Monitor

This script monitors the training progress and displays updates
"""
import time
import os
import json
from pathlib import Path

def monitor_training_progress(output_dir):
    """Monitor training progress by checking output directory"""
    output_path = Path(output_dir)
    
    print(f"🔍 Monitoring training progress in {output_dir}")
    print("=" * 60)
    
    # Wait for training to start
    print("⏳ Waiting for training to start...")
    
    start_time = time.time()
    timeout = 300  # 5 minutes timeout
    
    while time.time() - start_time < timeout:
        # Check for any files in output directory
        files = list(output_path.glob("*"))
        
        if files:
            print(f"📁 Files found: {[f.name for f in files]}")
            
            # Check for checkpoint file
            checkpoint_file = output_path / "training_checkpoint.json"
            if checkpoint_file.exists():
                try:
                    with open(checkpoint_file, 'r') as f:
                        checkpoint = json.load(f)
                    print(f"💾 Checkpoint: Episode {checkpoint.get('current_episode', 'Unknown')}")
                except Exception as e:
                    print(f"⚠️  Could not read checkpoint: {e}")
            
            # Check for results file
            results_files = list(output_path.glob("training_results_*.json"))
            if results_files:
                print(f"✅ Results files: {[f.name for f in results_files]}")
                break
        
        time.sleep(10)  # Check every 10 seconds
    
    print("\n🏁 Monitoring complete")

if __name__ == "__main__":
    monitor_training_progress("training_output/first_training")