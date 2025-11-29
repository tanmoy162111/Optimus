#!/usr/bin/env python3
"""
Test script for fully autonomous training
"""
import sys
import os

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), 'backend')
sys.path.insert(0, backend_path)

from training_environment.fully_autonomous_training import main

if __name__ == '__main__':
    # Test with our standard targets
    import sys
    sys.argv = [
        'fully_autonomous_training.py',
        '--targets', 'http://192.168.131.128', 'https://landscape.canonical.com',
        '--max-episodes', '3',
        '--max-time-per-episode', '600',  # 10 minutes per episode
        '--output-dir', 'training_output/fully_autonomous_test'
    ]
    
    main()