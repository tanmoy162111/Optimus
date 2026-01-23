#!/usr/bin/env python3
"""
Curriculum Configuration for Phase-Based Target Selection

This module defines the policy for which targets to use in each training phase.
"""

# Phase target policy mapping
PHASE_TARGET_POLICY = {
    "fundamentals": "localhost",
    "intermediate": "training_targets",
    "advanced": "training_targets", 
    "expert": "training_targets",
    "mastery": "training_targets"
}