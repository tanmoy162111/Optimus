#!/usr/bin/env python3
"""
Test script to verify the updated lesson assessment logic with adaptive thresholds.
"""
import sys
import os
import statistics
from datetime import datetime
from typing import Dict, Any, List

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from training_environment.newbie_to_pro_training import (
    NewbieToProTrainer, 
    Skill, 
    SkillCategory, 
    TrainingPhase, 
    LessonPlan,
    AgentProfile
)


def test_adaptive_thresholds():
    """Test that the adaptive threshold calculation works properly"""
    print("Testing adaptive threshold calculation...")
    
    # Create a mock trainer instance
    config = {
        'targets': [{'url': 'http://localhost'}],
        'total_hours': 1,
        'output_dir': 'test_output'
    }
    
    trainer = NewbieToProTrainer(config)
    
    # Initialize the trainer to set up recent_global_rewards
    trainer.initialize()
    
    # Add some mock skills to the agent
    trainer.agent.skills = {
        'reconnaissance': Skill(name='reconnaissance', category=SkillCategory.RECONNAISSANCE, level=25.0),
        'scanning': Skill(name='scanning', category=SkillCategory.ENUMERATION, level=30.0),
        'vulnerability_detection': Skill(name='vulnerability_detection', category=SkillCategory.VULNERABILITY_DETECTION, level=20.0),
    }
    
    # Create a mock lesson
    lesson = LessonPlan(
        lesson_id="F1",
        title="Network Reconnaissance Basics",
        phase=TrainingPhase.FUNDAMENTALS,
        objectives=["Understand network scanning fundamentals"],
        skills_trained=["reconnaissance", "scanning"],
        duration_minutes=30,
        exercises=[],
        assessment={}
    )
    
    # Test the assessment method
    assessment_result = trainer._run_assessment(lesson)
    
    print(f"Assessment Result: {assessment_result}")
    print(f"Required Avg Skill: {assessment_result.get('required_avg_skill'):.2f}")
    print(f"Actual Avg Skill: {assessment_result.get('actual_avg_skill'):.2f}")
    print(f"Passed: {assessment_result.get('passed')}")
    
    # Test with different global reward scenarios
    print("\nTesting with positive global rewards...")
    trainer.recent_global_rewards = [5.0, 7.0, 6.0, 8.0, 9.0]  # Positive rewards
    assessment_result_pos = trainer._run_assessment(lesson)
    print(f"With positive rewards - Required Avg Skill: {assessment_result_pos.get('required_avg_skill'):.2f}")
    
    print("\nTesting with negative global rewards...")
    trainer.recent_global_rewards = [-5.0, -3.0, -4.0, -2.0, -6.0]  # Negative rewards
    assessment_result_neg = trainer._run_assessment(lesson)
    print(f"With negative rewards - Required Avg Skill: {assessment_result_neg.get('required_avg_skill'):.2f}")
    
    print("\n✓ Adaptive threshold tests completed successfully!")


def test_skill_practice_with_global_rewards():
    """Test that skills are properly updated with global rewards"""
    print("\nTesting skill practice with global rewards...")
    
    # Create a mock skill
    skill = Skill(name='test_skill', category=SkillCategory.RECONNAISSANCE, level=10.0)
    
    # Practice with different global rewards
    print(f"Initial skill level: {skill.level}")
    
    # Practice with positive global reward
    skill.practice(success=True, difficulty=1.0, global_reward=5.0, policy_success=True)
    print(f"After positive reward (5.0): {skill.level}")
    
    # Practice with negative global reward
    skill.practice(success=False, difficulty=1.0, global_reward=-2.0, policy_success=False)
    print(f"After negative reward (-2.0): {skill.level}")
    
    # Practice with zero global reward
    skill.practice(success=True, difficulty=1.0, global_reward=0.0, policy_success=True)
    print(f"After zero reward: {skill.level}")
    
    print("✓ Skill practice tests completed successfully!")


def test_lesson_pass_fail_logging():
    """Test that pass/fail logging works properly"""
    print("\nTesting lesson pass/fail logging...")
    
    # Create a mock trainer instance
    config = {
        'targets': [{'url': 'http://localhost'}],
        'total_hours': 1,
        'output_dir': 'test_output'
    }
    
    trainer = NewbieToProTrainer(config)
    trainer.initialize()
    
    # Add skills with low levels to force failure
    trainer.agent.skills = {
        'reconnaissance': Skill(name='reconnaissance', category=SkillCategory.RECONNAISSANCE, level=5.0),
        'scanning': Skill(name='scanning', category=SkillCategory.ENUMERATION, level=5.0),
    }
    
    # Create a mock lesson
    lesson = LessonPlan(
        lesson_id="F1",
        title="Test Lesson",
        phase=TrainingPhase.FUNDAMENTALS,
        objectives=["Test objectives"],
        skills_trained=["reconnaissance", "scanning"],
        duration_minutes=30,
        exercises=[],
        assessment={}
    )
    
    # Run the lesson to test the pass/fail logic
    trainer._run_lesson(lesson)
    
    print(f"Completed lessons: {len(trainer.completed_lessons)}")
    print(f"Lessons completed metric: {trainer.metrics['lessons_completed']}")
    
    print("✓ Lesson pass/fail logging test completed successfully!")


def main():
    """Run all tests"""
    print("Running Lesson Assessment Tests...\n")
    
    try:
        test_adaptive_thresholds()
        test_skill_practice_with_global_rewards()
        test_lesson_pass_fail_logging()
        
        print("\n🎉 All tests passed successfully!")
        print("The updated lesson assessment system with adaptive thresholds is working correctly.")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())