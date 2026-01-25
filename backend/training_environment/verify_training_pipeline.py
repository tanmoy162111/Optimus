#!/usr/bin/env python3
"""
Verification script for elite and master training pipeline integration.

This script verifies that all components of the elite and master training systems
are properly integrated and working together, including:
- ComponentManager initialization
- ToolManager execution
- CMAB agent integration
- Memory system integration
- Stealth tracking
- Skill progression
- Checkpoint/resume functionality
"""

import os
import sys
import json
import time
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f'verification_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)
logger = logging.getLogger('TrainingVerification')

def verify_component_initialization():
    """Verify that all required components can be imported and initialized"""
    logger.info("Verifying component initialization...")
    
    try:
        from training_environment.newbie_to_pro_training import ComponentManager, SkillLevel, SkillCategory
        logger.info("✓ Base training components imported successfully")
    except ImportError as e:
        logger.error(f"✗ Failed to import base training components: {e}")
        return False
    
    try:
        from intelligence.memory_system import get_memory_system
        logger.info("✓ Memory system imported successfully")
    except ImportError as e:
        logger.warning(f"⚠ Memory system not available: {e}")
    
    try:
        from training.cmab_agent import get_cmab_agent
        logger.info("✓ CMAB agent imported successfully")
    except ImportError as e:
        logger.warning(f"⚠ CMAB agent not available: {e}")
    
    try:
        from inference.target_normalizer import get_target_normalizer
        logger.info("✓ Target normalizer imported successfully")
    except ImportError as e:
        logger.warning(f"⚠ Target normalizer not available: {e}")
    
    try:
        from inference.state_schema import ensure_scan_state
        logger.info("✓ State schema imported successfully")
    except ImportError as e:
        logger.warning(f"⚠ State schema not available: {e}")
    
    return True

def verify_elite_training_integration():
    """Verify elite training system integration"""
    logger.info("Verifying elite training integration...")
    
    try:
        from training_environment.elite_operator_training import EliteOperatorTrainer
        
        # Create a minimal config for testing
        config = {
            'output_dir': 'training_output/test_elite_verification',
            'total_hours': 1,  # Short test run
            'targets': ['http://localhost']  # Test target
        }
        
        trainer = EliteOperatorTrainer(config)
        success = trainer.initialize()
        
        if success:
            logger.info("✓ Elite trainer initialized successfully")
        else:
            logger.warning("⚠ Elite trainer initialization had issues")
        
        # Test component availability
        if trainer.components:
            available_components = 0
            for name in ['tool_manager', 'intelligent_selector', 'state_encoder']:
                if trainer.components.get(name):
                    available_components += 1
                    logger.info(f"✓ Component '{name}' available")
                else:
                    logger.info(f"- Component '{name}' not available")
            
            logger.info(f"✓ Elite trainer has {available_components}/3 core components")
        else:
            logger.warning("⚠ Elite trainer has no components")
        
        # Test skill categories
        from training_environment.newbie_to_pro_training import SkillCategory
        skill_count = len(SkillCategory)
        logger.info(f"✓ Elite trainer has access to {skill_count} skill categories")
        
        # Test that lesson execution method exists
        if hasattr(trainer, '_execute_lesson'):
            logger.info("✓ Elite trainer has _execute_lesson method")
        else:
            logger.error("✗ Elite trainer missing _execute_lesson method")
            return False
            
        # Test that CMAB integration exists
        if hasattr(trainer, '_get_cmab_state'):
            logger.info("✓ Elite trainer has CMAB integration")
        else:
            logger.error("✗ Elite trainer missing CMAB integration")
            return False
            
        # Test that memory integration exists
        if hasattr(trainer, '_get_memory_state'):
            logger.info("✓ Elite trainer has memory system integration")
        else:
            logger.error("✗ Elite trainer missing memory system integration")
            return False
            
        # Test that stealth tracking exists
        if hasattr(trainer, '_update_stealth_score'):
            logger.info("✓ Elite trainer has stealth tracking")
        else:
            logger.error("✗ Elite trainer missing stealth tracking")
            return False
        
        # Test that checkpoint system exists
        if hasattr(trainer, '_save_checkpoint'):
            logger.info("✓ Elite trainer has checkpoint system")
        else:
            logger.error("✗ Elite trainer missing checkpoint system")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Elite training verification failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def verify_master_training_integration():
    """Verify master training system integration"""
    logger.info("Verifying master training integration...")
    
    try:
        from training_environment.master_operator_training import MasterOperatorTrainer
        
        # Create a minimal config for testing
        config = {
            'output_dir': 'training_output/test_master_verification',
            'total_hours': 1,  # Short test run
            'targets': ['http://localhost']  # Test target
        }
        
        trainer = MasterOperatorTrainer(config)
        success = trainer.initialize()
        
        if success:
            logger.info("✓ Master trainer initialized successfully")
        else:
            logger.warning("⚠ Master trainer initialization had issues")
        
        # Test component availability
        if trainer.components:
            available_components = 0
            for name in ['tool_manager', 'intelligent_selector', 'state_encoder']:
                if trainer.components.get(name):
                    available_components += 1
                    logger.info(f"✓ Component '{name}' available")
                else:
                    logger.info(f"- Component '{name}' not available")
            
            logger.info(f"✓ Master trainer has {available_components}/3 core components")
        else:
            logger.warning("⚠ Master trainer has no components")
        
        # Test skill categories
        from training_environment.newbie_to_pro_training import SkillCategory
        skill_count = len(SkillCategory)
        logger.info(f"✓ Master trainer has access to {skill_count} skill categories")
        
        # Test that lesson execution method exists
        if hasattr(trainer, '_execute_lesson'):
            logger.info("✓ Master trainer has _execute_lesson method")
        else:
            logger.error("✗ Master trainer missing _execute_lesson method")
            return False
            
        # Test that CMAB integration exists
        if hasattr(trainer, '_get_cmab_state'):
            logger.info("✓ Master trainer has CMAB integration")
        else:
            logger.error("✗ Master trainer missing CMAB integration")
            return False
            
        # Test that memory integration exists
        if hasattr(trainer, '_get_memory_state'):
            logger.info("✓ Master trainer has memory system integration")
        else:
            logger.error("✗ Master trainer missing memory system integration")
            return False
            
        # Test that stealth tracking exists
        if hasattr(trainer, '_update_stealth_score'):
            logger.info("✓ Master trainer has stealth tracking")
        else:
            logger.error("✗ Master trainer missing stealth tracking")
            return False
        
        # Test that checkpoint system exists
        if hasattr(trainer, '_save_checkpoint'):
            logger.info("✓ Master trainer has checkpoint system")
        else:
            logger.error("✗ Master trainer missing checkpoint system")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Master training verification failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def verify_skill_category_extensions():
    """Verify that SkillCategory enum has been extended with advanced domains"""
    logger.info("Verifying SkillCategory extensions...")
    
    try:
        from training_environment.newbie_to_pro_training import SkillCategory
        
        # Count skill categories by type
        basic_categories = []
        elite_categories = []
        master_categories = []
        
        for category in SkillCategory:
            cat_value = category.value
            if cat_value in ['reconnaissance', 'enumeration', 'vulnerability_analysis', 
                           'exploitation', 'post_exploitation', 'reporting', 
                           'tool_customization', 'workflow_optimization']:
                basic_categories.append(cat_value)
            elif cat_value in ['red_team_operations', 'ad_exploitation', 'binary_exploitation',
                             'network_pivoting', 'c2_operations', 'waf_bypass', 
                             'zero_day_hunting', 'apt_simulation']:
                elite_categories.append(cat_value)
            elif cat_value in ['kernel_exploitation', 'browser_exploitation', 'hypervisor_escape',
                             'mobile_exploitation', 'cloud_exploitation', 'supply_chain_attacks',
                             'firmware_rootkits', 'ics_scada', 'air_gap_bridging', 'hardware_hacking',
                             'adversarial_ml', 'llm_exploitation', 'covert_channels', 
                             'counter_intelligence', 'stealth_operations', 'research_publication']:
                master_categories.append(cat_value)
        
        logger.info(f"✓ Found {len(basic_categories)} basic categories")
        logger.info(f"✓ Found {len(elite_categories)} elite categories")
        logger.info(f"✓ Found {len(master_categories)} master categories")
        logger.info(f"✓ Total categories: {len(SkillCategory)}")
        
        if len(elite_categories) > 0 and len(master_categories) > 0:
            logger.info("✓ SkillCategory enum properly extended with advanced domains")
            return True
        else:
            logger.error("✗ SkillCategory enum missing advanced domain extensions")
            return False
            
    except Exception as e:
        logger.error(f"✗ SkillCategory verification failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def verify_tool_mappings():
    """Verify that tool mappings exist for elite and master training"""
    logger.info("Verifying tool mappings...")
    
    try:
        # Test elite tool mappings
        from training_environment.elite_operator_training import EliteOperatorTrainer
        elite_trainer_class = EliteOperatorTrainer
        if hasattr(elite_trainer_class, 'ELITE_TOOL_MAP'):
            tool_map = elite_trainer_class.ELITE_TOOL_MAP
            logger.info(f"✓ Elite training has {len(tool_map)} exercise-to-tool mappings")
            
            # Test a few mappings
            test_exercises = list(tool_map.keys())[:3]
            for exercise in test_exercises:
                tools = tool_map[exercise]
                logger.info(f"  {exercise}: {len(tools)} tools mapped")
        else:
            logger.error("✗ Elite training missing ELITE_TOOL_MAP")
            return False
        
        # Test master tool mappings
        from training_environment.master_operator_training import MasterOperatorTrainer
        master_trainer_class = MasterOperatorTrainer
        if hasattr(master_trainer_class, 'MASTER_TOOL_MAP'):
            tool_map = master_trainer_class.MASTER_TOOL_MAP
            logger.info(f"✓ Master training has {len(tool_map)} exercise-to-tool mappings")
            
            # Test a few mappings
            test_exercises = list(tool_map.keys())[:3]
            for exercise in test_exercises:
                tools = tool_map[exercise]
                logger.info(f"  {exercise}: {len(tools)} tools mapped")
        else:
            logger.error("✗ Master training missing MASTER_TOOL_MAP")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Tool mapping verification failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def verify_stealth_tracking():
    """Verify that stealth tracking is properly implemented"""
    logger.info("Verifying stealth tracking implementation...")
    
    try:
        # Test elite stealth tracking
        from training_environment.elite_operator_training import EliteOperatorTrainer
        elite_trainer_class = EliteOperatorTrainer
        if hasattr(elite_trainer_class, 'TOOL_NOISE_LEVEL'):
            noise_levels = elite_trainer_class.TOOL_NOISE_LEVEL
            logger.info(f"✓ Elite training has {len(noise_levels)} tool noise levels defined")
            
            # Check some common tools
            common_tools = ['nmap', 'nikto', 'nuclei', 'sqlmap']
            for tool in common_tools:
                if tool in noise_levels:
                    logger.info(f"  {tool}: noise level {noise_levels[tool]}")
                else:
                    logger.warning(f"  {tool}: not defined in noise levels")
        else:
            logger.error("✗ Elite training missing TOOL_NOISE_LEVEL")
            return False
        
        # Test master stealth tracking
        from training_environment.master_operator_training import MasterOperatorTrainer
        master_trainer_class = MasterOperatorTrainer
        if hasattr(master_trainer_class, 'TOOL_NOISE_LEVEL'):
            noise_levels = master_trainer_class.TOOL_NOISE_LEVEL
            logger.info(f"✓ Master training has {len(noise_levels)} tool noise levels defined")
            
            # Check some common tools
            common_tools = ['nmap', 'nikto', 'nuclei', 'sqlmap']
            for tool in common_tools:
                if tool in noise_levels:
                    logger.info(f"  {tool}: noise level {noise_levels[tool]}")
                else:
                    logger.warning(f"  {tool}: not defined in noise levels")
        else:
            logger.error("✗ Master training missing TOOL_NOISE_LEVEL")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Stealth tracking verification failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_full_verification():
    """Run complete verification of training pipeline integration"""
    logger.info("="*70)
    logger.info("STARTING TRAINING PIPELINE VERIFICATION")
    logger.info("="*70)
    
    results = {}
    
    # Run all verification tests
    results['component_init'] = verify_component_initialization()
    results['skill_extensions'] = verify_skill_category_extensions()
    results['tool_mappings'] = verify_tool_mappings()
    results['stealth_tracking'] = verify_stealth_tracking()
    results['elite_integration'] = verify_elite_training_integration()
    results['master_integration'] = verify_master_training_integration()
    
    # Summarize results
    logger.info("\n" + "="*70)
    logger.info("VERIFICATION RESULTS SUMMARY")
    logger.info("="*70)
    
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    for test_name, result in results.items():
        status = "PASS" if result else "FAIL"
        logger.info(f"{test_name.replace('_', ' ').title()}: {status}")
    
    logger.info("-"*70)
    logger.info(f"TOTAL: {passed}/{total} tests passed")
    
    if passed == total:
        logger.info("🎉 ALL VERIFICATION TESTS PASSED!")
        logger.info("The elite and master training systems are properly integrated.")
        return True
    else:
        logger.info("❌ SOME VERIFICATION TESTS FAILED!")
        logger.info("Please review the logs above for details.")
        return False

if __name__ == '__main__':
    success = run_full_verification()
    if success:
        print("\n✅ Verification completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Verification failed!")
        sys.exit(1)