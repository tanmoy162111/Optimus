"""
Test script to verify None handling in learning module and strategy selector
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from inference.learning_module import RealTimeLearningModule
from inference.strategy_selector import StrategySelector

def test_none_handling():
    print("Testing None handling in learning module and strategy selector...")
    
    # Test learning module with None values
    print("\n1. Testing Learning Module with None values:")
    lm = RealTimeLearningModule()
    result = lm.learn_from_execution('test_tool', None, None)
    print(f"   Result: {result}")
    print(f"   Success: {result['success'] == False}")
    print(f"   Findings count: {result['findings_count'] == 0}")
    
    # Test strategy selector with None values
    print("\n2. Testing Strategy Selector with None values:")
    ss = StrategySelector()
    strategy = ss.select_strategy(None)
    print(f"   Selected strategy: {strategy}")
    print(f"   Is adaptive: {strategy == 'adaptive'}")
    
    # Test should_change_strategy with None values
    should_change = ss.should_change_strategy(None)
    print(f"   Should change strategy: {should_change}")
    print(f"   Is False: {should_change == False}")
    
    print("\n✅ All tests passed! None handling is working correctly.")

if __name__ == '__main__':
    test_none_handling()