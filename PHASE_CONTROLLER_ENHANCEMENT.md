# Phase Controller Enhancement

## Overview
This enhancement adds intelligent logic to the phase controller that allows the agent to run different tools until it finds something, and then make decisions about whether to follow a different approach or move to the next phase when all tools have been exhausted.

## Key Features Implemented

### 1. Tool Exhaustion Detection
The phase controller now detects when all tools in the current phase have been tried:
- Maintains a mapping of tools available for each phase
- Tracks executed tools and compares against phase tool set
- Identifies when all phase-appropriate tools have been exhausted

### 2. Approach Change Logic
When all tools in a phase have been tried without sufficient findings, the controller decides whether to:
- **Change Approach**: Stay in the current phase but try different techniques
- **Move to Next Phase**: Proceed to the next logical phase in the pentest workflow

### 3. Decision Criteria

#### When to Change Approach (Stay in Current Phase)
- Some findings exist but coverage is low (< 30%)
- Many tools tried (> 8) but very few findings (< 2)
- Early phases (reconnaissance, scanning) with no findings
- Strategic opportunity to try different techniques

#### When to Move to Next Phase
- Sufficient findings in current phase
- Exhausted approach changes (limit: 3)
- High confidence in current phase completion
- Coverage meets phase completion criteria

### 4. Fully Autonomous Mode Support
The enhancement also works in fully autonomous mode:
- Tracks approach changes and tool execution patterns
- Forces approach changes when progress stalls
- Cycles through different strategies when approaches are exhausted

## Implementation Details

### Phase Tools Mapping
```python
self.phase_tools = {
    'reconnaissance': ['sublist3r', 'amass', 'theHarvester', 'whatweb', 'dnsenum'],
    'scanning': ['nmap', 'nikto', 'nuclei', 'masscan'],
    'exploitation': ['sqlmap', 'dalfox', 'commix', 'ffuf', 'wpscan'],
    'post_exploitation': ['linpeas', 'winpeas'],
    'covering_tracks': ['clear_logs']
}
```

### New Methods Added

#### `_should_change_approach_or_phase()`
Determines if all tools in the current phase have been tried without sufficient findings.

#### `_should_change_approach()`
Decides whether to change approach or move to the next phase based on:
- Findings count and quality
- Coverage metrics
- Tools executed vs. findings ratio
- Current phase context

## Benefits

### 1. Improved Tool Utilization
- Ensures all relevant tools are tried before moving on
- Prevents premature phase transitions
- Maximizes information gathering in each phase

### 2. Adaptive Strategy
- Changes approach when stuck rather than immediately moving phases
- Provides multiple attempts at different techniques
- Balances exploration with progression

### 3. Better Decision Making
- Data-driven decisions based on findings and coverage
- Context-aware approach changes
- Prevents infinite loops in unproductive strategies

## Test Results
The implementation has been tested with various scenarios:
- ✅ All reconnaissance tools tried with no findings → Approach change suggested
- ✅ Many tools executed with few findings → Approach change suggested
- ✅ Sufficient findings achieved → Phase transition allowed
- ✅ Early phase with no findings → Approach change suggested

## Integration Points

### Phase Controller
- Enhanced `should_transition()` method
- Added new helper methods for decision logic
- Integrated with existing transition criteria

### Autonomous Agent
- Modified `run_autonomous_scan()` to handle approach changes
- Updated `_run_fully_autonomous_scan()` with similar logic
- Added tracking for approach changes and resets

## Future Enhancements
1. **Machine Learning Integration**: Use historical data to predict optimal approach changes
2. **Dynamic Tool Lists**: Adapt tool lists based on target characteristics
3. **Advanced Metrics**: Incorporate more sophisticated success indicators
4. **Feedback Loops**: Learn from approach effectiveness over time