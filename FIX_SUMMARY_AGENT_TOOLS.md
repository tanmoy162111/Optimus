# Fix Summary: Agent Running Few Tools Issue

## Problem Identified
The autonomous pentest agent was running few tools because of excessive timeout settings that prevented multiple tools from executing within the time budget.

## Root Causes

1. **Excessive Dynamic Timeouts**: The tool manager was applying dynamic timeout multipliers that could extend timeouts up to 5x the base timeout (e.g., 630 seconds for nikto instead of 120 seconds)

2. **Timeout Override**: The tool manager was completely ignoring the timeout parameter set by the autonomous agent and applying its own calculations

3. **Blocking Execution**: Long-running tools would block the entire scan process, preventing the agent from trying other tools

## Solutions Implemented

### 1. Reduced Timeout in Autonomous Agent
**File**: `backend/inference/autonomous_agent.py`
**Method**: `_generate_tool_parameters`

```python
# Before
'timeout': 120

# After  
'timeout': 90,  # Further reduced for autonomous mode
'autonomous_mode': True  # Flag to indicate autonomous mode
```

### 2. Strict Timeout Enforcement in Tool Manager
**File**: `backend/inference/tool_manager.py`
**Method**: `build_command`

Added logic to respect the timeout parameter when in autonomous mode:

```python
# Check if we're in autonomous mode - if so, respect the timeout strictly
if parameters.get('autonomous_mode', False):
    # In autonomous mode, use the provided timeout without modification
    final_timeout = base_timeout
    parameters['timeout'] = final_timeout
    print(f"[DEBUG] Autonomous mode: Using strict timeout of {final_timeout}s")
```

### 3. Fixed Method Name Issues
Fixed incorrect method calls in the tool manager:

```python
# Before
command = self.tool_kb.generate_command(tool_name, command_target, context)

# After  
command = self.tool_kb.build_command(tool_name, command_target, context)
```

## Results After Fix

### Test Results
- **Multiple Tool Execution**: Agent now executes 5+ different tools (nikto, nuclei, sqlmap, dalfox, commix) instead of getting stuck on one
- **Proper Timeout Handling**: 90-second timeout enforced instead of 630-second timeouts
- **Finding-Based Selection**: Agent correctly selects tools based on vulnerability findings
- **Progressive Exploration**: When priority tools are exhausted, agent continues exploring new tools

### Decision Logic Working Correctly
1. **Situation Analysis**: Agent correctly analyzes findings and tool execution history
2. **Tool Prioritization**: Based on finding types:
   - web_vulnerabilities → nikto, nuclei
   - xss → dalfox, xsser  
   - sql_injection → sqlmap, commix
3. **Coverage Tracking**: Agent tracks coverage improvements (0.05 → 0.10 → 0.15 → 0.20)

## Verification

Test with mock tool execution timeouts:
```
Tools executed: 5
Unique tools: 5  
Tools: {'dalfox', 'commix', 'nuclei', 'sqlmap', 'nikto'}
Total findings: 4
```

The agent now successfully:
- Executes multiple tools within reasonable time limits
- Makes autonomous decisions based on findings
- Continues exploring until it has tried a diverse set of tools
- Handles tool timeouts gracefully by moving to the next tool