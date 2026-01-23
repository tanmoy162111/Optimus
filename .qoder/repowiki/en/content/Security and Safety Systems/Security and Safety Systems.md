# Security and Safety Systems

<cite>
**Referenced Files in This Document**
- [command_safety.py](file://backend/inference/command_safety.py)
- [target_integrity_gate.py](file://backend/inference/target_integrity_gate.py)
- [target_schema.py](file://backend/inference/target_schema.py)
- [tool_manager.py](file://backend/inference/tool_manager.py)
- [config.py](file://backend/config.py)
- [test_post_exploitation_safety.py](file://backend/testing/test_post_exploitation_safety.py)
- [post_exploitation_training_logs.json](file://backend/training/data/phase_training_logs/post_exploitation_training_logs.json)
- [covering_tracks_training_logs.json](file://backend/training/data/phase_training_logs/covering_tracks_training_logs.json)
- [phase_controller.py](file://backend/inference/phase_controller.py)
- [rule_based_tool_selector.py](file://backend/inference/rule_based_tool_selector.py)
- [professional_report.py](file://backend/reporting/professional_report.py)
</cite>

## Table of Contents
1. [Introduction](#introduction)
2. [Project Structure](#project-structure)
3. [Core Components](#core-components)
4. [Architecture Overview](#architecture-overview)
5. [Detailed Component Analysis](#detailed-component-analysis)
6. [Dependency Analysis](#dependency-analysis)
7. [Performance Considerations](#performance-considerations)
8. [Troubleshooting Guide](#troubleshooting-guide)
9. [Conclusion](#conclusion)
10. [Appendices](#appendices)

## Introduction
This document details the security and safety systems in Optimus, focusing on three pillars:
- Command safety controls that validate and sanitize input commands before execution
- Target integrity gates that prevent destructive operations by enforcing authorized targets and safe formats
- Post-exploitation safety mechanisms that implement covering tracks and responsible disclosure practices

It explains how timeouts and resource limits are enforced, how input validation systems operate, and how these components collaborate to maintain system integrity during autonomous operations. Practical examples demonstrate configuration, risk assessment, and responsible disclosure alignment.

## Project Structure
The safety and integrity controls span several modules:
- Command safety: structured command validation, argument sanitization, and safe execution
- Target integrity: target normalization, authorization checks, and safe rendering per tool
- Post-exploitation safety: session gating, rate limiting, and timeout enforcement
- Supporting infrastructure: configuration, training logs, and reporting

```mermaid
graph TB
subgraph "Safety and Integrity"
CS["Command Safety<br/>command_safety.py"]
TIG["Target Integrity Gate<br/>target_integrity_gate.py"]
TS["Target Schema<br/>target_schema.py"]
TM["Tool Manager<br/>tool_manager.py"]
PC["Phase Controller<br/>phase_controller.py"]
RBS["Rule-Based Selector<br/>rule_based_tool_selector.py"]
end
subgraph "Configuration and Reporting"
CFG["Configuration<br/>config.py"]
PR["Professional Report<br/>professional_report.py"]
end
subgraph "Training Data"
PETL["Post-Exploitation Logs<br/>post_exploitation_training_logs.json"]
CCTL["Covering Tracks Logs<br/>covering_tracks_training_logs.json"]
end
CS --> TM
TIG --> TS
TIG --> TM
TM --> CFG
PC --> TM
RBS --> TM
PR --> CFG
PETL -.-> TM
CCTL -.-> TM
```

**Diagram sources**
- [command_safety.py](file://backend/inference/command_safety.py#L1-L319)
- [target_integrity_gate.py](file://backend/inference/target_integrity_gate.py#L1-L361)
- [target_schema.py](file://backend/inference/target_schema.py#L1-L81)
- [tool_manager.py](file://backend/inference/tool_manager.py#L1-L1480)
- [config.py](file://backend/config.py#L1-L115)
- [phase_controller.py](file://backend/inference/phase_controller.py#L290-L326)
- [rule_based_tool_selector.py](file://backend/inference/rule_based_tool_selector.py#L378-L416)
- [post_exploitation_training_logs.json](file://backend/training/data/phase_training_logs/post_exploitation_training_logs.json#L1-L800)
- [covering_tracks_training_logs.json](file://backend/training/data/phase_training_logs/covering_tracks_training_logs.json#L93-L324)
- [professional_report.py](file://backend/reporting/professional_report.py#L1-L200)

**Section sources**
- [command_safety.py](file://backend/inference/command_safety.py#L1-L319)
- [target_integrity_gate.py](file://backend/inference/target_integrity_gate.py#L1-L361)
- [target_schema.py](file://backend/inference/target_schema.py#L1-L81)
- [tool_manager.py](file://backend/inference/tool_manager.py#L1-L1480)
- [config.py](file://backend/config.py#L1-L115)
- [phase_controller.py](file://backend/inference/phase_controller.py#L290-L326)
- [rule_based_tool_selector.py](file://backend/inference/rule_based_tool_selector.py#L378-L416)
- [post_exploitation_training_logs.json](file://backend/training/data/phase_training_logs/post_exploitation_training_logs.json#L1-L800)
- [covering_tracks_training_logs.json](file://backend/training/data/phase_training_logs/covering_tracks_training_logs.json#L93-L324)
- [professional_report.py](file://backend/reporting/professional_report.py#L1-L200)

## Core Components
- Command Safety: Structured command schema, validator, logger, and safe executor with timeout enforcement and SSH/local execution paths
- Target Integrity Gate: Raw target validation, authorization checks, hostname/IP resolution, and tool-specific target formatting
- Post-Exploitation Safety: Session gating, rate limiting, and timeout restrictions for post-exploitation phases
- Configuration: Centralized timeouts, phase definitions, and tool catalogs
- Training Data: Behavioral logs for post-exploitation and covering tracks to inform safety policies
- Reporting: Professional report generator supporting responsible disclosure and remediation guidance

**Section sources**
- [command_safety.py](file://backend/inference/command_safety.py#L18-L319)
- [target_integrity_gate.py](file://backend/inference/target_integrity_gate.py#L19-L361)
- [tool_manager.py](file://backend/inference/tool_manager.py#L910-L955)
- [config.py](file://backend/config.py#L78-L115)
- [post_exploitation_training_logs.json](file://backend/training/data/phase_training_logs/post_exploitation_training_logs.json#L1-L800)
- [covering_tracks_training_logs.json](file://backend/training/data/phase_training_logs/covering_tracks_training_logs.json#L93-L324)
- [professional_report.py](file://backend/reporting/professional_report.py#L73-L200)

## Architecture Overview
The safety architecture enforces a layered defense:
- Input normalization and validation occur early (target integrity gate)
- Command construction and execution are mediated by a safe executor with timeouts and logging
- Post-exploitation safety adds session, rate, and timeout controls
- Reporting supports responsible disclosure with remediation guidance

```mermaid
sequenceDiagram
participant User as "User/Agent"
participant Gate as "TargetIntegrityGate"
participant Schema as "ValidatedTarget"
participant Manager as "ToolManager"
participant Safety as "SafeCommandExecutor"
participant Config as "Config"
User->>Gate : "Raw target"
Gate->>Gate : "validate_raw_target()"
Gate->>Gate : "validate_target_format()"
Gate->>Gate : "is_authorized_target()"
Gate->>Schema : "create ValidatedTarget"
Schema-->>Manager : "validated target"
Manager->>Manager : "dynamic timeout calculation"
Manager->>Safety : "execute_tool() with parameters"
Safety->>Safety : "validate_command()"
Safety->>Safety : "execute_command() with timeout"
Safety-->>Manager : "result or block"
Manager-->>User : "status and output"
```

**Diagram sources**
- [target_integrity_gate.py](file://backend/inference/target_integrity_gate.py#L62-L326)
- [target_schema.py](file://backend/inference/target_schema.py#L8-L81)
- [tool_manager.py](file://backend/inference/tool_manager.py#L910-L955)
- [command_safety.py](file://backend/inference/command_safety.py#L240-L315)
- [config.py](file://backend/config.py#L19-L24)

## Detailed Component Analysis

### Command Safety Controls
Command safety separates LLM suggestions from execution through:
- Structured command schema with tool, arguments, target, optional type, and timeout
- Validator that checks tool availability, target validity, and absence of dangerous patterns
- Safe executor that logs rejections and executions, and enforces timeouts for both local and SSH execution

Key behaviors:
- Argument sanitization prevents command chaining and injection
- Target deduplication avoids double injection in constructed command lines
- Timeout enforcement via subprocess and SSH clients
- Logging for auditability and incident response

```mermaid
classDiagram
class Command {
+string tool
+string[] arguments
+string target
+CommandType command_type
+int timeout
+to_command_line() string
}
class CommandValidator {
+validate_command(command) (bool, str)
-_is_valid_target(target) bool
-_is_valid_web_target(target) bool
-_has_dangerous_pattern(arg) bool
-_get_known_tools() set
-_is_tool_available(tool) bool
}
class CommandLogger {
+log_rejected_command(command, reason, phase, scan_id) void
+log_validated_command(command) void
+log_executed_command(command, result) void
}
class SafeCommandExecutor {
+execute_command(command, phase, scan_id) CompletedProcess?
+execute_command_safe(tool, arguments, target, phase, scan_id) CompletedProcess?
}
SafeCommandExecutor --> CommandValidator : "uses"
SafeCommandExecutor --> CommandLogger : "uses"
CommandValidator --> Command : "validates"
```

**Diagram sources**
- [command_safety.py](file://backend/inference/command_safety.py#L27-L319)

**Section sources**
- [command_safety.py](file://backend/inference/command_safety.py#L18-L319)

### Target Integrity Gate
The target integrity gate ensures only authorized and properly formatted targets are used:
- Raw target validation strips whitespace and rejects injection attempts
- Target format validation parses scheme/host/port and normalizes to a unified schema
- Authorization checks against authorized and blacklisted patterns and private networks
- Hostname resolution to IP with error handling
- Tool-specific target formatting for CLI and web tools

```mermaid
flowchart TD
Start(["Input target"]) --> Raw["validate_raw_target()"]
Raw --> Format["validate_target_format()"]
Format --> Auth{"is_authorized_target()"}
Auth --> |No| Block["Raise TargetIntegrityError"]
Auth --> |Yes| Resolve["resolve_hostname_to_ip()"]
Resolve --> Render["get_formatted_for_tool()"]
Render --> Done(["ValidatedTarget"])
```

**Diagram sources**
- [target_integrity_gate.py](file://backend/inference/target_integrity_gate.py#L62-L349)
- [target_schema.py](file://backend/inference/target_schema.py#L56-L81)

**Section sources**
- [target_integrity_gate.py](file://backend/inference/target_integrity_gate.py#L19-L361)
- [target_schema.py](file://backend/inference/target_schema.py#L8-L81)

### Post-Exploitation Safety Mechanisms
Post-exploitation safety integrates session gating, rate limiting, and timeout enforcement:
- Session gating requires a valid session identifier for post-exploitation tools
- Rate limiting blocks rapid-fire tool execution to reduce risk
- Timeout restrictions cap execution duration for post-exploitation tasks
- Training logs inform policies around detection probability, artifacts, and cleanup completeness

```mermaid
sequenceDiagram
participant Agent as "Agent"
participant Manager as "ToolManager"
participant Safety as "Post-Exploitation Guards"
participant Logs as "Training Logs"
Agent->>Manager : "execute_tool(phase='post_exploitation', params)"
Manager->>Safety : "validate session, rate, timeout"
alt "invalid session"
Safety-->>Manager : "block with error"
else "valid session"
Safety-->>Manager : "proceed"
end
Manager->>Logs : "monitor detection probability and artifacts"
Logs-->>Manager : "context for policy decisions"
Manager-->>Agent : "result"
```

**Diagram sources**
- [test_post_exploitation_safety.py](file://backend/testing/test_post_exploitation_safety.py#L11-L144)
- [tool_manager.py](file://backend/inference/tool_manager.py#L910-L955)
- [post_exploitation_training_logs.json](file://backend/training/data/phase_training_logs/post_exploitation_training_logs.json#L1-L800)
- [covering_tracks_training_logs.json](file://backend/training/data/phase_training_logs/covering_tracks_training_logs.json#L93-L324)

**Section sources**
- [test_post_exploitation_safety.py](file://backend/testing/test_post_exploitation_safety.py#L1-L189)
- [tool_manager.py](file://backend/inference/tool_manager.py#L910-L955)
- [post_exploitation_training_logs.json](file://backend/training/data/phase_training_logs/post_exploitation_training_logs.json#L1-L800)
- [covering_tracks_training_logs.json](file://backend/training/data/phase_training_logs/covering_tracks_training_logs.json#L93-L324)

### Covering Tracks and Responsible Disclosure
Covering tracks focuses on minimizing forensic footprint:
- Cleanup tools (e.g., clear logs, timestomp, shred) are prioritized
- Completion criteria include coverage thresholds and number of tools executed
- Responsible disclosure is supported by structured reporting with remediation guidance

```mermaid
flowchart TD
Start(["Post-Exploitation Phase"]) --> Select["Select cleanup tools"]
Select --> Execute["Execute cleanup actions"]
Execute --> Measure["Measure forensic evidence score"]
Measure --> Threshold{"Coverage threshold met?"}
Threshold --> |No| Continue["Continue executing cleanup tools"]
Threshold --> |Yes| Complete["Complete covering tracks"]
```

**Diagram sources**
- [rule_based_tool_selector.py](file://backend/inference/rule_based_tool_selector.py#L402-L416)
- [phase_controller.py](file://backend/inference/phase_controller.py#L303-L321)
- [covering_tracks_training_logs.json](file://backend/training/data/phase_training_logs/covering_tracks_training_logs.json#L93-L324)
- [professional_report.py](file://backend/reporting/professional_report.py#L73-L200)

**Section sources**
- [rule_based_tool_selector.py](file://backend/inference/rule_based_tool_selector.py#L402-L416)
- [phase_controller.py](file://backend/inference/phase_controller.py#L303-L321)
- [covering_tracks_training_logs.json](file://backend/training/data/phase_training_logs/covering_tracks_training_logs.json#L93-L324)
- [professional_report.py](file://backend/reporting/professional_report.py#L73-L200)

## Dependency Analysis
Safety components depend on configuration and training data:
- Configuration defines timeouts and phase/tool catalogs
- Training logs guide policy decisions for detection probability and cleanup effectiveness
- Tool manager orchestrates dynamic timeout adjustments and safety checks

```mermaid
graph LR
CFG["Config"] --> TM["ToolManager"]
CFG --> CS["SafeCommandExecutor"]
CFG --> TIG["TargetIntegrityGate"]
PETL["Post-Exploitation Logs"] --> TM
CCTL["Covering Tracks Logs"] --> TM
TIG --> TS["ValidatedTarget"]
TM --> CS
TM --> PR["Professional Report"]
```

**Diagram sources**
- [config.py](file://backend/config.py#L19-L115)
- [tool_manager.py](file://backend/inference/tool_manager.py#L910-L955)
- [command_safety.py](file://backend/inference/command_safety.py#L240-L315)
- [target_integrity_gate.py](file://backend/inference/target_integrity_gate.py#L19-L361)
- [target_schema.py](file://backend/inference/target_schema.py#L8-L81)
- [post_exploitation_training_logs.json](file://backend/training/data/phase_training_logs/post_exploitation_training_logs.json#L1-L800)
- [covering_tracks_training_logs.json](file://backend/training/data/phase_training_logs/covering_tracks_training_logs.json#L93-L324)
- [professional_report.py](file://backend/reporting/professional_report.py#L73-L200)

**Section sources**
- [config.py](file://backend/config.py#L19-L115)
- [tool_manager.py](file://backend/inference/tool_manager.py#L910-L955)
- [command_safety.py](file://backend/inference/command_safety.py#L240-L315)
- [target_integrity_gate.py](file://backend/inference/target_integrity_gate.py#L19-L361)
- [target_schema.py](file://backend/inference/target_schema.py#L8-L81)
- [post_exploitation_training_logs.json](file://backend/training/data/phase_training_logs/post_exploitation_training_logs.json#L1-L800)
- [covering_tracks_training_logs.json](file://backend/training/data/phase_training_logs/covering_tracks_training_logs.json#L93-L324)
- [professional_report.py](file://backend/reporting/professional_report.py#L73-L200)

## Performance Considerations
- Timeouts: Centralized via configuration and dynamically adjusted by tool category and coverage/time remaining
- Resource limiting: Enforced by timeouts and rate limiting in post-exploitation
- Validation overhead: Target integrity gate and command validator add minimal cost compared to tool execution
- Logging: Structured logs support auditing without significant runtime overhead

[No sources needed since this section provides general guidance]

## Troubleshooting Guide
Common issues and resolutions:
- Command rejected due to dangerous patterns: Review arguments for injection indicators and adjust tool parameters
- Target blocked by integrity gate: Verify target format and authorization; ensure hostname resolves to private or authorized networks
- Post-exploitation blocked: Confirm valid session ID, reduce execution frequency to avoid rate limits, and lower timeout values
- Excessive execution time: Adjust dynamic timeout parameters and tool categories in configuration

**Section sources**
- [command_safety.py](file://backend/inference/command_safety.py#L102-L133)
- [target_integrity_gate.py](file://backend/inference/target_integrity_gate.py#L102-L149)
- [test_post_exploitation_safety.py](file://backend/testing/test_post_exploitation_safety.py#L11-L144)
- [tool_manager.py](file://backend/inference/tool_manager.py#L910-L955)

## Conclusion
Optimus employs a layered safety architecture combining command validation, target integrity, and post-exploitation controls. Together with dynamic timeouts, rate limiting, and responsible disclosure reporting, these mechanisms preserve system integrity and minimize unintended impact during autonomous operations.

[No sources needed since this section summarizes without analyzing specific files]

## Appendices

### Practical Examples

- Configure timeouts and limits
  - Set command timeouts and connection parameters in configuration
  - Example paths:
    - [config.py](file://backend/config.py#L19-L24)
    - [tool_manager.py](file://backend/inference/tool_manager.py#L910-L955)

- Validate and execute a command safely
  - Build a structured command and pass through the safe executor
  - Example paths:
    - [command_safety.py](file://backend/inference/command_safety.py#L27-L319)

- Enforce target integrity
  - Normalize and authorize targets before tool execution
  - Example paths:
    - [target_integrity_gate.py](file://backend/inference/target_integrity_gate.py#L62-L349)
    - [target_schema.py](file://backend/inference/target_schema.py#L56-L81)

- Post-exploitation safety configuration
  - Enforce session gating, rate limiting, and timeout restrictions
  - Example paths:
    - [test_post_exploitation_safety.py](file://backend/testing/test_post_exploitation_safety.py#L11-L144)

- Responsible disclosure practices
  - Use professional report generator for remediation guidance
  - Example paths:
    - [professional_report.py](file://backend/reporting/professional_report.py#L73-L200)

### Risk Assessment Procedures
- Evaluate detection probability and forensic evidence from training logs
  - Example paths:
    - [post_exploitation_training_logs.json](file://backend/training/data/phase_training_logs/post_exploitation_training_logs.json#L1-L800)
    - [covering_tracks_training_logs.json](file://backend/training/data/phase_training_logs/covering_tracks_training_logs.json#L93-L324)

- Define acceptable risk thresholds for post-exploitation and covering tracks
  - Use completion criteria and coverage metrics
  - Example paths:
    - [phase_controller.py](file://backend/inference/phase_controller.py#L303-L321)
    - [rule_based_tool_selector.py](file://backend/inference/rule_based_tool_selector.py#L402-L416)