# Core Features

<cite>
**Referenced Files in This Document**
- [app.py](file://backend/app.py)
- [scan_engine.py](file://backend/core/scan_engine.py)
- [autonomous_agent.py](file://backend/inference/autonomous_agent.py)
- [memory_system.py](file://backend/intelligence/memory_system.py)
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py)
- [tool_selector.py](file://backend/inference/tool_selector.py)
- [exploit_executor.py](file://backend/exploitation/exploit_executor.py)
- [scan_routes.py](file://backend/api/scan_routes.py)
- [handlers.py](file://backend/websocket/handlers.py)
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

## Introduction
This document explains the Optimus core features that enable an AI-driven autonomous penetration testing platform. It covers the end-to-end autonomous workflow across multi-phase scanning (reconnaissance, scanning, exploitation, post-exploitation), intelligent tool selection powered by hybrid ML/RL/phase-aware models, real-time progress monitoring via WebSocket events, cross-scan memory for persistent knowledge, and adaptive exploitation strategies. It also documents the relationships among the autonomous agent, intelligence layer, and reporting system, and provides concrete examples from the codebase for scan orchestration, tool integration, and report generation.

## Project Structure
Optimus is organized around a modular backend with clear separation of concerns:
- API layer: HTTP endpoints for scan lifecycle and tool execution
- Core engine: Central orchestration and state management
- Inference: Autonomous agent, tool selection, and learning modules
- Intelligence: Cross-scan memory and knowledge systems
- Exploitation: Safe, validated exploit execution with feedback loops
- Reporting: AI-enhanced report generation
- WebSocket: Real-time progress and tool output streaming

```mermaid
graph TB
subgraph "API Layer"
SR["scan_routes.py"]
IR["intelligence_routes.py"]
TR["tool_routes.py"]
RR["report_routes.py"]
end
subgraph "Core Engine"
APP["app.py"]
SM["scan_engine.py"]
end
subgraph "Inference"
AA["autonomous_agent.py"]
TS["tool_selector.py"]
end
subgraph "Intelligence"
MS["memory_system.py"]
end
subgraph "Exploitation"
EE["exploit_executor.py"]
end
subgraph "Reporting"
IRPT["intelligent_reporter.py"]
end
subgraph "WebSocket"
WH["handlers.py"]
end
SR --> SM
APP --> SM
SM --> AA
AA --> TS
AA --> MS
AA --> EE
APP --> WH
IRPT --> APP
```

**Diagram sources**
- [app.py](file://backend/app.py#L179-L274)
- [scan_engine.py](file://backend/core/scan_engine.py#L26-L81)
- [autonomous_agent.py](file://backend/inference/autonomous_agent.py#L50-L131)
- [memory_system.py](file://backend/intelligence/memory_system.py#L42-L70)
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py#L72-L101)
- [tool_selector.py](file://backend/inference/tool_selector.py#L26-L67)
- [exploit_executor.py](file://backend/exploitation/exploit_executor.py#L106-L152)
- [scan_routes.py](file://backend/api/scan_routes.py#L40-L140)
- [handlers.py](file://backend/websocket/handlers.py#L26-L119)

**Section sources**
- [app.py](file://backend/app.py#L179-L274)
- [scan_engine.py](file://backend/core/scan_engine.py#L26-L81)
- [scan_routes.py](file://backend/api/scan_routes.py#L40-L140)
- [handlers.py](file://backend/websocket/handlers.py#L26-L119)

## Core Components
- Autonomous Pentest Agent: Orchestrates multi-phase scanning, adapts strategies, integrates ML/RL/phase-specific models, and coordinates tool execution and exploitation.
- Scan Manager: Central coordinator that initializes agents, manages threads, emits WebSocket events, and updates scan state.
- Tool Selector: Hybrid system combining phase-aware models, rule-based heuristics, and availability checks to recommend tools.
- Intelligence Layer: Cross-scan memory system storing attack patterns, target profiles, tool effectiveness, and vulnerability chains for persistent knowledge.
- Exploit Executor: Safely executes exploits with validation, output parsing, and feedback for learning.
- Reporting System: AI-enhanced report generator producing executive summaries, prioritized remediation plans, and attack chain analysis.

**Section sources**
- [autonomous_agent.py](file://backend/inference/autonomous_agent.py#L50-L131)
- [scan_engine.py](file://backend/core/scan_engine.py#L26-L81)
- [tool_selector.py](file://backend/inference/tool_selector.py#L26-L67)
- [memory_system.py](file://backend/intelligence/memory_system.py#L42-L70)
- [exploit_executor.py](file://backend/exploitation/exploit_executor.py#L106-L152)
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py#L72-L101)

## Architecture Overview
The platform’s runtime architecture ties the API, core engine, inference, intelligence, exploitation, and reporting layers together with real-time WebSocket updates.

```mermaid
sequenceDiagram
participant Client as "Client"
participant API as "scan_routes.py"
participant App as "app.py"
participant SM as "scan_engine.py"
participant Agent as "autonomous_agent.py"
participant WS as "handlers.py"
Client->>API : POST /api/scan/start {target, options}
API->>App : create scan state, store in active_scans
API->>SM : get_scan_manager(socketio, active_scans)
SM->>Agent : start_scan(target, options)
Agent->>WS : emit "scan_started"
loop Multi-phase orchestration
Agent->>Agent : select tools (tool_selector)
Agent->>WS : emit "phase_transition"
Agent->>WS : emit "tool_execution_start"
Agent->>WS : emit "tool_output"
Agent->>WS : emit "tool_execution_complete"
Agent->>Agent : update state, detect phase transitions
end
Agent->>WS : emit "scan_complete"
API-->>Client : scan status/results
```

**Diagram sources**
- [scan_routes.py](file://backend/api/scan_routes.py#L40-L140)
- [app.py](file://backend/app.py#L252-L274)
- [scan_engine.py](file://backend/core/scan_engine.py#L82-L148)
- [autonomous_agent.py](file://backend/inference/autonomous_agent.py#L133-L327)
- [handlers.py](file://backend/websocket/handlers.py#L123-L179)

## Detailed Component Analysis

### Autonomous Pentest Agent
The agent orchestrates the entire autonomous workflow:
- Initializes ToolManager, PhaseController, VulnerabilityKnowledgeBase, DynamicToolDatabase, StrategySelector, RealTimeLearningModule, and optional Deep RL agent and OptimusBrain.
- Runs a multi-phase loop across reconnaissance, scanning, exploitation, post-exploitation, and covering tracks.
- Adapts strategy and phase transitions based on findings and staleness detection.
- Generates tool parameters per phase and executes tools via ToolManager.
- Integrates exploitation via ExploitationManager and records results.

```mermaid
classDiagram
class AutonomousPentestAgent {
+run_autonomous_scan(target, config)
+conduct_scan(target, config)
-_run_fully_autonomous_scan(target, config)
-_make_autonomous_decision(state, analysis)
-_get_priority_tools_for_findings(types, tools)
-_generate_tool_parameters(tool, state, analysis)
}
class ToolManager
class PhaseController
class VulnerabilityKnowledgeBase
class DynamicToolDatabase
class StrategySelector
class RealTimeLearningModule
class ExploitationManager
class DeepRLAgent
class OptimusBrain
AutonomousPentestAgent --> ToolManager : "uses"
AutonomousPentestAgent --> PhaseController : "uses"
AutonomousPentestAgent --> VulnerabilityKnowledgeBase : "uses"
AutonomousPentestAgent --> DynamicToolDatabase : "uses"
AutonomousPentestAgent --> StrategySelector : "uses"
AutonomousPentestAgent --> RealTimeLearningModule : "uses"
AutonomousPentestAgent --> ExploitationManager : "optional"
AutonomousPentestAgent --> DeepRLAgent : "optional"
AutonomousPentestAgent --> OptimusBrain : "optional"
```

**Diagram sources**
- [autonomous_agent.py](file://backend/inference/autonomous_agent.py#L50-L131)

**Section sources**
- [autonomous_agent.py](file://backend/inference/autonomous_agent.py#L133-L327)
- [autonomous_agent.py](file://backend/inference/autonomous_agent.py#L564-L677)
- [autonomous_agent.py](file://backend/inference/autonomous_agent.py#L718-L794)

### Scan Manager and Orchestration
The Scan Manager centralizes scan lifecycle:
- Initializes ToolManager and AutonomousPentestAgent.
- Starts scans in background threads, emitting WebSocket events for phase transitions and completion.
- Manages stop/pause/resume controls and updates scan state atomically using locks.
- Provides tool execution and recommendations APIs.

```mermaid
sequenceDiagram
participant API as "scan_routes.py"
participant SM as "scan_engine.py"
participant Agent as "autonomous_agent.py"
participant WS as "handlers.py"
API->>SM : start_scan(scan_id, target, options)
SM->>Agent : run_autonomous_scan(target, config)
Agent->>WS : emit "phase_transition"
Agent->>WS : emit "tool_execution_start"
Agent->>WS : emit "tool_execution_complete"
Agent->>WS : emit "scan_complete"
SM->>API : update scan state, time_elapsed
```

**Diagram sources**
- [scan_engine.py](file://backend/core/scan_engine.py#L82-L148)
- [autonomous_agent.py](file://backend/inference/autonomous_agent.py#L133-L327)
- [handlers.py](file://backend/websocket/handlers.py#L162-L179)

**Section sources**
- [scan_engine.py](file://backend/core/scan_engine.py#L26-L81)
- [scan_engine.py](file://backend/core/scan_engine.py#L82-L148)
- [scan_engine.py](file://backend/core/scan_engine.py#L311-L364)

### Intelligent Tool Selection
The PhaseAwareToolSelector combines:
- Phase-specific models (when available) with rule-based heuristics.
- Availability checks via tool registry and anti-repetition filters.
- Confidence thresholds and reasoning for transparency.

```mermaid
flowchart TD
Start(["Recommend Tools"]) --> Prep["Prepare context for model"]
Prep --> PS{"Phase-specific model available?"}
PS --> |Yes| PSRec["Get ML recommendations"]
PS --> |No| Rule["Apply rule-based selector"]
PSRec --> Combine["Merge ML + rules + availability"]
Rule --> Combine
Combine --> Filter["Filter blacklisted/recently used/unregistered"]
Filter --> Empty{"Any tools left?"}
Empty --> |No| Suggest["Suggest next phase"]
Empty --> |Yes| Return["Return top tools"]
```

**Diagram sources**
- [tool_selector.py](file://backend/inference/tool_selector.py#L68-L186)
- [tool_selector.py](file://backend/inference/tool_selector.py#L188-L296)
- [tool_selector.py](file://backend/inference/tool_selector.py#L298-L390)

**Section sources**
- [tool_selector.py](file://backend/inference/tool_selector.py#L26-L67)
- [tool_selector.py](file://backend/inference/tool_selector.py#L68-L186)
- [tool_selector.py](file://backend/inference/tool_selector.py#L298-L390)

### Cross-Scan Memory and Persistent Knowledge
The SmartMemorySystem persists insights across scans:
- Stores attack patterns, target profiles, tool effectiveness, vulnerability chains, and scan history.
- Supports semantic recall with embeddings and tags.
- Enables cross-scan pattern recognition and improved tool selection.

```mermaid
erDiagram
MEMORIES {
string id PK
string memory_type
text content
blob embedding
float importance
int access_count
string created_at
string last_accessed
text tags
text related_memories
}
ATTACK_PATTERNS {
string id PK
string target_type
text technology_stack
text attack_sequence
float success_rate
float avg_time_seconds
int findings_count
string last_used
int use_count
}
TARGET_PROFILES {
string id PK
string target_hash UK
string target_type
text technologies
text open_ports
text vulnerabilities_found
text successful_tools
text failed_tools
int waf_detected
string first_seen
string last_seen
int scan_count
}
TOOL_EFFECTIVENESS {
int id PK
string tool_name
string target_type
string phase
string context_hash
int success
int vulns_found
float execution_time
string timestamp
}
VULN_CHAINS {
string id PK
text chain_steps
string initial_vuln
string final_impact
int success
string target_type
text technology_stack
string discovery_date
int use_count
}
MEMORIES ||--o{ ATTACK_PATTERNS : "stores"
MEMORIES ||--o{ TARGET_PROFILES : "stores"
MEMORIES ||--o{ TOOL_EFFECTIVENESS : "stores"
MEMORIES ||--o{ VULN_CHAINS : "stores"
```

**Diagram sources**
- [memory_system.py](file://backend/intelligence/memory_system.py#L80-L183)
- [memory_system.py](file://backend/intelligence/memory_system.py#L324-L414)
- [memory_system.py](file://backend/intelligence/memory_system.py#L474-L551)
- [memory_system.py](file://backend/intelligence/memory_system.py#L639-L722)
- [memory_system.py](file://backend/intelligence/memory_system.py#L763-L800)

**Section sources**
- [memory_system.py](file://backend/intelligence/memory_system.py#L42-L70)
- [memory_system.py](file://backend/intelligence/memory_system.py#L324-L414)
- [memory_system.py](file://backend/intelligence/memory_system.py#L474-L551)
- [memory_system.py](file://backend/intelligence/memory_system.py#L639-L722)
- [memory_system.py](file://backend/intelligence/memory_system.py#L763-L800)

### Adaptive Exploitation and Safe Execution
ExploitExecutor validates commands, executes via ToolManager, parses results, and provides recommendations:
- Safety validation against destructive patterns.
- Extraction of credentials, databases, tables, versions, and files.
- Status classification (success, partial, failed, blocked, timeout).
- Recommendations for next steps and learning feedback.

```mermaid
flowchart TD
A["Receive command/context"] --> B["Validate safety"]
B --> |Unsafe| E["Return ERROR with recommendations"]
B --> |Safe| C["Execute via ToolManager"]
C --> D["Analyze output<br/>extract data, credentials, files"]
D --> F{"Shell obtained?"}
F --> |Yes| G["SUCCESS"]
F --> |No| H{"Success indicators found?"}
H --> |Yes| I["SUCCESS"]
H --> |No| J{"Failure indicators found?"}
J --> |Yes| K["FAILED"]
J --> |No| L["PARTIAL or FAILED"]
G --> M["Store result, update history"]
I --> M
K --> M
L --> M
M --> N["Return ExploitResult with recommendations"]
```

**Diagram sources**
- [exploit_executor.py](file://backend/exploitation/exploit_executor.py#L240-L356)
- [exploit_executor.py](file://backend/exploitation/exploit_executor.py#L416-L533)
- [exploit_executor.py](file://backend/exploitation/exploit_executor.py#L535-L620)

**Section sources**
- [exploit_executor.py](file://backend/exploitation/exploit_executor.py#L106-L152)
- [exploit_executor.py](file://backend/exploitation/exploit_executor.py#L240-L356)
- [exploit_executor.py](file://backend/exploitation/exploit_executor.py#L416-L533)

### Reporting and Executive Summaries
The IntelligentReportGenerator produces:
- Executive summaries using LLM when available, with template fallback.
- Prioritized remediation items (P1–P4) with effort and impact.
- Risk scoring and attack chain analysis.
- Strategic recommendations based on findings.

```mermaid
classDiagram
class IntelligentReport {
+string report_id
+string target
+string scan_id
+string generated_at
+string executive_summary
+string[] key_findings
+string risk_rating
+float risk_score
+int total_findings
+int critical_count
+int high_count
+int medium_count
+int low_count
+RemediationItem[] remediation_plan
+Dict[] findings
+Dict[] attack_chains
+string[] strategic_recommendations
}
class RemediationItem {
+string priority
+string title
+string description
+string[] affected_assets
+string[] cve_ids
+string effort
+string impact
+string recommended_action
+string[] references
}
class IntelligentReportGenerator {
+generate_report(scan_state) IntelligentReport
-_count_by_severity(findings) Dict
-_calculate_risk_score(findings) float
-_get_risk_rating(score) string
-_generate_remediation_plan(findings) List
-_extract_key_findings(findings) List
-_generate_executive_summary(state, findings, counts, score) string
-_analyze_attack_chains(findings, state) List
-_generate_strategic_recommendations(findings, state) List
}
IntelligentReportGenerator --> IntelligentReport : "produces"
IntelligentReport --> RemediationItem : "contains"
```

**Diagram sources**
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py#L15-L70)
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py#L72-L101)
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py#L102-L160)

**Section sources**
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py#L102-L160)
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py#L188-L221)
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py#L223-L271)
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py#L388-L406)
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py#L484-L514)
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py#L516-L548)

### Real-Time Progress Monitoring
WebSocket handlers emit live events for:
- Scan lifecycle: started, update, phase transition, complete, error.
- Tool lifecycle: start, output, completion.
- Finding discovery and tool resolution.

```mermaid
sequenceDiagram
participant Agent as "autonomous_agent.py"
participant WS as "handlers.py"
participant FE as "Frontend"
Agent->>WS : emit "phase_transition"
Agent->>WS : emit "tool_execution_start"
Agent->>WS : emit "tool_output"
Agent->>WS : emit "tool_execution_complete"
Agent->>WS : emit "scan_complete"
FE->>WS : join_scan(room)
WS-->>FE : broadcast events
```

**Diagram sources**
- [handlers.py](file://backend/websocket/handlers.py#L123-L179)
- [handlers.py](file://backend/websocket/handlers.py#L181-L238)
- [handlers.py](file://backend/websocket/handlers.py#L240-L293)

**Section sources**
- [handlers.py](file://backend/websocket/handlers.py#L26-L119)
- [handlers.py](file://backend/websocket/handlers.py#L123-L179)
- [handlers.py](file://backend/websocket/handlers.py#L181-L238)

## Dependency Analysis
Key relationships:
- app.py registers blueprints and initializes the Scan Manager and optional intelligence modules, wiring SocketIO for real-time updates.
- scan_routes.py creates scan state, delegates to scan_engine.py, and returns results/status.
- scan_engine.py initializes the autonomous agent and orchestrates multi-phase scanning, emitting WebSocket events.
- autonomous_agent.py coordinates tool selection, exploitation, and state updates.
- tool_selector.py provides hybrid tool recommendations.
- exploit_executor.py executes validated exploits and feeds results back into the agent.
- memory_system.py persists and retrieves cross-scan knowledge.
- intelligent_reporter.py generates reports from scan state.

```mermaid
graph LR
APP["app.py"] --> SR["scan_routes.py"]
APP --> WH["handlers.py"]
SR --> SM["scan_engine.py"]
SM --> AA["autonomous_agent.py"]
AA --> TS["tool_selector.py"]
AA --> EE["exploit_executor.py"]
AA --> MS["memory_system.py"]
APP --> IRPT["intelligent_reporter.py"]
```

**Diagram sources**
- [app.py](file://backend/app.py#L179-L274)
- [scan_routes.py](file://backend/api/scan_routes.py#L40-L140)
- [scan_engine.py](file://backend/core/scan_engine.py#L26-L81)
- [autonomous_agent.py](file://backend/inference/autonomous_agent.py#L50-L131)
- [tool_selector.py](file://backend/inference/tool_selector.py#L26-L67)
- [exploit_executor.py](file://backend/exploitation/exploit_executor.py#L106-L152)
- [memory_system.py](file://backend/intelligence/memory_system.py#L42-L70)
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py#L72-L101)

**Section sources**
- [app.py](file://backend/app.py#L179-L274)
- [scan_engine.py](file://backend/core/scan_engine.py#L26-L81)
- [autonomous_agent.py](file://backend/inference/autonomous_agent.py#L50-L131)
- [tool_selector.py](file://backend/inference/tool_selector.py#L26-L67)
- [exploit_executor.py](file://backend/exploitation/exploit_executor.py#L106-L152)
- [memory_system.py](file://backend/intelligence/memory_system.py#L42-L70)
- [intelligent_reporter.py](file://backend/reporting/intelligent_reporter.py#L72-L101)

## Performance Considerations
- Asynchronous execution and background threads prevent blocking the API and keep WebSocket updates responsive.
- Tool execution history and memory caching reduce repeated computation and improve recommendations.
- Confidence thresholds and anti-repetition mechanisms limit redundant tool usage and reduce wasted time.
- Embedding-based semantic recall in memory system balances accuracy and performance with indexing and similarity ranking.

## Troubleshooting Guide
Common issues and mitigations:
- Circular imports: Lazy loading of scan manager and active scans in routes and handlers resolves import-time conflicts.
- Tool availability: Use tool registry checks and rule-based fallbacks to avoid attempting unregistered tools.
- Safety violations: ExploitExecutor blocks destructive commands; review recommendations and adjust exploit parameters.
- WebSocket failures: Verify SocketIO configuration and room joins; ensure correlation IDs are propagated for traceability.
- Intelligence disabled: If memory or brain modules are unavailable, the agent falls back to rule-based and heuristic strategies.

**Section sources**
- [scan_routes.py](file://backend/api/scan_routes.py#L22-L33)
- [handlers.py](file://backend/websocket/handlers.py#L16-L24)
- [exploit_executor.py](file://backend/exploitation/exploit_executor.py#L394-L414)
- [app.py](file://backend/app.py#L232-L239)

## Conclusion
Optimus delivers a robust, AI-driven autonomous penetration testing platform. Its multi-phase scanning, hybrid intelligent tool selection, real-time monitoring, cross-scan memory, and adaptive exploitation collectively enable efficient and effective security assessments. The modular architecture ensures maintainability, extensibility, and resilience, while the reporting system transforms raw findings into actionable insights for stakeholders.