# Overall Design

<cite>
**Referenced Files in This Document**
- [backend/app.py](file://backend/app.py)
- [backend/websocket/handlers.py](file://backend/websocket/handlers.py)
- [backend/core/scan_engine.py](file://backend/core/scan_engine.py)
- [backend/inference/autonomous_agent.py](file://backend/inference/autonomous_agent.py)
- [backend/execution/ssh_client.py](file://backend/execution/ssh_client.py)
- [backend/config.py](file://backend/config.py)
- [backend/intelligence/optimus_brain.py](file://backend/intelligence/optimus_brain.py)
- [backend/training/deep_rl_agent.py](file://backend/training/deep_rl_agent.py)
- [backend/tools/hybrid_tool_system.py](file://backend/tools/hybrid_tool_system.py)
- [frontend/src/App.tsx](file://frontend/src/App.tsx)
- [frontend/src/services/socket.ts](file://frontend/src/services/socket.ts)
- [frontend/package.json](file://frontend/package.json)
- [README.md](file://README.md)
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
Optimus is an AI-driven autonomous penetration testing platform that integrates a React-based frontend dashboard with a Flask backend API. The backend orchestrates multi-phase security assessments, leveraging AI/ML capabilities for intelligent tool selection, adaptive exploitation, and real-time reporting. It uses SSH-based integration with a Kali Linux VM to execute security tools, emitting live progress via WebSocket connections to the frontend. The system balances centralized orchestration with distributed tool execution, trading off performance for security and operational control.

## Project Structure
The repository follows a layered backend architecture with a dedicated frontend SPA:
- Backend (Flask + SocketIO): API endpoints, WebSocket handlers, scan orchestration, AI/ML engines, and tool integration.
- Frontend (React + TypeScript): Dashboard UI, routing, real-time WebSocket subscriptions, and typed event handling.
- AI/ML subsystems: Deep RL agents, explainable AI, memory systems, and LLM integrations.
- Infrastructure: SSH client for Kali VM execution, configuration management, and environment variables.

```mermaid
graph TB
subgraph "Frontend"
FE_App["React App<br/>App.tsx"]
FE_WS["WebSocket Service<br/>socket.ts"]
end
subgraph "Backend"
BE_Flask["Flask App<br/>app.py"]
BE_Socket["SocketIO Handlers<br/>websocket/handlers.py"]
BE_ScanMgr["Scan Manager<br/>core/scan_engine.py"]
BE_Agent["Autonomous Agent<br/>inference/autonomous_agent.py"]
BE_AI["Optimus Brain<br/>intelligence/optimus_brain.py"]
BE_RL["Deep RL Agent<br/>training/deep_rl_agent.py"]
BE_Hybrid["Hybrid Tool System<br/>tools/hybrid_tool_system.py"]
BE_SSH["SSH Client<br/>execution/ssh_client.py"]
BE_Config["Config<br/>config.py"]
end
FE_App --> FE_WS
FE_WS --> BE_Socket
BE_Flask --> BE_Socket
BE_Flask --> BE_ScanMgr
BE_ScanMgr --> BE_Agent
BE_Agent --> BE_AI
BE_Agent --> BE_RL
BE_Agent --> BE_Hybrid
BE_Hybrid --> BE_SSH
BE_Socket --> BE_ScanMgr
BE_ScanMgr --> BE_SSH
BE_Flask --> BE_Config
```

**Diagram sources**
- [backend/app.py](file://backend/app.py#L120-L163)
- [backend/websocket/handlers.py](file://backend/websocket/handlers.py#L26-L119)
- [backend/core/scan_engine.py](file://backend/core/scan_engine.py#L26-L81)
- [backend/inference/autonomous_agent.py](file://backend/inference/autonomous_agent.py#L50-L132)
- [backend/intelligence/optimus_brain.py](file://backend/intelligence/optimus_brain.py#L46-L170)
- [backend/training/deep_rl_agent.py](file://backend/training/deep_rl_agent.py#L187-L300)
- [backend/tools/hybrid_tool_system.py](file://backend/tools/hybrid_tool_system.py#L65-L113)
- [backend/execution/ssh_client.py](file://backend/execution/ssh_client.py#L12-L86)
- [backend/config.py](file://backend/config.py#L6-L115)

**Section sources**
- [backend/app.py](file://backend/app.py#L120-L163)
- [frontend/src/App.tsx](file://frontend/src/App.tsx#L81-L161)
- [frontend/src/services/socket.ts](file://frontend/src/services/socket.ts#L64-L106)
- [README.md](file://README.md#L15-L22)

## Core Components
- Flask application with CORS and SocketIO initialization, global state for active scans, and blueprints for API routes.
- WebSocket handlers for real-time scan lifecycle events, tool execution, and AI recommendations.
- Scan manager coordinating autonomous scans, background threads, and event emission.
- Autonomous agent implementing multi-phase decision-making, tool selection, and state updates.
- AI/ML engines: Optimus Brain for unified intelligence, Deep RL agent for adaptive tool selection.
- Hybrid tool system resolving and generating commands with multiple sources (KB, memory, discovery, LLM, web).
- SSH client for secure execution on a Kali VM with configurable timeouts and retries.
- Configuration module centralizing environment-driven settings for tools, LLMs, and RL parameters.

**Section sources**
- [backend/app.py](file://backend/app.py#L168-L275)
- [backend/websocket/handlers.py](file://backend/websocket/handlers.py#L26-L119)
- [backend/core/scan_engine.py](file://backend/core/scan_engine.py#L26-L81)
- [backend/inference/autonomous_agent.py](file://backend/inference/autonomous_agent.py#L50-L132)
- [backend/intelligence/optimus_brain.py](file://backend/intelligence/optimus_brain.py#L46-L170)
- [backend/training/deep_rl_agent.py](file://backend/training/deep_rl_agent.py#L187-L300)
- [backend/tools/hybrid_tool_system.py](file://backend/tools/hybrid_tool_system.py#L65-L113)
- [backend/execution/ssh_client.py](file://backend/execution/ssh_client.py#L12-L86)
- [backend/config.py](file://backend/config.py#L6-L115)

## Architecture Overview
Optimus employs a centralized orchestration model with distributed tool execution:
- Centralized orchestration: Flask app initializes components, registers routes, and manages global state. The scan manager coordinates autonomous scans and emits real-time events.
- Distributed tool execution: The hybrid tool system resolves commands and delegates execution to the SSH client on the Kali VM. This maintains security isolation and reduces backend load.
- Event-driven architecture: WebSocket connections propagate scan lifecycle events, tool execution updates, and AI recommendations to the frontend.
- AI/ML integration: The autonomous agent leverages the Optimus Brain and Deep RL agent to adaptively select tools and strategies based on scan context and historical performance.

```mermaid
graph TB
Client["Browser Client<br/>React SPA"]
WS["WebSocket Layer<br/>SocketIO"]
API["Flask API<br/>Blueprints"]
SM["Scan Manager<br/>core/scan_engine.py"]
Agent["Autonomous Agent<br/>inference/autonomous_agent.py"]
Brain["Optimus Brain<br/>intelligence/optimus_brain.py"]
RL["Deep RL Agent<br/>training/deep_rl_agent.py"]
Hybrid["Hybrid Tool System<br/>tools/hybrid_tool_system.py"]
SSH["SSH Client<br/>execution/ssh_client.py"]
Kali["Kali VM"]
Client --> WS
WS --> API
API --> SM
SM --> Agent
Agent --> Brain
Agent --> RL
Agent --> Hybrid
Hybrid --> SSH
SSH --> Kali
```

**Diagram sources**
- [backend/app.py](file://backend/app.py#L120-L163)
- [backend/websocket/handlers.py](file://backend/websocket/handlers.py#L26-L119)
- [backend/core/scan_engine.py](file://backend/core/scan_engine.py#L26-L81)
- [backend/inference/autonomous_agent.py](file://backend/inference/autonomous_agent.py#L50-L132)
- [backend/intelligence/optimus_brain.py](file://backend/intelligence/optimus_brain.py#L46-L170)
- [backend/training/deep_rl_agent.py](file://backend/training/deep_rl_agent.py#L187-L300)
- [backend/tools/hybrid_tool_system.py](file://backend/tools/hybrid_tool_system.py#L65-L113)
- [backend/execution/ssh_client.py](file://backend/execution/ssh_client.py#L12-L86)

## Detailed Component Analysis

### Flask Application and API Routing
- Initializes logging, creates required directories, sets CORS policies, and configures SocketIO.
- Registers blueprints for API endpoints and WebSocket handlers.
- Provides health checks and root endpoint exposing available endpoints.
- Manages global state for active scans and integrates intelligence and hybrid tool systems.

```mermaid
sequenceDiagram
participant Client as "Client"
participant Flask as "Flask App"
participant API as "API Blueprints"
participant WS as "WebSocket Handlers"
Client->>Flask : GET /health
Flask-->>Client : {status, components}
Client->>API : GET /api/dashboard/stats
API-->>Client : {stats}
Client->>WS : connect
WS-->>Client : system_status connected
```

**Diagram sources**
- [backend/app.py](file://backend/app.py#L276-L308)
- [backend/api/routes.py](file://backend/api/routes.py#L10-L54)
- [backend/websocket/handlers.py](file://backend/websocket/handlers.py#L29-L48)

**Section sources**
- [backend/app.py](file://backend/app.py#L90-L163)
- [backend/api/routes.py](file://backend/api/routes.py#L10-L54)

### WebSocket Event Handling
- Establishes connection, tracks clients, and manages rooms per scan.
- Emits lifecycle events: scan_started, scan_update, phase_transition, tool_execution_start/complete, tool_output, finding_discovered, scan_complete/error.
- Provides event emitters for other modules to publish updates.

```mermaid
sequenceDiagram
participant FE as "Frontend SocketService"
participant WS as "WebSocket Handlers"
participant SM as "Scan Manager"
FE->>WS : join_scan({scan_id})
WS-->>FE : system_status joined
FE->>WS : execute_tool({scan_id, tool, target})
WS->>SM : execute_tool(...)
SM-->>WS : result
WS-->>FE : tool_execution_start/complete + tool_output
```

**Diagram sources**
- [frontend/src/services/socket.ts](file://frontend/src/services/socket.ts#L165-L232)
- [backend/websocket/handlers.py](file://backend/websocket/handlers.py#L50-L119)
- [backend/core/scan_engine.py](file://backend/core/scan_engine.py#L423-L434)

**Section sources**
- [backend/websocket/handlers.py](file://backend/websocket/handlers.py#L26-L119)
- [frontend/src/services/socket.ts](file://frontend/src/services/socket.ts#L64-L106)

### Scan Orchestration and Management
- Centralized ScanManager coordinates autonomous scans in background threads, manages stop/pause/resume, and emits events.
- Integrates with the robust orchestrator or legacy agent depending on availability.
- Tracks scan state, calculates elapsed time, and updates findings/tools executed.

```mermaid
flowchart TD
Start([Start Scan]) --> Init["Initialize Components"]
Init --> Thread["Spawn Background Thread"]
Thread --> Run["Run Orchestrator or Agent"]
Run --> Events["Emit Events (started, updates, transitions)"]
Events --> Results["Collect Results"]
Results --> Complete([Complete/Stop/Pause])
```

**Diagram sources**
- [backend/core/scan_engine.py](file://backend/core/scan_engine.py#L82-L148)
- [backend/core/scan_engine.py](file://backend/core/scan_engine.py#L150-L310)

**Section sources**
- [backend/core/scan_engine.py](file://backend/core/scan_engine.py#L26-L81)
- [backend/core/scan_engine.py](file://backend/core/scan_engine.py#L82-L148)
- [backend/core/scan_engine.py](file://backend/core/scan_engine.py#L150-L310)

### Autonomous Agent and AI/ML Integration
- Orchestrates multi-phase scanning, selects tools, executes them, and adapts strategy based on findings.
- Integrates Optimus Brain for intelligence and Deep RL agent for adaptive tool selection.
- Maintains state, tracks findings, and coordinates with the hybrid tool system.

```mermaid
classDiagram
class AutonomousPentestAgent {
+run_autonomous_scan(target, config)
+conduct_scan(target, config)
-_get_tool_recommendation(state)
-_execute_tool_real(tool, target, state, params)
-_update_scan_state_real(state, result)
}
class OptimusBrain {
+start_scan(target, options)
+select_tool(tools, context)
+process_tool_result(tool, context, output, findings)
+get_exploitation_plan(findings, context)
}
class DeepRLAgent {
+select_action(state, available_tools, training)
+store_experience(state, action, reward, next_state, done)
+train_step()
+calculate_global_reward(action, result, state, ...)
}
class HybridToolSystem {
+resolve_tool(name, task, target, context)
+get_available_tools(category)
+create_execution_plan(resolution, context)
}
AutonomousPentestAgent --> OptimusBrain : "uses"
AutonomousPentestAgent --> DeepRLAgent : "uses"
AutonomousPentestAgent --> HybridToolSystem : "uses"
```

**Diagram sources**
- [backend/inference/autonomous_agent.py](file://backend/inference/autonomous_agent.py#L50-L132)
- [backend/intelligence/optimus_brain.py](file://backend/intelligence/optimus_brain.py#L46-L170)
- [backend/training/deep_rl_agent.py](file://backend/training/deep_rl_agent.py#L187-L300)
- [backend/tools/hybrid_tool_system.py](file://backend/tools/hybrid_tool_system.py#L65-L113)

**Section sources**
- [backend/inference/autonomous_agent.py](file://backend/inference/autonomous_agent.py#L133-L327)
- [backend/intelligence/optimus_brain.py](file://backend/intelligence/optimus_brain.py#L173-L226)
- [backend/training/deep_rl_agent.py](file://backend/training/deep_rl_agent.py#L312-L369)

### Hybrid Tool System and SSH Execution
- Resolves tools through a priority chain: knowledge base, memory, discovered tools, LLM generation, web research.
- Generates commands tailored to tasks and targets, with confidence and warnings.
- Executes resolved commands via SSH client on the Kali VM with configurable timeouts and retries.

```mermaid
flowchart TD
Req["Tool Resolution Request"] --> KB{"Knowledge Base?"}
KB --> |Resolved| EmitKB["Emit RESOLVED"]
KB --> |Partial| Mem{"Memory?"}
Mem --> |Resolved| EmitMem["Emit RESOLVED"]
Mem --> |Partial| Disc{"Discovered?"}
Disc --> |Resolved| EmitDisc["Emit RESOLVED"]
Disc --> |Partial| LLM{"LLM Generation?"}
LLM --> |Resolved/Partial| EmitLLM["Emit RESOLVED/PARTIAL"]
LLM --> |Failed| Web{"Web Research?"}
Web --> |Resolved/Partial| EmitWeb["Emit RESOLVED/PARTIAL"]
Web --> |Failed| Fail["Emit FAILED"]
```

**Diagram sources**
- [backend/tools/hybrid_tool_system.py](file://backend/tools/hybrid_tool_system.py#L166-L220)
- [backend/execution/ssh_client.py](file://backend/execution/ssh_client.py#L87-L196)

**Section sources**
- [backend/tools/hybrid_tool_system.py](file://backend/tools/hybrid_tool_system.py#L166-L220)
- [backend/execution/ssh_client.py](file://backend/execution/ssh_client.py#L87-L196)

### Frontend Integration and Real-Time Updates
- React SPA with routing and WebSocket service for real-time updates.
- SocketService manages connection, reconnection, and event subscriptions.
- App initializes WebSocket on startup and renders pages with real-time scan data.

```mermaid
sequenceDiagram
participant App as "React App"
participant Hook as "useSocket"
participant WS as "SocketService"
participant BE as "Backend"
App->>Hook : useSocket()
Hook->>WS : connect()
WS->>BE : connect
BE-->>WS : system_status connected
WS-->>App : on('scan_started'|...)
```

**Diagram sources**
- [frontend/src/App.tsx](file://frontend/src/App.tsx#L81-L84)
- [frontend/src/services/socket.ts](file://frontend/src/services/socket.ts#L83-L106)
- [backend/websocket/handlers.py](file://backend/websocket/handlers.py#L29-L48)

**Section sources**
- [frontend/src/App.tsx](file://frontend/src/App.tsx#L81-L84)
- [frontend/src/services/socket.ts](file://frontend/src/services/socket.ts#L64-L106)
- [frontend/package.json](file://frontend/package.json#L29-L29)

## Dependency Analysis
- Backend depends on configuration for SSH credentials, LLM settings, and RL parameters.
- Scan manager depends on the autonomous agent and tool manager for orchestration.
- Hybrid tool system depends on SSH client and optional LLM/memory integrations.
- Frontend depends on SocketIO client and typed event contracts.

```mermaid
graph LR
Config["config.py"] --> App["app.py"]
App --> ScanMgr["core/scan_engine.py"]
ScanMgr --> Agent["inference/autonomous_agent.py"]
Agent --> Brain["intelligence/optimus_brain.py"]
Agent --> RL["training/deep_rl_agent.py"]
Agent --> Hybrid["tools/hybrid_tool_system.py"]
Hybrid --> SSH["execution/ssh_client.py"]
App --> WS["websocket/handlers.py"]
WS --> FE["frontend/socket.ts"]
```

**Diagram sources**
- [backend/config.py](file://backend/config.py#L6-L115)
- [backend/app.py](file://backend/app.py#L232-L275)
- [backend/core/scan_engine.py](file://backend/core/scan_engine.py#L26-L81)
- [backend/inference/autonomous_agent.py](file://backend/inference/autonomous_agent.py#L50-L132)
- [backend/intelligence/optimus_brain.py](file://backend/intelligence/optimus_brain.py#L46-L170)
- [backend/training/deep_rl_agent.py](file://backend/training/deep_rl_agent.py#L187-L300)
- [backend/tools/hybrid_tool_system.py](file://backend/tools/hybrid_tool_system.py#L65-L113)
- [backend/execution/ssh_client.py](file://backend/execution/ssh_client.py#L12-L86)
- [backend/websocket/handlers.py](file://backend/websocket/handlers.py#L26-L119)
- [frontend/src/services/socket.ts](file://frontend/src/services/socket.ts#L64-L106)

**Section sources**
- [backend/config.py](file://backend/config.py#L6-L115)
- [backend/app.py](file://backend/app.py#L232-L275)
- [backend/core/scan_engine.py](file://backend/core/scan_engine.py#L26-L81)

## Performance Considerations
- Centralized orchestration with background threads ensures non-blocking event emission and scan coordination.
- SSH timeouts and retries are tuned for Windows environments and long-running tools, balancing reliability and responsiveness.
- WebSocket threading mode and keepalive settings optimize real-time updates.
- RL agent uses prioritized experience replay and target networks to stabilize training and improve sample efficiency.
- Frontend uses polling and WebSocket transports with reconnection strategies to maintain UX continuity.

[No sources needed since this section provides general guidance]

## Troubleshooting Guide
- Logging: Safe formatter handles Unicode and adds correlation IDs for traceability.
- Error handling: Flask error handlers return structured JSON for 404/500.
- WebSocket: Connection/disconnect events and reconnection attempts tracked by SocketService.
- SSH connectivity: Connection retries, keepalive, and data timeout safeguards against stalled sessions.
- Environment configuration: Ensure Kali VM credentials and Ollama settings are correctly set in environment variables.

**Section sources**
- [backend/app.py](file://backend/app.py#L50-L117)
- [backend/app.py](file://backend/app.py#L311-L318)
- [frontend/src/services/socket.ts](file://frontend/src/services/socket.ts#L137-L160)
- [backend/execution/ssh_client.py](file://backend/execution/ssh_client.py#L20-L78)
- [backend/config.py](file://backend/config.py#L12-L52)

## Conclusion
Optimus combines a React frontend with a Flask backend to deliver an event-driven, AI-enhanced penetration testing platform. Centralized orchestration coordinates autonomous scans, while distributed tool execution on a Kali VM enforces security boundaries. The integration of AI/ML components—particularly the Deep RL agent and Optimus Brain—enables adaptive, intelligent decision-making. Trade-offs emphasize security and operational control through SSH-based execution and centralized management, with performance optimized via background threads, prioritized experience replay, and resilient WebSocket communications.

## Appendices

### System Boundaries and Integrations
- Frontend boundary: React SPA with typed WebSocket events and routing.
- Backend boundary: Flask API with SocketIO and global state management.
- External security tools: SSH-based execution on Kali VM; tool discovery and command generation.
- AI/ML: Local LLMs via Ollama, Deep RL models, and explainable AI components.

**Section sources**
- [README.md](file://README.md#L15-L22)
- [backend/config.py](file://backend/config.py#L48-L52)
- [backend/execution/ssh_client.py](file://backend/execution/ssh_client.py#L12-L86)

### Infrastructure Requirements
- Local development: Python 3.10+, Node.js 16+, Ollama, Kali Linux VM with SSH access.
- Production deployment: Containerized backend with persistent volumes for logs and models; reverse proxy for HTTPS; scalable WebSocket handling; isolated Kali VM network access.

**Section sources**
- [README.md](file://README.md#L23-L30)
- [backend/config.py](file://backend/config.py#L12-L52)

### Scalability Considerations
- Concurrency: Background threads per scan; SocketIO threading mode supports multiple clients.
- Throughput: SSH client timeouts accommodate long-running tools; WebSocket batching for frequent updates.
- AI/ML: RL agent training decoupled from scan execution; model persistence for reuse.

**Section sources**
- [backend/core/scan_engine.py](file://backend/core/scan_engine.py#L118-L126)
- [backend/websocket/handlers.py](file://backend/websocket/handlers.py#L152-L162)
- [backend/execution/ssh_client.py](file://backend/execution/ssh_client.py#L87-L196)
- [backend/training/deep_rl_agent.py](file://backend/training/deep_rl_agent.py#L617-L697)