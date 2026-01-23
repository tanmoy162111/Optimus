# Training Pipeline Management

<cite>
**Referenced Files in This Document**
- [deep_rl_trainer.py](file://backend/training/deep_rl_trainer.py)
- [rl_trainer.py](file://backend/training/rl_trainer.py)
- [rl_training_config.py](file://backend/training/rl_training_config.py)
- [experience_collector.py](file://backend/training/experience_collector.py)
- [reward_calculator.py](file://backend/training/reward_calculator.py)
- [prioritized_replay.py](file://backend/training/prioritized_replay.py)
- [model_trainer.py](file://backend/training/model_trainer.py)
- [phase_specific_models.py](file://backend/training/phase_specific_models.py)
- [train_phase_models.py](file://backend/training/train_phase_models.py)
- [data_augmentation.py](file://backend/training/data_augmentation.py)
- [run_rl_training.py](file://backend/training/run_rl_training.py)
- [continuous_retraining.py](file://backend/training/continuous_retraining.py)
- [curriculum_config.py](file://backend/training/curriculum_config.py)
- [newbie_to_pro_training.py](file://backend/training_environment/newbie_to_pro_training.py)
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
This document describes the training pipeline management system for the Optimus platform. It covers the end-to-end workflow from data preparation to model deployment, including:
- Reinforcement Learning (RL) training with DQN, experience replay, and epsilon-greedy exploration
- Supervised learning models for vulnerability detection, attack classification, and tool recommendation
- Curriculum learning progression and phase-specific training strategies
- Training configuration management, hyperparameter optimization, and automated workflows
- Practical setup, progress monitoring, and troubleshooting guidance
- Environment isolation, resource allocation, and performance optimization strategies

## Project Structure
The training system is organized around modular components:
- RL training orchestration and agents
- Experience collection and reward shaping
- Supervised learning trainers and phase-specific models
- Data augmentation and continuous retraining
- Curriculum-driven training environments

```mermaid
graph TB
subgraph "RL Training"
RLTrainer["DeepRLTrainer<br/>orchestrates episodes"]
Agent["EnhancedRLAgent<br/>DQN + epsilon-greedy"]
Exper["ExperienceCollector<br/>collects transitions"]
Reward["GlobalRewardCalculator<br/>reward shaping"]
Config["RLTrainingConfig<br/>hyperparameters"]
end
subgraph "Supervised Learning"
MTrainer["SecurityMLTrainer<br/>multi-model trainer"]
PSModels["PhaseSpecificModelTrainer<br/>phase models"]
PSelector["PhaseSpecificToolSelector<br/>runtime selection"]
Aug["AttackDataAugmenter<br/>synthetic data"]
end
subgraph "Automation"
Runner["run_rl_training.py<br/>CLI entry point"]
Retrain["ContinuousRetrainingPipeline<br/>auto-retrain"]
end
RLTrainer --> Agent
RLTrainer --> Exper
RLTrainer --> Reward
RLTrainer --> Config
MTrainer --> PSModels
PSModels --> PSelector
Aug --> MTrainer
Runner --> RLTrainer
Retrain --> PSModels
```

**Diagram sources**
- [deep_rl_trainer.py](file://backend/training/deep_rl_trainer.py#L27-L122)
- [rl_trainer.py](file://backend/training/rl_trainer.py#L15-L42)
- [experience_collector.py](file://backend/training/experience_collector.py#L49-L82)
- [reward_calculator.py](file://backend/training/reward_calculator.py#L13-L37)
- [rl_training_config.py](file://backend/training/rl_training_config.py#L31-L126)
- [model_trainer.py](file://backend/training/model_trainer.py#L20-L27)
- [phase_specific_models.py](file://backend/training/phase_specific_models.py#L15-L25)
- [phase_specific_models.py](file://backend/training/phase_specific_models.py#L407-L415)
- [data_augmentation.py](file://backend/training/data_augmentation.py#L8-L15)
- [run_rl_training.py](file://backend/training/run_rl_training.py#L91-L187)
- [continuous_retraining.py](file://backend/training/continuous_retraining.py#L27-L43)

**Section sources**
- [deep_rl_trainer.py](file://backend/training/deep_rl_trainer.py#L1-L122)
- [rl_trainer.py](file://backend/training/rl_trainer.py#L15-L42)
- [experience_collector.py](file://backend/training/experience_collector.py#L49-L82)
- [reward_calculator.py](file://backend/training/reward_calculator.py#L13-L37)
- [rl_training_config.py](file://backend/training/rl_training_config.py#L31-L126)
- [model_trainer.py](file://backend/training/model_trainer.py#L20-L27)
- [phase_specific_models.py](file://backend/training/phase_specific_models.py#L15-L25)
- [phase_specific_models.py](file://backend/training/phase_specific_models.py#L407-L415)
- [data_augmentation.py](file://backend/training/data_augmentation.py#L8-L15)
- [run_rl_training.py](file://backend/training/run_rl_training.py#L91-L187)
- [continuous_retraining.py](file://backend/training/continuous_retraining.py#L27-L43)

## Core Components
- Deep RL Trainer orchestrates multi-target training, episode loops, and periodic evaluation/saving.
- RL Agent implements DQN with epsilon-greedy action selection and experience replay.
- Experience Collector records transitions with metadata for offline analysis.
- Reward Calculator computes unified rewards combining environment, episode, and lesson signals.
- Supervised ML Trainer trains classifiers/regressors for vulnerability detection, attack classification, and severity prediction.
- Phase-Specific Models train separate models per pentesting phase with cross-validation.
- Data Augmentation synthesizes rare attack types to balance datasets.
- Continuous Retraining Pipeline automates model updates using production logs.
- Curriculum and Training Environment define structured learning progression.

**Section sources**
- [deep_rl_trainer.py](file://backend/training/deep_rl_trainer.py#L27-L122)
- [rl_trainer.py](file://backend/training/rl_trainer.py#L15-L42)
- [experience_collector.py](file://backend/training/experience_collector.py#L49-L82)
- [reward_calculator.py](file://backend/training/reward_calculator.py#L13-L37)
- [model_trainer.py](file://backend/training/model_trainer.py#L20-L98)
- [phase_specific_models.py](file://backend/training/phase_specific_models.py#L15-L25)
- [data_augmentation.py](file://backend/training/data_augmentation.py#L8-L15)
- [continuous_retraining.py](file://backend/training/continuous_retraining.py#L27-L43)
- [curriculum_config.py](file://backend/training/curriculum_config.py#L8-L15)
- [newbie_to_pro_training.py](file://backend/training_environment/newbie_to_pro_training.py#L131-L138)

## Architecture Overview
The RL training pipeline integrates state encoding, tool execution, reward computation, experience storage, and agent updates. The supervised learning stack builds on curated and augmented datasets to improve detection and recommendation capabilities.

```mermaid
sequenceDiagram
participant CLI as "run_rl_training.py"
participant Trainer as "DeepRLTrainer"
participant Agent as "EnhancedRLAgent"
participant Collector as "ExperienceCollector"
participant Reward as "GlobalRewardCalculator"
participant Tool as "ToolManager"
CLI->>Trainer : train(targets, resume_from)
loop For each target and episode
Trainer->>Agent : select_action(state, available_tools)
Agent-->>Trainer : action_idx, tool_name
Trainer->>Tool : execute_tool(tool_name, target, phase)
Tool-->>Trainer : result
Trainer->>Reward : calculate_global_reward(...)
Reward-->>Trainer : reward
Trainer->>Collector : add_experience(state, action, reward, next_state, done, ...)
Trainer->>Agent : store_experience(state, action, reward, next_state, done)
Trainer->>Agent : train_step() (periodically)
end
Trainer-->>CLI : training summary
```

**Diagram sources**
- [run_rl_training.py](file://backend/training/run_rl_training.py#L179-L187)
- [deep_rl_trainer.py](file://backend/training/deep_rl_trainer.py#L123-L169)
- [rl_trainer.py](file://backend/training/rl_trainer.py#L69-L109)
- [experience_collector.py](file://backend/training/experience_collector.py#L83-L130)
- [reward_calculator.py](file://backend/training/reward_calculator.py#L38-L169)

## Detailed Component Analysis

### RL Trainer Architecture with DQN Implementation
The RL trainer coordinates training across multiple targets, managing episode loops, tool execution, reward calculation, and agent updates. It supports checkpointing, evaluation, and periodic saves.

Key responsibilities:
- Episode lifecycle: initialize state, select actions, execute tools, update state, compute rewards, store experiences, and train the agent.
- Phase transitions: advance from reconnaissance to scanning, exploitation, post-exploitation, and covering tracks based on heuristics.
- Evaluation and best model tracking: periodic evaluation and saving the best model based on average reward.

```mermaid
classDiagram
class DeepRLTrainer {
+config : RLTrainingConfig
+state_encoder
+rl_agent
+experience_collector
+reward_calculator
+total_steps : int
+total_episodes : int
+best_avg_reward : float
+train(targets, resume_from) Dict
+_train_on_target(target)
+_run_training_episode(agent, tool_manager, target, episode_num) Dict
+_evaluate_agent(target)
+_save_checkpoint(filename)
+_load_checkpoint(filepath)
}
class EnhancedRLAgent {
+q_network
+target_network
+epsilon : float
+memory : Deque
+select_action(state, available_tools, epsilon) str
+remember(state, action, reward, next_state, done)
+replay() float
+update(state, action, reward, next_state, done)
+save_model(path)
+load_model(path)
}
class ExperienceCollector {
+experiences : List[Experience]
+add_experience(...)
+end_episode(final_findings) Dict
+save_experiences(filename)
+load_experiences(filepath)
}
class GlobalRewardCalculator {
+rewards : Dict
+calculate_global_reward(tool_name, result, scan_state, execution_time, episode_reward, lesson_reward) float
+calculate_episode_end_reward(scan_state, completed_normally, total_time, max_time) float
}
DeepRLTrainer --> EnhancedRLAgent : "uses"
DeepRLTrainer --> ExperienceCollector : "uses"
DeepRLTrainer --> GlobalRewardCalculator : "uses"
```

**Diagram sources**
- [deep_rl_trainer.py](file://backend/training/deep_rl_trainer.py#L27-L122)
- [rl_trainer.py](file://backend/training/rl_trainer.py#L15-L42)
- [experience_collector.py](file://backend/training/experience_collector.py#L49-L82)
- [reward_calculator.py](file://backend/training/reward_calculator.py#L13-L37)

**Section sources**
- [deep_rl_trainer.py](file://backend/training/deep_rl_trainer.py#L58-L169)
- [rl_trainer.py](file://backend/training/rl_trainer.py#L69-L148)
- [experience_collector.py](file://backend/training/experience_collector.py#L83-L162)
- [reward_calculator.py](file://backend/training/reward_calculator.py#L38-L169)

### Experience Replay Mechanisms and Prioritized Experience Replay
The system supports both standard and prioritized experience replay:
- Standard replay buffer stores transitions and samples uniformly.
- Prioritized Experience Replay (PER) uses a sum tree to sample experiences proportional to TD error, with importance sampling weights to correct bias.

```mermaid
flowchart TD
Start(["Add Experience"]) --> AddToBuffer["Add to PER buffer<br/>priority = (|TD-error| + ε)^α"]
AddToBuffer --> SampleBatch["Stratified sample batch<br/>segments by priority"]
SampleBatch --> Weights["Compute IS weights<br/>(N·P(i))^-β"]
Weights --> Train["Train on batch"]
Train --> UpdatePriorities["Update priorities<br/>by TD errors"]
UpdatePriorities --> End(["Done"])
```

**Diagram sources**
- [prioritized_replay.py](file://backend/training/prioritized_replay.py#L233-L349)
- [prioritized_replay.py](file://backend/training/prioritized_replay.py#L351-L367)

**Section sources**
- [prioritized_replay.py](file://backend/training/prioritized_replay.py#L176-L376)
- [prioritized_replay.py](file://backend/training/prioritized_replay.py#L378-L461)

### Epsilon-Greedy Exploration Strategies
The RL agent selects actions using epsilon-greedy:
- With probability epsilon, choose randomly among available actions.
- Otherwise, select the action with the highest Q-value masked to available actions.
- Epsilon decays after episodes to reduce exploration over time.

```mermaid
flowchart TD
Start(["Select Action"]) --> CheckEpsilon{"Random < epsilon?"}
CheckEpsilon --> |Yes| RandomAction["Pick random available action"]
CheckEpsilon --> |No| BestAction["Pick argmax_a Q(state, a)"]
RandomAction --> End(["Return action"])
BestAction --> End
```

**Diagram sources**
- [rl_trainer.py](file://backend/training/rl_trainer.py#L69-L109)

**Section sources**
- [rl_trainer.py](file://backend/training/rl_trainer.py#L69-L109)
- [rl_trainer.py](file://backend/training/rl_trainer.py#L231-L242)

### Supervised Learning: Model Trainer and Cross-Validation
The model trainer builds ensembles and individual models for:
- Vulnerability detector (binary classification)
- Attack classifier (multi-class)
- Tool recommender (classification)
- Severity predictor (regression)
- Cloud attack detector (binary)
- AI jailbreak detector (text classification)

Cross-validation and feature engineering are integrated, with standardized scaling and encoding.

```mermaid
classDiagram
class SecurityMLTrainer {
+scaler
+feature_names : List[str]
+models : Dict
+train_vulnerability_detector(examples) Dict
+train_attack_classifier(examples) Dict
+train_tool_recommender(logs) Dict
+train_severity_predictor(examples) Dict
+train_cloud_detector(examples) Dict
+train_ai_attack_detector(examples) Dict
+save_model(model_data, model_name, output_dir)
+load_model(model_name, model_dir)
}
```

**Diagram sources**
- [model_trainer.py](file://backend/training/model_trainer.py#L20-L98)

**Section sources**
- [model_trainer.py](file://backend/training/model_trainer.py#L28-L361)

### Phase-Specific Training Strategies and Tool Recommendation
Phase-specific models tailor recommendations to each pentesting phase:
- Feature sets are curated per phase (reconnaissance, scanning, exploitation, post-exploitation, covering tracks).
- Models are trained with cross-validation and saved for runtime selection.
- Runtime selector loads models and recommends tools conditioned on context, excluding previously executed tools.

```mermaid
sequenceDiagram
participant Selector as "PhaseSpecificToolSelector"
participant Trainer as "PhaseSpecificModelTrainer"
participant FS as "Feature Extractor"
participant Model as "Saved Model"
Selector->>Trainer : extract_phase_features(context, phase)
Trainer-->>FS : encoded features
FS-->>Selector : features
Selector->>Model : predict_proba(features)
Model-->>Selector : tool probabilities
Selector-->>Selector : filter executed tools
Selector-->>Selector : return top tools
```

**Diagram sources**
- [phase_specific_models.py](file://backend/training/phase_specific_models.py#L407-L415)
- [phase_specific_models.py](file://backend/training/phase_specific_models.py#L468-L542)
- [phase_specific_models.py](file://backend/training/phase_specific_models.py#L252-L358)

**Section sources**
- [phase_specific_models.py](file://backend/training/phase_specific_models.py#L26-L151)
- [phase_specific_models.py](file://backend/training/phase_specific_models.py#L252-L358)
- [phase_specific_models.py](file://backend/training/phase_specific_models.py#L407-L542)

### Data Augmentation Techniques for Rare Attack Types
Synthetic data generation augments underrepresented attack categories:
- XXE payloads with mutations
- SSRF targets with variations
- Insecure deserialization payloads across languages

```mermaid
flowchart TD
Start(["Load Existing Data"]) --> Count["Count attack types"]
Count --> Identify["Identify rare classes (< threshold)"]
Identify --> GenerateXXE["Generate XXE payloads"]
Identify --> GenerateSSRF["Generate SSRF payloads"]
Identify --> GenerateDeser["Generate deserialization payloads"]
GenerateXXE --> Merge["Merge with original data"]
GenerateSSRF --> Merge
GenerateDeser --> Merge
Merge --> Save["Save augmented dataset"]
Save --> End(["Ready for retraining"])
```

**Diagram sources**
- [data_augmentation.py](file://backend/training/data_augmentation.py#L218-L270)
- [data_augmentation.py](file://backend/training/data_augmentation.py#L316-L334)

**Section sources**
- [data_augmentation.py](file://backend/training/data_augmentation.py#L16-L270)
- [data_augmentation.py](file://backend/training/data_augmentation.py#L316-L334)

### Training Configuration Management and Hyperparameter Optimization
Training configuration encapsulates:
- Targets, episodes, time limits, and DQN hyperparameters
- Prioritized experience replay settings
- Exploration schedules and training schedule
- Reward shaping constants

```mermaid
classDiagram
class RLTrainingConfig {
+targets : List[TrainingTarget]
+episodes_per_target : int
+max_steps_per_episode : int
+max_time_per_episode : int
+learning_rate : float
+gamma : float
+batch_size : int
+use_per : bool
+use_noisy_nets : bool
+epsilon_start : float
+epsilon_end : float
+epsilon_decay_steps : int
+warmup_steps : int
+train_freq : int
+save_freq : int
+eval_freq : int
+model_save_dir : str
+experience_save_dir : str
+log_dir : str
+rewards : Dict[str, float]
+get_enabled_targets() List[TrainingTarget]
+to_dict() Dict
}
```

**Diagram sources**
- [rl_training_config.py](file://backend/training/rl_training_config.py#L31-L126)

**Section sources**
- [rl_training_config.py](file://backend/training/rl_training_config.py#L11-L159)

### Automated Training Workflows
Automated workflows include:
- Quick-start RL training script with CLI argument parsing
- Continuous retraining pipeline that exports production logs, backs up models, compares accuracy, and deploys improvements

```mermaid
sequenceDiagram
participant User as "User"
participant Runner as "run_rl_training.py"
participant Retrain as "continuous_retraining.py"
participant Collector as "ProductionDataCollector"
participant Trainer as "PhaseSpecificModelTrainer"
User->>Runner : python run_rl_training.py [args]
Runner->>Trainer : DeepRLTrainer.train(...)
User->>Retrain : python continuous_retraining.py [--schedule]
Retrain->>Collector : export_training_data()
Retrain->>Trainer : train_all_phase_models(combined_data)
Trainer-->>Retrain : new models
Retrain-->>User : deploy improved models
```

**Diagram sources**
- [run_rl_training.py](file://backend/training/run_rl_training.py#L91-L187)
- [continuous_retraining.py](file://backend/training/continuous_retraining.py#L128-L212)

**Section sources**
- [run_rl_training.py](file://backend/training/run_rl_training.py#L91-L201)
- [continuous_retraining.py](file://backend/training/continuous_retraining.py#L66-L212)

### Curriculum Learning Progression and Phase-Specific Training
The curriculum defines structured learning progression from novice to mastery, with phase-specific targets and lessons.

```mermaid
graph TB
Fund["Fundamentals (Hours 1-2)"]
Inter["Intermediate (Hours 3-4)"]
Adv["Advanced (Hours 5-7)"]
Expert["Expert (Hours 8-10)"]
Mastery["Mastery (Hours 11-12)"]
Fund --> Inter
Inter --> Adv
Adv --> Expert
Expert --> Mastery
```

**Diagram sources**
- [newbie_to_pro_training.py](file://backend/training_environment/newbie_to_pro_training.py#L19-L51)
- [curriculum_config.py](file://backend/training/curriculum_config.py#L8-L15)

**Section sources**
- [newbie_to_pro_training.py](file://backend/training_environment/newbie_to_pro_training.py#L131-L138)
- [newbie_to_pro_training.py](file://backend/training_environment/newbie_to_pro_training.py#L295-L694)
- [curriculum_config.py](file://backend/training/curriculum_config.py#L8-L15)

## Dependency Analysis
The training system exhibits clear separation of concerns:
- RL components depend on configuration, reward calculation, and experience collection.
- Supervised learning depends on curated datasets and augmentation.
- Automation pipelines depend on both RL and supervised components.

```mermaid
graph TB
Config["RLTrainingConfig"]
Trainer["DeepRLTrainer"]
Agent["EnhancedRLAgent"]
Exper["ExperienceCollector"]
Reward["GlobalRewardCalculator"]
MTrainer["SecurityMLTrainer"]
PSModels["PhaseSpecificModelTrainer"]
PSelector["PhaseSpecificToolSelector"]
Aug["AttackDataAugmenter"]
Runner["run_rl_training.py"]
Retrain["continuous_retraining.py"]
Trainer --> Config
Trainer --> Agent
Trainer --> Exper
Trainer --> Reward
MTrainer --> PSModels
PSModels --> PSelector
Aug --> MTrainer
Runner --> Trainer
Retrain --> PSModels
```

**Diagram sources**
- [deep_rl_trainer.py](file://backend/training/deep_rl_trainer.py#L33-L41)
- [rl_training_config.py](file://backend/training/rl_training_config.py#L31-L126)
- [model_trainer.py](file://backend/training/model_trainer.py#L20-L27)
- [phase_specific_models.py](file://backend/training/phase_specific_models.py#L15-L25)
- [data_augmentation.py](file://backend/training/data_augmentation.py#L8-L15)
- [run_rl_training.py](file://backend/training/run_rl_training.py#L20-L22)
- [continuous_retraining.py](file://backend/training/continuous_retraining.py#L21-L38)

**Section sources**
- [deep_rl_trainer.py](file://backend/training/deep_rl_trainer.py#L33-L41)
- [rl_training_config.py](file://backend/training/rl_training_config.py#L31-L126)
- [model_trainer.py](file://backend/training/model_trainer.py#L20-L27)
- [phase_specific_models.py](file://backend/training/phase_specific_models.py#L15-L25)
- [data_augmentation.py](file://backend/training/data_augmentation.py#L8-L15)
- [run_rl_training.py](file://backend/training/run_rl_training.py#L20-L22)
- [continuous_retraining.py](file://backend/training/continuous_retraining.py#L21-L38)

## Performance Considerations
- Use prioritized experience replay to focus on informative transitions and accelerate learning.
- Tune epsilon decay and exploration parameters to balance exploration and exploitation.
- Employ cross-validation for supervised models to avoid overfitting and ensure robustness.
- Monitor training metrics (average reward, episode lengths, findings counts) and adjust hyperparameters accordingly.
- Utilize standardized scaling and feature engineering to improve model convergence.

[No sources needed since this section provides general guidance]

## Troubleshooting Guide
Common issues and resolutions:
- Training interrupted: Check for keyboard interrupts and ensure checkpoints are saved.
- No targets configured: Verify training targets are enabled and URLs are valid.
- Tool execution failures: Inspect tool results and handle exceptions gracefully; review timeouts and errors.
- Poor reward shaping: Adjust reward constants and penalties to encourage desired behaviors.
- Model loading errors: Ensure model files exist and compatible with the current environment.

**Section sources**
- [deep_rl_trainer.py](file://backend/training/deep_rl_trainer.py#L104-L114)
- [deep_rl_trainer.py](file://backend/training/deep_rl_trainer.py#L247-L250)
- [reward_calculator.py](file://backend/training/reward_calculator.py#L67-L75)
- [phase_specific_models.py](file://backend/training/phase_specific_models.py#L422-L427)

## Conclusion
The Optimus training pipeline integrates RL and supervised learning with structured curriculum progression and automation. RL agents learn tool selection via DQN with experience replay and epsilon-greedy exploration, while supervised models improve detection and recommendation through curated and augmented datasets. Automated workflows continuously refine models using production data, ensuring sustained performance gains.

[No sources needed since this section summarizes without analyzing specific files]

## Appendices

### Practical Examples
- Start RL training with default targets and episodes:
  - [run_rl_training.py](file://backend/training/run_rl_training.py#L179-L187)
- Resume training from a checkpoint:
  - [run_rl_training.py](file://backend/training/run_rl_training.py#L186-L187)
- Train phase-specific models with synthetic augmentation:
  - [train_phase_models.py](file://backend/training/train_phase_models.py#L218-L263)
- Retrain models automatically using production logs:
  - [continuous_retraining.py](file://backend/training/continuous_retraining.py#L307-L345)

**Section sources**
- [run_rl_training.py](file://backend/training/run_rl_training.py#L179-L187)
- [train_phase_models.py](file://backend/training/train_phase_models.py#L218-L263)
- [continuous_retraining.py](file://backend/training/continuous_retraining.py#L307-L345)