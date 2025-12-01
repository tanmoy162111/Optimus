"""
Continuous Learning & Zero-Day Discovery Module

This module implements:

1. Continuous Learning from Production
   - Real-time model weight updates from scan feedback
   - Success/failure pattern extraction
   - Cross-scan knowledge transfer
   - Adaptive model improvement

2. Zero-Day Discovery
   - Anomaly detection in responses
   - Fuzzing with intelligent mutation
   - Pattern deviation analysis
   - Unknown vulnerability identification
"""

import os
import json
import logging
import hashlib
import pickle
import time
import random
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import numpy as np
from pathlib import Path

logger = logging.getLogger(__name__)


# ===================== CONTINUOUS LEARNING =====================

class LearningSignal(Enum):
    """Types of learning signals from production"""
    TOOL_SUCCESS = "tool_success"
    TOOL_FAILURE = "tool_failure"
    VULN_CONFIRMED = "vuln_confirmed"
    VULN_FALSE_POSITIVE = "vuln_false_positive"
    CHAIN_SUCCESS = "chain_success"
    CHAIN_FAILURE = "chain_failure"
    EVASION_SUCCESS = "evasion_success"
    EVASION_FAILURE = "evasion_failure"


@dataclass
class LearningExample:
    """A single learning example from production"""
    signal_type: LearningSignal
    context: Dict[str, Any]  # Input features
    action: str  # What was done
    outcome: bool  # Success/failure
    reward: float  # Reward signal (-1 to 1)
    timestamp: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class OnlineModelUpdater:
    """
    Updates model weights in real-time based on production feedback
    Uses online gradient descent for continuous learning
    """
    
    def __init__(self, model_path: str = "data/models"):
        self.model_path = Path(model_path)
        self.model_path.mkdir(parents=True, exist_ok=True)
        
        # Learning rates
        self.learning_rate = 0.01
        self.momentum = 0.9
        
        # Feature weights (simple linear model for interpretability)
        self.tool_weights: Dict[str, Dict[str, float]] = defaultdict(
            lambda: defaultdict(lambda: 0.5)
        )  # tool -> context_feature -> weight
        
        self.pattern_weights: Dict[str, float] = defaultdict(lambda: 0.5)
        
        # Momentum buffers
        self.weight_momentum: Dict[str, float] = defaultdict(float)
        
        # Load existing weights
        self._load_weights()
        
        # Learning history
        self.learning_history: List[Dict] = []
        self.update_count = 0
    
    def _load_weights(self):
        """Load weights from disk"""
        weight_file = self.model_path / "online_weights.json"
        if weight_file.exists():
            try:
                with open(weight_file, 'r') as f:
                    data = json.load(f)
                    self.tool_weights = defaultdict(
                        lambda: defaultdict(lambda: 0.5),
                        {k: defaultdict(lambda: 0.5, v) for k, v in data.get('tool_weights', {}).items()}
                    )
                    self.pattern_weights = defaultdict(lambda: 0.5, data.get('pattern_weights', {}))
                logger.info(f"Loaded weights from {weight_file}")
            except Exception as e:
                logger.error(f"Error loading weights: {e}")
    
    def _save_weights(self):
        """Save weights to disk"""
        weight_file = self.model_path / "online_weights.json"
        try:
            data = {
                'tool_weights': {k: dict(v) for k, v in self.tool_weights.items()},
                'pattern_weights': dict(self.pattern_weights),
                'update_count': self.update_count,
                'last_updated': datetime.now().isoformat()
            }
            with open(weight_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving weights: {e}")
    
    def update_from_example(self, example: LearningExample):
        """Update model weights from a single example"""
        self.update_count += 1
        
        if example.signal_type in [LearningSignal.TOOL_SUCCESS, LearningSignal.TOOL_FAILURE]:
            self._update_tool_weights(example)
        elif example.signal_type in [LearningSignal.VULN_CONFIRMED, LearningSignal.VULN_FALSE_POSITIVE]:
            self._update_pattern_weights(example)
        elif example.signal_type in [LearningSignal.CHAIN_SUCCESS, LearningSignal.CHAIN_FAILURE]:
            self._update_chain_weights(example)
        
        # Periodic save
        if self.update_count % 10 == 0:
            self._save_weights()
        
        # Record in history
        self.learning_history.append({
            'timestamp': example.timestamp,
            'signal': example.signal_type.value,
            'reward': example.reward
        })
    
    def _update_tool_weights(self, example: LearningExample):
        """Update tool selection weights"""
        tool = example.action
        context = example.context
        reward = example.reward
        
        # Extract context features
        features = self._extract_features(context)
        
        for feature_name, feature_value in features.items():
            if feature_value:
                # Current weight
                current_weight = self.tool_weights[tool][feature_name]
                
                # Gradient (simple: positive reward increases weight)
                gradient = reward * feature_value
                
                # Momentum update
                momentum_key = f"{tool}_{feature_name}"
                self.weight_momentum[momentum_key] = (
                    self.momentum * self.weight_momentum[momentum_key] +
                    self.learning_rate * gradient
                )
                
                # Update weight
                new_weight = current_weight + self.weight_momentum[momentum_key]
                
                # Clip to [0, 1]
                new_weight = max(0.0, min(1.0, new_weight))
                
                self.tool_weights[tool][feature_name] = new_weight
                
                logger.debug(f"Updated weight: {tool}/{feature_name}: {current_weight:.3f} -> {new_weight:.3f}")
    
    def _update_pattern_weights(self, example: LearningExample):
        """Update vulnerability pattern weights"""
        context = example.context
        reward = example.reward
        
        # Extract pattern identifiers
        vuln_type = context.get('vulnerability_type', '')
        tech_stack = context.get('technology', '')
        
        pattern_key = f"{vuln_type}_{tech_stack}"
        
        current_weight = self.pattern_weights[pattern_key]
        new_weight = current_weight + self.learning_rate * reward
        new_weight = max(0.0, min(1.0, new_weight))
        
        self.pattern_weights[pattern_key] = new_weight
    
    def _update_chain_weights(self, example: LearningExample):
        """Update attack chain weights"""
        context = example.context
        chain_pattern = context.get('chain_pattern', '')
        reward = example.reward
        
        pattern_key = f"chain_{chain_pattern}"
        
        current_weight = self.pattern_weights[pattern_key]
        new_weight = current_weight + self.learning_rate * reward
        new_weight = max(0.0, min(1.0, new_weight))
        
        self.pattern_weights[pattern_key] = new_weight
    
    def _extract_features(self, context: Dict) -> Dict[str, float]:
        """Extract numerical features from context"""
        features = {}
        
        # Target type features
        target_type = context.get('target_type', '')
        features[f'target_{target_type}'] = 1.0
        
        # Technology features
        technologies = context.get('technologies', [])
        for tech in technologies:
            features[f'tech_{tech.lower()}'] = 1.0
        
        # Phase features
        phase = context.get('phase', '')
        features[f'phase_{phase}'] = 1.0
        
        # Defense features
        defenses = context.get('defenses', [])
        for defense in defenses:
            features[f'defense_{defense}'] = 1.0
        
        return features
    
    def get_tool_score(self, tool: str, context: Dict) -> float:
        """Get score for a tool given context"""
        features = self._extract_features(context)
        
        score = 0.0
        feature_count = 0
        
        for feature_name, feature_value in features.items():
            if feature_value:
                weight = self.tool_weights[tool].get(feature_name, 0.5)
                score += weight * feature_value
                feature_count += 1
        
        if feature_count > 0:
            score /= feature_count
        else:
            score = 0.5  # Default
        
        return score
    
    def get_learning_stats(self) -> Dict[str, Any]:
        """Get learning statistics"""
        return {
            'total_updates': self.update_count,
            'tools_learned': len(self.tool_weights),
            'patterns_learned': len(self.pattern_weights),
            'recent_rewards': [h['reward'] for h in self.learning_history[-100:]],
            'avg_recent_reward': np.mean([h['reward'] for h in self.learning_history[-100:]]) if self.learning_history else 0
        }


class ContinuousLearningEngine:
    """
    Main engine for continuous learning from production
    """
    
    def __init__(self, memory_system=None):
        self.memory_system = memory_system
        self.model_updater = OnlineModelUpdater()
        
        # Learning buffer
        self.pending_examples: List[LearningExample] = []
        
        # Pattern extractor
        self.pattern_extractor = PatternExtractor()
        
        logger.info("Continuous Learning Engine initialized")
    
    def record_tool_result(self, tool: str, context: Dict, 
                          success: bool, vulns_found: int):
        """Record tool execution result for learning"""
        # Calculate reward
        if success and vulns_found > 0:
            reward = 0.5 + min(0.5, vulns_found * 0.1)  # More vulns = higher reward
        elif success:
            reward = 0.2
        else:
            reward = -0.5
        
        example = LearningExample(
            signal_type=LearningSignal.TOOL_SUCCESS if success else LearningSignal.TOOL_FAILURE,
            context=context,
            action=tool,
            outcome=success,
            reward=reward,
            timestamp=datetime.now().isoformat(),
            metadata={'vulns_found': vulns_found}
        )
        
        self.pending_examples.append(example)
        self._process_pending_examples()
    
    def record_vuln_verification(self, vuln_type: str, context: Dict,
                                confirmed: bool):
        """Record vulnerability verification result"""
        reward = 0.8 if confirmed else -0.8
        
        example = LearningExample(
            signal_type=LearningSignal.VULN_CONFIRMED if confirmed else LearningSignal.VULN_FALSE_POSITIVE,
            context={**context, 'vulnerability_type': vuln_type},
            action=vuln_type,
            outcome=confirmed,
            reward=reward,
            timestamp=datetime.now().isoformat()
        )
        
        self.pending_examples.append(example)
        self._process_pending_examples()
    
    def record_chain_result(self, chain_pattern: str, context: Dict,
                           success: bool):
        """Record attack chain result"""
        reward = 1.0 if success else -0.5
        
        example = LearningExample(
            signal_type=LearningSignal.CHAIN_SUCCESS if success else LearningSignal.CHAIN_FAILURE,
            context={**context, 'chain_pattern': chain_pattern},
            action=chain_pattern,
            outcome=success,
            reward=reward,
            timestamp=datetime.now().isoformat()
        )
        
        self.pending_examples.append(example)
        self._process_pending_examples()
    
    def _process_pending_examples(self):
        """Process pending learning examples"""
        while self.pending_examples:
            example = self.pending_examples.pop(0)
            
            # Update online model
            self.model_updater.update_from_example(example)
            
            # Extract patterns
            patterns = self.pattern_extractor.extract_patterns(example)
            
            # Store in memory if available
            if self.memory_system and patterns:
                for pattern in patterns:
                    self.memory_system.store_memory(
                        memory_type='learned_pattern',
                        content=pattern,
                        tags=[example.signal_type.value],
                        importance=abs(example.reward)
                    )
    
    def get_recommended_tool(self, tools: List[str], context: Dict) -> str:
        """Get recommended tool based on learned weights"""
        scores = {}
        for tool in tools:
            scores[tool] = self.model_updater.get_tool_score(tool, context)
        
        # Return highest scoring tool
        return max(scores, key=scores.get)
    
    def get_learning_stats(self) -> Dict[str, Any]:
        """Get learning statistics"""
        return self.model_updater.get_learning_stats()


class PatternExtractor:
    """Extracts reusable patterns from learning examples"""
    
    def extract_patterns(self, example: LearningExample) -> List[Dict]:
        """Extract patterns from a learning example"""
        patterns = []
        
        if example.signal_type == LearningSignal.TOOL_SUCCESS and example.outcome:
            # Extract tool-context pattern
            pattern = {
                'type': 'tool_context_success',
                'tool': example.action,
                'context_features': self._get_key_features(example.context),
                'confidence': example.reward
            }
            patterns.append(pattern)
        
        elif example.signal_type == LearningSignal.VULN_CONFIRMED:
            # Extract vulnerability pattern
            pattern = {
                'type': 'vuln_detection_pattern',
                'vuln_type': example.context.get('vulnerability_type'),
                'indicators': example.context.get('indicators', []),
                'confidence': example.reward
            }
            patterns.append(pattern)
        
        return patterns
    
    def _get_key_features(self, context: Dict) -> Dict:
        """Get key features from context"""
        return {
            'target_type': context.get('target_type'),
            'technologies': context.get('technologies', [])[:3],
            'phase': context.get('phase')
        }


# ===================== ZERO-DAY DISCOVERY =====================

class AnomalyType(Enum):
    """Types of anomalies that might indicate zero-days"""
    UNUSUAL_RESPONSE = "unusual_response"
    TIMING_ANOMALY = "timing_anomaly"
    ERROR_PATTERN = "error_pattern"
    BEHAVIOR_DEVIATION = "behavior_deviation"
    UNEXPECTED_DATA = "unexpected_data"


@dataclass
class Anomaly:
    """Detected anomaly that might indicate unknown vulnerability"""
    id: str
    anomaly_type: AnomalyType
    description: str
    confidence: float
    endpoint: str
    payload: Optional[str]
    response_snippet: str
    baseline_deviation: float
    timestamp: str
    investigation_priority: int  # 1-10


class ResponseBaselineBuilder:
    """Builds baselines of normal responses for anomaly detection"""
    
    def __init__(self):
        # Response baselines per endpoint
        self.baselines: Dict[str, Dict] = {}
        
        # Statistical parameters
        self.min_samples = 5
    
    def add_response(self, endpoint: str, response: Dict):
        """Add a response to build baseline"""
        if endpoint not in self.baselines:
            self.baselines[endpoint] = {
                'response_times': [],
                'response_lengths': [],
                'status_codes': [],
                'content_patterns': [],
                'error_patterns': []
            }
        
        baseline = self.baselines[endpoint]
        
        # Record metrics
        baseline['response_times'].append(response.get('time', 0))
        baseline['response_lengths'].append(response.get('length', 0))
        baseline['status_codes'].append(response.get('status_code', 200))
        
        # Extract content patterns (simplified)
        content = response.get('content', '')
        if content:
            # Check for error patterns
            error_patterns = self._extract_error_patterns(content)
            baseline['error_patterns'].extend(error_patterns)
        
        # Keep bounded
        for key in baseline:
            if len(baseline[key]) > 100:
                baseline[key] = baseline[key][-100:]
    
    def _extract_error_patterns(self, content: str) -> List[str]:
        """Extract error patterns from response content"""
        patterns = []
        
        error_indicators = [
            r'error|exception|warning|fatal|fail',
            r'stack\s*trace',
            r'at\s+\w+\.\w+\(',  # Stack trace pattern
            r'SQLException|PDOException|MySql',
            r'undefined|null pointer|segfault'
        ]
        
        for pattern in error_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                patterns.append(pattern)
        
        return patterns
    
    def get_baseline_stats(self, endpoint: str) -> Optional[Dict]:
        """Get baseline statistics for endpoint"""
        if endpoint not in self.baselines:
            return None
        
        baseline = self.baselines[endpoint]
        
        if len(baseline['response_times']) < self.min_samples:
            return None
        
        return {
            'avg_time': np.mean(baseline['response_times']),
            'std_time': np.std(baseline['response_times']),
            'avg_length': np.mean(baseline['response_lengths']),
            'std_length': np.std(baseline['response_lengths']),
            'common_status': max(set(baseline['status_codes']), key=baseline['status_codes'].count),
            'known_error_patterns': list(set(baseline['error_patterns']))
        }


class IntelligentFuzzer:
    """
    Intelligent fuzzing for zero-day discovery
    Uses mutation strategies guided by previous results
    """
    
    def __init__(self):
        # Mutation strategies
        self.mutations = {
            'overflow': self._overflow_mutation,
            'format_string': self._format_string_mutation,
            'encoding': self._encoding_mutation,
            'boundary': self._boundary_mutation,
            'type_confusion': self._type_confusion_mutation,
            'special_chars': self._special_char_mutation,
            'unicode': self._unicode_mutation
        }
        
        # Interesting payloads that caused anomalies
        self.interesting_payloads: List[Dict] = []
        
        # Mutation effectiveness tracking
        self.mutation_scores: Dict[str, float] = defaultdict(lambda: 0.5)
    
    def generate_payloads(self, base_value: str, context: Dict) -> List[Dict]:
        """Generate fuzz payloads based on context"""
        payloads = []
        
        # Select mutations based on scores
        selected_mutations = self._select_mutations(context)
        
        for mutation_name in selected_mutations:
            mutation_func = self.mutations.get(mutation_name)
            if mutation_func:
                mutated = mutation_func(base_value)
                for m in mutated:
                    payloads.append({
                        'payload': m,
                        'mutation_type': mutation_name,
                        'base_value': base_value
                    })
        
        return payloads
    
    def _select_mutations(self, context: Dict) -> List[str]:
        """Select mutations based on context and past effectiveness"""
        # Sort mutations by score
        sorted_mutations = sorted(
            self.mutation_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        # Select top mutations plus some exploration
        selected = [m[0] for m in sorted_mutations[:4]]
        
        # Add random mutation for exploration
        remaining = [m for m in self.mutations.keys() if m not in selected]
        if remaining:
            selected.append(random.choice(remaining))
        
        return selected
    
    def record_result(self, mutation_type: str, caused_anomaly: bool):
        """Record mutation result for learning"""
        current = self.mutation_scores[mutation_type]
        
        if caused_anomaly:
            self.mutation_scores[mutation_type] = min(1.0, current + 0.1)
        else:
            self.mutation_scores[mutation_type] = max(0.1, current - 0.02)
    
    def _overflow_mutation(self, value: str) -> List[str]:
        """Generate overflow mutations"""
        return [
            'A' * 256,
            'A' * 1024,
            'A' * 4096,
            'A' * 10000,
            '%s' * 100,
            value + 'A' * 1000
        ]
    
    def _format_string_mutation(self, value: str) -> List[str]:
        """Generate format string mutations"""
        return [
            '%s%s%s%s%s',
            '%x%x%x%x',
            '%n%n%n%n',
            '%p%p%p%p',
            '%.1000d',
            '%99999999s'
        ]
    
    def _encoding_mutation(self, value: str) -> List[str]:
        """Generate encoding mutations"""
        import urllib.parse
        return [
            urllib.parse.quote(value),
            urllib.parse.quote(urllib.parse.quote(value)),
            value.encode('utf-8').hex(),
            ''.join(f'%{ord(c):02x}' for c in value),
            value.replace(' ', '+')
        ]
    
    def _boundary_mutation(self, value: str) -> List[str]:
        """Generate boundary value mutations"""
        return [
            '-1',
            '0',
            '2147483647',  # INT_MAX
            '-2147483648',  # INT_MIN
            '4294967295',  # UINT_MAX
            '9999999999999999999',
            '0.0000000001',
            'NaN',
            'Infinity',
            '-Infinity'
        ]
    
    def _type_confusion_mutation(self, value: str) -> List[str]:
        """Generate type confusion mutations"""
        return [
            '[]',
            '{}',
            'null',
            'undefined',
            'true',
            'false',
            '["nested"]',
            '{"key": "value"}',
            '[1,2,3]'
        ]
    
    def _special_char_mutation(self, value: str) -> List[str]:
        """Generate special character mutations"""
        return [
            value + '\x00',
            value + '\n\r',
            '\x00' + value,
            value.replace('a', '\x00'),
            '`' + value + '`',
            '${' + value + '}',
            '{{' + value + '}}',
            '<' + value + '>',
            value + '<!--',
            value + '%>'
        ]
    
    def _unicode_mutation(self, value: str) -> List[str]:
        """Generate unicode mutations"""
        return [
            value + '\uffff',
            '\u0000' + value,
            value.replace('a', '\u0430'),  # Cyrillic 'а'
            value + '\u202e',  # Right-to-left override
            '\ufeff' + value,  # BOM
            value + '\u0000' * 10
        ]


class ZeroDayDiscoveryEngine:
    """
    Main engine for zero-day vulnerability discovery
    """
    
    def __init__(self, memory_system=None):
        self.memory_system = memory_system
        
        # Components
        self.baseline_builder = ResponseBaselineBuilder()
        self.fuzzer = IntelligentFuzzer()
        
        # Detected anomalies
        self.anomalies: List[Anomaly] = []
        
        # Investigation queue
        self.investigation_queue: List[Anomaly] = []
        
        # Known vulnerability signatures to exclude
        self.known_signatures: Set[str] = set()
        
        logger.info("Zero-Day Discovery Engine initialized")
    
    def analyze_response(self, endpoint: str, payload: str,
                        response: Dict) -> Optional[Anomaly]:
        """Analyze a response for anomalies"""
        # Add to baseline
        self.baseline_builder.add_response(endpoint, response)
        
        # Get baseline stats
        baseline = self.baseline_builder.get_baseline_stats(endpoint)
        
        if not baseline:
            return None  # Not enough baseline data yet
        
        # Check for anomalies
        anomaly = self._detect_anomaly(endpoint, payload, response, baseline)
        
        if anomaly:
            self.anomalies.append(anomaly)
            
            # Update fuzzer learning
            mutation_type = self._get_mutation_type(payload)
            if mutation_type:
                self.fuzzer.record_result(mutation_type, True)
            
            # Add to investigation queue if high priority
            if anomaly.investigation_priority >= 7:
                self.investigation_queue.append(anomaly)
            
            logger.info(f"Detected anomaly: {anomaly.anomaly_type.value} at {endpoint}")
        
        return anomaly
    
    def _detect_anomaly(self, endpoint: str, payload: str,
                       response: Dict, baseline: Dict) -> Optional[Anomaly]:
        """Detect anomalies in response"""
        anomalies_found = []
        
        # Check timing anomaly
        response_time = response.get('time', 0)
        if baseline['std_time'] > 0:
            z_score = (response_time - baseline['avg_time']) / baseline['std_time']
            if abs(z_score) > 3:
                anomalies_found.append({
                    'type': AnomalyType.TIMING_ANOMALY,
                    'description': f"Response time {response_time:.2f}s is {z_score:.1f} std devs from mean",
                    'deviation': abs(z_score),
                    'priority': min(10, int(abs(z_score)))
                })
        
        # Check response length anomaly
        response_length = response.get('length', 0)
        if baseline['std_length'] > 0:
            z_score = (response_length - baseline['avg_length']) / baseline['std_length']
            if abs(z_score) > 3:
                anomalies_found.append({
                    'type': AnomalyType.UNUSUAL_RESPONSE,
                    'description': f"Response length {response_length} is {z_score:.1f} std devs from mean",
                    'deviation': abs(z_score),
                    'priority': min(10, int(abs(z_score)))
                })
        
        # Check for new error patterns
        content = response.get('content', '')
        error_patterns = self._check_error_patterns(content, baseline['known_error_patterns'])
        if error_patterns:
            anomalies_found.append({
                'type': AnomalyType.ERROR_PATTERN,
                'description': f"New error patterns detected: {', '.join(error_patterns)}",
                'deviation': len(error_patterns),
                'priority': 8
            })
        
        # Check for unexpected data exposure
        data_exposure = self._check_data_exposure(content)
        if data_exposure:
            anomalies_found.append({
                'type': AnomalyType.UNEXPECTED_DATA,
                'description': f"Potential data exposure: {data_exposure}",
                'deviation': 5,
                'priority': 9
            })
        
        if not anomalies_found:
            return None
        
        # Return highest priority anomaly
        best = max(anomalies_found, key=lambda x: x['priority'])
        
        anomaly_id = hashlib.md5(f"{endpoint}_{payload}_{best['type'].value}".encode()).hexdigest()[:12]
        
        return Anomaly(
            id=anomaly_id,
            anomaly_type=best['type'],
            description=best['description'],
            confidence=min(1.0, best['deviation'] / 5),
            endpoint=endpoint,
            payload=payload,
            response_snippet=content[:500] if content else '',
            baseline_deviation=best['deviation'],
            timestamp=datetime.now().isoformat(),
            investigation_priority=best['priority']
        )
    
    def _check_error_patterns(self, content: str, 
                             known_patterns: List[str]) -> List[str]:
        """Check for new error patterns"""
        new_patterns = []
        
        error_checks = [
            (r'stack\s*trace', 'stack_trace'),
            (r'exception\s+in\s+thread', 'java_exception'),
            (r'segmentation\s+fault', 'segfault'),
            (r'memory\s+error', 'memory_error'),
            (r'internal\s+server\s+error', 'internal_error'),
            (r'debug\s*:', 'debug_info'),
            (r'password|secret|api[_\s]?key', 'credential_leak'),
            (r'/home/\w+|/var/www|C:\\\\', 'path_disclosure'),
            (r'MySQL|PostgreSQL|Oracle|MSSQL', 'db_error'),
        ]
        
        for pattern, name in error_checks:
            if re.search(pattern, content, re.IGNORECASE):
                if name not in known_patterns:
                    new_patterns.append(name)
        
        return new_patterns
    
    def _check_data_exposure(self, content: str) -> Optional[str]:
        """Check for unexpected data exposure"""
        exposures = []
        
        # Check for sensitive data patterns
        patterns = [
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'email'),
            (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', 'credit_card'),
            (r'\b\d{3}-\d{2}-\d{4}\b', 'ssn'),
            (r'(?:password|passwd|pwd)\s*[:=]\s*\S+', 'password'),
            (r'(?:api[_\s]?key|apikey)\s*[:=]\s*\S+', 'api_key'),
            (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', 'private_key'),
            (r'(?:aws|amazon)\s*(?:access|secret)\s*(?:key)?\s*[:=]\s*\S+', 'aws_key'),
        ]
        
        for pattern, name in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                exposures.append(name)
        
        return ', '.join(exposures) if exposures else None
    
    def _get_mutation_type(self, payload: str) -> Optional[str]:
        """Get mutation type from payload"""
        # Simple heuristics
        if len(payload) > 1000:
            return 'overflow'
        if '%' in payload and any(c in payload for c in 'snxp'):
            return 'format_string'
        if re.search(r'\\u[0-9a-f]{4}', payload, re.IGNORECASE):
            return 'unicode'
        if re.search(r'%[0-9a-f]{2}', payload, re.IGNORECASE):
            return 'encoding'
        
        return None
    
    def generate_fuzz_payloads(self, endpoint: str, 
                              base_value: str) -> List[Dict]:
        """Generate fuzz payloads for an endpoint"""
        context = {
            'endpoint': endpoint,
            'base_value': base_value
        }
        
        return self.fuzzer.generate_payloads(base_value, context)
    
    def get_investigation_queue(self) -> List[Dict]:
        """Get anomalies requiring investigation"""
        return [
            {
                'id': a.id,
                'type': a.anomaly_type.value,
                'endpoint': a.endpoint,
                'description': a.description,
                'priority': a.investigation_priority,
                'confidence': a.confidence,
                'payload': a.payload
            }
            for a in sorted(self.investigation_queue, 
                          key=lambda x: x.investigation_priority, 
                          reverse=True)
        ]
    
    def mark_as_known(self, anomaly_id: str, vuln_type: str = None):
        """Mark an anomaly as known (either known vuln or false positive)"""
        self.investigation_queue = [
            a for a in self.investigation_queue if a.id != anomaly_id
        ]
        
        if vuln_type:
            # It was a real finding - store for future reference
            if self.memory_system:
                anomaly = next((a for a in self.anomalies if a.id == anomaly_id), None)
                if anomaly:
                    self.memory_system.store_memory(
                        memory_type='zero_day_pattern',
                        content={
                            'anomaly_type': anomaly.anomaly_type.value,
                            'payload': anomaly.payload,
                            'response_pattern': anomaly.response_snippet[:200],
                            'resulted_in': vuln_type
                        },
                        tags=['zero_day', vuln_type],
                        importance=0.9
                    )
    
    def get_discovery_stats(self) -> Dict[str, Any]:
        """Get zero-day discovery statistics"""
        return {
            'total_anomalies': len(self.anomalies),
            'pending_investigation': len(self.investigation_queue),
            'by_type': {
                t.value: len([a for a in self.anomalies if a.anomaly_type == t])
                for t in AnomalyType
            },
            'mutation_effectiveness': dict(self.fuzzer.mutation_scores),
            'endpoints_baselined': len(self.baseline_builder.baselines)
        }


# Singleton instances
_learning_engine = None
_zeroday_engine = None

def get_learning_engine(memory_system=None) -> ContinuousLearningEngine:
    """Get the singleton continuous learning engine"""
    global _learning_engine
    if _learning_engine is None:
        _learning_engine = ContinuousLearningEngine(memory_system)
    return _learning_engine

def get_zeroday_engine(memory_system=None) -> ZeroDayDiscoveryEngine:
    """Get the singleton zero-day discovery engine"""
    global _zeroday_engine
    if _zeroday_engine is None:
        _zeroday_engine = ZeroDayDiscoveryEngine(memory_system)
    return _zeroday_engine
