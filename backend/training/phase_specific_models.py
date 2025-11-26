"""Phase-Specific Tool Recommender Models
Each pentesting phase has its own specialized model"""
import numpy as np
import joblib
from typing import Dict, List, Any
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import cross_val_score
from datetime import datetime
import logging
import os

logger = logging.getLogger(__name__)

class PhaseSpecificModelTrainer:
    """
    Train separate models for each pentesting phase
    """
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_configs = self._define_phase_features()
        self.tool_configs = self._define_phase_tools()
    
    def _define_phase_features(self) -> Dict[str, List[str]]:
        """
        Define phase-specific feature sets
        Each phase only needs relevant features
        """
        return {
            'reconnaissance': [
                # Target characteristics
                'target_type',              # web, api, network, cloud
                'domain_complexity',        # Estimated complexity (0-1)
                
                # Progress tracking
                'passive_recon_complete',   # All passive tools done
                'active_recon_started',     # Active phase initiated
                'subdomains_discovered',    # Count
                'emails_discovered',        # Count
                'technologies_discovered',  # Count
                'employees_discovered',     # Count
                
                # Time & stealth
                'time_in_phase',            # Seconds
                'stealth_required',         # Boolean
                'detection_risk',           # 0-1 score
                
                # Tools executed
                'num_tools_executed',
                'passive_tools_ratio',      # Ratio of passive to total
            ],
            
            'scanning': [
                # Target info from recon
                'target_type',
                'technologies_known',       # Count
                'subdomains_count',
                'open_ports_found',         # From nmap
                
                # Scan progress
                'scan_coverage',            # 0-1 score
                'vulnerabilities_found',    # Count so far
                'services_enumerated',      # Count
                
                # Technology-specific
                'wordpress_detected',
                'joomla_detected',
                'has_ssl_tls',
                'has_database',
                'has_smb',
                
                # Resources
                'time_in_phase',
                'num_tools_executed',
                'aggressive_mode',          # Boolean
            ],
            
            'exploitation': [
                # Vulnerability context
                'sql_injection_found',      # Boolean flags for each vuln type
                'xss_found',
                'command_injection_found',
                'xxe_found',
                'ssrf_found',
                'file_upload_found',
                'auth_bypass_found',
                
                # Severity indicators
                'highest_severity',         # CVSS score
                'num_critical_vulns',
                'num_exploitable_vulns',
                
                # Target state
                'waf_detected',
                'authentication_required',
                'target_hardening_level',   # 0-1 score
                
                # Exploitation progress
                'access_gained',            # Boolean
                'exploit_attempts',         # Count
                'time_in_phase',
            ],
            
            'post_exploitation': [
                # Access context
                'current_user_privilege',   # user, admin, root (encoded)
                'os_type',                  # linux, windows, mac
                'os_version',               # Detected version
                
                # Objectives
                'privilege_escalated',      # Boolean
                'persistence_established',
                'credentials_dumped',
                'lateral_movement_success',
                
                # Environment
                'domain_joined',
                'antivirus_detected',
                'edr_detected',
                'other_hosts_visible',      # Count
                
                # Resources
                'time_in_phase',
                'num_tools_executed',
                'detection_probability',    # 0-1 score
            ],
            
            'covering_tracks': [
                # Cleanup requirements
                'log_entries_present',      # Count
                'artifacts_present',        # Count (files, users, etc.)
                'backdoors_installed',      # Count
                'forensic_evidence_score',  # 0-10 score
                
                # Cleanup progress
                'logs_cleaned',             # Boolean
                'timestamps_modified',
                'artifacts_removed',
                
                # Constraints
                'time_remaining',           # Seconds before exit
                'stealth_critical',         # Boolean
                'detection_imminent',       # Boolean
                
                # System state
                'os_type',
                'admin_access',             # Boolean
            ]
        }
    
    def _define_phase_tools(self) -> Dict[str, List[str]]:
        """
        Define available tools per phase
        """
        return {
            'reconnaissance': [
                'sublist3r', 'amass', 'theHarvester', 'shodan', 'censys',
                'builtwith', 'whatweb', 'wappalyzer', 'dnsenum', 'fierce',
                'recon-ng', 'spiderfoot', 'maltego'
            ],
            'scanning': [
                'nmap', 'masscan', 'nuclei', 'nikto', 'nessus',
                'wpscan', 'joomscan', 'droopescan', 'sslscan', 'testssl.sh',
                'enum4linux', 'smbclient', 'snmp-check', 'ldapsearch'
            ],
            'exploitation': [
                'sqlmap', 'metasploit', 'hydra', 'medusa', 'dalfox',
                'xsser', 'commix', 'xxeinjector', 'ssrfmap', 'weevely',
                'burp', 'zap', 'sqlninja'
            ],
            'post_exploitation': [
                'linpeas', 'winpeas', 'linenum', 'windows-exploit-suggester',
                'mimikatz', 'lazagne', 'secretsdump', 'bloodhound',
                'crackmapexec', 'psexec', 'wmiexec', 'empire'
            ],
            'covering_tracks': [
                'clear_logs', 'log_wiper', 'timestomp', 'wevtutil',
                'shred', 'wipe', 'secure_delete', 'bleachbit'
            ]
        }
    
    def extract_phase_features(self, context: Dict[str, Any], phase: str) -> np.ndarray:
        """
        Extract phase-specific features from context
        """
        feature_names = self.feature_configs[phase]
        features = []
        
        for feature_name in feature_names:
            value = self._get_feature_value(context, feature_name, phase)
            features.append(value)
        
        return np.array(features)
    
    def _get_feature_value(self, context: Dict, feature_name: str, phase: str) -> float:
        """
        Extract single feature value with appropriate encoding
        """
        # Direct numeric features
        if feature_name in ['time_in_phase', 'subdomains_discovered', 'num_tools_executed',
                           'vulnerabilities_found', 'open_ports_found', 'log_entries_present',
                           'emails_discovered', 'technologies_discovered', 'employees_discovered',
                           'services_enumerated', 'num_critical_vulns', 'num_exploitable_vulns',
                           'exploit_attempts', 'other_hosts_visible', 'artifacts_present',
                           'backdoors_installed', 'time_remaining', 'subdomains_count',
                           'technologies_known']:
            return float(context.get(feature_name, 0))
        
        # Boolean features
        if feature_name in ['passive_recon_complete', 'active_recon_started', 'stealth_required',
                           'wordpress_detected', 'joomla_detected', 'has_ssl_tls', 'has_database',
                           'has_smb', 'aggressive_mode', 'sql_injection_found', 'xss_found',
                           'command_injection_found', 'xxe_found', 'ssrf_found', 'file_upload_found',
                           'auth_bypass_found', 'waf_detected', 'authentication_required',
                           'access_gained', 'privilege_escalated', 'persistence_established',
                           'credentials_dumped', 'lateral_movement_success', 'domain_joined',
                           'antivirus_detected', 'edr_detected', 'logs_cleaned', 'timestamps_modified',
                           'artifacts_removed', 'stealth_critical', 'detection_imminent', 'admin_access']:
            return 1.0 if context.get(feature_name, False) else 0.0
        
        # Categorical features (encoded)
        if feature_name == 'target_type':
            types = {'web': 0, 'api': 1, 'network': 2, 'cloud': 3}
            return float(types.get(context.get('target_type', 'web'), 0))
        
        if feature_name == 'os_type':
            os_map = {'linux': 0, 'windows': 1, 'mac': 2}
            return float(os_map.get(context.get('os_type', 'linux'), 0))
        
        if feature_name == 'current_user_privilege':
            priv_map = {'user': 0, 'admin': 1, 'root': 2, 'system': 2}
            return float(priv_map.get(context.get('current_user_privilege', 'user'), 0))
        
        # Normalized scores (0-1)
        if feature_name in ['scan_coverage', 'detection_risk', 'domain_complexity',
                           'passive_tools_ratio', 'target_hardening_level', 'detection_probability']:
            return float(context.get(feature_name, 0.5))
        
        # CVSS scores (0-10)
        if feature_name in ['highest_severity', 'forensic_evidence_score']:
            return float(context.get(feature_name, 0.0))
        
        # OS version (simple encoding)
        if feature_name == 'os_version':
            return float(hash(str(context.get('os_version', ''))) % 100) / 100.0
        
        # Default
        return 0.0
    
    def train_phase_model(self, phase: str, training_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Train model for specific phase
        
        Args:
            phase: Phase name
            training_logs: List of tool execution logs from this phase
            [{
                'context': {...},
                'tool': 'tool_name',
                'success': True/False,
                'vulns_found': int,
                'execution_time': float
            }]
        
        Returns:
            Trained model + metadata
        """
        print(f"\n{'='*80}")
        print(f"TRAINING MODEL FOR: {phase.upper()}")
        print(f"{'='*80}")
        
        if len(training_logs) < 20:
            print(f"⚠️  WARNING: Only {len(training_logs)} training samples (recommend ≥100)")
        
        # Extract features and labels
        X = []
        y = []
        
        for log in training_logs:
            features = self.extract_phase_features(log['context'], phase)
            X.append(features)
            y.append(log['tool'])
        
        X = np.array(X)
        y = np.array(y)
        
        print(f"Training samples: {len(X)}")
        print(f"Features per sample: {X.shape[1]}")
        print(f"Unique tools: {len(np.unique(y))}")
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Train ensemble
        rf = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            random_state=42
        )
        
        gb = GradientBoostingClassifier(
            n_estimators=50,
            max_depth=6,
            learning_rate=0.1,
            random_state=42
        )
        
        # Train both
        rf.fit(X_scaled, y)
        gb.fit(X_scaled, y)
        
        # Evaluate
        rf_scores = cross_val_score(rf, X_scaled, y, cv=min(5, len(X)//10 if len(X) >= 10 else 2), scoring='accuracy')
        gb_scores = cross_val_score(gb, X_scaled, y, cv=min(5, len(X)//10 if len(X) >= 10 else 2), scoring='accuracy')
        
        # Choose best
        if rf_scores.mean() > gb_scores.mean():
            model = rf
            model_type = 'RandomForest'
            cv_score = rf_scores.mean()
            cv_std = rf_scores.std()
        else:
            model = gb
            model_type = 'GradientBoosting'
            cv_score = gb_scores.mean()
            cv_std = gb_scores.std()
        
        print(f"\nBest model: {model_type}")
        print(f"Cross-validation accuracy: {cv_score:.3f} ± {cv_std:.3f}")
        
        # Feature importance
        if hasattr(model, 'feature_importances_'):
            importances = model.feature_importances_
            feature_names = self.feature_configs[phase]
            
            print(f"\nTop 5 Most Important Features:")
            indices = np.argsort(importances)[-5:][::-1]
            for i in indices:
                print(f"  {feature_names[i]:30s}: {importances[i]:.4f}")
        
        return {
            'model': model,
            'scaler': scaler,
            'model_type': model_type,
            'phase': phase,
            'cv_accuracy': float(cv_score),
            'cv_std': float(cv_std),
            'feature_names': self.feature_configs[phase],
            'available_tools': self.tool_configs[phase],
            'training_samples': len(X),
            'metadata': {
                'trained_date': datetime.now().isoformat()
            }
        }
    
    def train_all_phase_models(self, training_data: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """
        Train models for all phases
        
        Args:
            training_data: {
                'reconnaissance': [logs...],
                'scanning': [logs...],
                'exploitation': [logs...],
                'post_exploitation': [logs...],
                'covering_tracks': [logs...]
            }
        """
        print("\n" + "="*80)
        print("TRAINING PHASE-SPECIFIC MODELS")
        print("="*80)
        
        models = {}
        
        for phase in ['reconnaissance', 'scanning', 'exploitation',
                      'post_exploitation', 'covering_tracks']:
            
            if phase not in training_data or len(training_data[phase]) == 0:
                print(f"\n⚠️  No training data for {phase}, skipping...")
                continue
            
            model_data = self.train_phase_model(phase, training_data[phase])
            models[phase] = model_data
            
            # Save individual model
            os.makedirs('models', exist_ok=True)
            save_path = f'models/tool_recommender_{phase}.pkl'
            joblib.dump(model_data, save_path)
            print(f"✅ Saved to: {save_path}")
        
        print("\n" + "="*80)
        print("TRAINING COMPLETE")
        print("="*80)
        print(f"Models trained: {len(models)}/5")
        
        for phase, model_data in models.items():
            print(f"  {phase:20s}: {model_data['cv_accuracy']:.1%} accuracy "
                  f"({model_data['training_samples']} samples)")
        
        return models


class PhaseSpecificToolSelector:
    """
    Runtime tool selection using phase-specific models
    """
    
    def __init__(self):
        self.models = {}
        self.load_all_models()
    
    def load_all_models(self):
        """Load all trained phase-specific models"""
        import os
        # Try multiple possible locations
        possible_base_paths = [
            'models',  # From training directory
            '../models',  # From testing directory
            os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')  # Absolute from backend
        ]
        
        for phase in ['reconnaissance', 'scanning', 'exploitation',
                      'post_exploitation', 'covering_tracks']:
            loaded = False
            for base_path in possible_base_paths:
                try:
                    model_path = os.path.join(base_path, f'tool_recommender_{phase}.pkl')
                    self.models[phase] = joblib.load(model_path)
                    logger.info(f"✅ Loaded {phase} model from {model_path}")
                    loaded = True
                    break
                except (FileNotFoundError, OSError):
                    continue
            
            if not loaded:
                logger.warning(f"⚠️  Model not found for {phase}")
    
    def recommend_tools(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recommend tools using phase-specific model
        """
        phase = context.get('phase', 'reconnaissance')
        
        if phase not in self.models:
            logger.error(f"No model loaded for phase: {phase}")
            return {
                'tools': [],
                'error': f'No model for phase {phase}'
            }
        
        model_data = self.models[phase]
        model = model_data['model']
        scaler = model_data['scaler']
        
        # Extract phase-specific features
        trainer = PhaseSpecificModelTrainer()
        features = trainer.extract_phase_features(context, phase)
        features_scaled = scaler.transform([features])
        
        # Predict probabilities for all tools
        probas = model.predict_proba(features_scaled)[0]
        tools = model.classes_
        
        # Sort by probability
        tool_probas = sorted(zip(tools, probas), key=lambda x: x[1], reverse=True)
        
        # Filter out already-executed tools
        tools_executed = set(context.get('tools_executed', []))
        available_tools = [(tool, prob) for tool, prob in tool_probas
                          if tool not in tools_executed]
        
        # Return top 3
        top_tools = [tool for tool, prob in available_tools[:3]]
        top_probas = [prob for tool, prob in available_tools[:3]]
        
        return {
            'tools': top_tools,
            'probabilities': top_probas,
            'phase': phase,
            'model_type': model_data['model_type'],
            'confidence': top_probas[0] if top_probas else 0.0
        }
