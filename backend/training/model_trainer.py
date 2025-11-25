"""
ML Model Trainer for Security Detection
Trains multiple ML models for vulnerability detection, attack classification, and severity prediction
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score, roc_auc_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
import joblib
from typing import Dict, List, Any, Tuple
from datetime import datetime
import os

class SecurityMLTrainer:
    """Train ML models for security vulnerability detection"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.feature_names = []
        self.models = {}
        
    def train_vulnerability_detector(self, training_examples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Train binary classifier to detect vulnerabilities
        Returns: {'model', 'scaler', 'metrics', 'feature_names'}
        """
        print("\n[Training] Vulnerability Detector...")
        
        # Convert dicts to arrays
        X = self._encode_features(training_examples)
        y = np.array([ex['label'] for ex in training_examples])
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.15, stratify=y, random_state=42
        )
        
        # Train ensemble
        rf = RandomForestClassifier(
            n_estimators=200, 
            max_depth=15, 
            min_samples_split=5,
            random_state=42,
            n_jobs=-1
        )
        
        gb = GradientBoostingClassifier(
            n_estimators=100, 
            max_depth=10,
            random_state=42
        )
        
        mlp = MLPClassifier(
            hidden_layer_sizes=(128, 64, 32), 
            max_iter=500,
            random_state=42,
            early_stopping=True
        )
        
        ensemble = VotingClassifier(
            estimators=[('rf', rf), ('gb', gb), ('mlp', mlp)],
            voting='soft',
            n_jobs=-1
        )
        
        print(f"  Training on {len(X_train)} samples...")
        ensemble.fit(X_train, y_train)
        
        # Evaluate
        y_pred = ensemble.predict(X_test)
        y_proba = ensemble.predict_proba(X_test)[:, 1]
        
        metrics = {
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1': f1_score(y_test, y_pred),
            'accuracy': accuracy_score(y_test, y_pred),
            'roc_auc': roc_auc_score(y_test, y_proba)
        }
        
        print(f"  ✓ Precision: {metrics['precision']:.3f}")
        print(f"  ✓ Recall: {metrics['recall']:.3f}")
        print(f"  ✓ F1: {metrics['f1']:.3f}")
        print(f"  ✓ ROC-AUC: {metrics['roc_auc']:.3f}")
        
        return {
            'model': ensemble,
            'scaler': self.scaler,
            'metrics': metrics,
            'feature_names': self.feature_names
        }
    
    def train_attack_classifier(self, training_examples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Train multi-class classifier for attack type classification
        Returns: {'model', 'metrics', 'classes'}
        """
        print("\n[Training] Attack Type Classifier...")
        
        X = self._encode_features(training_examples)
        y = np.array([ex['attack_type'] for ex in training_examples])
        
        # Get unique classes
        classes = np.unique(y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.15, random_state=42, stratify=y
        )
        
        # Train RandomForest with class balancing
        clf = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
        
        print(f"  Training on {len(X_train)} samples, {len(classes)} classes...")
        clf.fit(X_train, y_train)
        
        # Evaluate
        y_pred = clf.predict(X_test)
        
        metrics = {
            'precision': precision_score(y_test, y_pred, average='weighted', zero_division=0),
            'recall': recall_score(y_test, y_pred, average='weighted', zero_division=0),
            'f1': f1_score(y_test, y_pred, average='weighted', zero_division=0),
            'accuracy': accuracy_score(y_test, y_pred)
        }
        
        print(f"  ✓ Precision: {metrics['precision']:.3f}")
        print(f"  ✓ Recall: {metrics['recall']:.3f}")
        print(f"  ✓ F1: {metrics['f1']:.3f}")
        print(f"  ✓ Accuracy: {metrics['accuracy']:.3f}")
        
        return {
            'model': clf,
            'metrics': metrics,
            'classes': classes.tolist()
        }
    
    def train_tool_recommender(self, tool_execution_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Train model to recommend best tools based on context
        Returns: {'model', 'metrics'}
        """
        print("\n[Training] Tool Recommender...")
        
        # Extract features from tool execution context
        X = []
        y = []
        
        for log in tool_execution_logs:
            context_features = self._encode_tool_context(log['context'])
            X.append(context_features)
            y.append(log['tool_name'])
        
        X = np.array(X)
        y = np.array(y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.15, random_state=42
        )
        
        # Train GradientBoosting
        clf = GradientBoostingClassifier(
            n_estimators=150,
            max_depth=12,
            learning_rate=0.1,
            random_state=42
        )
        
        print(f"  Training on {len(X_train)} tool executions...")
        clf.fit(X_train, y_train)
        
        # Evaluate
        y_pred = clf.predict(X_test)
        
        metrics = {
            'precision': precision_score(y_test, y_pred, average='weighted', zero_division=0),
            'recall': recall_score(y_test, y_pred, average='weighted', zero_division=0),
            'f1': f1_score(y_test, y_pred, average='weighted', zero_division=0),
            'accuracy': accuracy_score(y_test, y_pred)
        }
        
        print(f"  ✓ F1: {metrics['f1']:.3f}")
        print(f"  ✓ Accuracy: {metrics['accuracy']:.3f}")
        
        return {
            'model': clf,
            'metrics': metrics
        }
    
    def train_severity_predictor(self, vulnerability_examples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Train regression model to predict CVSS severity scores
        Returns: {'model', 'metrics'}
        """
        print("\n[Training] Severity Predictor (CVSS)...")
        
        X = self._encode_severity_features(vulnerability_examples)
        y = np.array([ex['severity'] for ex in vulnerability_examples])
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.15, random_state=42
        )
        
        # Train GradientBoostingRegressor
        regressor = GradientBoostingRegressor(
            n_estimators=150,
            max_depth=10,
            learning_rate=0.1,
            random_state=42
        )
        
        print(f"  Training on {len(X_train)} vulnerability examples...")
        regressor.fit(X_train, y_train)
        
        # Evaluate
        y_pred = regressor.predict(X_test)
        
        # Calculate regression metrics
        mae = np.mean(np.abs(y_test - y_pred))
        rmse = np.sqrt(np.mean((y_test - y_pred) ** 2))
        r2 = regressor.score(X_test, y_test)
        
        metrics = {
            'mae': mae,
            'rmse': rmse,
            'r2': r2
        }
        
        print(f"  ✓ MAE: {metrics['mae']:.3f}")
        print(f"  ✓ RMSE: {metrics['rmse']:.3f}")
        print(f"  ✓ R²: {metrics['r2']:.3f}")
        
        return {
            'model': regressor,
            'metrics': metrics
        }
    
    def train_cloud_detector(self, cloud_attack_examples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Train classifier for cloud security anomaly detection
        Returns: {'model', 'metrics'}
        """
        print("\n[Training] Cloud Attack Detector...")
        
        X = []
        y = []
        
        for ex in cloud_attack_examples:
            features = list(ex['features'].values())
            X.append(features)
            y.append(ex['label'])
        
        X = np.array(X)
        y = np.array(y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.15, random_state=42, stratify=y
        )
        
        # Train RandomForest
        clf = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
        
        print(f"  Training on {len(X_train)} cloud events...")
        clf.fit(X_train, y_train)
        
        # Evaluate
        y_pred = clf.predict(X_test)
        y_proba = clf.predict_proba(X_test)[:, 1]
        
        metrics = {
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1': f1_score(y_test, y_pred),
            'accuracy': accuracy_score(y_test, y_pred),
            'roc_auc': roc_auc_score(y_test, y_proba)
        }
        
        print(f"  ✓ F1: {metrics['f1']:.3f}")
        print(f"  ✓ ROC-AUC: {metrics['roc_auc']:.3f}")
        
        return {
            'model': clf,
            'metrics': metrics
        }
    
    def train_ai_attack_detector(self, jailbreak_examples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Train text classifier for AI jailbreak detection
        Returns: {'model', 'vectorizer', 'metrics'}
        """
        print("\n[Training] AI Jailbreak Detector...")
        
        # Extract text and labels
        texts = [ex['prompt'] for ex in jailbreak_examples]
        y = np.array([ex['label'] for ex in jailbreak_examples])
        
        # TF-IDF vectorization
        vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 3),
            min_df=2
        )
        
        X = vectorizer.fit_transform(texts)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.15, random_state=42, stratify=y
        )
        
        # Train LinearSVC
        clf = LinearSVC(
            C=1.0,
            class_weight='balanced',
            max_iter=2000,
            random_state=42
        )
        
        print(f"  Training on {len(y_train)} text samples...")
        clf.fit(X_train, y_train)
        
        # Evaluate
        y_pred = clf.predict(X_test)
        
        metrics = {
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1': f1_score(y_test, y_pred),
            'accuracy': accuracy_score(y_test, y_pred)
        }
        
        print(f"  ✓ F1: {metrics['f1']:.3f}")
        print(f"  ✓ Accuracy: {metrics['accuracy']:.3f}")
        
        return {
            'model': clf,
            'vectorizer': vectorizer,
            'metrics': metrics
        }
    
    def _encode_features(self, examples: List[Dict[str, Any]]) -> np.ndarray:
        """Convert feature dicts to numpy array"""
        if not examples:
            return np.array([])
        
        # Get feature names from first example
        if 'features' in examples[0]:
            self.feature_names = list(examples[0]['features'].keys())
            X = np.array([list(ex['features'].values()) for ex in examples])
        else:
            # Direct features
            self.feature_names = [k for k in examples[0].keys() if k not in ['label', 'attack_type']]
            X = np.array([[ex[k] for k in self.feature_names] for ex in examples])
        
        # Scale features
        X = self.scaler.fit_transform(X)
        
        return X
    
    def _encode_tool_context(self, context: Dict[str, Any]) -> np.ndarray:
        """Encode tool execution context into features"""
        features = []
        
        # Phase encoding (one-hot)
        phases = ['reconnaissance', 'scanning', 'exploitation', 'post_exploitation', 'covering_tracks']
        for phase in phases:
            features.append(1.0 if context.get('phase') == phase else 0.0)
        
        # Other context features
        features.append(context.get('num_vulns_found', 0))
        features.append(context.get('highest_severity', 0.0))
        features.append(context.get('time_elapsed', 0) / 3600.0)  # Normalize to hours
        features.append(context.get('coverage', 0.0))
        features.append(context.get('ml_confidence', 0.5))
        
        return np.array(features)
    
    def _encode_severity_features(self, examples: List[Dict[str, Any]]) -> np.ndarray:
        """Encode features for severity prediction"""
        X = []
        
        for ex in examples:
            features = []
            
            # Attack type encoding
            attack_types = ['sql_injection', 'xss', 'rce', 'lfi', 'xxe', 'csrf', 'ssrf']
            for atype in attack_types:
                features.append(1.0 if ex.get('attack_type') == atype else 0.0)
            
            # Other features
            features.append(ex.get('exploitable', 0))
            features.append(ex.get('confidence', 0.5))
            features.append(len(ex.get('evidence', '')))
            features.append(ex.get('impact_score', 5.0))
            features.append(ex.get('ease_of_exploit', 5.0))
            
            X.append(features)
        
        return np.array(X)
    
    def save_model(self, model_data: Dict[str, Any], model_name: str, output_dir: str = './models'):
        """Save trained model to disk"""
        os.makedirs(output_dir, exist_ok=True)
        model_path = os.path.join(output_dir, f"{model_name}.pkl")
        
        joblib.dump(model_data, model_path)
        print(f"  ✓ Model saved: {model_path}")
        
        return model_path
    
    def load_model(self, model_name: str, model_dir: str = './models') -> Dict[str, Any]:
        """Load trained model from disk"""
        model_path = os.path.join(model_dir, f"{model_name}.pkl")
        
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
        
        model_data = joblib.load(model_path)
        print(f"  ✓ Model loaded: {model_path}")
        
        return model_data
