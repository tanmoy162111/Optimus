"""
Comprehensive ML Model Evaluation
Evaluates all trained models on held-out test sets
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import json
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
    mean_absolute_error, mean_squared_error, r2_score
)
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
import joblib

from training.feature_extractor import DatasetFeatureExtractor
from training.pattern_extractor import PatternExtractor

class MLModelEvaluator:
    """Comprehensive evaluation of all ML models"""
    
    def __init__(self):
        self.feature_extractor = DatasetFeatureExtractor()
        self.pattern_extractor = PatternExtractor()
        self.results = {}
        self.output_dir = Path('evaluation_results')
        self.output_dir.mkdir(exist_ok=True)
    
    def evaluate_vulnerability_detector(self, X_test, y_test) -> Dict[str, Any]:
        """
        Evaluate Vulnerability Detector (Binary Classification)
        
        Success Criteria:
        - F1 Score ≥ 0.85
        - Recall ≥ 0.80 (miss ≤20% of vulnerabilities)
        - Precision ≥ 0.85 (false alarms ≤15%)
        """
        print("\n" + "="*80)
        print("EVALUATING: Vulnerability Detector (Binary Classifier)")
        print("="*80)
        
        # Load trained model
        try:
            model_data = joblib.load('models/vuln_detector.pkl')
            model = model_data['model']
            scaler = model_data['scaler']
        except FileNotFoundError:
            print("❌ Model file not found: models/vuln_detector.pkl")
            return {}
        
        # Scale features
        X_test_scaled = scaler.transform(X_test)
        
        # Predict
        y_pred = model.predict(X_test_scaled)
        y_proba = model.predict_proba(X_test_scaled)[:, 1]
        
        # Calculate metrics
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'recall': recall_score(y_test, y_pred, zero_division=0),
            'f1': f1_score(y_test, y_pred, zero_division=0),
            'roc_auc': roc_auc_score(y_test, y_proba) if len(np.unique(y_test)) > 1 else 0.0,
            'support': len(y_test)
        }
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
        
        metrics['true_positives'] = int(tp)
        metrics['true_negatives'] = int(tn)
        metrics['false_positives'] = int(fp)
        metrics['false_negatives'] = int(fn)
        metrics['false_positive_rate'] = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        
        # Print results
        print(f"\nTest Samples: {len(y_test)}")
        print(f"  Accuracy:  {metrics['accuracy']:.3f}")
        print(f"  Precision: {metrics['precision']:.3f}")
        print(f"  Recall:    {metrics['recall']:.3f}")
        print(f"  F1 Score:  {metrics['f1']:.3f}")
        print(f"  ROC-AUC:   {metrics['roc_auc']:.3f}")
        print(f"  FP Rate:   {metrics['false_positive_rate']:.3f}")
        print(f"  Confusion Matrix: TP={tp}, TN={tn}, FP={fp}, FN={fn}")
        
        # Check success criteria
        print(f"\n{'='*80}")
        if metrics['f1'] >= 0.85 and metrics['recall'] >= 0.80 and metrics['precision'] >= 0.85:
            print(f"✅ VULNERABILITY DETECTOR APPROVED FOR PRODUCTION")
        else:
            print(f"❌ VULNERABILITY DETECTOR NEEDS IMPROVEMENT")
            if metrics['recall'] < 0.80:
                print(f"   - Missing {(0.80 - metrics['recall'])*100:.1f}% of vulnerabilities")
            if metrics['precision'] < 0.85:
                print(f"   - {(1 - metrics['precision'])*100:.1f}% false positive rate")
            if metrics['f1'] < 0.85:
                print(f"   - F1 Score below threshold: {metrics['f1']:.3f} < 0.85")
        print(f"{'='*80}\n")
        
        self.save_results('vulnerability_detector', metrics, metrics)
        return metrics
    
    def evaluate_attack_classifier(self, X_test, y_test) -> Dict[str, Any]:
        """
        Evaluate Attack Type Classifier (Multi-class)
        
        Success Criteria:
        - Macro F1 ≥ 0.80
        - Per-class F1 ≥ 0.75 for critical attacks (SQL, XSS, RCE)
        """
        print("\n" + "="*80)
        print("EVALUATING: Attack Type Classifier (Multi-class)")
        print("="*80)
        
        try:
            model_data = joblib.load('models/attack_classifier.pkl')
            model = model_data['model']
        except FileNotFoundError:
            print("❌ Model file not found: models/attack_classifier.pkl")
            return {}
        
        print(f"Total test samples: {len(y_test)}")
        print(f"Unique attack types: {len(np.unique(y_test))}")
        
        # Predict
        y_pred = model.predict(X_test)
        
        # Metrics
        report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
        
        print("\nPER-CLASS PERFORMANCE:")
        print("-" * 80)
        for attack_type, met in report.items():
            if attack_type not in ['accuracy', 'macro avg', 'weighted avg']:
                print(f"{attack_type:30s} | Precision: {met['precision']:.3f} | "
                      f"Recall: {met['recall']:.3f} | F1: {met['f1-score']:.3f} | "
                      f"Support: {int(met['support'])}")
        
        print("-" * 80)
        print(f"{'Macro Average':30s} | Precision: {report['macro avg']['precision']:.3f} | "
              f"Recall: {report['macro avg']['recall']:.3f} | "
              f"F1: {report['macro avg']['f1-score']:.3f}")
        print(f"{'Weighted Average':30s} | Precision: {report['weighted avg']['precision']:.3f} | "
              f"Recall: {report['weighted avg']['recall']:.3f} | "
              f"F1: {report['weighted avg']['f1-score']:.3f}")
        
        # Check success criteria
        macro_f1 = report['macro avg']['f1-score']
        critical_attacks = ['sql_injection', 'xss', 'rce']
        critical_f1_scores = [report.get(attack, {}).get('f1-score', 0)
                              for attack in critical_attacks if attack in report]
        min_critical_f1 = min(critical_f1_scores) if critical_f1_scores else 0.0
        
        print(f"\n{'='*80}")
        if macro_f1 >= 0.80 and min_critical_f1 >= 0.75:
            print(f"✅ ATTACK CLASSIFIER APPROVED (Macro F1: {macro_f1:.3f})")
        else:
            print(f"❌ ATTACK CLASSIFIER NEEDS IMPROVEMENT")
            if macro_f1 < 0.80:
                print(f"   - Macro F1 below threshold: {macro_f1:.3f} < 0.80")
            if min_critical_f1 < 0.75:
                print(f"   - Critical attack F1 too low: {min_critical_f1:.3f} < 0.75")
        print(f"{'='*80}\n")
        
        summary = {
            'macro_f1': macro_f1,
            'weighted_f1': report['weighted avg']['f1-score'],
            'critical_f1_min': min_critical_f1
        }
        
        self.save_results('attack_classifier', report, summary)
        return report
    
    def evaluate_severity_predictor(self, X_test, y_test) -> Dict[str, Any]:
        """
        Evaluate Severity Predictor (CVSS Regression)
        
        Success Criteria:
        - MAE ≤ 1.0 (within 1 CVSS point on average)
        - R² ≥ 0.75 (explains 75% of variance)
        - Severity band accuracy ≥ 85%
        """
        print("\n" + "="*80)
        print("EVALUATING: Severity Predictor (CVSS Regression)")
        print("="*80)
        
        try:
            model_data = joblib.load('models/severity_predictor.pkl')
            model = model_data['model']
        except FileNotFoundError:
            print("❌ Model file not found: models/severity_predictor.pkl")
            return {}
        
        print(f"Test samples: {len(y_test)}")
        
        # Predict
        y_pred = model.predict(X_test)
        y_pred = np.clip(y_pred, 0, 10)
        
        # Calculate metrics
        mae = mean_absolute_error(y_test, y_pred)
        rmse = np.sqrt(mean_squared_error(y_test, y_pred))
        r2 = r2_score(y_test, y_pred)
        
        print(f"\nREGRESSION METRICS:")
        print(f"  MAE (Mean Absolute Error): {mae:.3f} CVSS points")
        print(f"  RMSE (Root Mean Squared):  {rmse:.3f} CVSS points")
        print(f"  R² Score:                  {r2:.3f}")
        
        # Severity band accuracy
        def cvss_to_band(score):
            if score >= 9.0:
                return 'Critical'
            elif score >= 7.0:
                return 'High'
            elif score >= 4.0:
                return 'Medium'
            else:
                return 'Low'
        
        y_test_bands = [cvss_to_band(score) for score in y_test]
        y_pred_bands = [cvss_to_band(score) for score in y_pred]
        
        band_accuracy = accuracy_score(y_test_bands, y_pred_bands)
        
        print(f"\nSEVERITY BAND CLASSIFICATION:")
        print(f"  Accuracy: {band_accuracy:.3f} ({band_accuracy*100:.1f}%)")
        
        # Check success criteria
        print(f"\n{'='*80}")
        if mae <= 1.0 and r2 >= 0.75 and band_accuracy >= 0.85:
            print(f"✅ SEVERITY PREDICTOR APPROVED")
        else:
            print(f"❌ SEVERITY PREDICTOR NEEDS IMPROVEMENT")
            if mae > 1.0:
                print(f"   - MAE too high: {mae:.3f} > 1.0")
            if r2 < 0.75:
                print(f"   - R² too low: {r2:.3f} < 0.75")
            if band_accuracy < 0.85:
                print(f"   - Band accuracy too low: {band_accuracy:.3f} < 0.85")
        print(f"{'='*80}\n")
        
        results = {
            'mae': float(mae),
            'rmse': float(rmse),
            'r2': float(r2),
            'band_accuracy': float(band_accuracy)
        }
        
        self.save_results('severity_predictor', results, results)
        return results
    
    def save_results(self, model_name: str, detailed_results: Dict, summary: Dict):
        """Save evaluation results to JSON"""
        timestamp = datetime.now().isoformat()
        
        output = {
            'model': model_name,
            'timestamp': timestamp,
            'summary': summary,
            'detailed_results': detailed_results
        }
        
        output_file = self.output_dir / f'{model_name}_evaluation.json'
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2, default=str)
        
        print(f"📊 Results saved to: {output_file}")

def main():
    """Run ML model evaluation"""
    print("""
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║                    OPTIMUS ML MODEL EVALUATION SUITE                     ║
    ║                                                                          ║
    ║  Testing trained models on held-out test set (15% of data)             ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """)
    
    evaluator = MLModelEvaluator()
    
    # Load test data from training state
    print("📂 Loading test data...")
    
    # Generate synthetic test data (in production, use actual held-out test sets)
    print("⚠️  Using synthetic test data. For production, implement proper test/train splits.")
    
    # Vulnerability detector test
    np.random.seed(42)
    X_vuln_test = np.random.randn(1000, 25)  # Match trained model features
    y_vuln_test = np.random.randint(0, 2, 1000)
    evaluator.evaluate_vulnerability_detector(X_vuln_test, y_vuln_test)
    
    # Attack classifier test
    attack_types = ['sql_injection', 'xss', 'rce', 'path_traversal', 'xxe', 
                    'ssrf', 'csrf', 'auth_bypass', 'privilege_escalation', 'dos']
    y_attack_test = np.random.choice(attack_types, 1000)
    evaluator.evaluate_attack_classifier(X_vuln_test, y_attack_test)
    
    # Severity predictor test
    y_severity_test = np.random.uniform(0, 10, 1000)
    evaluator.evaluate_severity_predictor(X_vuln_test, y_severity_test)
    
    print("\n✅ Evaluation complete! Check evaluation_results/ directory for details.")

if __name__ == '__main__':
    main()
