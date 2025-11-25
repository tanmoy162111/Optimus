"""
Test ML Model Training
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from training.model_trainer import SecurityMLTrainer
from training.feature_extractor import DatasetFeatureExtractor
import numpy as np

def generate_synthetic_data():
    """Generate synthetic training data for testing"""
    print("\n[Generating] Synthetic training data...")
    
    extractor = DatasetFeatureExtractor()
    
    # SQL Injection examples
    sql_payloads = [
        "admin' OR '1'='1'--",
        "1' UNION SELECT null, null--",
        "'; DROP TABLE users--",
        "1' AND '1'='1",
        "admin'--",
        "' OR 1=1--",
        "1' UNION ALL SELECT null--",
    ]
    
    # XSS examples
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
    ]
    
    # Benign examples
    benign_payloads = [
        "admin",
        "user123",
        "search query",
        "normal text",
        "hello world",
        "test",
        "example",
    ]
    
    training_examples = []
    
    # Add malicious SQL examples
    for payload in sql_payloads:
        features = extractor.extract_http_features(payload)
        training_examples.append({
            'features': features,
            'label': 1,
            'attack_type': 'sql_injection',
            'severity': np.random.uniform(7.0, 10.0),
            'exploitable': True,
            'confidence': np.random.uniform(0.8, 1.0),
            'evidence': payload,
            'impact_score': 8.0,
            'ease_of_exploit': 7.0
        })
    
    # Add malicious XSS examples
    for payload in xss_payloads:
        features = extractor.extract_http_features(payload)
        training_examples.append({
            'features': features,
            'label': 1,
            'attack_type': 'xss',
            'severity': np.random.uniform(6.0, 8.5),
            'exploitable': True,
            'confidence': np.random.uniform(0.8, 1.0),
            'evidence': payload,
            'impact_score': 7.0,
            'ease_of_exploit': 6.0
        })
    
    # Add benign examples
    for payload in benign_payloads:
        features = extractor.extract_http_features(payload)
        training_examples.append({
            'features': features,
            'label': 0,
            'attack_type': 'none',
            'severity': 0.0,
            'exploitable': False,
            'confidence': np.random.uniform(0.8, 1.0),
            'evidence': payload,
            'impact_score': 0.0,
            'ease_of_exploit': 0.0
        })
    
    # Duplicate data to have more samples
    training_examples = training_examples * 10
    
    print(f"  ✓ Generated {len(training_examples)} training examples")
    print(f"    - Malicious: {sum(1 for ex in training_examples if ex['label'] == 1)}")
    print(f"    - Benign: {sum(1 for ex in training_examples if ex['label'] == 0)}")
    
    return training_examples

def test_ml_training():
    """Test ML model training"""
    print("\n" + "="*70)
    print("TESTING ML MODEL TRAINING")
    print("="*70)
    
    # Generate data
    training_data = generate_synthetic_data()
    
    # Initialize trainer
    trainer = SecurityMLTrainer()
    
    # Test 1: Vulnerability Detector
    print("\n[Test 1] Training Vulnerability Detector...")
    try:
        vuln_model = trainer.train_vulnerability_detector(training_data)
        assert vuln_model['metrics']['f1'] > 0.7, f"F1 score too low: {vuln_model['metrics']['f1']}"
        print(f"  ✓ Test passed - F1: {vuln_model['metrics']['f1']:.3f}")
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        return False
    
    # Test 2: Attack Classifier
    print("\n[Test 2] Training Attack Classifier...")
    try:
        attack_model = trainer.train_attack_classifier(training_data)
        assert attack_model['metrics']['f1'] > 0.6, f"F1 score too low: {attack_model['metrics']['f1']}"
        print(f"  ✓ Test passed - F1: {attack_model['metrics']['f1']:.3f}")
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        return False
    
    # Test 3: Severity Predictor
    print("\n[Test 3] Training Severity Predictor...")
    try:
        severity_data = [ex for ex in training_data if ex['label'] == 1]  # Only malicious
        severity_model = trainer.train_severity_predictor(severity_data)
        assert severity_model['metrics']['r2'] > 0.3, f"R² too low: {severity_model['metrics']['r2']}"
        print(f"  ✓ Test passed - R²: {severity_model['metrics']['r2']:.3f}")
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        return False
    
    # Test 4: Save and load model
    print("\n[Test 4] Testing Model Persistence...")
    try:
        # Save
        model_path = trainer.save_model(vuln_model, 'test_vuln_detector', './models')
        
        # Load
        loaded_model = trainer.load_model('test_vuln_detector', './models')
        
        assert 'model' in loaded_model
        assert 'metrics' in loaded_model
        print(f"  ✓ Test passed - Model saved and loaded successfully")
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        return False
    
    # Test 5: Prediction
    print("\n[Test 5] Testing Prediction...")
    try:
        # Create test payload
        extractor = DatasetFeatureExtractor()
        test_payload = "' OR 1=1--"
        test_features = extractor.extract_http_features(test_payload)
        
        # Predict
        test_X = trainer.scaler.transform([list(test_features.values())])
        prediction = vuln_model['model'].predict(test_X)[0]
        probability = vuln_model['model'].predict_proba(test_X)[0]
        
        print(f"  Test payload: {test_payload}")
        print(f"  Prediction: {'MALICIOUS' if prediction == 1 else 'BENIGN'}")
        print(f"  Confidence: {probability[1]:.3f}")
        print(f"  ✓ Test passed - Prediction works")
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n" + "="*70)
    print("ALL ML TRAINING TESTS PASSED ✓")
    print("="*70)
    
    return True

if __name__ == "__main__":
    try:
        success = test_ml_training()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ ML training test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
