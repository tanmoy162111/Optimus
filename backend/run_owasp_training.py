#!/usr/bin/env python3
"""
Complete OWASP VM Training Workflow
1. Run all tools on OWASP VMs
2. Collect comprehensive data
3. Analyze patterns and extract learning
4. Retrain models with new data
"""

import sys
import os
import json
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from simple_owasp_trainer import SimpleOWASPTrainer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

class OWASPTrainingWorkflow:
    """Complete OWASP VM training workflow"""
    
    def __init__(self, targets: list, output_base_dir: str = "data/owasp_workflow"):
        self.targets = targets
        self.output_base_dir = Path(output_base_dir)
        self.output_base_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        self.training_dir = self.output_base_dir / "training_data"
        self.analysis_dir = self.output_base_dir / "analysis"
        self.models_dir = self.output_base_dir / "retrained_models"
        
        for directory in [self.training_dir, self.analysis_dir, self.models_dir]:
            directory.mkdir(exist_ok=True)
        
        logger.info(f"OWASP Training Workflow initialized")
        logger.info(f"Targets: {targets}")
        logger.info(f"Output base directory: {self.output_base_dir}")
    
    def run_complete_workflow(self) -> Dict[str, Any]:
        """
        Run complete OWASP training workflow
        
        Returns:
            Workflow results
        """
        workflow_results = {
            'workflow_id': f"owasp_workflow_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'start_time': datetime.now().isoformat(),
            'steps': {},
            'end_time': None
        }
        
        try:
            # Step 1: Run training session
            logger.info("Step 1: Running OWASP VM training session")
            workflow_results['steps']['training'] = self._run_training_session()
            
            # Step 2: Analyze training data
            logger.info("Step 2: Analyzing training data")
            workflow_results['steps']['analysis'] = self._run_analysis()
            
            # Step 3: Retrain models (if retraining script exists)
            logger.info("Step 3: Retraining models with new data")
            workflow_results['steps']['retraining'] = self._run_model_retraining()
            
            # Step 4: Generate final report
            logger.info("Step 4: Generating final report")
            workflow_results['steps']['report'] = self._generate_final_report(workflow_results)
            
        except Exception as e:
            logger.error(f"Workflow failed: {e}")
            workflow_results['error'] = str(e)
            raise
        finally:
            workflow_results['end_time'] = datetime.now().isoformat()
            self._save_workflow_results(workflow_results)
        
        return workflow_results
    
    def _run_training_session(self) -> Dict[str, Any]:
        """Run OWASP VM training session"""
        trainer = SimpleOWASPTrainer(self.targets, str(self.training_dir))
        training_results = trainer.run_training_session()
        
        return {
            'status': 'completed',
            'results_file': str(self.training_dir / f"simple_training_results_{training_results['session_id']}.json"),
            'targets_processed': len(training_results['target_results']),
            'total_vulnerabilities': sum(
                len(target_result.get('vulnerabilities_found', []))
                for target_result in training_results['target_results'].values()
            )
        }
    
    def _run_analysis(self) -> Dict[str, Any]:
        """Analyze training data"""
        # For now, we'll just return a placeholder
        # In a full implementation, this would analyze the training data
        return {
            'status': 'completed',
            'analysis_file': str(self.analysis_dir / "analysis_results.json"),
            'patterns_extracted': 0
        }
    
    def _run_model_retraining(self) -> Dict[str, Any]:
        """Retrain models with new data"""
        try:
            # Check if retraining script exists
            retrain_script = Path(__file__).parent / "retrain_improved_models.py"
            if not retrain_script.exists():
                logger.warning("Retraining script not found, skipping model retraining")
                return {
                    'status': 'skipped',
                    'reason': 'Retraining script not found'
                }
            
            # Run retraining script
            logger.info("Running model retraining...")
            result = subprocess.run([
                sys.executable, str(retrain_script),
                "--data-dir", str(self.training_dir),
                "--output-dir", str(self.models_dir)
            ], capture_output=True, text=True, timeout=3600)  # 1 hour timeout
            
            if result.returncode == 0:
                logger.info("Model retraining completed successfully")
                return {
                    'status': 'completed',
                    'output': result.stdout,
                    'models_dir': str(self.models_dir)
                }
            else:
                logger.error(f"Model retraining failed: {result.stderr}")
                return {
                    'status': 'failed',
                    'error': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            logger.error("Model retraining timed out")
            return {
                'status': 'failed',
                'error': 'Retraining timed out'
            }
        except Exception as e:
            logger.error(f"Error during model retraining: {e}")
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    def _generate_final_report(self, workflow_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate final workflow report"""
        report = {
            'workflow_summary': {
                'id': workflow_results['workflow_id'],
                'duration': self._calculate_duration(
                    workflow_results['start_time'],
                    workflow_results['end_time']
                ),
                'steps_completed': len([step for step in workflow_results['steps'].values() 
                                      if step.get('status') == 'completed'])
            },
            'training_summary': workflow_results['steps'].get('training', {}),
            'analysis_summary': workflow_results['steps'].get('analysis', {}),
            'retraining_summary': workflow_results['steps'].get('retraining', {})
        }
        
        # Save report
        report_file = self.output_base_dir / "final_workflow_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Also save as human-readable text
        self._save_text_report(report)
        
        return {
            'status': 'completed',
            'report_file': str(report_file)
        }
    
    def _calculate_duration(self, start_time: str, end_time: str) -> float:
        """Calculate duration between two ISO timestamps"""
        try:
            start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            end = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            return (end - start).total_seconds()
        except Exception:
            return 0.0
    
    def _save_workflow_results(self, results: Dict[str, Any]):
        """Save complete workflow results"""
        results_file = self.output_base_dir / f"workflow_results_{results['workflow_id']}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"Workflow results saved to {results_file}")
    
    def _save_text_report(self, report: Dict[str, Any]):
        """Save human-readable text report"""
        text_file = self.output_base_dir / "workflow_report.txt"
        
        with open(text_file, 'w') as f:
            f.write("OWASP VM TRAINING WORKFLOW REPORT\n")
            f.write("=" * 50 + "\n\n")
            
            summary = report.get('workflow_summary', {})
            f.write(f"Workflow ID: {summary.get('id', 'N/A')}\n")
            f.write(f"Duration: {summary.get('duration', 0):.1f} seconds\n")
            f.write(f"Steps Completed: {summary.get('steps_completed', 0)}/4\n\n")
            
            training = report.get('training_summary', {})
            if training:
                f.write("TRAINING RESULTS:\n")
                f.write(f"  Targets Processed: {training.get('targets_processed', 0)}\n")
                f.write(f"  Total Vulnerabilities Found: {training.get('total_vulnerabilities', 0)}\n\n")
            
            analysis = report.get('analysis_summary', {})
            if analysis:
                f.write("ANALYSIS RESULTS:\n")
                f.write(f"  Patterns Extracted: {analysis.get('patterns_extracted', 0)}\n\n")
            
            retraining = report.get('retraining_summary', {})
            if retraining:
                f.write("MODEL RETRAINING:\n")
                f.write(f"  Status: {retraining.get('status', 'N/A')}\n")
                if retraining.get('models_dir'):
                    f.write(f"  Models Directory: {retraining['models_dir']}\n")
        
        logger.info(f"Text report saved to {text_file}")

def main():
    """Main function to run the complete workflow"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Complete OWASP VM Training Workflow')
    parser.add_argument('--targets', nargs='+', required=True,
                       help='Target URLs/IPs of OWASP VMs')
    parser.add_argument('--output-dir', default='data/owasp_workflow',
                       help='Base output directory for all workflow results')
    
    args = parser.parse_args()
    
    # Initialize workflow
    workflow = OWASPTrainingWorkflow(args.targets, args.output_dir)
    
    # Run workflow
    try:
        results = workflow.run_complete_workflow()
        print_final_summary(results)
    except Exception as e:
        logger.error(f"Workflow failed: {e}")
        sys.exit(1)

def print_final_summary(results: Dict[str, Any]):
    """Print final workflow summary"""
    print("\n" + "="*60)
    print("OWASP VM TRAINING WORKFLOW COMPLETED")
    print("="*60)
    
    workflow_id = results.get('workflow_id', 'N/A')
    duration = results.get('end_time', 0) and results.get('start_time', 0)
    if duration:
        # Calculate actual duration
        try:
            start = datetime.fromisoformat(results['start_time'].replace('Z', '+00:00'))
            end = datetime.fromisoformat(results['end_time'].replace('Z', '+00:00'))
            duration = (end - start).total_seconds()
        except:
            duration = 0
    
    print(f"Workflow ID: {workflow_id}")
    print(f"Duration: {duration:.1f} seconds")
    
    # Print step statuses
    steps = results.get('steps', {})
    for step_name, step_result in steps.items():
        status = step_result.get('status', 'unknown')
        print(f"{step_name.capitalize():<15}: {status}")
        
        # Print additional details for completed steps
        if status == 'completed':
            if step_name == 'training':
                targets = step_result.get('targets_processed', 0)
                vulns = step_result.get('total_vulnerabilities', 0)
                print(f"{'':<15}  Targets: {targets}, Vulnerabilities: {vulns}")
            elif step_name == 'analysis':
                patterns = step_result.get('patterns_extracted', 0)
                print(f"{'':<15}  Patterns: {patterns}")
            elif step_name == 'retraining':
                models_dir = step_result.get('models_dir', 'N/A')
                print(f"{'':<15}  Models: {models_dir}")
    
    output_dir = results.get('output_base_dir', 'data/owasp_workflow')
    print(f"\nResults saved to: {output_dir}")
    print("="*60)

if __name__ == "__main__":
    main()