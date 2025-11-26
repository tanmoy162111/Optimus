"""
Continuous Retraining Pipeline - Automatically retrain models with new production data
"""
import os
import sys
sys.path.append('..')

import json
import logging
try:
    import schedule
    SCHEDULING_AVAILABLE = True
except ImportError:
    SCHEDULING_AVAILABLE = False
    print("Warning: 'schedule' module not installed. Auto-scheduling disabled.")
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any
from pathlib import Path

from phase_specific_models import PhaseSpecificModelTrainer
from production_data_collector import ProductionDataCollector

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ContinuousRetrainingPipeline:
    """
    Automated pipeline for continuous model improvement
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._default_config()
        self.collector = ProductionDataCollector(
            data_dir=self.config['production_data_dir']
        )
        self.trainer = PhaseSpecificModelTrainer()
        
        self.last_retrain_time = {}
        self.retrain_history = []
        
        logger.info("Continuous retraining pipeline initialized")
    
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration"""
        return {
            'production_data_dir': 'data/production_logs',
            'training_data_dir': 'data/phase_training_logs',
            'models_dir': '../models',
            'backup_dir': 'models/backups',
            
            # Retraining triggers
            'min_new_samples': 50,  # Minimum new samples to trigger retrain
            'retrain_interval_hours': 24,  # Maximum time between retrains
            'min_accuracy_improvement': 0.02,  # 2% minimum improvement to deploy
            
            # Scheduling
            'auto_schedule': True,
            'schedule_time': '02:00',  # Run at 2 AM daily
            
            # Model validation
            'validation_split': 0.2,
            'min_samples_per_phase': 30,
        }
    
    def check_and_retrain(self, force: bool = False) -> Dict[str, Any]:
        """
        Check if retraining is needed and execute if conditions met
        
        Returns:
            Dict with retrain results
        """
        logger.info("="*80)
        logger.info("CHECKING RETRAINING CONDITIONS")
        logger.info("="*80)
        
        # Get production data stats
        stats = self.collector.get_collection_stats()
        logger.info(f"Production data collected: {stats['total_entries']} total entries")
        
        for phase, count in stats['by_phase'].items():
            logger.info(f"  {phase:20s}: {count:4d} samples")
        
        # Check if retrain needed
        retrain_needed = force or self._should_retrain(stats)
        
        if not retrain_needed:
            logger.info("Retraining not needed at this time")
            return {'retrained': False, 'reason': 'Conditions not met'}
        
        logger.info("\n\u2705 Retraining conditions met, starting pipeline...\n")
        
        # Execute retraining
        results = self._execute_retraining()
        
        # Log results
        self.retrain_history.append({
            'timestamp': datetime.now().isoformat(),
            'results': results
        })
        
        return results
    
    def _should_retrain(self, stats: Dict[str, Any]) -> bool:
        """Determine if retraining should be triggered"""
        
        # Check minimum samples threshold
        total_new = stats['total_entries']
        if total_new < self.config['min_new_samples']:
            logger.info(f"Not enough new samples: {total_new} < {self.config['min_new_samples']}")
            return False
        
        # Check time since last retrain
        last_retrain = max(self.last_retrain_time.values()) if self.last_retrain_time else None
        if last_retrain:
            hours_since = (datetime.now() - last_retrain).total_seconds() / 3600
            if hours_since < self.config['retrain_interval_hours']:
                logger.info(f"Too soon since last retrain: {hours_since:.1f}h < {self.config['retrain_interval_hours']}h")
                return False
        
        # Check per-phase minimums
        for phase, count in stats['by_phase'].items():
            if count > 0 and count < self.config['min_samples_per_phase']:
                logger.warning(f"Phase {phase} has {count} samples, minimum {self.config['min_samples_per_phase']}")
        
        return True
    
    def _execute_retraining(self) -> Dict[str, Any]:
        """Execute the complete retraining pipeline"""
        results = {
            'started_at': datetime.now().isoformat(),
            'phases_retrained': [],
            'models_improved': [],
            'models_deployed': [],
            'errors': []
        }
        
        try:
            # Step 1: Export production data to training format
            logger.info("Step 1: Exporting production data to training format...")
            exported = self.collector.export_training_data(
                output_dir=self.config['training_data_dir']
            )
            
            for phase, count in exported.items():
                logger.info(f"  Exported {count} samples for {phase}")
            
            # Step 2: Load combined training data (production + existing)
            logger.info("\nStep 2: Loading training data...")
            training_data = self._load_training_data()
            
            for phase, samples in training_data.items():
                logger.info(f"  {phase:20s}: {len(samples):4d} total samples")
            
            # Step 3: Backup existing models
            logger.info("\nStep 3: Backing up existing models...")
            self._backup_models()
            
            # Step 4: Train new models
            logger.info("\nStep 4: Training new models...")
            new_models = self.trainer.train_all_phase_models(training_data)
            
            # Step 5: Validate and compare
            logger.info("\nStep 5: Validating new models...")
            for phase, model_data in new_models.items():
                results['phases_retrained'].append(phase)
                
                new_accuracy = model_data['cv_accuracy']
                
                # Load old model accuracy
                old_accuracy = self._get_old_model_accuracy(phase)
                
                improvement = new_accuracy - old_accuracy if old_accuracy else new_accuracy
                
                logger.info(f"{phase:20s}: {old_accuracy:.1%} -> {new_accuracy:.1%} (Δ {improvement:+.1%})")
                
                # Decide whether to deploy
                if improvement >= self.config['min_accuracy_improvement'] or old_accuracy == 0:
                    results['models_improved'].append({
                        'phase': phase,
                        'old_accuracy': old_accuracy,
                        'new_accuracy': new_accuracy,
                        'improvement': improvement
                    })
                    
                    # Deploy new model
                    self._deploy_model(phase, model_data)
                    results['models_deployed'].append(phase)
                    logger.info(f"  \u2705 Deployed improved model for {phase}")
                else:
                    logger.info(f"  \u26a0\ufe0f  Improvement too small, keeping old model for {phase}")
            
            # Step 6: Update retrain timestamps
            for phase in results['phases_retrained']:
                self.last_retrain_time[phase] = datetime.now()
            
            results['completed_at'] = datetime.now().isoformat()
            results['success'] = True
            
            logger.info("\n" + "="*80)
            logger.info("RETRAINING COMPLETE")
            logger.info("="*80)
            logger.info(f"Models deployed: {', '.join(results['models_deployed'])}")
            
        except Exception as e:
            logger.error(f"Retraining failed: {e}")
            results['errors'].append(str(e))
            results['success'] = False
            import traceback
            traceback.print_exc()
        
        return results
    
    def _load_training_data(self) -> Dict[str, List[Dict]]:
        """Load all training data (production + synthetic)"""
        training_data = {}
        
        phases = ['reconnaissance', 'scanning', 'exploitation',
                  'post_exploitation', 'covering_tracks']
        
        for phase in phases:
            file_path = os.path.join(self.config['training_data_dir'], 
                                    f'{phase}_training_logs.json')
            
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        training_data[phase] = json.load(f)
                except Exception as e:
                    logger.warning(f"Error loading {phase} training data: {e}")
                    training_data[phase] = []
            else:
                training_data[phase] = []
        
        return training_data
    
    def _backup_models(self):
        """Backup existing models before retraining"""
        backup_dir = os.path.join(self.config['backup_dir'], 
                                 datetime.now().strftime('%Y%m%d_%H%M%S'))
        os.makedirs(backup_dir, exist_ok=True)
        
        models_dir = self.config['models_dir']
        
        for phase in ['reconnaissance', 'scanning', 'exploitation',
                     'post_exploitation', 'covering_tracks']:
            model_file = f'tool_recommender_{phase}.pkl'
            src = os.path.join(models_dir, model_file)
            dst = os.path.join(backup_dir, model_file)
            
            if os.path.exists(src):
                import shutil
                shutil.copy2(src, dst)
                logger.info(f"  Backed up {model_file}")
    
    def _get_old_model_accuracy(self, phase: str) -> float:
        """Get accuracy of existing model"""
        try:
            import joblib
            model_file = os.path.join(self.config['models_dir'], 
                                     f'tool_recommender_{phase}.pkl')
            
            if os.path.exists(model_file):
                model_data = joblib.load(model_file)
                return model_data.get('cv_accuracy', 0.0)
        except:
            pass
        
        return 0.0
    
    def _deploy_model(self, phase: str, model_data: Dict[str, Any]):
        """Deploy newly trained model"""
        import joblib
        
        model_file = os.path.join(self.config['models_dir'], 
                                 f'tool_recommender_{phase}.pkl')
        
        joblib.dump(model_data, model_file)
        logger.info(f"  Saved model to {model_file}")
    
    def start_scheduler(self):
        """Start automated retraining scheduler"""
        if not self.config['auto_schedule']:
            logger.info("Auto-scheduling disabled")
            return
        
        schedule_time = self.config['schedule_time']
        
        # Schedule daily retrain
        schedule.every().day.at(schedule_time).do(self.check_and_retrain)
        
        logger.info(f"\u2705 Scheduled daily retraining at {schedule_time}")
        logger.info("Starting scheduler loop (press Ctrl+C to stop)...")
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        except KeyboardInterrupt:
            logger.info("\nScheduler stopped")
    
    def get_retrain_history(self) -> List[Dict[str, Any]]:
        """Get history of retraining runs"""
        return self.retrain_history


def main():
    """Run continuous retraining pipeline"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Continuous Model Retraining')
    parser.add_argument('--force', action='store_true', 
                       help='Force retraining regardless of conditions')
    parser.add_argument('--schedule', action='store_true',
                       help='Start automated scheduler')
    parser.add_argument('--check-only', action='store_true',
                       help='Only check conditions without retraining')
    
    args = parser.parse_args()
    
    pipeline = ContinuousRetrainingPipeline()
    
    if args.schedule:
        # Start scheduler
        pipeline.start_scheduler()
    elif args.check_only:
        # Check conditions only
        stats = pipeline.collector.get_collection_stats()
        should_retrain = pipeline._should_retrain(stats)
        print(f"\nRetrain needed: {should_retrain}")
    else:
        # Single retrain run
        results = pipeline.check_and_retrain(force=args.force)
        
        if results['success']:
            print("\n\u2705 Retraining completed successfully")
            if results['models_deployed']:
                print(f"Deployed models: {', '.join(results['models_deployed'])}")
        else:
            print(f"\n\u274c Retraining failed: {results.get('errors', [])}")


if __name__ == '__main__':
    main()
