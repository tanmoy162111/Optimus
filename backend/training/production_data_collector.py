"""
Production Data Collector - Collects real scan data for continuous model improvement
"""
import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict
import threading

logger = logging.getLogger(__name__)

class ProductionDataCollector:
    """
    Collects tool execution data from production scans for model retraining
    """
    
    def __init__(self, data_dir: str = 'data/production_logs'):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        
        # In-memory buffer for batch writes
        self.buffer = defaultdict(list)
        self.buffer_size = 100
        self.lock = threading.Lock()
        
        # Separate logs by phase
        self.phase_files = {
            'reconnaissance': os.path.join(data_dir, 'reconnaissance_prod.jsonl'),
            'scanning': os.path.join(data_dir, 'scanning_prod.jsonl'),
            'exploitation': os.path.join(data_dir, 'exploitation_prod.jsonl'),
            'post_exploitation': os.path.join(data_dir, 'post_exploitation_prod.jsonl'),
            'covering_tracks': os.path.join(data_dir, 'covering_tracks_prod.jsonl')
        }
        
        logger.info(f"Production data collector initialized: {data_dir}")
    
    def log_tool_execution(self, execution_data: Dict[str, Any]):
        """
        Log a tool execution event
        
        Args:
            execution_data: {
                'scan_id': str,
                'phase': str,
                'tool': str,
                'target': str,
                'context': Dict,  # Scan state before execution
                'result': Dict,   # Execution result
                'timestamp': str,
                'success': bool,
                'vulns_found': int,
                'execution_time': float
            }
        """
        try:
            phase = execution_data.get('phase', 'unknown')
            
            # Validate required fields
            required = ['scan_id', 'phase', 'tool', 'context']
            if not all(field in execution_data for field in required):
                logger.error(f"Missing required fields in execution_data: {required}")
                return
            
            # Add metadata
            log_entry = {
                **execution_data,
                'logged_at': datetime.now().isoformat(),
                'version': '1.0'
            }
            
            # Add to buffer
            with self.lock:
                self.buffer[phase].append(log_entry)
                
                # Flush if buffer full
                if len(self.buffer[phase]) >= self.buffer_size:
                    self._flush_buffer(phase)
            
            logger.debug(f"Logged tool execution: {execution_data['tool']} in {phase}")
            
        except Exception as e:
            logger.error(f"Error logging tool execution: {e}")
    
    def log_phase_transition(self, scan_id: str, from_phase: str, to_phase: str,
                           metrics: Dict[str, Any]):
        """
        Log phase transition with metrics
        
        Args:
            metrics: {
                'tools_executed': List[str],
                'vulns_found': int,
                'time_in_phase': float,
                'coverage': float,
                'success_rate': float
            }
        """
        try:
            log_entry = {
                'scan_id': scan_id,
                'event_type': 'phase_transition',
                'from_phase': from_phase,
                'to_phase': to_phase,
                'metrics': metrics,
                'timestamp': datetime.now().isoformat()
            }
            
            # Save to transitions file
            transitions_file = os.path.join(self.data_dir, 'phase_transitions.jsonl')
            with open(transitions_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            logger.info(f"Logged phase transition: {from_phase} -> {to_phase}")
            
        except Exception as e:
            logger.error(f"Error logging phase transition: {e}")
    
    def log_scan_complete(self, scan_id: str, scan_summary: Dict[str, Any]):
        """
        Log scan completion summary
        
        Args:
            scan_summary: {
                'total_time': float,
                'phases_completed': List[str],
                'total_vulns': int,
                'total_tools': int,
                'highest_severity': float,
                'tool_effectiveness': Dict[str, Dict]
            }
        """
        try:
            log_entry = {
                'scan_id': scan_id,
                'event_type': 'scan_complete',
                'summary': scan_summary,
                'timestamp': datetime.now().isoformat()
            }
            
            # Save to completions file
            completions_file = os.path.join(self.data_dir, 'scan_completions.jsonl')
            with open(completions_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            logger.info(f"Logged scan completion: {scan_id}")
            
        except Exception as e:
            logger.error(f"Error logging scan completion: {e}")
    
    def _flush_buffer(self, phase: str):
        """Flush buffer to disk"""
        try:
            if phase not in self.buffer or not self.buffer[phase]:
                return
            
            file_path = self.phase_files.get(phase)
            if not file_path:
                logger.error(f"Unknown phase: {phase}")
                return
            
            # Write buffered entries
            with open(file_path, 'a') as f:
                for entry in self.buffer[phase]:
                    f.write(json.dumps(entry) + '\n')
            
            count = len(self.buffer[phase])
            self.buffer[phase].clear()
            
            logger.info(f"Flushed {count} entries to {file_path}")
            
        except Exception as e:
            logger.error(f"Error flushing buffer for {phase}: {e}")
    
    def flush_all(self):
        """Flush all buffers to disk"""
        with self.lock:
            for phase in self.buffer.keys():
                self._flush_buffer(phase)
        
        logger.info("Flushed all buffers")
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics about collected data"""
        stats = {
            'total_entries': 0,
            'by_phase': {},
            'buffer_status': {}
        }
        
        # Count entries in files
        for phase, file_path in self.phase_files.items():
            count = 0
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    count = sum(1 for _ in f)
            
            stats['by_phase'][phase] = count
            stats['total_entries'] += count
        
        # Buffer status
        with self.lock:
            for phase, entries in self.buffer.items():
                stats['buffer_status'][phase] = len(entries)
        
        return stats
    
    def export_training_data(self, output_dir: str = 'data/phase_training_logs') -> Dict[str, int]:
        """
        Export production data to training format
        
        Returns:
            Dict mapping phase to number of samples exported
        """
        os.makedirs(output_dir, exist_ok=True)
        exported = {}
        
        for phase, file_path in self.phase_files.items():
            if not os.path.exists(file_path):
                exported[phase] = 0
                continue
            
            # Read production logs
            training_samples = []
            with open(file_path, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        
                        # Convert to training format
                        training_sample = {
                            'context': entry.get('context', {}),
                            'tool': entry.get('tool'),
                            'success': entry.get('success', False),
                            'vulns_found': entry.get('vulns_found', 0),
                            'execution_time': entry.get('execution_time', 0)
                        }
                        
                        training_samples.append(training_sample)
                        
                    except json.JSONDecodeError:
                        continue
            
            # Save training data
            if training_samples:
                output_file = os.path.join(output_dir, f'{phase}_training_logs.json')
                
                # Load existing training data
                existing = []
                if os.path.exists(output_file):
                    try:
                        with open(output_file, 'r') as f:
                            existing = json.load(f)
                    except:
                        existing = []
                
                # Merge and save
                combined = existing + training_samples
                with open(output_file, 'w') as f:
                    json.dump(combined, f, indent=2)
                
                exported[phase] = len(training_samples)
                logger.info(f"Exported {len(training_samples)} training samples for {phase}")
            else:
                exported[phase] = 0
        
        return exported


# Global collector instance
_collector = None

def get_collector() -> ProductionDataCollector:
    """Get global collector instance"""
    global _collector
    if _collector is None:
        _collector = ProductionDataCollector()
    return _collector
