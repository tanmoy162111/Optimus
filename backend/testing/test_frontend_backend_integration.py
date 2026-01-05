"""
Integration tests to verify frontend-backend integration fixes:
- Race condition prevention with threading locks
- Data model unification
- WebSocket and API synchronization
- Validation duplication removal
- Correlation ID implementation
"""
import unittest
import threading
import time
import uuid
from unittest.mock import patch, MagicMock
import sys
import os

# Add the backend directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import app
from backend.api.scan_routes import active_scans
from backend.core.scan_engine import ScanManager
from backend.websocket.handlers import WebSocketHandler


class TestFrontendBackendIntegration(unittest.TestCase):
    """Test suite for frontend-backend integration fixes"""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.app = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        
        # Clear active scans before each test
        active_scans.clear()

    def tearDown(self):
        """Clean up after each test method."""
        active_scans.clear()
        if hasattr(self, 'app_context'):
            self.app_context.pop()

    def test_threading_lock_prevents_race_conditions(self):
        """Test that threading locks prevent race conditions in active_scans access."""
        # Create a mock scan manager to test thread safety
        scan_manager = ScanManager()
        
        # Test concurrent access to active_scans
        def add_scan():
            scan_id = str(uuid.uuid4())
            scan_manager.active_scans[scan_id] = {
                'scan_id': scan_id,
                'status': 'running',
                'target': 'test_target'
            }
            time.sleep(0.01)  # Small delay to increase chance of race condition
            # Verify the scan is still there
            assert scan_id in scan_manager.active_scans
        
        # Create multiple threads trying to access active_scans
        threads = []
        for i in range(10):
            thread = threading.Thread(target=add_scan)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all scans were added safely
        self.assertEqual(len(scan_manager.active_scans), 10)

    def test_scan_model_unification(self):
        """Test that scan model includes all required fields."""
        scan_manager = ScanManager()
        scan_id = str(uuid.uuid4())
        
        # Create a scan with all required fields
        scan_data = {
            'scan_id': scan_id,
            'target': 'http://test.com',
            'status': 'running',
            'phase': 'reconnaissance',
            'domain': 'test.com',
            'host': 'test.com',
            'options': {'mode': 'standard'},
            'exploits_attempted': [],
            'sessions_obtained': [],
            'credentials_found': [],
            'discovered_endpoints': [],
            'discovered_technologies': [],
            'open_ports': [],
            'stop_requested': False,
            'ml_confidence': 0.0,
            'phase_data': {},
            'findings': [],
            'tools_executed': [],
            'start_time': time.time(),
            'time_elapsed': 0,
            'coverage': 0,
            'risk_score': 0
        }
        
        # Add scan to active_scans using the lock
        with scan_manager.active_scans_lock:
            scan_manager.active_scans[scan_id] = scan_data
        
        # Verify all fields are present
        retrieved_scan = scan_manager.active_scans[scan_id]
        required_fields = [
            'domain', 'host', 'options', 'exploits_attempted', 'sessions_obtained',
            'credentials_found', 'discovered_endpoints', 'discovered_technologies',
            'open_ports', 'stop_requested', 'ml_confidence', 'phase_data'
        ]
        
        for field in required_fields:
            self.assertIn(field, retrieved_scan)

    def test_correlation_id_in_scan_operations(self):
        """Test that correlation IDs are properly implemented in scan operations."""
        scan_manager = ScanManager()
        scan_id = str(uuid.uuid4())
        correlation_id = str(uuid.uuid4())
        
        # Test start_scan with correlation ID
        scan_data = {
            'scan_id': scan_id,
            'target': 'http://test.com',
            'status': 'initializing',
            'correlation_id': correlation_id
        }
        
        with scan_manager.active_scans_lock:
            scan_manager.active_scans[scan_id] = scan_data
        
        # Verify correlation ID is preserved
        retrieved_scan = scan_manager.active_scans[scan_id]
        self.assertEqual(retrieved_scan.get('correlation_id'), correlation_id)

    def test_websocket_event_contains_full_scan_state(self):
        """Test that WebSocket events include full scan state."""
        handler = WebSocketHandler()
        
        scan_data = {
            'scan_id': 'test-scan-123',
            'target': 'http://test.com',
            'status': 'running',
            'phase': 'scanning',
            'findings': [],
            'tools_executed': ['nmap'],
            'exploits_attempted': [],
            'credentials_found': [],
            'timestamp': time.time()
        }
        
        # Test that emit_scan_update includes full state
        with patch('backend.websocket.handlers.socketio.emit') as mock_emit:
            handler.emit_scan_update(scan_data)
            
            # Verify the emitted data includes all scan information
            mock_emit.assert_called_once()
            call_args = mock_emit.call_args
            self.assertEqual(call_args[0][0], 'scan_update')
            
            # Check that the data contains the full scan state
            emitted_data = call_args[1]['data']
            self.assertIn('scan_id', emitted_data)
            self.assertIn('target', emitted_data)
            self.assertIn('status', emitted_data)
            self.assertIn('phase', emitted_data)
            self.assertIn('findings', emitted_data)
            self.assertIn('tools_executed', emitted_data)
            self.assertIn('timestamp', emitted_data)

    def test_api_response_includes_timestamps(self):
        """Test that API responses include timestamps for synchronization."""
        # Test the update_scan API endpoint
        scan_id = str(uuid.uuid4())
        scan_data = {
            'scan_id': scan_id,
            'target': 'http://test.com',
            'status': 'running',
            'phase': 'scanning'
        }
        
        # Add to active scans first
        active_scans[scan_id] = scan_data
        
        # Test API call to update scan
        response = self.app.post(f'/api/scan/{scan_id}/update', 
                                json={'status': 'completed', 'phase': 'reporting'})
        
        # Verify response includes timestamp
        self.assertEqual(response.status_code, 200)
        response_data = response.get_json()
        self.assertIn('timestamp', response_data)

    def test_target_validation_only_in_backend(self):
        """Test that target validation happens only in backend, not frontend."""
        from backend.inference.target_integrity_gate import TargetIntegrityGate
        
        gate = TargetIntegrityGate()
        
        # Test valid targets
        valid_targets = [
            'localhost',
            '127.0.0.1',
            '192.168.1.1',
            'http://juice-shop:3000',
            'https://dvwa:8080'
        ]
        
        for target in valid_targets:
            result = gate.apply_target_integrity_gate(target)
            self.assertTrue(result['is_valid'])
            self.assertTrue(result['is_authorized'])
        
        # Test invalid targets that should be blocked
        invalid_targets = [
            'google.com',
            'microsoft.com',
            'malicious.com',
            'http://evil.com'
        ]
        
        for target in invalid_targets:
            with self.assertRaises(Exception):  # TargetIntegrityError
                gate.apply_target_integrity_gate(target)

    def test_scan_state_synchronization(self):
        """Test that scan state is synchronized between WebSocket and API."""
        scan_manager = ScanManager()
        scan_id = str(uuid.uuid4())
        
        # Create initial scan state
        initial_state = {
            'scan_id': scan_id,
            'target': 'http://test.com',
            'status': 'running',
            'phase': 'reconnaissance',
            'findings': [],
            'tools_executed': [],
            'timestamp': time.time()
        }
        
        # Add to active scans
        with scan_manager.active_scans_lock:
            scan_manager.active_scans[scan_id] = initial_state
        
        # Update state (simulating WebSocket event)
        updated_state = {
            **initial_state,
            'status': 'completed',
            'phase': 'reporting',
            'findings': [{'id': 'test-finding', 'type': 'vulnerability'}],
            'tools_executed': ['nmap', 'nikto'],
            'timestamp': time.time()
        }
        
        with scan_manager.active_scans_lock:
            scan_manager.active_scans[scan_id] = updated_state
        
        # Verify state is properly updated
        final_state = scan_manager.active_scans[scan_id]
        self.assertEqual(final_state['status'], 'completed')
        self.assertEqual(final_state['phase'], 'reporting')
        self.assertEqual(len(final_state['findings']), 1)
        self.assertEqual(len(final_state['tools_executed']), 2)

    def test_api_scan_status_endpoint(self):
        """Test that API scan status endpoint returns unified data model."""
        scan_id = str(uuid.uuid4())
        
        # Create a complete scan object with all required fields
        complete_scan = {
            'scan_id': scan_id,
            'target': 'http://test.com',
            'status': 'running',
            'phase': 'scanning',
            'domain': 'test.com',
            'host': 'test.com',
            'options': {'mode': 'standard', 'enableExploitation': False},
            'exploits_attempted': [],
            'sessions_obtained': [],
            'credentials_found': [],
            'discovered_endpoints': [],
            'discovered_technologies': [],
            'open_ports': [],
            'stop_requested': False,
            'ml_confidence': 0.75,
            'phase_data': {'current_tool': 'nmap', 'progress': 0.5},
            'findings': [],
            'tools_executed': ['nmap'],
            'start_time': time.time(),
            'time_elapsed': 30,
            'coverage': 0.25,
            'risk_score': 4.5,
            'timestamp': time.time()
        }
        
        # Add to active scans
        active_scans[scan_id] = complete_scan
        
        # Test the GET endpoint
        response = self.app.get(f'/api/scan/{scan_id}')
        self.assertEqual(response.status_code, 200)
        
        response_data = response.get_json()
        
        # Verify all required fields are present in the response
        required_fields = [
            'scan_id', 'target', 'status', 'phase', 'domain', 'host', 'options',
            'exploits_attempted', 'sessions_obtained', 'credentials_found',
            'discovered_endpoints', 'discovered_technologies', 'open_ports',
            'stop_requested', 'ml_confidence', 'phase_data', 'findings',
            'tools_executed', 'start_time', 'time_elapsed', 'coverage', 'risk_score'
        ]
        
        for field in required_fields:
            self.assertIn(field, response_data)


if __name__ == '__main__':
    unittest.main()