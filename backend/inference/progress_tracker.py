"""
Scan Progress Estimation and ETA Calculator

Provides accurate progress tracking and time estimation for penetration tests.

Features:
- Phase-based progress tracking
- Dynamic ETA calculation
- Historical data for better estimates
- Real-time progress updates via WebSocket
- Tool execution time prediction

Usage:
    progress = ScanProgressTracker(scan_id, target, socketio)
    progress.start_scan()
    
    # During scan
    progress.start_phase("reconnaissance")
    progress.start_tool("nmap")
    progress.complete_tool("nmap", findings_count=5)
    progress.complete_phase("reconnaissance")
    
    # Get status
    status = progress.get_status()
    print(f"Progress: {status['progress']}%")
    print(f"ETA: {status['eta_formatted']}")
"""

import time
import json
import logging
import threading
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class ScanPhase(Enum):
    """Scan phases with expected durations"""
    INITIALIZATION = "initialization"
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


@dataclass
class PhaseMetrics:
    """Metrics for a scan phase"""
    name: str
    weight: float  # Percentage of total scan (0-100)
    expected_duration: int  # Expected seconds
    min_tools: int
    max_tools: int
    
    # Runtime data
    actual_duration: float = 0
    tools_executed: int = 0
    findings_count: int = 0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    status: str = "pending"  # pending, running, completed, skipped


@dataclass
class ToolMetrics:
    """Metrics for a tool execution"""
    name: str
    phase: str
    expected_duration: int  # Expected seconds
    
    # Runtime data
    actual_duration: float = 0
    findings_count: int = 0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    status: str = "pending"


# Default phase configurations
DEFAULT_PHASE_CONFIGS = {
    ScanPhase.INITIALIZATION: PhaseMetrics(
        name="initialization",
        weight=2,
        expected_duration=10,
        min_tools=0,
        max_tools=2,
    ),
    ScanPhase.RECONNAISSANCE: PhaseMetrics(
        name="reconnaissance",
        weight=20,
        expected_duration=180,  # 3 minutes
        min_tools=5,
        max_tools=15,
    ),
    ScanPhase.ENUMERATION: PhaseMetrics(
        name="enumeration",
        weight=20,
        expected_duration=240,  # 4 minutes
        min_tools=5,
        max_tools=20,
    ),
    ScanPhase.VULNERABILITY_SCAN: PhaseMetrics(
        name="vulnerability_scan",
        weight=30,
        expected_duration=360,  # 6 minutes
        min_tools=8,
        max_tools=25,
    ),
    ScanPhase.EXPLOITATION: PhaseMetrics(
        name="exploitation",
        weight=20,
        expected_duration=180,  # 3 minutes
        min_tools=3,
        max_tools=15,
    ),
    ScanPhase.POST_EXPLOITATION: PhaseMetrics(
        name="post_exploitation",
        weight=5,
        expected_duration=60,  # 1 minute
        min_tools=2,
        max_tools=10,
    ),
    ScanPhase.REPORTING: PhaseMetrics(
        name="reporting",
        weight=3,
        expected_duration=15,
        min_tools=0,
        max_tools=1,
    ),
}

# Average tool execution times (seconds)
TOOL_EXPECTED_DURATIONS = {
    # Fast tools (< 30s)
    'curl': 5,
    'whatweb': 10,
    'wafw00f': 10,
    'dig': 5,
    'whois': 5,
    'ping': 5,
    
    # Medium tools (30s - 2min)
    'nmap': 60,
    'masscan': 30,
    'nuclei': 90,
    'nikto': 120,
    'sslscan': 20,
    'testssl': 45,
    'enum4linux': 60,
    'smbmap': 30,
    'ldapsearch': 20,
    
    # Slow tools (2-5min)
    'gobuster': 180,
    'ffuf': 150,
    'dirb': 200,
    'dirsearch': 150,
    'wpscan': 180,
    'droopescan': 120,
    'joomscan': 120,
    'xsstrike': 120,
    
    # Very slow tools (5min+)
    'sqlmap': 300,
    'commix': 240,
    'hydra': 600,
    'medusa': 600,
    'metasploit': 180,
    
    # Default
    'default': 60,
}


class ScanProgressTracker:
    """
    Tracks scan progress and estimates completion time.
    
    Features:
    - Real-time progress calculation
    - Dynamic ETA based on actual performance
    - WebSocket progress updates
    - Historical learning for better estimates
    """
    
    def __init__(
        self,
        scan_id: str,
        target: str,
        socketio=None,
        history_file: str = None
    ):
        self.scan_id = scan_id
        self.target = target
        self.socketio = socketio
        self.history_file = history_file or str(
            Path(__file__).parent.parent / "data" / "scan_history.json"
        )
        
        # Initialize phase metrics
        self.phases: Dict[str, PhaseMetrics] = {
            phase.value: PhaseMetrics(
                name=config.name,
                weight=config.weight,
                expected_duration=config.expected_duration,
                min_tools=config.min_tools,
                max_tools=config.max_tools,
            )
            for phase, config in DEFAULT_PHASE_CONFIGS.items()
        }
        
        # Current state
        self.current_phase: Optional[str] = None
        self.current_tool: Optional[str] = None
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        
        # Tool tracking
        self.tools_executed: List[ToolMetrics] = []
        self.current_tool_metrics: Optional[ToolMetrics] = None
        
        # Statistics
        self.total_findings: int = 0
        self.total_tools: int = 0
        
        # ETA calculation
        self._eta_samples: List[float] = []
        self._last_progress: float = 0
        self._last_progress_time: float = 0
        
        # Update thread
        self._update_thread: Optional[threading.Thread] = None
        self._stop_updates = threading.Event()
        
        # Load historical data
        self._load_history()
    
    def _load_history(self):
        """Load historical scan data for better estimates"""
        try:
            if Path(self.history_file).exists():
                with open(self.history_file, 'r') as f:
                    history = json.load(f)
                    
                # Update expected durations based on history
                for phase_name, data in history.get('phases', {}).items():
                    if phase_name in self.phases:
                        avg_duration = data.get('avg_duration')
                        if avg_duration:
                            self.phases[phase_name].expected_duration = int(avg_duration)
                
                logger.info(f"[Progress] Loaded historical data for better estimates")
        except Exception as e:
            logger.debug(f"[Progress] Could not load history: {e}")
    
    def _save_history(self):
        """Save scan data for future estimates"""
        try:
            # Load existing
            history = {}
            if Path(self.history_file).exists():
                with open(self.history_file, 'r') as f:
                    history = json.load(f)
            
            # Update with this scan's data
            if 'phases' not in history:
                history['phases'] = {}
            
            for phase_name, metrics in self.phases.items():
                if metrics.actual_duration > 0:
                    if phase_name not in history['phases']:
                        history['phases'][phase_name] = {
                            'durations': [],
                            'avg_duration': metrics.expected_duration,
                        }
                    
                    # Add this duration
                    history['phases'][phase_name]['durations'].append(metrics.actual_duration)
                    
                    # Keep last 10 samples
                    history['phases'][phase_name]['durations'] = \
                        history['phases'][phase_name]['durations'][-10:]
                    
                    # Update average
                    durations = history['phases'][phase_name]['durations']
                    history['phases'][phase_name]['avg_duration'] = sum(durations) / len(durations)
            
            # Save
            Path(self.history_file).parent.mkdir(parents=True, exist_ok=True)
            with open(self.history_file, 'w') as f:
                json.dump(history, f, indent=2)
                
        except Exception as e:
            logger.warning(f"[Progress] Could not save history: {e}")
    
    def start_scan(self):
        """Mark scan as started"""
        self.started_at = datetime.now()
        
        # Start progress update thread
        self._stop_updates.clear()
        self._update_thread = threading.Thread(
            target=self._progress_update_loop,
            daemon=True
        )
        self._update_thread.start()
        
        self._emit_progress()
        logger.info(f"[Progress] Scan {self.scan_id} started")
    
    def complete_scan(self):
        """Mark scan as completed"""
        self.completed_at = datetime.now()
        self._stop_updates.set()
        
        # Save historical data
        self._save_history()
        
        self._emit_progress()
        logger.info(f"[Progress] Scan {self.scan_id} completed")
    
    def start_phase(self, phase_name: str):
        """Start a scan phase"""
        if phase_name in self.phases:
            self.current_phase = phase_name
            self.phases[phase_name].status = "running"
            self.phases[phase_name].started_at = datetime.now().isoformat()
            
            self._emit_progress()
            logger.info(f"[Progress] Phase started: {phase_name}")
    
    def complete_phase(self, phase_name: str):
        """Complete a scan phase"""
        if phase_name in self.phases:
            phase = self.phases[phase_name]
            phase.status = "completed"
            phase.completed_at = datetime.now().isoformat()
            
            if phase.started_at:
                start = datetime.fromisoformat(phase.started_at)
                phase.actual_duration = (datetime.now() - start).total_seconds()
            
            self._emit_progress()
            logger.info(f"[Progress] Phase completed: {phase_name} ({phase.actual_duration:.1f}s)")
    
    def skip_phase(self, phase_name: str, reason: str = ""):
        """Skip a scan phase"""
        if phase_name in self.phases:
            self.phases[phase_name].status = "skipped"
            logger.info(f"[Progress] Phase skipped: {phase_name} - {reason}")
    
    def start_tool(self, tool_name: str, phase: str = None):
        """Start tool execution"""
        phase = phase or self.current_phase or "unknown"
        
        expected_duration = TOOL_EXPECTED_DURATIONS.get(
            tool_name.lower(),
            TOOL_EXPECTED_DURATIONS['default']
        )
        
        self.current_tool = tool_name
        self.current_tool_metrics = ToolMetrics(
            name=tool_name,
            phase=phase,
            expected_duration=expected_duration,
            started_at=datetime.now().isoformat(),
            status="running"
        )
        
        self._emit_progress()
        logger.debug(f"[Progress] Tool started: {tool_name}")
    
    def complete_tool(
        self,
        tool_name: str,
        findings_count: int = 0,
        success: bool = True
    ):
        """Complete tool execution"""
        if self.current_tool_metrics and self.current_tool_metrics.name == tool_name:
            metrics = self.current_tool_metrics
            metrics.completed_at = datetime.now().isoformat()
            metrics.findings_count = findings_count
            metrics.status = "completed" if success else "failed"
            
            if metrics.started_at:
                start = datetime.fromisoformat(metrics.started_at)
                metrics.actual_duration = (datetime.now() - start).total_seconds()
            
            self.tools_executed.append(metrics)
            self.total_tools += 1
            self.total_findings += findings_count
            
            # Update phase metrics
            if self.current_phase and self.current_phase in self.phases:
                self.phases[self.current_phase].tools_executed += 1
                self.phases[self.current_phase].findings_count += findings_count
        
        self.current_tool = None
        self.current_tool_metrics = None
        
        self._emit_progress()
        logger.debug(f"[Progress] Tool completed: {tool_name} ({findings_count} findings)")
    
    def add_findings(self, count: int):
        """Add findings to current phase"""
        self.total_findings += count
        
        if self.current_phase and self.current_phase in self.phases:
            self.phases[self.current_phase].findings_count += count
        
        self._emit_progress()
    
    def get_progress(self) -> float:
        """
        Calculate overall scan progress (0-100).
        
        Progress is calculated based on:
        - Completed phases (weighted)
        - Current phase progress (by tools executed)
        - Time elapsed vs expected
        """
        if not self.started_at:
            return 0
        
        progress = 0
        
        for phase_name, phase in self.phases.items():
            if phase.status == "completed":
                # Completed phase: full weight
                progress += phase.weight
            elif phase.status == "running":
                # Running phase: partial credit based on tools
                if phase.max_tools > 0:
                    tool_progress = min(1.0, phase.tools_executed / phase.min_tools)
                else:
                    # Time-based progress
                    if phase.started_at:
                        elapsed = (datetime.now() - datetime.fromisoformat(phase.started_at)).total_seconds()
                        tool_progress = min(1.0, elapsed / phase.expected_duration)
                    else:
                        tool_progress = 0
                
                progress += phase.weight * tool_progress * 0.9  # 90% credit for in-progress
            elif phase.status == "skipped":
                # Skipped phase: full weight (counts as done)
                progress += phase.weight
        
        return min(100, max(0, progress))
    
    def get_eta(self) -> Optional[int]:
        """
        Calculate estimated time remaining in seconds.
        
        Uses:
        - Current progress rate
        - Remaining phase expected durations
        - Historical data
        """
        if not self.started_at:
            return None
        
        progress = self.get_progress()
        
        if progress >= 100:
            return 0
        
        if progress <= 0:
            # Use total expected duration
            return sum(p.expected_duration for p in self.phases.values())
        
        elapsed = (datetime.now() - self.started_at).total_seconds()
        
        # Method 1: Linear extrapolation
        if progress > 0:
            linear_eta = (elapsed / progress) * (100 - progress)
        else:
            linear_eta = float('inf')
        
        # Method 2: Sum remaining phase durations
        remaining_duration = 0
        for phase in self.phases.values():
            if phase.status == "pending":
                remaining_duration += phase.expected_duration
            elif phase.status == "running" and phase.started_at:
                phase_elapsed = (datetime.now() - datetime.fromisoformat(phase.started_at)).total_seconds()
                remaining_duration += max(0, phase.expected_duration - phase_elapsed)
        
        # Weighted average of methods
        if remaining_duration > 0 and linear_eta < float('inf'):
            eta = int(0.4 * linear_eta + 0.6 * remaining_duration)
        elif linear_eta < float('inf'):
            eta = int(linear_eta)
        else:
            eta = remaining_duration
        
        return max(0, eta)
    
    def get_eta_formatted(self) -> str:
        """Get human-readable ETA"""
        eta_seconds = self.get_eta()
        
        if eta_seconds is None:
            return "Unknown"
        
        if eta_seconds <= 0:
            return "Complete"
        
        if eta_seconds < 60:
            return f"{eta_seconds}s"
        elif eta_seconds < 3600:
            minutes = eta_seconds // 60
            seconds = eta_seconds % 60
            return f"{minutes}m {seconds}s"
        else:
            hours = eta_seconds // 3600
            minutes = (eta_seconds % 3600) // 60
            return f"{hours}h {minutes}m"
    
    def get_status(self) -> Dict[str, Any]:
        """Get complete progress status"""
        progress = self.get_progress()
        eta = self.get_eta()
        
        elapsed = 0
        if self.started_at:
            elapsed = (datetime.now() - self.started_at).total_seconds()
        
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "progress": round(progress, 1),
            "progress_bar": self._make_progress_bar(progress),
            "eta_seconds": eta,
            "eta_formatted": self.get_eta_formatted(),
            "elapsed_seconds": int(elapsed),
            "elapsed_formatted": self._format_duration(elapsed),
            "current_phase": self.current_phase,
            "current_tool": self.current_tool,
            "phases": {
                name: {
                    "status": phase.status,
                    "progress": self._get_phase_progress(phase),
                    "tools_executed": phase.tools_executed,
                    "findings": phase.findings_count,
                    "duration": phase.actual_duration,
                }
                for name, phase in self.phases.items()
            },
            "total_tools": self.total_tools,
            "total_findings": self.total_findings,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
    
    def _get_phase_progress(self, phase: PhaseMetrics) -> float:
        """Calculate progress within a phase"""
        if phase.status == "completed":
            return 100
        elif phase.status == "skipped":
            return 100
        elif phase.status == "running":
            if phase.min_tools > 0:
                return min(100, (phase.tools_executed / phase.min_tools) * 100)
            return 50
        return 0
    
    def _make_progress_bar(self, progress: float, width: int = 20) -> str:
        """Create ASCII progress bar"""
        filled = int(width * progress / 100)
        empty = width - filled
        return f"[{'█' * filled}{'░' * empty}] {progress:.1f}%"
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human readable form"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds // 60)}m {int(seconds % 60)}s"
        else:
            return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60)}m"
    
    def _progress_update_loop(self):
        """Background thread for periodic progress updates"""
        while not self._stop_updates.is_set():
            self._emit_progress()
            time.sleep(2)  # Update every 2 seconds
    
    def _emit_progress(self):
        """Emit progress update via WebSocket"""
        if self.socketio:
            try:
                status = self.get_status()
                self.socketio.emit(
                    'scan_progress',
                    status,
                    room=f'scan_{self.scan_id}'
                )
            except Exception as e:
                logger.debug(f"[Progress] WebSocket emit failed: {e}")


class ScanProgressManager:
    """
    Manager for multiple scan progress trackers.
    """
    
    def __init__(self, socketio=None):
        self.socketio = socketio
        self.trackers: Dict[str, ScanProgressTracker] = {}
    
    def create_tracker(self, scan_id: str, target: str) -> ScanProgressTracker:
        """Create a new progress tracker"""
        tracker = ScanProgressTracker(scan_id, target, self.socketio)
        self.trackers[scan_id] = tracker
        return tracker
    
    def get_tracker(self, scan_id: str) -> Optional[ScanProgressTracker]:
        """Get existing tracker"""
        return self.trackers.get(scan_id)
    
    def remove_tracker(self, scan_id: str):
        """Remove a tracker"""
        if scan_id in self.trackers:
            del self.trackers[scan_id]
    
    def get_all_status(self) -> Dict[str, Dict]:
        """Get status of all active scans"""
        return {
            scan_id: tracker.get_status()
            for scan_id, tracker in self.trackers.items()
        }


# Singleton
_progress_manager: Optional[ScanProgressManager] = None


def get_progress_manager(socketio=None) -> ScanProgressManager:
    """Get singleton progress manager"""
    global _progress_manager
    if _progress_manager is None:
        _progress_manager = ScanProgressManager(socketio)
    elif socketio:
        _progress_manager.socketio = socketio
    return _progress_manager
