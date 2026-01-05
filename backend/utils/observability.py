"""
Centralized Observability System with Trace ID Support
Provides comprehensive logging for the Optimus platform with end-to-end traceability
"""
import logging
import uuid
import json
import threading
from datetime import datetime
from typing import Dict, Any, Optional, Callable
from contextlib import contextmanager
from pathlib import Path


class TraceContext:
    """Thread-local storage for trace context"""
    _local = threading.local()
    
    @classmethod
    def get_trace_id(cls) -> Optional[str]:
        """Get current trace ID from thread local storage"""
        return getattr(cls._local, 'trace_id', None)
    
    @classmethod
    def set_trace_id(cls, trace_id: str):
        """Set current trace ID in thread local storage"""
        cls._local.trace_id = trace_id
    
    @classmethod
    def clear_trace_id(cls):
        """Clear current trace ID from thread local storage"""
        if hasattr(cls._local, 'trace_id'):
            delattr(cls._local, 'trace_id')


class OptimusFormatter(logging.Formatter):
    """Custom formatter that includes trace ID in all log messages"""
    
    def format(self, record):
        # Add trace ID to the record if available
        trace_id = TraceContext.get_trace_id()
        if trace_id:
            record.trace_id = trace_id
        else:
            record.trace_id = 'N/A'
        
        # Call parent format method
        return super().format(record)


class ObservabilityLogger:
    """Centralized observability logger with trace ID support"""
    
    def __init__(self, name: str = 'optimus', log_level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(log_level)
        
        # Create formatter that includes trace ID
        formatter = OptimusFormatter(
            '%(asctime)s - %(name)s - TRACE:%(trace_id)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler
        from pathlib import Path
        import os
        BACKEND_DIR = Path(__file__).parent.parent
        PROJECT_ROOT = BACKEND_DIR.parent
        LOGS_DIR = PROJECT_ROOT / 'logs'
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(LOGS_DIR / 'observability.log', encoding='utf-8')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Prevent duplicate logs if parent already has handlers
        self.logger.propagate = False
        
        # Store the name for convenience
        self.name = name
    
    def _log_with_context(self, level: int, message: str, **context):
        """Log a message with context and trace ID"""
        # Add timestamp to context
        context['timestamp'] = datetime.now().isoformat()
        
        # Add trace ID to context if available
        trace_id = TraceContext.get_trace_id()
        if trace_id:
            context['trace_id'] = trace_id
        
        # Format message with context
        if context:
            formatted_message = f"{message} | Context: {json.dumps(context, default=str)}"
        else:
            formatted_message = message
        
        self.logger.log(level, formatted_message)
    
    def info(self, message: str, **context):
        """Log info level message"""
        self._log_with_context(logging.INFO, message, **context)
    
    def debug(self, message: str, **context):
        """Log debug level message"""
        self._log_with_context(logging.DEBUG, message, **context)
    
    def warning(self, message: str, **context):
        """Log warning level message"""
        self._log_with_context(logging.WARNING, message, **context)
    
    def error(self, message: str, **context):
        """Log error level message"""
        self._log_with_context(logging.ERROR, message, **context)
    
    def critical(self, message: str, **context):
        """Log critical level message"""
        self._log_with_context(logging.CRITICAL, message, **context)
    
    def log_target(self, target: str, **context):
        """Log target information"""
        self._log_with_context(logging.INFO, f"TARGET: {target}", target=target, **context)
    
    def log_tool(self, tool_name: str, **context):
        """Log tool execution"""
        self._log_with_context(logging.INFO, f"TOOL: {tool_name}", tool=tool_name, **context)
    
    def log_command(self, command: str, **context):
        """Log command execution"""
        self._log_with_context(logging.INFO, f"COMMAND: {command}", command=command, **context)
    
    def log_output(self, output: str, **context):
        """Log command output"""
        self._log_with_context(logging.INFO, f"OUTPUT: {output[:500]}...", output=output[:500], **context)
    
    def log_finding(self, finding: Dict[str, Any], **context):
        """Log security finding"""
        self._log_with_context(logging.INFO, f"FINDING: {finding.get('type', 'unknown')}", finding=finding, **context)
    
    def log_reward(self, reward: float, **context):
        """Log reward information"""
        self._log_with_context(logging.INFO, f"REWARD: {reward}", reward=reward, **context)
    
    def log_skill(self, skill: str, **context):
        """Log skill acquisition or update"""
        self._log_with_context(logging.INFO, f"SKILL: {skill}", skill=skill, **context)
    
    def log_lesson_decision(self, decision: str, **context):
        """Log lesson decision"""
        self._log_with_context(logging.INFO, f"LESSON_DECISION: {decision}", decision=decision, **context)


# Global observability logger instance
observability_logger = ObservabilityLogger()


@contextmanager
def trace_context(trace_id: Optional[str] = None):
    """Context manager for trace ID management"""
    if trace_id is None:
        trace_id = str(uuid.uuid4())
    
    old_trace_id = TraceContext.get_trace_id()
    TraceContext.set_trace_id(trace_id)
    
    try:
        yield trace_id
    finally:
        if old_trace_id is not None:
            TraceContext.set_trace_id(old_trace_id)
        else:
            TraceContext.clear_trace_id()


def generate_trace_id() -> str:
    """Generate a new trace ID"""
    return str(uuid.uuid4())


def get_current_trace_id() -> Optional[str]:
    """Get the current trace ID"""
    return TraceContext.get_trace_id()


def log_target(target: str, **context):
    """Log target information"""
    observability_logger.log_target(target, **context)


def log_tool(tool_name: str, **context):
    """Log tool execution"""
    observability_logger.log_tool(tool_name, **context)


def log_command(command: str, **context):
    """Log command execution"""
    observability_logger.log_command(command, **context)


def log_output(output: str, **context):
    """Log command output"""
    observability_logger.log_output(output, **context)


def log_finding(finding: Dict[str, Any], **context):
    """Log security finding"""
    observability_logger.log_finding(finding, **context)


def log_reward(reward: float, **context):
    """Log reward information"""
    observability_logger.log_reward(reward, **context)


def log_skill(skill: str, **context):
    """Log skill acquisition or update"""
    observability_logger.log_skill(skill, **context)


def log_lesson_decision(decision: str, **context):
    """Log lesson decision"""
    observability_logger.log_lesson_decision(decision, **context)


def info(message: str, **context):
    """Log info level message"""
    observability_logger.info(message, **context)


def debug(message: str, **context):
    """Log debug level message"""
    observability_logger.debug(message, **context)


def warning(message: str, **context):
    """Log warning level message"""
    observability_logger.warning(message, **context)


def error(message: str, **context):
    """Log error level message"""
    observability_logger.error(message, **context)


def critical(message: str, **context):
    """Log critical level message"""
    observability_logger.critical(message, **context)


# Initialize the observability system
def init_observability():
    """Initialize the observability system"""
    # Create logs directory if it doesn't exist
    from pathlib import Path
    import os
    BACKEND_DIR = Path(__file__).parent.parent
    PROJECT_ROOT = BACKEND_DIR.parent
    LOGS_DIR = PROJECT_ROOT / 'logs'
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    
    print(f"[OBSERVABILITY] Initialized with logs directory: {LOGS_DIR}")


# Initialize on module import
init_observability()