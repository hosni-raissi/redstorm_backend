"""
Enhanced Logging Utility for RedStorm
"""
import logging
import logging.handlers
import os
from datetime import datetime
from pathlib import Path

def setup_logging(
    log_level: str = None,
    log_file: str = None,
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5
) -> logging.Logger:
    """
    Setup enhanced logging for RedStorm application
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Log file path
        max_bytes: Maximum bytes per log file
        backup_count: Number of backup files to keep
    
    Returns:
        Configured logger instance
    """
    # Default configuration
    if log_level is None:
        log_level = os.getenv("LOG_LEVEL", "INFO")
    
    if log_file is None:
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        log_file = log_dir / f"redstorm_{datetime.now().strftime('%Y%m%d')}.log"
    
    # Create logs directory if it doesn't exist
    log_file = Path(log_file)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Create logger
    logger = logging.getLogger("redstorm")
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(simple_formatter)
    logger.addHandler(console_handler)
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_handler.setLevel(getattr(logging, log_level.upper()))
    file_handler.setFormatter(detailed_formatter)
    logger.addHandler(file_handler)
    
    # Error file handler for critical errors
    error_log_file = log_file.parent / f"{log_file.stem}_errors{log_file.suffix}"
    error_handler = logging.handlers.RotatingFileHandler(
        error_log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(detailed_formatter)
    logger.addHandler(error_handler)
    
    # Security event handler
    security_log_file = log_file.parent / f"{log_file.stem}_security{log_file.suffix}"
    security_handler = logging.handlers.RotatingFileHandler(
        security_log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    security_handler.setLevel(logging.WARNING)
    security_handler.setFormatter(detailed_formatter)
    
    # Create security logger
    security_logger = logging.getLogger("redstorm.security")
    security_logger.addHandler(security_handler)
    security_logger.setLevel(logging.WARNING)
    
    return logger

def get_logger(name: str = None) -> logging.Logger:
    """
    Get a logger instance
    
    Args:
        name: Logger name (defaults to 'redstorm')
    
    Returns:
        Logger instance
    """
    if name is None:
        name = "redstorm"
    return logging.getLogger(name)

class SecurityLogger:
    """Specialized logger for security events"""
    
    def __init__(self):
        self.logger = logging.getLogger("redstorm.security")
    
    def log_security_event(self, event_type: str, details: dict, severity: str = "WARNING"):
        """Log security-related events"""
        log_data = {
            "event_type": event_type,
            "timestamp": datetime.now().isoformat(),
            "details": details
        }
        
        log_message = f"SECURITY EVENT: {json.dumps(log_data)}"
        
        if severity.upper() == "CRITICAL":
            self.logger.critical(log_message)
        elif severity.upper() == "ERROR":
            self.logger.error(log_message)
        else:
            self.logger.warning(log_message)
    
    def log_authentication_attempt(self, username: str, success: bool, ip_address: str = None):
        """Log authentication attempts"""
        self.log_security_event("AUTHENTICATION_ATTEMPT", {
            "username": username,
            "success": success,
            "ip_address": ip_address
        }, "ERROR" if not success else "WARNING")
    
    def log_authorization_failure(self, user: str, resource: str, action: str):
        """Log authorization failures"""
        self.log_security_event("AUTHORIZATION_FAILURE", {
            "user": user,
            "resource": resource,
            "action": action
        }, "ERROR")
    
    def log_exploit_attempt(self, target: str, exploit_type: str, success: bool, details: dict = None):
        """Log exploit attempts (even simulated ones)"""
        self.log_security_event("EXPLOIT_ATTEMPT", {
            "target": target,
            "exploit_type": exploit_type,
            "success": success,
            "details": details or {}
        }, "CRITICAL" if success else "WARNING")
    
    def log_consent_validation(self, target: str, validation_result: dict):
        """Log consent validation events"""
        self.log_security_event("CONSENT_VALIDATION", {
            "target": target,
            "validation_result": validation_result
        }, "ERROR" if not validation_result.get("valid", False) else "INFO")

# Global security logger instance
security_logger = SecurityLogger()

# JSON formatting for structured logging
class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record):
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        if hasattr(record, 'extra_data'):
            log_data.update(record.extra_data)
        
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)

# Performance logger
class PerformanceLogger:
    """Logger for performance metrics"""
    
    def __init__(self):
        self.logger = logging.getLogger("redstorm.performance")
        self.handler = None
        self._setup_performance_logging()
    
    def _setup_performance_logging(self):
        """Setup performance logging"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        performance_log = log_dir / "performance.log"
        handler = logging.handlers.RotatingFileHandler(
            performance_log,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        
        formatter = JSONFormatter()
        handler.setFormatter(formatter)
        
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        self.handler = handler
    
    def log_scan_performance(self, scan_type: str, target: str, duration: float, results_count: int):
        """Log scan performance metrics"""
        self.logger.info("Scan performance", extra={
            "event_type": "SCAN_PERFORMANCE",
            "scan_type": scan_type,
            "target": target,
            "duration_seconds": duration,
            "results_count": results_count,
            "performance_metric": "scan_duration"
        })
    
    def log_api_performance(self, endpoint: str, method: str, duration: float, status_code: int):
        """Log API performance metrics"""
        self.logger.info("API performance", extra={
            "event_type": "API_PERFORMANCE",
            "endpoint": endpoint,
            "method": method,
            "duration_seconds": duration,
            "status_code": status_code,
            "performance_metric": "api_response_time"
        })

# Global performance logger
performance_logger = PerformanceLogger()