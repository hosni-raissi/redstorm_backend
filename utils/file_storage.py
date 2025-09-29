"""
File-based storage manager for RedStorm
Saves all assessment data, results, and logs to local files
"""
import json
import os
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
import logging
from pathlib import Path

logger = logging.getLogger("redstorm.file_storage")

class FileStorageManager:
    """File-based storage for all RedStorm data"""
    
    def __init__(self, base_dir: str = "data"):
        self.base_dir = Path(base_dir)
        self.assessments_dir = self.base_dir / "assessments"
        self.scans_dir = self.base_dir / "scans"
        self.vulnerabilities_dir = self.base_dir / "vulnerabilities"
        self.logs_dir = self.base_dir / "logs"
        self.metrics_dir = self.base_dir / "metrics"
        
        # Create directories
        for dir_path in [self.base_dir, self.assessments_dir, self.scans_dir, 
                        self.vulnerabilities_dir, self.logs_dir, self.metrics_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def _generate_id(self) -> str:
        """Generate unique ID"""
        return str(uuid.uuid4())
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        return datetime.now().isoformat()
    
    def _save_json(self, file_path: Path, data: Dict[str, Any]):
        """Save data to JSON file"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving JSON to {file_path}: {e}")
            raise
    
    def _load_json(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Load data from JSON file"""
        try:
            if not file_path.exists():
                return None
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading JSON from {file_path}: {e}")
            return None
    
    # Assessment operations
    async def create_assessment(self, assessment_data: Dict[str, Any]) -> str:
        """Create new assessment"""
        try:
            assessment_id = assessment_data.get("assessment_id", self._generate_id())
            assessment_data["assessment_id"] = assessment_id
            assessment_data["created_at"] = self._get_timestamp()
            assessment_data["updated_at"] = self._get_timestamp()
            
            file_path = self.assessments_dir / f"{assessment_id}.json"
            self._save_json(file_path, assessment_data)
            
            logger.info(f"Created assessment: {assessment_id}")
            return assessment_id
        except Exception as e:
            logger.error(f"Create assessment error: {e}")
            raise
    
    async def update_assessment_status(self, assessment_id: str, status: str, 
                                     current_phase: Optional[str] = None,
                                     results: Optional[Dict] = None):
        """Update assessment status"""
        try:
            file_path = self.assessments_dir / f"{assessment_id}.json"
            assessment = self._load_json(file_path)
            
            if not assessment:
                raise ValueError(f"Assessment {assessment_id} not found")
            
            assessment["status"] = status
            assessment["updated_at"] = self._get_timestamp()
            
            if current_phase:
                assessment["current_phase"] = current_phase
            if results:
                assessment["results"] = results
            
            self._save_json(file_path, assessment)
            logger.debug(f"Updated assessment {assessment_id} status to {status}")
        except Exception as e:
            logger.error(f"Update assessment status error: {e}")
            raise
    
    async def get_assessment(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        """Get assessment by ID"""
        try:
            file_path = self.assessments_dir / f"{assessment_id}.json"
            return self._load_json(file_path)
        except Exception as e:
            logger.error(f"Get assessment error: {e}")
            return None
    
    async def get_active_assessments(self, client_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get active assessments"""
        try:
            active_assessments = []
            
            for file_path in self.assessments_dir.glob("*.json"):
                assessment = self._load_json(file_path)
                if assessment and assessment.get("status") in ["running", "paused"]:
                    if not client_id or assessment.get("client_id") == client_id:
                        active_assessments.append(assessment)
            
            return active_assessments
        except Exception as e:
            logger.error(f"Get active assessments error: {e}")
            return []
    
    # Scan results operations
    async def save_scan_results(self, scan_data: Dict[str, Any]) -> str:
        """Save scan results"""
        try:
            scan_id = scan_data.get("scan_id", self._generate_id())
            scan_data["scan_id"] = scan_id
            scan_data["created_at"] = self._get_timestamp()
            
            file_path = self.scans_dir / f"{scan_id}.json"
            self._save_json(file_path, scan_data)
            
            logger.info(f"Saved scan results: {scan_id}")
            return scan_id
        except Exception as e:
            logger.error(f"Save scan results error: {e}")
            raise
    
    async def get_scan_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan results by ID"""
        try:
            file_path = self.scans_dir / f"{scan_id}.json"
            return self._load_json(file_path)
        except Exception as e:
            logger.error(f"Get scan results error: {e}")
            return None
    
    # Vulnerability findings operations
    async def save_vulnerability_finding(self, finding_data: Dict[str, Any]) -> int:
        """Save vulnerability finding"""
        try:
            finding_id = hash(finding_data.get("vulnerability_name", "") + 
                            finding_data.get("target", "") + 
                            self._get_timestamp())
            
            finding_data["id"] = finding_id
            finding_data["created_at"] = self._get_timestamp()
            
            # Save individual finding
            file_path = self.vulnerabilities_dir / f"{finding_id}.json"
            self._save_json(file_path, finding_data)
            
            logger.info(f"Saved vulnerability finding: {finding_id}")
            return finding_id
        except Exception as e:
            logger.error(f"Save vulnerability finding error: {e}")
            raise
    
    async def get_vulnerability_findings(self, assessment_id: Optional[str] = None,
                                       target: Optional[str] = None,
                                       severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get vulnerability findings"""
        try:
            findings = []
            
            for file_path in self.vulnerabilities_dir.glob("*.json"):
                finding = self._load_json(file_path)
                if finding:
                    # Apply filters
                    if assessment_id and finding.get("assessment_id") != assessment_id:
                        continue
                    if target and finding.get("target") != target:
                        continue
                    if severity and finding.get("severity") != severity:
                        continue
                    
                    findings.append(finding)
            
            return sorted(findings, key=lambda x: x.get("created_at", ""), reverse=True)
        except Exception as e:
            logger.error(f"Get vulnerability findings error: {e}")
            return []
    
    # Audit logging
    async def log_audit_event(self, event_data: Dict[str, Any]):
        """Log audit event"""
        try:
            event_data["timestamp"] = self._get_timestamp()
            event_id = hash(event_data.get("event_type", "") + 
                          event_data.get("action", "") + 
                          self._get_timestamp())
            
            file_path = self.logs_dir / f"audit_{event_id}.json"
            self._save_json(file_path, event_data)
        except Exception as e:
            logger.error(f"Log audit event error: {e}")
    
    # Consent validation
    async def log_consent_validation(self, target: str, validation_result: Dict[str, Any]):
        """Log consent validation"""
        try:
            consent_data = {
                "target": target,
                "validation_result": validation_result,
                "consent_details": validation_result.get("details", {}),
                "timestamp": self._get_timestamp()
            }
            
            file_path = self.logs_dir / f"consent_{hash(target + self._get_timestamp())}.json"
            self._save_json(file_path, consent_data)
        except Exception as e:
            logger.error(f"Log consent validation error: {e}")
    
    # System metrics
    async def save_metric(self, metric_name: str, metric_value: float,
                         metric_type: str, tags: Optional[Dict[str, Any]] = None):
        """Save system metric"""
        try:
            metric_data = {
                "metric_name": metric_name,
                "metric_value": metric_value,
                "metric_type": metric_type,
                "tags": tags or {},
                "timestamp": self._get_timestamp()
            }
            
            file_path = self.metrics_dir / f"metric_{hash(metric_name + self._get_timestamp())}.json"
            self._save_json(file_path, metric_data)
        except Exception as e:
            logger.error(f"Save metric error: {e}")
    
    async def get_system_metrics(self, metric_name: Optional[str] = None,
                                time_range: str = "1h") -> List[Dict[str, Any]]:
        """Get system metrics"""
        try:
            metrics = []
            
            for file_path in self.metrics_dir.glob("*.json"):
                metric = self._load_json(file_path)
                if metric:
                    # Apply filters
                    if metric_name and metric.get("metric_name") != metric_name:
                        continue
                    
                    # Time range filter (simplified)
                    metrics.append(metric)
            
            return sorted(metrics, key=lambda x: x.get("timestamp", ""), reverse=True)
        except Exception as e:
            logger.error(f"Get system metrics error: {e}")
            return []
    
    # Health check
    async def health_check(self) -> Dict[str, Any]:
        """Health check for file storage"""
        try:
            # Check if directories are accessible
            test_file = self.base_dir / "health_check.txt"
            with open(test_file, 'w') as f:
                f.write("health_check")
            test_file.unlink()  # Remove test file
            
            # Count files
            assessment_count = len(list(self.assessments_dir.glob("*.json")))
            scan_count = len(list(self.scans_dir.glob("*.json")))
            vuln_count = len(list(self.vulnerabilities_dir.glob("*.json")))
            
            return {
                "status": "healthy",
                "storage_type": "file_system",
                "assessments_count": assessment_count,
                "scans_count": scan_count,
                "vulnerabilities_count": vuln_count,
                "data_directory": str(self.base_dir)
            }
        except Exception as e:
            return {"status": "unhealthy", "error": str(e), "storage_type": "file_system"}
    
    # System statistics
    async def get_system_statistics(self) -> Dict[str, Any]:
        """Get system statistics"""
        try:
            # Count assessments by status
            assessments_by_status = {}
            for file_path in self.assessments_dir.glob("*.json"):
                assessment = self._load_json(file_path)
                if assessment:
                    status = assessment.get("status", "unknown")
                    assessments_by_status[status] = assessments_by_status.get(status, 0) + 1
            
            # Count vulnerabilities by severity
            vulns_by_severity = {}
            for file_path in self.vulnerabilities_dir.glob("*.json"):
                finding = self._load_json(file_path)
                if finding and not finding.get("false_positive", False):
                    severity = finding.get("severity", "unknown")
                    vulns_by_severity[severity] = vulns_by_severity.get(severity, 0) + 1
            
            # Recent activity (last 24 hours)
            recent_assessments = 0
            recent_targets = set()
            
            for file_path in self.assessments_dir.glob("*.json"):
                assessment = self._load_json(file_path)
                if assessment:
                    created_at = assessment.get("created_at")
                    if created_at:
                        # Simple check - in production, parse the timestamp properly
                        recent_assessments += 1
                        target = assessment.get("target")
                        if target:
                            recent_targets.add(target)
            
            return {
                "assessments": {
                    "total": sum(assessments_by_status.values()),
                    **assessments_by_status
                },
                "vulnerabilities": {
                    "total": sum(vulns_by_severity.values()),
                    **vulns_by_severity
                },
                "recent_activity": {
                    "assessments_24h": recent_assessments,
                    "unique_targets_24h": len(recent_targets)
                }
            }
        except Exception as e:
            logger.error(f"Get system statistics error: {e}")
            return {}
    # ----------  NEW  ----------
    async def health_check(self) -> dict:
        """Health check for file storage."""
        try:
            # write + delete test file
            test_file = self.base_dir / "health_check.txt"
            with open(test_file, "w") as f:
                f.write("health_check")
            test_file.unlink()  # remove test file

            # counts
            assessment_count = len(list(self.assessments_dir.glob("*.json")))
            scan_count       = len(list(self.scans_dir.glob("*.json")))
            vuln_count       = len(list(self.vulnerabilities_dir.glob("*.json")))

            return {
                "status": "healthy",
                "storage_type": "file_system",
                "assessments_count": assessment_count,
                "scans_count": scan_count,
                "vulnerabilities_count": vuln_count,
                "data_directory": str(self.base_dir),
            }
        except Exception as e:
            return {"status": "unhealthy", "error": str(e), "storage_type": "file_system"}
# Global file storage instance
file_storage = FileStorageManager()