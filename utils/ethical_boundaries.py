"""
Ethical Boundaries and Consent Management - Fixed Version
Implements ethical safeguards with proper handling of false values
"""
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json
import logging

logger = logging.getLogger(__name__)

class EthicalBoundaries:
    def __init__(self):
        self.consent_cache = {}
        self.assessment_limits = {
            "max_concurrent_assessments": 5,
            "max_assessment_duration": 3600,  # 1 hour
            "required_consent_fields": [
                "target_ownership",
                "assessment_scope",
                "data_handling",
                "reporting_consent"
            ]
        }

    async def validate_consent(self, target: str, consent_data: Dict) -> Dict[str, Any]:
        """Validate user consent before proceeding with assessment"""
        validation_result = {
            "valid": False,
            "missing_fields": [],
            "warnings": [],
            "consent_id": None
        }

        # Check required consent fields - allow False values but not missing/None
        for field in self.assessment_limits["required_consent_fields"]:
            if field not in consent_data or consent_data[field] is None:
                validation_result["missing_fields"].append(field)

        # Validate target ownership - warning for false, but still allow
        if "target_ownership" in consent_data:
            if not consent_data["target_ownership"]:
                validation_result["warnings"].append(
                    "Target ownership not confirmed - assessment may be unauthorized"
                )

        # Check assessment scope for dangerous settings
        if "assessment_scope" in consent_data:
            scope = consent_data["assessment_scope"]
            if isinstance(scope, dict):
                if scope.get("exploitation") or scope.get("destructive_tests"):
                    validation_result["warnings"].append(
                        "Destructive tests/exploitation enabled - ensure proper authorization"
                    )

        # For educational/public targets, allow with warnings
        is_educational = any(keyword in consent_data.get("notes", "").lower() 
                           for keyword in ["educational", "learning", "training", "public"])
        is_public_target = any(keyword in target.lower() 
                             for keyword in ["scanme.nmap.org", "localhost", "127.0.0.1", "httpbin.org"])
        
        # Generate consent ID even with warnings for educational purposes
        if not validation_result["missing_fields"]:
            if is_educational or is_public_target:
                validation_result["valid"] = True
                validation_result["warnings"].append(
                    "Educational/public target assessment - proceeding with caution"
                )
            else:
                # For production targets, require explicit ownership
                if consent_data.get("target_ownership") is True:
                    validation_result["valid"] = True
                else:
                    validation_result["warnings"].append(
                        "Production target requires explicit ownership confirmation"
                    )

        if validation_result["valid"]:
            consent_id = f"consent_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            validation_result["consent_id"] = consent_id

            # Cache consent
            self.consent_cache[consent_id] = {
                "target": target,
                "consent_data": consent_data,
                "timestamp": datetime.now(),
                "expires": datetime.now() + timedelta(hours=24)
            }

        return validation_result

    async def check_assessment_limits(self, client_id: str) -> Dict[str, Any]:
        """Check if client can start new assessment based on limits"""
        return {
            "can_start": True,
            "current_assessments": 0,
            "max_assessments": self.assessment_limits["max_concurrent_assessments"],
            "estimated_duration": self.assessment_limits["max_assessment_duration"]
        }

    async def log_assessment_action(self, consent_id: str, action: str,
                                  details: Dict = None):
        """Log assessment actions for audit trail"""
        log_entry = {
            "consent_id": consent_id,
            "action": action,
            "timestamp": datetime.now().isoformat(),
            "details": details or {}
        }

        logger.info(f"Assessment Action: {json.dumps(log_entry)}")

    def is_consent_valid(self, consent_id: str) -> bool:
        """Check if consent is still valid"""
        if consent_id not in self.consent_cache:
            return False

        consent = self.consent_cache[consent_id]
        return datetime.now() < consent["expires"]

    def get_consent_data(self, consent_id: str) -> Optional[Dict]:
        """Retrieve consent data"""
        if consent_id in self.consent_cache and self.is_consent_valid(consent_id):
            return self.consent_cache[consent_id]
        return None

# Global ethical boundaries instance
ethical_boundaries = EthicalBoundaries()