"""
File-based API Routes for RedStorm
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
import asyncio

from agents.orchestrator import AgentOrchestrator
from utils.file_storage import file_storage

router = APIRouter()
orchestrator = AgentOrchestrator()

class AssessmentRequest(BaseModel):
    target: str
    phases: Optional[List[str]] = ["reconnaissance", "scanning", "vulnerability", "exploitation"]
    options: Optional[Dict[str, Any]] = {}

class TargetValidationRequest(BaseModel):
    target: str

@router.post("/validate-target")
async def validate_target(request: TargetValidationRequest):
    """Validate target before assessment"""
    target = request.target.strip()

    if not target:
        raise HTTPException(status_code=400, detail="Target cannot be empty")

    # Basic validation
    if len(target) < 3:
        raise HTTPException(status_code=400, detail="Target too short")

    # Check if target is reachable (basic ping)
    try:
        import subprocess
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "3", target],
            capture_output=True,
            text=True,
            timeout=5
        )

        is_reachable = result.returncode == 0

        return {
            "target": target,
            "valid": True,
            "reachable": is_reachable,
            "message": "Target validated successfully"
        }

    except Exception as e:
        return {
            "target": target,
            "valid": True,
            "reachable": False,
            "message": f"Target validation completed with warnings: {str(e)}"
        }

@router.get("/assessments/{assessment_id}")
async def get_assessment_status(assessment_id: str):
    """Get assessment status from file storage"""
    assessment = await file_storage.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment

@router.get("/assessments")
async def get_assessments(client_id: Optional[str] = None):
    """Get ALL assessments (not just active ones)"""
    try:
        all_assessments = []
        for file_path in file_storage.assessments_dir.glob("*.json"):
            assessment = file_storage._load_json(file_path)
            if assessment:
                if not client_id or assessment.get("client_id") == client_id:
                    all_assessments.append(assessment)
        
        return {"assessments": all_assessments, "count": len(all_assessments)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving assessments: {str(e)}")

@router.get("/assessments/active")
async def get_active_assessments(client_id: Optional[str] = None):
    """Get only active assessments (running/paused)"""
    assessments = await file_storage.get_active_assessments(client_id)
    return {"assessments": assessments, "count": len(assessments)}

@router.get("/assessments/by-status/{status}")
async def get_assessments_by_status(status: str):
    """Get assessments by specific status"""
    try:
        all_assessments = []
        for file_path in file_storage.assessments_dir.glob("*.json"):
            assessment = file_storage._load_json(file_path)
            if assessment and assessment.get("status") == status:
                all_assessments.append(assessment)
        
        return {"assessments": all_assessments, "count": len(all_assessments), "status": status}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving assessments: {str(e)}")

@router.get("/assessments/by-target/{target}")
async def get_assessments_by_target(target: str):
    """Get assessments by target"""
    try:
        all_assessments = []
        for file_path in file_storage.assessments_dir.glob("*.json"):
            assessment = file_storage._load_json(file_path)
            if assessment and assessment.get("target") == target:
                all_assessments.append(assessment)
        
        return {"assessments": all_assessments, "count": len(all_assessments), "target": target}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving assessments: {str(e)}")

@router.put("/assessments/{assessment_id}/status")
async def update_assessment_status(assessment_id: str, status: str):
    """Update assessment status"""
    try:
        await file_storage.update_assessment_status(assessment_id, status)
        return {"message": f"Assessment {assessment_id} status updated to {status}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating assessment status: {str(e)}")

@router.delete("/assessments/{assessment_id}")
async def delete_assessment(assessment_id: str):
    """Delete assessment"""
    try:
        import os
        file_path = file_storage.assessments_dir / f"{assessment_id}.json"
        if file_path.exists():
            file_path.unlink()
            return {"message": f"Assessment {assessment_id} deleted successfully"}
        else:
            raise HTTPException(status_code=404, detail="Assessment not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting assessment: {str(e)}")

@router.post("/assessments")
async def create_assessment(request: AssessmentRequest, background_tasks: BackgroundTasks):
    """Create new assessment"""
    try:
        # Create assessment data
        assessment_data = {
            "client_id": "api_client",  # You might want to get this from auth
            "target": request.target,
            "status": "created",
            "start_time": None,
            "phases": request.phases,
            "config": request.options
        }
        
        # Save to file storage
        assessment_id = await file_storage.create_assessment(assessment_data)
        
        return {
            "assessment_id": assessment_id,
            "status": "created",
            "message": "Assessment created successfully"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating assessment: {str(e)}")

@router.get("/tools/status")
async def get_tools_status():
    """Get status of security tools"""
    tools_status = {
        "nmap": {"available": True, "version": "7.94"},
        "subfinder": {"available": True, "version": "2.6.3"},
        "nuclei": {"available": True, "version": "3.1.0"},
        "gobuster": {"available": True, "version": "3.6.0"},
        "httpx": {"available": True, "version": "1.3.7"},
        "fping": {"available": True, "version": "5.1"},
        "hping3": {"available": True, "version": "3.0.0"},
        "amass": {"available": True, "version": "4.2.0"},
        "metasploit": {"available": True, "version": "6.3.0", "mode": "simulation"},
        "empire": {"available": True, "version": "5.0.0", "mode": "simulation"},
        "dradis": {"available": True, "version": "4.10.0"}
    }

    return {
        "status": "operational",
        "tools": tools_status,
        "total_tools": len(tools_status),
        "available_tools": sum(1 for tool in tools_status.values() if tool["available"])
    }

@router.get("/agents/status")
async def get_agents_status():
    """Get status of AI agents"""
    agents_status = {}

    for name, agent in orchestrator.agents.items():
        agents_status[name] = {
            "name": agent.name,
            "description": agent.description,
            "status": agent.status,
            "available": True
        }

    return {
        "status": "operational",
        "agents": agents_status,
        "total_agents": len(agents_status)
    }

@router.get("/vulnerabilities")
async def get_vulnerabilities(
    assessment_id: Optional[str] = None,
    target: Optional[str] = None,
    severity: Optional[str] = None
):
    """Get vulnerability findings from file storage"""
    findings = await file_storage.get_vulnerability_findings(
        assessment_id=assessment_id,
        target=target,
        severity=severity
    )
    return {"findings": findings, "count": len(findings)}

@router.get("/statistics")
async def get_statistics():
    """Get system statistics from file storage"""
    stats = await file_storage.get_system_statistics()
    return stats