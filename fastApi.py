"""
RedStorm AI-Powered Real-Time Attack Simulator
File-based version – No database required
Real-time step-by-step pipeline exposed via WebSocket
"""
import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from agents.orchestrator import AgentOrchestrator
from utils.websocket_manager import WebSocketManager
from utils.cache_manager import cache_manager
from utils.ethical_boundaries import ethical_boundaries
from utils.file_storage import file_storage

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class ConsentData(BaseModel):
    target: str
    client_name: Optional[str] = None
    scope: Optional[str] = None
    authorization: Optional[str] = None
    constraints: Optional[List[str]] = []

class AssessmentRequest(BaseModel):
    target: str
    assessment_type: Optional[str] = "full"
    options: Optional[Dict[str, Any]] = {}

class AssessmentStop(BaseModel):
    assessment_id: Optional[str] = None
    reason: Optional[str] = "user_requested"

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="RedStorm Attack Simulator",
    description="AI-Powered Real-Time Penetration Testing Simulator – File-based Storage",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "https://your-frontend-domain.com",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
websocket_manager = WebSocketManager()
orchestrator       = AgentOrchestrator()
active_connections: Dict[str, WebSocket] = {}
cancel_flags: Dict[str, bool] = {}          # graceful stop per client

# ---------------------------------------------------------------------------
# Helper – push single message to one client
# ---------------------------------------------------------------------------
async def send(client_id: str, payload: dict):
    await websocket_manager.send_personal_message(client_id, json.dumps(payload))

# ---------------------------------------------------------------------------
# Life-cycle
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def startup():
    try:
        await cache_manager.connect()
        health = await file_storage.health_check()
        logger.info("✓ Redis cache connected")
        logger.info("✓ File-storage health: %s", health)
    except Exception as exc:
        logger.exception("❌ Startup error: %s", exc)
        raise

@app.on_event("shutdown")
async def shutdown():
    for cid, ws in active_connections.items():
        try:
            await ws.close()
        except Exception:
            pass
    for aid, data in orchestrator.active_assessments.items():
        if data.get("status") == "running":
            data["cancelled"] = True
    await cache_manager.disconnect()
    logger.info("✓ Shutdown complete")

# ---------------------------------------------------------------------------
# Real-time pipeline runner
# ---------------------------------------------------------------------------
async def run_step_by_step(client_id: str, target: str, options: dict):
    """
    Executes the full pipeline and streams each result to the front-end.
    Stops early if client sends {type:'stop_assessment'} (cancel_flags set).
    """
    assessment_id = uuid.uuid4().hex
    cancel_flags[client_id] = False

    # ---- consent ----------------------------------------------------------
    await send(client_id, {"type": "consent_check", "status": "running"})
    consent = await ethical_boundaries.validate_consent(target, {"target": target})
    await send(client_id, {"type": "consent_result", "valid": consent.get("valid"), "reason": consent.get("reason")})
    if not consent.get("valid"):
        await send(client_id, {"type": "assessment_stopped", "reason": consent.get("reason")})
        return

    # ---- pre-engagement ---------------------------------------------------
    await send(client_id, {"type": "preengagement_start"})
    pre = await orchestrator.run_agent("preengagement", target, options)
    await send(client_id, {"type": "preengagement_result", "data": pre})
    if cancel_flags.get(client_id):
        await send(client_id, {"type": "assessment_stopped", "reason": "user_requested"})
        return

    # ---- reconnaissance ---------------------------------------------------
    await send(client_id, {"type": "reconnaissance_start"})
    rec = await orchestrator.run_agent("reconnaissance", target, options, prior=pre)
    await send(client_id, {"type": "reconnaissance_result", "data": rec})
    if cancel_flags.get(client_id):
        await send(client_id, {"type": "assessment_stopped", "reason": "user_requested"})
        return

    # ---- scanning ---------------------------------------------------------
    await send(client_id, {"type": "scanning_start"})
    scan = await orchestrator.run_agent("scanning", target, options, prior=rec)
    await send(client_id, {"type": "scanning_result", "data": scan})
    if cancel_flags.get(client_id):
        await send(client_id, {"type": "assessment_stopped", "reason": "user_requested"})
        return

    # ---- vulnerability ----------------------------------------------------
    await send(client_id, {"type": "vulnerability_start"})
    vuln = await orchestrator.run_agent("vulnerability", target, options, prior=scan)
    await send(client_id, {"type": "vulnerability_result", "data": vuln})
    if cancel_flags.get(client_id):
        await send(client_id, {"type": "assessment_stopped", "reason": "user_requested"})
        return

    # ---- exploitation (simulation) ---------------------------------------
    await send(client_id, {"type": "exploitation_start"})
    exp = await orchestrator.run_agent("exploitation", target, options, prior=vuln)
    await send(client_id, {"type": "exploitation_result", "data": exp})

    # ---- save full report -------------------------------------------------
    full_report = {
        "assessment_id": assessment_id,
        "target": target,
        "client_id": client_id,
        "phases": {
            "preengagement": pre,
            "reconnaissance": rec,
            "scanning": scan,
            "vulnerability": vuln,
            "exploitation": exp,
        },
        "finished_at": datetime.now().isoformat(),
    }
    await file_storage.save_assessment(assessment_id, full_report)
    await send(client_id, {"type": "assessment_complete", "assessment_id": assessment_id})
    cancel_flags.pop(client_id, None)

# ---------------------------------------------------------------------------
# HTTP extra endpoints
# ---------------------------------------------------------------------------
@app.post("/api/v1/consent/validate")
async def validate_consent(consent: ConsentData):
    try:
        result = await ethical_boundaries.validate_consent(consent.target, consent.dict())
        await file_storage.log_consent_validation(consent.target, result)
        return result
    except Exception as exc:
        logger.exception("Consent validation error")
        return JSONResponse(status_code=500, content={"error": str(exc)})

@app.post("/api/v1/assessments/start")
async def start_assessment_http(req: AssessmentRequest, client_id: str):
    consent = await ethical_boundaries.validate_consent(req.target, {"target": req.target})
    if not consent.get("valid"):
        raise HTTPException(status_code=400, detail=consent.get("reason", "Consent denied"))
    # fire-and-forget background task – UI can poll or open WS later
    asyncio.create_task(run_step_by_step(client_id, req.target, req.options or {}))
    return {"status": "started", "message": "Assessment pipeline launched (connect WebSocket for live feed)"}

@app.post("/api/v1/assessments/{assessment_id}/stop")
async def stop_assessment_http(assessment_id: str, stop: AssessmentStop):
    assessment = orchestrator.get_assessment_status(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    cancel_flags[assessment["client_id"]] = True
    return {"status": "stopped"}

@app.get("/api/v1/assessments/{assessment_id}")
async def get_assessment(assessment_id: str):
    data = orchestrator.get_assessment_status(assessment_id)
    if data:
        return {"source": "active", "assessment": data}
    data = await file_storage.get_assessment(assessment_id)
    if data:
        return {"source": "stored", "assessment": data}
    raise HTTPException(status_code=404, detail="Assessment not found")

@app.get("/api/v1/assessments")
async def list_assessments(client_id: Optional[str] = None, status: Optional[str] = None):
    active = [
        {"source": "active", **adata}
        for aid, adata in orchestrator.active_assessments.items()
        if (not client_id or adata.get("client_id") == client_id)
        and (not status or adata.get("status") == status)
    ]
    stored = await file_storage.get_active_assessments(client_id)
    for s in stored:
        s["source"] = "stored"
    merged = active + stored
    merged.sort(key=lambda x: x.get("start_time", ""), reverse=True)
    return {"assessments": merged, "count": len(merged)}

@app.get("/api/v1/vulnerabilities")
async def get_vulnerabilities(
    assessment_id: Optional[str] = None,
    target: Optional[str] = None,
    severity: Optional[str] = None,
):
    findings = await file_storage.get_vulnerability_findings(
        assessment_id=assessment_id, target=target, severity=severity
    )
    return {"findings": findings, "count": len(findings)}

@app.get("/api/v1/statistics")
async def stats():
    file_stats = await file_storage.get_system_statistics()
    return {
        **file_stats,
        "orchestrator": {
            "active_assessments": len(orchestrator.active_assessments),
            "running_assessments": sum(
                1 for d in orchestrator.active_assessments.values() if d.get("status") == "running"
            ),
            "websocket_connections": len(active_connections),
            "agent_types": list(orchestrator.agents.keys()),
        },
        "timestamp": datetime.now().isoformat(),
    }

# ---------------------------------------------------------------------------
# WebSocket – entry point for real-time step-by-step
# ---------------------------------------------------------------------------
@app.websocket("/ws/{client_id}")
async def websocket_endpoint(ws: WebSocket, client_id: str):
    await websocket_manager.connect(ws, client_id)
    active_connections[client_id] = ws
    try:
        await ws.send_json({"type": "connection_established", "client_id": client_id})
        while True:
            msg = json.loads(await ws.receive_text())
            logger.info("WS msg %s: %s", client_id, msg["type"])

            if msg["type"] == "start_assessment":
                # launch pipeline in background so websocket stays responsive
                asyncio.create_task(run_step_by_step(client_id, msg["target"], msg.get("options", {})))

            elif msg["type"] == "stop_assessment":
                cancel_flags[client_id] = True
                await ws.send_json({"type": "assessment_stopped", "reason": "user_requested"})

            elif msg["type"] == "ping":
                await ws.send_json({"type": "pong", "timestamp": datetime.now().isoformat()})

    except WebSocketDisconnect:
        logger.info("WS disconnect %s", client_id)
    finally:
        websocket_manager.disconnect(client_id)
        active_connections.pop(client_id, None)
        cancel_flags.pop(client_id, None)

# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/")
async def root():
    return {
        "message": "RedStorm Attack Simulator API – File-based Storage",
        "status": "active",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "active_assessments": len(orchestrator.active_assessments),
        "websocket_connections": len(active_connections),
    }

@app.get("/health")
async def health():
    try:
        storage = await file_storage.health_check()
        cache = await cache_manager.health_check()
    except Exception as e:
        storage = cache = {"status": "unhealthy", "error": str(e)}
    return {
        "status": "healthy" if storage["status"] == "healthy" and cache["status"] == "healthy" else "degraded",
        "components": {"file_storage": storage, "cache": cache},
        "active_assessments": len(orchestrator.active_assessments),
        "websocket_connections": len(active_connections),
        "timestamp": datetime.now().isoformat(),
    }

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(
        "fastApi:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )