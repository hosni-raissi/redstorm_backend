"""
Pre-Engagement Agent – Lightweight reachability & firewall probe
"""
import asyncio
import json
import subprocess
from pathlib import Path
from typing import Dict, Any
from .base_agent import BaseAgent

_TOOL_DIR = Path(__file__).resolve().parent.parent / "tools"
_REDSTORM_TOOLS = _TOOL_DIR / "redstorm-tools"


class PreEngagementAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="preengagement",
            description="Lightweight reachability & firewall probe"
        )

    async def execute(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run pre-engagement probe (go wrapper) and return JSON."""
        options = options or {}
        if not await self.validate_target(target):
            return {"error": "Invalid target"}

        self.status = "running"
        ws = options.get("websocket_manager")
        cid = options.get("client_id")

        await self.send_update(ws, cid, {"status": "preengagement", "message": "Probing target availability…"})

        try:
            cmd = [_REDSTORM_TOOLS, "preengagement", "-t", target, "-T", "25"]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # give the wrapper plenty of head-room
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=35          # 35 s > 15 s probe window
            )

            if proc.returncode != 0:
                return {"error": f"Probe exited {proc.returncode}: {stderr.decode()}"}

            # strip banners / colours / progress text
            json_start = stdout.find(b'{')
            if json_start == -1:
                return {"error": "No JSON object returned from preengagement wrapper"}

            data = json.loads(stdout[json_start:])
            self.status = "completed"
            return data

        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            self.status = "error"
            self.log_activity("Pre-engagement probe timed out after 35 s", "error")
            return {"error": "Pre-engagement probe timed out after 35 s"}

        except Exception as e:
            self.status = "error"
            self.log_activity(f"Pre-engagement error: {str(e)}", "error")
            return {"error": str(e)}