"""
Base Agent class for all RedStorm AI agents
"""
import asyncio
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime

class BaseAgent(ABC):
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.logger = logging.getLogger(f"agent.{name}")
        self.status = "idle"
        self.results = {}

    @abstractmethod
    async def execute(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute the agent's main functionality"""
        pass

    async def send_update(self, websocket_manager, client_id: str, update: Dict[str, Any]):
        """Send real-time update to frontend"""
        # Only send update if websocket_manager is provided
        if websocket_manager is not None and client_id is not None:
            try:
                message = {
                    "type": "agent_update",
                    "agent": self.name,
                    "timestamp": datetime.now().isoformat(),
                    "data": update
                }
                await websocket_manager.send_personal_message(json.dumps(message), client_id)
            except Exception as e:
                self.logger.warning(f"Failed to send WebSocket update: {str(e)}")
        else:
            # Log the update instead for testing
            self.logger.info(f"Agent update: {update}")

    def log_activity(self, message: str, level: str = "info"):
        """Log agent activity"""
        getattr(self.logger, level)(f"[{self.name}] {message}")

    async def validate_target(self, target: str) -> bool:
        """Validate target before execution"""
        # Basic validation - can be extended
        if not target or len(target.strip()) == 0:
            return False
        return True