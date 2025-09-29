"""
Agent Orchestrator - Manages the execution flow of all agents
Parallel execution with ordered results & pre-engagement gate
AI service selector + final report via Ollama
"""
import asyncio
import json
from typing import Dict, Any, Optional
from datetime import datetime

from .reconnaissance_agent import ReconnaissanceAgent
from .scanning_agent import ScanningAgent
from .vulnerability_agent import VulnerabilityAgent
from .exploitation_agent import ExploitationAgent
from .preengagement_agent import PreEngagementAgent
from .ollama_analyst import query, query_json


class AgentOrchestrator:
    """
    Main orchestrator class that manages the execution flow of security assessment agents.
    Handles parallel execution, AI service selection, and final reporting.
    """
    
    # Valid service hints for AI service selector
    VALID_SERVICE_HINTS = {
        "http", "https", "wordpress", "drupal", "joomla", "prestashop", "magento",
        "opencart", "shopify", "ghost", "grav", "craftcms", "strapi", "typo3",
        "concrete5", "processwire", "octobercms", "modx", "expressionengine",
        "alfresco", "plone", "django-cms", "wagtail", "mezzanine", "cms-made-simple",
        "phpbb", "mybb", "vanilla-forums", "flarum", "nodebb", "discourse",
        "mediawiki", "dokuwiki", "tiki-wiki", "twenty-seventeen", "sharepoint",
        "bitrix", "typo3-neos", "orchard", "umbraco", "kentico", "sitecore",
        "webflow", "wix", "squarespace", "weebly", "jimdo", "ghost-pro",
        "blogger", "tumblr", "medium", "substack", "hashnode", "dev-to",
        "gatsby", "next-js", "nuxt-js", "astro", "hugo", "jekyll", "eleventy",
        "hexo", "pelican", "mkdocs", "docsify", "vuepress", "docusaurus",
        "gitbook", "read-the-docs", "netlify-cms", "contentful", "sanity",
        "prismic", "storyblok", "graphcms", "hasura", "postgraphile", "apigee",
        "swagger", "openapi", "graphql", "rest", "json-api", "json-rpc",
        "xml-rpc", "soap", "grpc", "thrift", "avro", "protobuf", "msgpack",
        "bson", "ubjson", "smile", "cbor", "ion", "capn", "flatbuf", "arrow",
        "parquet", "orc"
    }

    def __init__(self):
        """Initialize the orchestrator with all agent instances."""
        self.agents = {
            "preengagement": PreEngagementAgent(),
            "reconnaissance": ReconnaissanceAgent(),
            "scanning": ScanningAgent(),
            "vulnerability": VulnerabilityAgent(),
            "exploitation": ExploitationAgent()
        }
        self.active_assessments: Dict[str, Dict[str, Any]] = {}

    # ----------------------------------------------------------
    # Public API Methods
    # ----------------------------------------------------------

    async def start_assessment(self, target: str, client_id: str, websocket_manager) -> str:
        """
        Start a new security assessment for the given target.
        
        Args:
            target: The target to assess
            client_id: Unique identifier for the client
            websocket_manager: WebSocket manager for real-time updates
            
        Returns:
            assessment_id: Unique identifier for this assessment
        """
        assessment_id = f"{client_id}_{int(datetime.now().timestamp())}"
        
        # Initialize assessment state
        self.active_assessments[assessment_id] = {
            "target": target,
            "client_id": client_id,
            "status": "running",
            "current_phase": "preengagement",
            "results": {},
            "ai_service_hint": "http",  # default
            "ai_final_report": "",
            "start_time": datetime.now(),
            "cancelled": False
        }

        # Notify client that assessment has started
        await self._send_message(client_id, websocket_manager, "assessment_started", {
            "assessment_id": assessment_id,
            "target": target,
            "phases": list(self.agents.keys())
        })

        # Execute all phases in parallel
        phases = list(self.agents.keys())
        error_occurred = False
        
        try:
            async with asyncio.TaskGroup() as task_group:
                tasks = {
                    phase: task_group.create_task(
                        self._run_phase(phase, target, client_id, websocket_manager, assessment_id)
                    )
                    for phase in phases
                }
            
            # Collect results in original order for predictable JSON
            for phase in phases:
                if assessment_id in self.active_assessments:  # Check if still exists
                    self.active_assessments[assessment_id]["results"][phase] = tasks[phase].result()
                    
        except* asyncio.CancelledError:
            if assessment_id in self.active_assessments:
                self.active_assessments[assessment_id]["status"] = "cancelled"
                await self._send_message(client_id, websocket_manager, "assessment_cancelled", {
                    "assessment_id": assessment_id
                })
            error_occurred = True
            
        except* Exception as eg:
            error = eg.exceptions[0] if eg.exceptions else Exception("Unknown phase error")
            if assessment_id in self.active_assessments:
                self.active_assessments[assessment_id]["status"] = "error"
                await self._send_message(client_id, websocket_manager, "assessment_error", {
                    "assessment_id": assessment_id,
                    "error": str(error)
                })
            error_occurred = True

        if error_occurred:
            return assessment_id

        # Generate AI final report after all phases complete
        await self._generate_final_report(assessment_id, client_id, websocket_manager)
        
        return assessment_id

    async def stop_assessment(self, client_id: str) -> None:
        """Stop any running assessment for the given client."""
        for assessment_id, data in self.active_assessments.items():
            if data["client_id"] == client_id and data["status"] == "running":
                data["cancelled"] = True
                break

    def get_assessment_status(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        """Get the current status of an assessment."""
        return self.active_assessments.get(assessment_id)

    # ----------------------------------------------------------
    # Private Helper Methods
    # ----------------------------------------------------------

    async def _send_message(self, client_id: str, websocket_manager, msg_type: str, payload: Dict[str, Any]) -> None:
        """Send a message to the client via WebSocket."""
        try:
            message = json.dumps({"type": msg_type, **payload})
            await websocket_manager.send_personal_message(message, client_id)
        except Exception as e:
            print(f"Failed to send message to client {client_id}: {e}")

    async def _run_phase(self, phase: str, target: str, client_id: str, websocket_manager, assessment_id: str) -> Dict[str, Any]:
        """Execute a single assessment phase."""
        # Check if assessment was cancelled
        if self.active_assessments[assessment_id].get("cancelled"):
            raise asyncio.CancelledError(f"{phase} cancelled")

        # Notify phase start
        await self._send_message(client_id, websocket_manager, "phase_started", {
            "phase": phase,
            "assessment_id": assessment_id
        })

        # Pre-engagement gate: skip heavy phases if target is down
        if phase != "preengagement":
            pre_results = self.active_assessments[assessment_id]["results"].get("preengagement", {})
            if not pre_results.get("is_available", True):
                return {
                    "skipped": True,
                    "reason": "Target unreachable during pre-engagement"
                }

        # AI service selector (before exploitation only)
        if phase == "exploitation":
            await self._select_ai_service(assessment_id)

        # Execute the agent
        agent = self.agents[phase]
        options = {
            "websocket_manager": websocket_manager,
            "client_id": client_id,
            "assessment_id": assessment_id
        }

        try:
            result = await agent.execute(target, options)
        except Exception as e:
            result = {
                "error": True,
                "message": str(e),
                "phase": phase
            }

        # Announce phase completion
        await self._send_message(client_id, websocket_manager, "phase_completed", {
            "phase": phase,
            "results": result,
            "assessment_id": assessment_id
        })

        return result

    async def _select_ai_service(self, assessment_id: str) -> None:
        """Select the appropriate service for exploitation using AI."""
        # Build summary of previous phases for Ollama
        previous_results = {
            k: v for k, v in self.active_assessments[assessment_id]["results"].items()
            if k != "exploitation"
        }

        try:
            ai_prompt = """You are a red-team operator.
Based on the JSON above, return ONLY the **single word** service name that exploitation should target.
Choose the most appropriate option from the available services based on the reconnaissance and vulnerability data.
Return only one word - no explanations or additional text."""

            hint = query(previous_results, prompt=ai_prompt)
            
            # Sanitize and validate the AI response
            hint = hint.strip().strip('"').lower()
            
            if hint in self.VALID_SERVICE_HINTS:
                self.active_assessments[assessment_id]["ai_service_hint"] = hint
            else:
                # Fallback to default if AI returns invalid service
                self.active_assessments[assessment_id]["ai_service_hint"] = "http"
                print(f"AI returned invalid service hint '{hint}', using default 'http'")
                
        except Exception as e:
            # Fallback on any error
            self.active_assessments[assessment_id]["ai_service_hint"] = "http"
            print(f"AI service hint selection failed: {e}")

    async def _generate_final_report(self, assessment_id: str, client_id: str, websocket_manager) -> None:
        """Generate and send the final AI-powered assessment report."""
        if assessment_id not in self.active_assessments:
            return
            
        full_results = self.active_assessments[assessment_id]["results"]
        
        try:
            ai_prompt = """You are a senior red-team operator writing for a CISO.
Write a concise executive summary (≤20 lines) that includes:
- Overall risk score (0-10)
- Top 3 critical findings
- One actionable remediation recommendation
Focus on business impact, not technical details. Do not repeat raw JSON keys."""

            report = query(full_results, prompt=ai_prompt)
            self.active_assessments[assessment_id]["ai_final_report"] = report
            
        except Exception as e:
            self.active_assessments[assessment_id]["ai_final_report"] = f"AI report generation failed: {e}"

        # Mark assessment as completed and send final results
        self.active_assessments[assessment_id]["status"] = "completed"
        await self._send_message(client_id, websocket_manager, "assessment_completed", {
            "assessment_id": assessment_id,
            "results": full_results,
            "ai_final_report": self.active_assessments[assessment_id]["ai_final_report"]
        })