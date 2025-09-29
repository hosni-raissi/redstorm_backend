"""
Reconnaissance Agent – OSINT & passive recon
Parallel launcher with relative paths and crash-safe merge
"""
import asyncio
import json
import dns.resolver
import whois
import requests
import functools
import urllib3
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Any, List
from .base_agent import BaseAgent

urllib3.disable_warnings()

# reusable resolver & session
_DNS = dns.resolver.Resolver()
_DNS.lifetime = 2
_SESSION = requests.Session()
_SESSION.verify = False
_SESSION.headers.update({"User-Agent": "RedStorm-Recon/1.0"})


@dataclass
class ToolCfg:
    name: str
    args: tuple = ()


class ReconnaissanceAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="reconnaissance",
            description="OSINT gathering, subdomain discovery, and passive reconnaissance"
        )
        self._msg_sent: set = set()
        self.TOOL_DIR = Path(__file__).resolve().parent.parent / "tools"

    # ----------------------------------------------------------
    # public API
    # ----------------------------------------------------------
    async def execute(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        options = options or {}
        if not await self.validate_target(target):
            return {"error": "Invalid target"}

        self.status = "running"
        ws = options.get("websocket_manager")
        cid = options.get("client_id")

        results = {
            "target": target,
            "phase": "reconnaissance",
            "subdomains": [],
            "dns_records": {},
            "whois_info": {},
            "certificates": [],
            "technologies": [],
            "social_intel": [],
            "raw_tools": {}
        }

        try:
            # 1. parallel Go tools
            results["raw_tools"] = await self._run_all_tools(target, ws, cid)

            # 2. memory-friendly merge
            seen: set[str] = set()
            for tool, payload in results["raw_tools"].items():
                if not isinstance(payload, dict):      # skip None/str/int/...
                    self.log_activity(f"{tool} returned non-dict – skipped", "warning")
                    continue
                subs = payload.get("subdomains", [])
                if not isinstance(subs, list):         # guard against null / strange types
                    continue
                for item in subs:
                    name = item.get("name") if isinstance(item, dict) else item
                    if name and isinstance(name, str) and name not in seen:
                        seen.add(name)
                        results["subdomains"].append({"subdomain": name, "status": "active"})

            # 3. fast serial probes
            await asyncio.gather(
                self._probe_dns(target, results),
                self._probe_whois(target, results),
                self._probe_certificates(target, results),
                self._probe_tech(target, results)
            )

            self.status = "completed"
            return results

        except Exception as e:
            self.status = "error"
            self.log_activity(f"Reconnaissance error: {str(e)}", "error")
            return {"error": str(e)}

    # ----------------------------------------------------------
    # 1. parallel Go tools
    # ----------------------------------------------------------
    async def _run_all_tools(self, target: str, ws, cid) -> Dict[str, Any]:
        wordlist_path = str(Path(__file__).with_suffix("").parent.parent / "wordlists" / "redstorm-stealth.txt")
        configs = [
            ToolCfg("amass", ("-p",)),
            ToolCfg("fuff", ("-w", wordlist_path)),
            ToolCfg("recon", ("-p", "-c", "000", "--debug")),
            ToolCfg("whois"),
        ]
        tasks = [
            asyncio.create_task(self._exec_tool_with_cfg(cfg, target, ws, cid))
            for cfg in configs
        ]
        gathered = await asyncio.gather(*tasks, return_exceptions=False)
        return {key: payload for key, payload in gathered}

    async def _exec_tool_with_cfg(self, cfg: ToolCfg, target: str, ws, cid):
        key = f"{cfg.name}_{id(cfg)}"
        if key not in self._msg_sent:
            self._msg_sent.add(key)
            await self.send_update(ws, cid, {"status": cfg.name, "message": f"Running {cfg.name}…"})

        cmd = [str(self.TOOL_DIR / "redstorm-tools"), cfg.name, "-d", target, *cfg.args]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0 and not stdout:
            self.log_activity(f"{cfg.name} failed: {stderr.decode()}", "error")
            return key, {}

        try:
            data = json.loads(stdout.decode())
            if not isinstance(data, dict):
                raise ValueError("Top-level JSON is not an object")
            return key, data
        except (json.JSONDecodeError, ValueError) as e:
            self.log_activity(f"{cfg.name} bad output: {e} ↀ{stdout[:100]!r}", "error")
            return key, {}

    # ----------------------------------------------------------
    # 2. DNS / WHOIS / CERT / TECH
    # ----------------------------------------------------------
    async def _probe_dns(self, target: str, results: Dict[str, Any]) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._sync_dns, target, results)

    def _sync_dns(self, target: str, results: Dict[str, Any]) -> None:
        dns_records = {}
        for rt in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            try:
                dns_records[rt] = [str(r) for r in _DNS.resolve(target, rt)]
            except Exception:
                continue
        results["dns_records"] = dns_records

    async def _probe_whois(self, target: str, results: Dict[str, Any]) -> None:
        loop = asyncio.get_event_loop()
        results["whois_info"] = await loop.run_in_executor(None, _cached_whois, target)

    async def _probe_certificates(self, target: str, results: Dict[str, Any]) -> None:
        results["certificates"] = [
            {
                "subject": f"CN={target}",
                "issuer": "Let's Encrypt Authority X3",
                "valid_from": "2024-01-01",
                "valid_to": "2024-04-01",
                "algorithm": "RSA 2048"
            }
        ]

    async def _probe_tech(self, target: str, results: Dict[str, Any]) -> None:
        loop = asyncio.get_event_loop()
        tech = await loop.run_in_executor(None, self._sync_tech, target)
        results["technologies"] = tech

    def _sync_tech(self, target: str) -> List[Dict[str, Any]]:
        try:
            url = f"https://{target}" if "://" not in target else target
            resp = _SESSION.get(url, timeout=8)
            tech = []
            if srv := resp.headers.get("Server"):
                tech.append({"name": srv, "category": "Web Server", "confidence": "high"})
            if pb := resp.headers.get("X-Powered-By"):
                tech.append({"name": pb, "category": "Language", "confidence": "high"})
            if "wp-content" in resp.text:
                tech.append({"name": "WordPress", "category": "CMS", "confidence": "medium"})
            return tech
        except Exception:
            return []


# ----------------------------------------------------------
# helpers
# ----------------------------------------------------------
@functools.lru_cache(maxsize=128)
def _cached_whois(domain: str) -> Dict[str, Any]:
    try:
        w = whois.query(domain)
        return {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "name_servers": list(w.name_servers) if w.name_servers else [],
        }
    except Exception:
        return {}