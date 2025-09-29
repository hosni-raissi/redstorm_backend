"""
Updated Scanning Agent - Network scanning and service discovery
Now works with functional Go tools!
"""
import asyncio
import subprocess
import json
import socket
import logging
import os
from typing import Dict, Any, List
from .base_agent import BaseAgent

class ScanningAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="scanning",
            description="Network scanning, port discovery, and service enumeration"
        )
        
    async def execute(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute scanning phase"""
        if not await self.validate_target(target):
            return {"error": "Invalid target"}
            
        self.status = "running"
        results = {
            "target": target,
            "phase": "scanning",
            "open_ports": [],
            "services": [],
            "os_detection": {},
            "host_discovery": [],
            "scan_summary": {}
        }
        
        try:
            # Handle None options
            if options is None:
                options = {}
            
            # Host discovery
            await self.send_update(options.get("websocket_manager"), options.get("client_id"), {
                "status": "host_discovery",
                "message": "Discovering live hosts..."
            })
            results["host_discovery"] = await self.discover_hosts(target)
            
            # Port scanning with working Go tools!
            await self.send_update(options.get("websocket_manager"), options.get("client_id"), {
                "status": "port_scanning",
                "message": "Scanning for open ports with Go tools..."
            })
            results["open_ports"] = await self.scan_ports_with_go_tools(target)
            
            # Service detection
            await self.send_update(options.get("websocket_manager"), options.get("client_id"), {
                "status": "service_detection",
                "message": "Detecting services and versions..."
            })
            results["services"] = await self.detect_services(target, results["open_ports"])
            
            # OS detection
            await self.send_update(options.get("websocket_manager"), options.get("client_id"), {
                "status": "os_detection",
                "message": "Detecting operating system..."
            })
            results["os_detection"] = await self.detect_os(target)
            
            # Generate scan summary
            results["scan_summary"] = self.generate_scan_summary(results)
            
            self.status = "completed"
            return results
            
        except Exception as e:
            self.status = "error"
            self.log_activity(f"Error during scanning: {str(e)}", "error")
            return {"error": str(e)}
    
    async def discover_hosts(self, target: str) -> List[Dict[str, Any]]:
        """Discover live hosts in the network"""
        hosts = []
        
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "3", target],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                hosts.append({
                    "ip": target,
                    "status": "up",
                    "response_time": "< 10ms"
                })
            else:
                hosts.append({
                    "ip": target,
                    "status": "down",
                    "response_time": "timeout"
                })
                
        except Exception as e:
            self.log_activity(f"Host discovery failed: {str(e)}", "error")
            
        return hosts
    
    async def scan_ports_with_go_tools(self, target: str) -> List[Dict[str, Any]]:
        """Scan ports using Go tools"""
        try:
            # Use the working Go tools with proper arguments
            cmd = ["./tools/redstorm-tools", "scan", "-t", target, "-p", "1-1000", "-s", "syn"]
            
            self.log_activity(f"Running Go tools command: {' '.join(cmd)}")
            
            # Set working directory to backend folder
            current_dir = os.path.dirname(os.path.abspath(__file__))
            backend_dir = os.path.join(current_dir, '..')
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=backend_dir
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                # Parse the JSON output from Go tools
                result = json.loads(stdout.decode())
                self.log_activity(f"Go tools found {len(result.get('ports', []))} open ports")
                
                # Convert to expected format
                ports = []
                for port_data in result.get("ports", []):
                    if port_data.get("state") == "open":
                        ports.append({
                            "port": port_data.get("port"),
                            "protocol": port_data.get("protocol", "tcp"),
                            "state": port_data.get("state", "unknown"),
                            "service": port_data.get("service", "unknown"),
                            "version": port_data.get("version", "")
                        })
                
                return ports
            else:
                self.log_activity(f"Port scanning failed: {stderr.decode()}", "error")
                return []
                
        except Exception as e:
            self.log_activity(f"Port scanning error: {str(e)}", "error")
            return []
    
    async def detect_services(self, target: str, open_ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect services running on open ports"""
        services = []
        
        for port_info in open_ports:
            if port_info.get("state") == "open":
                service = {
                    "port": port_info.get("port"),
                    "protocol": port_info.get("protocol", "tcp"),
                    "service": port_info.get("service", "unknown"),
                    "version": port_info.get("version", ""),
                    "banner": await self.grab_banner(target, port_info.get("port")),
                    "risk_level": self.assess_service_risk(port_info.get("service", ""))
                }
                services.append(service)
        
        return services
    
    async def grab_banner(self, target: str, port: int) -> str:
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            result = sock.connect_ex((target, port))
            if result == 0:
                # Send HTTP request for web services
                if port in [80, 443, 8080, 8443]:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                else:
                    sock.send(b"\r\n")
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                return banner[:200]  # Limit banner length
            
            sock.close()
            return ""
            
        except Exception:
            return ""
    
    def assess_service_risk(self, service: str) -> str:
        """Assess risk level of detected service"""
        high_risk_services = ["ssh", "telnet", "ftp", "smtp", "pop3", "imap", "snmp"]
        medium_risk_services = ["http", "https", "mysql", "postgresql", "mongodb"]
        
        service_lower = service.lower()
        
        if any(risky in service_lower for risky in high_risk_services):
            return "high"
        elif any(medium in service_lower for medium in medium_risk_services):
            return "medium"
        else:
            return "low"
    
    async def detect_os(self, target: str) -> Dict[str, Any]:
        """Detect operating system"""
        os_info = {
            "os_family": "unknown",
            "os_version": "unknown",
            "confidence": "low",
            "details": []
        }
        
        try:
            # TTL-based OS detection
            result = subprocess.run(
                ["ping", "-c", "1", target],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if "ttl=64" in result.stdout.lower():
                os_info["os_family"] = "Linux/Unix"
                os_info["confidence"] = "medium"
            elif "ttl=128" in result.stdout.lower():
                os_info["os_family"] = "Windows"
                os_info["confidence"] = "medium"
            elif "ttl=255" in result.stdout.lower():
                os_info["os_family"] = "Cisco/Network Device"
                os_info["confidence"] = "medium"
                
        except Exception as e:
            self.log_activity(f"OS detection failed: {str(e)}", "error")
        
        return os_info
    
    def generate_scan_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate scanning summary"""
        open_ports = results.get("open_ports", [])
        services = results.get("services", [])
        
        summary = {
            "total_ports_scanned": 1000,
            "open_ports_found": len(open_ports),
            "services_identified": len(services),
            "high_risk_services": len([s for s in services if s.get("risk_level") == "high"]),
            "medium_risk_services": len([s for s in services if s.get("risk_level") == "medium"]),
            "low_risk_services": len([s for s in services if s.get("risk_level") == "low"]),
            "scan_duration": "variable",
            "scan_type": "SYN Connect Scan via Go Tools"
        }
        
        return summary
    
    async def validate_target(self, target: str) -> bool:
        """Validate target format"""
        import re
        # Simple validation for IP or domain
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$'
        
        return bool(re.match(ip_pattern, target) or re.match(domain_pattern, target))
    
    async def send_update(self, websocket_manager, client_id, data):
        """Send WebSocket update if available"""
        if websocket_manager and client_id:
            await websocket_manager.send_update(client_id, data)