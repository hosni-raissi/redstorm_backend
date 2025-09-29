"""
Async Executor for Parallel Tool Execution
Implements optimized parallel execution as specified in the guide
"""
import asyncio
import subprocess
import json
from typing import List, Dict, Any, Callable
from concurrent.futures import ThreadPoolExecutor
import logging

logger = logging.getLogger(__name__)

class AsyncToolExecutor:
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
    
    async def execute_tool_async(self, tool_command: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Execute a single tool command asynchronously"""
        loop = asyncio.get_event_loop()
        
        def run_command():
            try:
                result = subprocess.run(
                    tool_command,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False
                )
                
                # Try to parse JSON output
                try:
                    output_data = json.loads(result.stdout)
                except json.JSONDecodeError:
                    output_data = {
                        "raw_output": result.stdout,
                        "error_output": result.stderr
                    }
                
                return {
                    "success": result.returncode == 0,
                    "data": output_data,
                    "command": " ".join(tool_command),
                    "return_code": result.returncode
                }
            except subprocess.TimeoutExpired:
                return {
                    "success": False,
                    "error": "Command timeout",
                    "command": " ".join(tool_command)
                }
            except Exception as e:
                return {
                    "success": False,
                    "error": str(e),
                    "command": " ".join(tool_command)
                }
        
        return await loop.run_in_executor(self.executor, run_command)
    
    async def execute_parallel_tools(self, tool_commands: List[List[str]], 
                                   timeout: int = 300) -> List[Dict[str, Any]]:
        """Execute multiple tools in parallel"""
        tasks = [
            self.execute_tool_async(cmd, timeout) 
            for cmd in tool_commands
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    "success": False,
                    "error": str(result),
                    "command": " ".join(tool_commands[i])
                })
            else:
                processed_results.append(result)
        
        return processed_results
    
    async def execute_with_callback(self, tool_commands: List[List[str]], 
                                  progress_callback: Callable = None,
                                  timeout: int = 300) -> List[Dict[str, Any]]:
        """Execute tools with progress callback for real-time updates"""
        results = []
        total_tools = len(tool_commands)
        
        for i, cmd in enumerate(tool_commands):
            if progress_callback:
                await progress_callback(f"Executing {' '.join(cmd)}", i, total_tools)
            
            result = await self.execute_tool_async(cmd, timeout)
            results.append(result)
            
            if progress_callback:
                status = "completed" if result["success"] else "failed"
                await progress_callback(f"Tool {status}: {' '.join(cmd)}", i + 1, total_tools)
        
        return results
    
    def cleanup(self):
        """Cleanup executor resources"""
        self.executor.shutdown(wait=True)

# Global executor instance
async_executor = AsyncToolExecutor()
