"""
Parallel execution utilities for RedStorm optimization
"""
import asyncio
import concurrent.futures
from typing import List, Dict, Any, Callable, Optional
from functools import wraps
import time

class ParallelExecutor:
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)

    async def execute_parallel_scans(self, scan_tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Execute multiple scan tasks in parallel"""
        loop = asyncio.get_event_loop()
        
        # Create futures for all scan tasks
        futures = []
        for task in scan_tasks:
            future = loop.run_in_executor(
                self.thread_pool,
                self._execute_scan_task,
                task
            )
            futures.append(future)
        
        # Wait for all tasks to complete
        results = await asyncio.gather(*futures, return_exceptions=True)
        
        # Process results and handle exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    "task": scan_tasks[i],
                    "error": str(result),
                    "status": "failed"
                })
            else:
                processed_results.append(result)
        
        return processed_results

    def _execute_scan_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single scan task"""
        import subprocess
        import json
        
        try:
            start_time = time.time()
            
            # Build command based on task type
            cmd = self._build_command(task)
            
            # Execute command with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=task.get('timeout', 300)  # 5 minute default timeout
            )
            
            execution_time = time.time() - start_time
            
            # Parse output
            if result.returncode == 0:
                try:
                    output_data = json.loads(result.stdout)
                except json.JSONDecodeError:
                    output_data = {"raw_output": result.stdout}
                
                return {
                    "task": task,
                    "result": output_data,
                    "execution_time": execution_time,
                    "status": "completed"
                }
            else:
                return {
                    "task": task,
                    "error": result.stderr,
                    "execution_time": execution_time,
                    "status": "failed"
                }
                
        except subprocess.TimeoutExpired:
            return {
                "task": task,
                "error": "Task timed out",
                "status": "timeout"
            }
        except Exception as e:
            return {
                "task": task,
                "error": str(e),
                "status": "error"
            }

    def _build_command(self, task: Dict[str, Any]) -> List[str]:
        """Build command based on task configuration"""
        tool = task.get('tool')
        target = task.get('target')
        options = task.get('options', {})
        
        if tool == 'nmap':
            cmd = ['redstorm-tools', 'scan', '-t', target]
            if 'ports' in options:
                cmd.extend(['-p', options['ports']])
            if 'scan_type' in options:
                cmd.extend(['-s', options['scan_type']])
                
        elif tool == 'amass':
            cmd = ['redstorm-tools', 'amass', '-d', target]
            if options.get('passive', True):
                cmd.append('-p')
                
        elif tool == 'gobuster':
            cmd = ['redstorm-tools', 'enum', '-t', target]
            if 'wordlist' in options:
                cmd.extend(['-w', options['wordlist']])
            if 'extensions' in options:
                cmd.extend(['-x', options['extensions']])
                
        elif tool == 'fping':
            cmd = ['redstorm-tools', 'preengagement', '-t', target]
            
        else:
            raise ValueError(f"Unknown tool: {tool}")
        
        return cmd

    async def execute_with_rate_limit(self, tasks: List[Dict[str, Any]], 
                                    rate_limit: int = 5) -> List[Dict[str, Any]]:
        """Execute tasks with rate limiting"""
        semaphore = asyncio.Semaphore(rate_limit)
        
        async def rate_limited_task(task):
            async with semaphore:
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
                    self.thread_pool,
                    self._execute_scan_task,
                    task
                )
        
        # Execute all tasks with rate limiting
        results = await asyncio.gather(
            *[rate_limited_task(task) for task in tasks],
            return_exceptions=True
        )
        
        return results

# Global executor instance
executor = ParallelExecutor()

def async_cached(cache_key_func: Callable = None, ttl: int = 3600):
    """Decorator for async caching with Redis"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            from .redis_cache import cache
            
            # Generate cache key
            if cache_key_func:
                cache_key = cache_key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}:{hash(str(args) + str(kwargs))}"
            
            # Try to get from cache
            cached_result = cache.get(cache_key)
            if cached_result:
                return cached_result
            
            # Execute function and cache result
            result = await func(*args, **kwargs)
            cache.set(cache_key, result, ttl)
            
            return result
        return wrapper
    return decorator
