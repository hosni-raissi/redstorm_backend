"""
Redis Cache Manager for RedStorm
Implements caching for repeated queries and optimization
"""
import redis.asyncio as aioredis
import json
import hashlib
from typing import Any, Optional
from datetime import timedelta
import asyncio

class CacheManager:
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_url = redis_url
        self.redis = None
        
    async def connect(self):
        """Initialize Redis connection"""
        self.redis = await aioredis.from_url(self.redis_url, decode_responses=True)
        
    async def disconnect(self):
        """Close Redis connection"""
        if self.redis:
            await self.redis.close()
    
    def _generate_key(self, tool: str, target: str, params: dict = None) -> str:
        """Generate cache key from tool, target, and parameters"""
        key_data = f"{tool}:{target}"
        if params:
            key_data += f":{json.dumps(params, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    async def get_cached_result(self, tool: str, target: str, params: dict = None) -> Optional[dict]:
        """Retrieve cached result if available"""
        if not self.redis:
            return None
            
        key = self._generate_key(tool, target, params)
        cached_data = await self.redis.get(key)
        
        if cached_data:
            return json.loads(cached_data)
        return None
    
    async def cache_result(self, tool: str, target: str, result: dict, 
                          params: dict = None, ttl: int = 3600):
        """Cache result with TTL (default 1 hour)"""
        if not self.redis:
            return
            
        key = self._generate_key(tool, target, params)
        await self.redis.setex(key, ttl, json.dumps(result))
    
    async def invalidate_target_cache(self, target: str):
        """Invalidate all cached results for a target"""
        if not self.redis:
            return
            
        pattern = f"*:{target}:*"
        keys = await self.redis.keys(pattern)
        if keys:
            await self.redis.delete(*keys)
    # ----------  NEW  ----------
    async def health_check(self) -> dict:
        """Return cache health."""
        if not self.redis:
            return {"status": "unhealthy", "error": "not connected"}
        try:
            await self.redis.ping()
            return {"status": "healthy", "message": "Redis reachable"}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
# Global cache manager instance
cache_manager = CacheManager()
