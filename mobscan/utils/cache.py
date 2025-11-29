"""
Redis Cache Manager for Mobscan.

Provides caching functionality for scan results, analysis data,
and other cacheable artifacts to improve performance.
"""

import redis
import pickle
import json
from typing import Any, Optional, Dict, Union
from datetime import timedelta
import logging
from abc import ABC, abstractmethod


logger = logging.getLogger(__name__)


class CacheBackend(ABC):
    """Abstract base class for cache backends"""

    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        pass

    @abstractmethod
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        pass

    @abstractmethod
    def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        pass

    @abstractmethod
    def clear(self) -> bool:
        """Clear entire cache"""
        pass

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        pass


class RedisCacheBackend(CacheBackend):
    """Redis-based cache backend"""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        ssl: bool = False,
        decode_responses: bool = False,
        ttl_default: int = 3600,
    ):
        """
        Initialize Redis cache backend.

        Args:
            host: Redis server host
            port: Redis server port
            db: Database number
            password: Redis password if required
            ssl: Use SSL connection
            decode_responses: Decode responses to strings
            ttl_default: Default TTL in seconds (1 hour)
        """
        self.host = host
        self.port = port
        self.db = db
        self.ttl_default = ttl_default

        try:
            self.redis_client = redis.Redis(
                host=host,
                port=port,
                db=db,
                password=password,
                ssl=ssl,
                decode_responses=decode_responses,
                socket_connect_timeout=5,
                socket_keepalive=True,
            )
            # Test connection
            self.redis_client.ping()
            logger.info(f"Connected to Redis at {host}:{port}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.redis_client = None

    def is_connected(self) -> bool:
        """Check if Redis is connected"""
        if self.redis_client is None:
            return False
        try:
            self.redis_client.ping()
            return True
        except Exception:
            return False

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if not self.is_connected():
            logger.warning("Redis not connected, returning None")
            return None

        try:
            value = self.redis_client.get(key)
            if value is None:
                return None
            # Try to deserialize as pickle (for complex objects)
            try:
                return pickle.loads(value)
            except (pickle.UnpicklingError, TypeError):
                # If pickle fails, try JSON
                try:
                    return json.loads(value.decode('utf-8') if isinstance(value, bytes) else value)
                except (json.JSONDecodeError, AttributeError):
                    # Return raw value if all else fails
                    return value
        except Exception as e:
            logger.warning(f"Error retrieving from cache: {e}")
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        if not self.is_connected():
            logger.warning("Redis not connected, skipping cache set")
            return False

        try:
            ttl = ttl or self.ttl_default
            # Try to serialize as pickle
            try:
                serialized = pickle.dumps(value)
            except (pickle.PicklingError, TypeError):
                # If pickle fails, try JSON
                try:
                    serialized = json.dumps(value).encode('utf-8')
                except TypeError:
                    serialized = str(value).encode('utf-8')

            self.redis_client.setex(key, ttl, serialized)
            logger.debug(f"Cached key '{key}' with TTL {ttl}s")
            return True
        except Exception as e:
            logger.warning(f"Error setting cache: {e}")
            return False

    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        if not self.is_connected():
            return False

        try:
            result = self.redis_client.delete(key)
            return result > 0
        except Exception as e:
            logger.warning(f"Error deleting from cache: {e}")
            return False

    def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        if not self.is_connected():
            return False

        try:
            return self.redis_client.exists(key) > 0
        except Exception as e:
            logger.warning(f"Error checking cache existence: {e}")
            return False

    def clear(self) -> bool:
        """Clear entire cache"""
        if not self.is_connected():
            return False

        try:
            self.redis_client.flushdb()
            logger.info("Cache cleared")
            return True
        except Exception as e:
            logger.warning(f"Error clearing cache: {e}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        if not self.is_connected():
            return {"connected": False}

        try:
            info = self.redis_client.info()
            dbsize = self.redis_client.dbsize()
            return {
                "connected": True,
                "used_memory": info.get("used_memory_human", "N/A"),
                "used_memory_bytes": info.get("used_memory", 0),
                "keys": dbsize,
                "expired_keys": info.get("expired_keys", 0),
                "evicted_keys": info.get("evicted_keys", 0),
                "uptime_seconds": info.get("uptime_in_seconds", 0),
            }
        except Exception as e:
            logger.warning(f"Error getting cache stats: {e}")
            return {"connected": False, "error": str(e)}


class MemoryCacheBackend(CacheBackend):
    """In-memory cache backend (fallback when Redis unavailable)"""

    def __init__(self, ttl_default: int = 3600):
        """Initialize memory cache backend"""
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.ttl_default = ttl_default
        logger.info("Using in-memory cache (Redis unavailable)")

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if key not in self.cache:
            return None
        return self.cache[key].get("value")

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        self.cache[key] = {"value": value, "ttl": ttl or self.ttl_default}
        return True

    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        if key in self.cache:
            del self.cache[key]
            return True
        return False

    def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        return key in self.cache

    def clear(self) -> bool:
        """Clear entire cache"""
        self.cache.clear()
        return True

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            "type": "memory",
            "keys": len(self.cache),
            "backend": "in-memory",
        }


class CacheManager:
    """
    Cache manager that provides a unified interface for caching.
    Automatically falls back to memory cache if Redis is unavailable.
    """

    def __init__(
        self,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_db: int = 0,
        redis_password: Optional[str] = None,
        use_redis: bool = True,
        ttl_default: int = 3600,
    ):
        """Initialize cache manager"""
        self.ttl_default = ttl_default

        if use_redis:
            redis_backend = RedisCacheBackend(
                host=redis_host,
                port=redis_port,
                db=redis_db,
                password=redis_password,
                ttl_default=ttl_default,
            )
            # Use Redis if connected, otherwise use memory
            if redis_backend.is_connected():
                self.backend = redis_backend
            else:
                logger.warning("Redis not available, falling back to memory cache")
                self.backend = MemoryCacheBackend(ttl_default=ttl_default)
        else:
            self.backend = MemoryCacheBackend(ttl_default=ttl_default)

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        return self.backend.get(key)

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        return self.backend.set(key, value, ttl)

    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        return self.backend.delete(key)

    def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        return self.backend.exists(key)

    def clear(self) -> bool:
        """Clear entire cache"""
        return self.backend.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return self.backend.get_stats()

    def cache_result(self, key: str, ttl: Optional[int] = None):
        """
        Decorator for caching function results.

        Usage:
            @cache_manager.cache_result("scan_results", ttl=3600)
            def expensive_function(arg1, arg2):
                return result
        """
        def decorator(func):
            def wrapper(*args, **kwargs):
                cache_key = f"{key}:{args}:{kwargs}"
                cached = self.get(cache_key)
                if cached is not None:
                    logger.debug(f"Cache hit for {key}")
                    return cached

                result = func(*args, **kwargs)
                self.set(cache_key, result, ttl)
                return result
            return wrapper
        return decorator


# Global cache manager instance
_cache_manager: Optional[CacheManager] = None


def initialize_cache(
    redis_host: str = "localhost",
    redis_port: int = 6379,
    redis_db: int = 0,
    redis_password: Optional[str] = None,
    use_redis: bool = True,
    ttl_default: int = 3600,
) -> CacheManager:
    """Initialize global cache manager"""
    global _cache_manager
    _cache_manager = CacheManager(
        redis_host=redis_host,
        redis_port=redis_port,
        redis_db=redis_db,
        redis_password=redis_password,
        use_redis=use_redis,
        ttl_default=ttl_default,
    )
    return _cache_manager


def get_cache_manager() -> Optional[CacheManager]:
    """Get global cache manager instance"""
    return _cache_manager
