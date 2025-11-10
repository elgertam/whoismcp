"""
Concurrent lookup service using AnyIO's structured concurrency.
Efficiently handles bulk lookups without overwhelming servers.
"""

import asyncio
from typing import Any, AsyncIterator, Optional, Callable
from dataclasses import dataclass
from datetime import datetime

import anyio
import structlog
from anyio import create_task_group, Semaphore, create_memory_object_stream

from ..config import Config
from ..services.whois_service import WhoisService
from ..services.rdap_service import RDAPService
from ..services.cache_service import CacheService
from ..utils.validators import is_valid_domain, is_valid_ip

logger = structlog.get_logger(__name__)


@dataclass
class LookupTask:
    """Represents a single lookup task."""
    target: str
    lookup_type: str  # 'whois' or 'rdap'
    target_type: str  # 'domain' or 'ip'
    use_cache: bool = True
    brief: bool = False
    fields: Optional[list[str]] = None


@dataclass
class LookupResult:
    """Result of a lookup operation."""
    target: str
    status: str  # 'success', 'error', 'cached'
    data: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    timestamp: datetime = None
    from_cache: bool = False
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class ConcurrentLookupService:
    """Service for handling concurrent lookups with rate limiting."""
    
    def __init__(self, config: Config):
        self.config = config
        self.whois_service = WhoisService(config)
        self.rdap_service = RDAPService(config)
        self.cache_service = CacheService(config)
        
        # Rate limiting configuration
        self.max_concurrent_whois = config.max_concurrent_lookups or 5
        self.max_concurrent_rdap = config.max_concurrent_lookups or 10
        self.delay_between_requests = config.delay_between_requests or 0.1
        
        # Semaphores for rate limiting
        self.whois_semaphore = Semaphore(self.max_concurrent_whois)
        self.rdap_semaphore = Semaphore(self.max_concurrent_rdap)
        
        # Track active lookups
        self.active_lookups = 0
        self.total_lookups = 0
        self.failed_lookups = 0
    
    async def _perform_single_lookup(self, task: LookupTask) -> LookupResult:
        """Perform a single lookup with appropriate service."""
        try:
            # Check cache first
            if task.use_cache:
                cache_key = f"{task.lookup_type}:{task.target}"
                cached_data = await self.cache_service.get(cache_key)
                if cached_data:
                    logger.debug(f"Cache hit for {task.target}")
                    return LookupResult(
                        target=task.target,
                        status="success",
                        data=cached_data,
                        from_cache=True
                    )
            
            # Select appropriate semaphore
            semaphore = self.whois_semaphore if task.lookup_type == "whois" else self.rdap_semaphore
            
            async with semaphore:
                self.active_lookups += 1
                try:
                    # Add small delay to avoid overwhelming servers
                    await anyio.sleep(self.delay_between_requests)
                    
                    # Perform lookup
                    if task.lookup_type == "whois":
                        service = self.whois_service
                    else:
                        service = self.rdap_service
                    
                    if task.target_type == "domain":
                        result = await service.lookup_domain(task.target)
                    else:
                        result = await service.lookup_ip(task.target)
                    
                    # Cache successful result
                    if task.use_cache and result.get("success"):
                        cache_key = f"{task.lookup_type}:{task.target}"
                        await self.cache_service.set(cache_key, result)
                    
                    return LookupResult(
                        target=task.target,
                        status="success" if result.get("success") else "error",
                        data=result,
                        error=result.get("error")
                    )
                    
                finally:
                    self.active_lookups -= 1
                    self.total_lookups += 1
                    
        except Exception as e:
            self.failed_lookups += 1
            logger.error(f"Lookup failed for {task.target}", error=str(e))
            return LookupResult(
                target=task.target,
                status="error",
                error=str(e)
            )
    
    async def bulk_lookup(
        self,
        targets: list[str],
        lookup_type: str = "whois",
        use_cache: bool = True,
        max_concurrent: Optional[int] = None,
        progress_callback: Optional[Callable[[LookupResult], None]] = None
    ) -> AsyncIterator[LookupResult]:
        """
        Perform bulk lookups with structured concurrency.
        Yields results as they complete.
        """
        # Override max concurrent if specified
        if max_concurrent:
            semaphore = Semaphore(max_concurrent)
        else:
            semaphore = self.whois_semaphore if lookup_type == "whois" else self.rdap_semaphore
        
        # Create tasks
        tasks = []
        for target in targets:
            # Determine target type
            if is_valid_domain(target):
                target_type = "domain"
            elif is_valid_ip(target):
                target_type = "ip"
            else:
                # Yield error immediately for invalid targets
                result = LookupResult(
                    target=target,
                    status="error",
                    error=f"Invalid target: {target}"
                )
                if progress_callback:
                    progress_callback(result)
                yield result
                continue
            
            tasks.append(LookupTask(
                target=target,
                lookup_type=lookup_type,
                target_type=target_type,
                use_cache=use_cache
            ))
        
        # Process tasks with structured concurrency
        async with create_task_group() as tg:
            # Create stream for results
            send_stream, receive_stream = create_memory_object_stream(max_buffer_size=len(tasks))
            
            async def process_task(task: LookupTask):
                """Process a single task and send result to stream."""
                result = await self._perform_single_lookup(task)
                if progress_callback:
                    progress_callback(result)
                await send_stream.send(result)
            
            # Start all tasks
            for task in tasks:
                tg.start_soon(process_task, task)
            
            # Close send stream when all tasks complete
            async def close_when_done():
                # Wait for all tasks to complete
                await anyio.sleep(0)  # Let tasks start
                while self.active_lookups > 0:
                    await anyio.sleep(0.1)
                await send_stream.aclose()
            
            tg.start_soon(close_when_done)
            
            # Yield results as they become available
            async with receive_stream:
                async for result in receive_stream:
                    yield result
    
    async def parallel_lookup(
        self,
        targets: list[str],
        use_both_services: bool = True,
        use_cache: bool = True,
        max_concurrent: Optional[int] = None
    ) -> dict[str, dict[str, LookupResult]]:
        """
        Perform lookups using both Whois and RDAP in parallel.
        Returns a dictionary mapping targets to their results from both services.
        """
        results = {}
        
        async with create_task_group() as tg:
            # Create stream for results
            send_stream, receive_stream = create_memory_object_stream(max_buffer_size=len(targets) * 2)
            
            async def lookup_both(target: str):
                """Lookup target with both services."""
                # Determine target type
                if is_valid_domain(target):
                    target_type = "domain"
                elif is_valid_ip(target):
                    target_type = "ip"
                else:
                    await send_stream.send((target, "error", LookupResult(
                        target=target,
                        status="error",
                        error=f"Invalid target: {target}"
                    )))
                    return
                
                # Perform both lookups
                if use_both_services:
                    # Whois lookup
                    whois_task = LookupTask(
                        target=target,
                        lookup_type="whois",
                        target_type=target_type,
                        use_cache=use_cache
                    )
                    whois_result = await self._perform_single_lookup(whois_task)
                    await send_stream.send((target, "whois", whois_result))
                    
                    # RDAP lookup
                    rdap_task = LookupTask(
                        target=target,
                        lookup_type="rdap",
                        target_type=target_type,
                        use_cache=use_cache
                    )
                    rdap_result = await self._perform_single_lookup(rdap_task)
                    await send_stream.send((target, "rdap", rdap_result))
                else:
                    # Just whois
                    whois_task = LookupTask(
                        target=target,
                        lookup_type="whois",
                        target_type=target_type,
                        use_cache=use_cache
                    )
                    whois_result = await self._perform_single_lookup(whois_task)
                    await send_stream.send((target, "whois", whois_result))
            
            # Start tasks for all targets
            for target in targets:
                tg.start_soon(lookup_both, target)
            
            # Close stream when done
            async def close_when_done():
                await anyio.sleep(0)  # Let tasks start
                while self.active_lookups > 0:
                    await anyio.sleep(0.1)
                await send_stream.aclose()
            
            tg.start_soon(close_when_done)
            
            # Collect results
            async with receive_stream:
                async for target, service_type, result in receive_stream:
                    if target not in results:
                        results[target] = {}
                    results[target][service_type] = result
        
        return results
    
    def get_statistics(self) -> dict[str, Any]:
        """Get service statistics."""
        return {
            "active_lookups": self.active_lookups,
            "total_lookups": self.total_lookups,
            "failed_lookups": self.failed_lookups,
            "success_rate": (self.total_lookups - self.failed_lookups) / self.total_lookups if self.total_lookups > 0 else 0,
            "cache_stats": {
                "size": len(self.cache_service._cache),
                "max_size": self.config.cache_max_size
            }
        }