"""Centralized Asynchronous HTTP Client with retries, rate limiting, and backoff."""

from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import Any, Dict, Optional
import httpx
from detecti.config import settings

logger = logging.getLogger("detecti.http")


class AsyncHTTPClient:
    """Production-grade asynchronous HTTP client with rate-limiting and retry logic."""

    def __init__(
        self,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        backoff_factor: Optional[float] = None,
        concurrency_limit: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.timeout = timeout or settings.http_timeout
        self.max_retries = max_retries or settings.http_max_retries
        self.backoff_factor = backoff_factor or settings.http_backoff_factor
        self.concurrency_limit = concurrency_limit or settings.http_concurrency_limit

        default_headers = {
            "User-Agent": settings.user_agent,
            "Accept": "application/json, text/plain, */*",
        }
        if headers:
            default_headers.update(headers)

        self._headers = default_headers
        self._client: Optional[httpx.AsyncClient] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._domain_locks: Dict[str, asyncio.Lock] = {}
        self._domain_last_request: Dict[str, float] = {}

    async def get_client(self) -> httpx.AsyncClient:
        """Get or initialize the underlying httpx.AsyncClient."""
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.concurrency_limit)
            
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout, connect=10.0),
                headers=self._headers,
                follow_redirects=True,
                limits=httpx.Limits(
                    max_connections=50,
                    max_keepalive_connections=20,
                    keepalive_expiry=30.0,
                ),
            )
        return self._client

    async def close(self) -> None:
        """Close the underlying client session."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> AsyncHTTPClient:
        await self.get_client()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    def _get_domain_lock(self, host: str) -> asyncio.Lock:
        if host not in self._domain_locks:
            self._domain_locks[host] = asyncio.Lock()
        return self._domain_locks[host]

    async def _enforce_domain_rate_limit(self, url: str) -> None:
        """Enforce specific delays for rate-limited endpoints like NVD or HackerTarget."""
        parsed_url = httpx.URL(url)
        host = parsed_url.host

        delay = 0.0
        if "services.nvd.nist.gov" in host:
            delay = (
                settings.nvd_delay_with_key
                if settings.nvd_api_key
                else settings.nvd_delay_without_key
            )
        elif "hackertarget.com" in host:
            delay = settings.hackertarget_delay
        elif "shodan.io" in host:
            delay = settings.shodan_delay

        if delay > 0:
            lock = self._get_domain_lock(host)
            async with lock:
                now = time.monotonic()
                last_time = self._domain_last_request.get(host, 0.0)
                elapsed = now - last_time
                if elapsed < delay:
                    wait_time = delay - elapsed
                    await asyncio.sleep(wait_time)
                self._domain_last_request[host] = time.monotonic()

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        max_retry_delay: float = 8.0,
        raise_for_status: bool = True,
    ) -> httpx.Response:
        """Execute an HTTP request with automatic retries, backoff, and concurrency control."""
        client = await self.get_client()
        req_timeout = timeout or self.timeout
        effective_retries = max_retries if max_retries is not None else self.max_retries

        for attempt in range(1, effective_retries + 1):
            await self._enforce_domain_rate_limit(url)

            try:
                async with self._semaphore:
                    response = await client.request(
                        method=method,
                        url=url,
                        headers=headers,
                        params=params,
                        json=json,
                        data=data,
                        timeout=req_timeout,
                    )

                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After")
                    try:
                        sleep_time = float(retry_after) if retry_after else (self.backoff_factor * (2 ** (attempt - 1)) + random.uniform(0.5, 2.0))
                    except (ValueError, TypeError):
                        sleep_time = self.backoff_factor * (2 ** (attempt - 1)) + random.uniform(0.5, 2.0)

                    if sleep_time > max_retry_delay:
                        logger.warning(
                            f"HTTP 429 (Rate Limit) on {url}. Server requested {sleep_time:.1f}s delay (exceeds {max_retry_delay}s threshold). Skipping automatic wait."
                        )
                        if raise_for_status:
                            response.raise_for_status()
                        return response

                    if attempt < effective_retries:
                        logger.info(f"Rate limited (HTTP 429) on {url}. Backing off for {sleep_time:.1f}s (attempt {attempt}/{effective_retries})...")
                        await asyncio.sleep(sleep_time)
                        continue

                if response.status_code in (500, 502, 503, 504):
                    if attempt < effective_retries:
                        sleep_time = self.backoff_factor * (2 ** (attempt - 1)) + random.uniform(0.1, 0.5)
                        await asyncio.sleep(sleep_time)
                        continue

                if raise_for_status:
                    response.raise_for_status()

                return response

            except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout, httpx.RemoteProtocolError) as exc:
                if attempt >= effective_retries:
                    logger.warning(f"HTTP request to {url} failed after {effective_retries} attempts: {exc}")
                    raise
                sleep_time = self.backoff_factor * (2 ** (attempt - 1)) + random.uniform(0.1, 0.5)
                await asyncio.sleep(sleep_time)

        raise httpx.RequestError(f"Failed to complete request to {url} after {effective_retries} attempts")

    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        max_retry_delay: float = 8.0,
        raise_for_status: bool = True,
    ) -> httpx.Response:
        """Convenience GET request."""
        return await self.request(
            method="GET",
            url=url,
            headers=headers,
            params=params,
            timeout=timeout,
            max_retries=max_retries,
            max_retry_delay=max_retry_delay,
            raise_for_status=raise_for_status,
        )

    async def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        max_retry_delay: float = 8.0,
        raise_for_status: bool = True,
    ) -> httpx.Response:
        """Convenience POST request."""
        return await self.request(
            method="POST",
            url=url,
            headers=headers,
            params=params,
            json=json,
            data=data,
            timeout=timeout,
            max_retries=max_retries,
            max_retry_delay=max_retry_delay,
            raise_for_status=raise_for_status,
        )

    async def get_json(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        max_retry_delay: float = 8.0,
    ) -> Optional[Any]:
        """Fetch URL and parse JSON payload safely. Returns None on 404 or non-critical errors."""
        try:
            resp = await self.get(
                url=url,
                headers=headers,
                params=params,
                timeout=timeout,
                max_retries=max_retries,
                max_retry_delay=max_retry_delay,
                raise_for_status=False,
            )
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return None
            elif resp.status_code == 429:
                logger.warning(f"HTTP 429 Rate Limit encountered for {url}")
                return None
            else:
                logger.debug(f"HTTP {resp.status_code} for GET {url}")
                return None
        except Exception as err:
            logger.debug(f"Error fetching JSON from {url}: {err}")
            return None

    async def post_json(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
        timeout: Optional[float] = None,
    ) -> Optional[Any]:
        """Send POST request and parse JSON payload safely. Returns None on 404 or non-critical errors."""
        try:
            resp = await self.post(
                url=url,
                headers=headers,
                params=params,
                json=json,
                data=data,
                timeout=timeout,
                raise_for_status=False,
            )
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return None
            else:
                logger.debug(f"HTTP {resp.status_code} for POST {url}: {resp.text}")
                return None
        except Exception as err:
            logger.debug(f"Error fetching JSON from POST {url}: {err}")
            return None


# Global HTTP client instance
http_client = AsyncHTTPClient()
