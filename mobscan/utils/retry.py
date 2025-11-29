"""
Retry Logic with Exponential Backoff.

Provides decorators and utilities for retrying operations with
configurable backoff strategies.
"""

import time
import logging
from typing import Callable, Any, Type, Tuple, Optional, TypeVar
from functools import wraps
import random


logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def exponential_backoff(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    jitter: bool = True,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
) -> Callable[[F], F]:
    """
    Decorator for retrying a function with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Base delay in seconds
        max_delay: Maximum delay cap in seconds
        jitter: Add random jitter to delay
        exceptions: Tuple of exceptions to catch

    Returns:
        Decorated function that retries on failure

    Example:
        @exponential_backoff(max_retries=3, base_delay=1.0)
        def call_external_api():
            return requests.get("https://api.example.com")
    """

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            attempt = 0
            last_exception = None

            while attempt <= max_retries:
                try:
                    result = func(*args, **kwargs)
                    if attempt > 0:
                        logger.info(
                            f"Function {func.__name__} succeeded after {attempt} retries"
                        )
                    return result
                except exceptions as e:
                    last_exception = e
                    attempt += 1

                    if attempt > max_retries:
                        logger.error(
                            f"Function {func.__name__} failed after {max_retries} retries: {e}"
                        )
                        raise

                    # Calculate delay
                    delay = base_delay * (2 ** (attempt - 1))
                    delay = min(delay, max_delay)

                    # Add jitter
                    if jitter:
                        delay += random.uniform(0, delay * 0.1)

                    logger.warning(
                        f"Function {func.__name__} failed (attempt {attempt}/{max_retries}), "
                        f"retrying in {delay:.2f}s: {e}"
                    )
                    time.sleep(delay)

            # Should not reach here
            if last_exception:
                raise last_exception

        return wrapper  # type: ignore

    return decorator


def retry_with_backoff(
    func: Callable,
    *args,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    jitter: bool = True,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
    **kwargs,
) -> Any:
    """
    Retry a function call with exponential backoff.

    Args:
        func: Function to call
        args: Positional arguments for function
        max_retries: Maximum number of retries
        base_delay: Base delay in seconds
        max_delay: Maximum delay cap
        jitter: Add random jitter
        exceptions: Exceptions to catch and retry
        kwargs: Keyword arguments for function

    Returns:
        Function result on success

    Raises:
        Last exception if all retries fail
    """
    attempt = 0
    last_exception = None

    while attempt <= max_retries:
        try:
            return func(*args, **kwargs)
        except exceptions as e:
            last_exception = e
            attempt += 1

            if attempt > max_retries:
                logger.error(
                    f"Function call failed after {max_retries} retries: {e}"
                )
                raise

            # Calculate delay
            delay = base_delay * (2 ** (attempt - 1))
            delay = min(delay, max_delay)

            # Add jitter
            if jitter:
                delay += random.uniform(0, delay * 0.1)

            logger.warning(
                f"Function call failed (attempt {attempt}/{max_retries}), "
                f"retrying in {delay:.2f}s: {e}"
            )
            time.sleep(delay)

    if last_exception:
        raise last_exception


class RetryableSession:
    """Session wrapper that applies retry logic to method calls"""

    def __init__(
        self,
        session: Any,
        max_retries: int = 3,
        base_delay: float = 1.0,
        exceptions: Tuple[Type[Exception], ...] = (Exception,),
    ):
        """
        Initialize retryable session.

        Args:
            session: Session object (e.g., requests.Session)
            max_retries: Maximum retries
            base_delay: Base delay in seconds
            exceptions: Exceptions to retry on
        """
        self.session = session
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.exceptions = exceptions

    def request(self, method: str, url: str, **kwargs) -> Any:
        """Make HTTP request with retry logic"""
        return retry_with_backoff(
            self.session.request,
            method,
            url,
            max_retries=self.max_retries,
            base_delay=self.base_delay,
            exceptions=self.exceptions,
            **kwargs,
        )

    def get(self, url: str, **kwargs) -> Any:
        """GET request with retry"""
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Any:
        """POST request with retry"""
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> Any:
        """PUT request with retry"""
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> Any:
        """DELETE request with retry"""
        return self.request("DELETE", url, **kwargs)


class CircuitBreaker:
    """Circuit breaker pattern for failing services"""

    def __init__(
        self,
        failure_threshold: int = 5,
        timeout: int = 60,
        expected_exception: Type[Exception] = Exception,
    ):
        """
        Initialize circuit breaker.

        Args:
            failure_threshold: Failures before opening circuit
            timeout: Seconds before attempting recovery
            expected_exception: Exception type to track
        """
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.expected_exception = expected_exception
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "closed"  # closed, open, half-open

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Call function with circuit breaker protection.

        Args:
            func: Function to call
            args: Positional arguments
            kwargs: Keyword arguments

        Returns:
            Function result

        Raises:
            RuntimeError: If circuit is open
        """
        if self.state == "open":
            if time.time() - self.last_failure_time > self.timeout:
                logger.info("Circuit breaker entering half-open state")
                self.state = "half-open"
            else:
                raise RuntimeError("Circuit breaker is open")

        try:
            result = func(*args, **kwargs)
            if self.state == "half-open":
                logger.info("Circuit breaker closing (service recovered)")
                self.state = "closed"
                self.failure_count = 0
            return result
        except self.expected_exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()

            if self.failure_count >= self.failure_threshold:
                logger.error(
                    f"Circuit breaker opening after {self.failure_count} failures"
                )
                self.state = "open"

            raise

    def is_closed(self) -> bool:
        """Check if circuit is closed"""
        return self.state == "closed"

    def is_open(self) -> bool:
        """Check if circuit is open"""
        return self.state == "open"

    def reset(self):
        """Reset circuit breaker"""
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "closed"
        logger.info("Circuit breaker reset")
