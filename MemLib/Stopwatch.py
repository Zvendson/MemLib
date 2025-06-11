"""
Simple stopwatch utility for measuring elapsed time and expiration in Python.

This module provides a `Stopwatch` class to time operations, measure elapsed time,
check expiration, and restart timing intervals. Useful for timeout logic, benchmarks,
and periodic tasks.

Features:
    * Track elapsed time in seconds or milliseconds
    * Check if timer is running or expired
    * Restart with optional new duration

Example:
    sw = Stopwatch(3.0)
    while sw.running:
        if not do_something():
            break
    print(f"Elapsed: {sw.elapsed_time:.2f}s")

References:
    https://docs.python.org/3/library/time.html
"""

import time



class Stopwatch:
    """
    A simple stopwatch utility for measuring elapsed time and expiration logic.

    Args:
        watch_time (float): Duration in seconds until the stopwatch is considered expired.
    """

    def __init__(self, watch_time: float) -> None:
        """
        Initializes the stopwatch.

        Args:
            watch_time (float): Duration in seconds until the stopwatch is considered expired.
        """
        self._watch_time: float = watch_time
        self._time_started: float = time.time()

    @property
    def watch_time(self) -> float:
        """
        Returns the duration in seconds until the stopwatch expires.

        Returns:
            float: The expiration interval in seconds.
        """
        return self._watch_time

    @property
    def time_started(self) -> float:
        """
        Returns the epoch timestamp when the stopwatch was started or last restarted.

        Returns:
            float: The epoch time in seconds.
        """
        return self._time_started

    @property
    def expired(self) -> bool:
        """
        Checks whether the stopwatch has expired.

        Returns:
            bool: True if elapsed time >= watch_time, otherwise False.
        """
        return self.elapsed_time >= self._watch_time

    @property
    def running(self) -> bool:
        """
        Indicates whether the stopwatch is still running (i.e., not expired).

        Returns:
            bool: True if elapsed time < watch_time (not expired), otherwise False.
        """
        return self.elapsed_time < self._watch_time

    @property
    def elapsed_time(self) -> float:
        """
        Returns the elapsed time since the stopwatch was started.

        Returns:
            float: Elapsed time in seconds.
        """
        return time.time() - self._time_started

    @property
    def elapsed_time_in_ms(self) -> int:
        """
        Returns the elapsed time since the stopwatch was started, in milliseconds.

        Returns:
            int: Elapsed time in milliseconds.
        """
        return int(self.elapsed_time * 1000.0)

    def restart(self, new_time: float = None) -> None:
        """
        Restarts the stopwatch, optionally updating the expiration interval.

        Args:
            new_time (float, optional): New expiration interval in seconds. If None, keeps the current watch_time.

        Returns:
            None
        """
        if new_time is not None:
            self._watch_time = new_time
        self._time_started = time.time()

    def __str__(self) -> str:
        """
        Returns a concise summary of the stopwatch state.

        Returns:
            str: Human-readable summary.
        """
        return (f"Stopwatch(watch_time={self._watch_time:.3f}s, elapsed={self.elapsed_time:.3f}s expired="
                f"{self.expired})")

    def __repr__(self) -> str:
        """
        Returns a detailed string representation for debugging.

        Returns:
            str: Full internal state as string.
        """
        return (f"Stopwatch(watch_time={self._watch_time:.3f}, time_started={self.time_started:.3f}s, elapsed_time="
                f"{self.elapsed_time:.3f}s, in_ms={self.elapsed_time_in_ms}s, expired={self.expired})")
