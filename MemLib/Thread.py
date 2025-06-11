"""
Windows thread abstraction and control utilities.

This module provides a `Thread` class for managing Windows thread handles, priorities, suspension,
resumption, and joining, as well as a `Priority` enum with typical Windows thread priority values.

Features:
    * Open, close, suspend, resume, join, and terminate threads
    * Get/set thread priority with error handling
    * Context manager support for thread handle lifetime
    * Comparison by thread/process identity

Warning:
    Do not instantiate `Thread` directly—use the corresponding methods of the `Process` class to retrieve Thread objects.

Example:
    # Retrieve Thread objects via process.GetThreads() or similar.

References:
    https://learn.microsoft.com/en-us/windows/win32/procthread/process-and-thread-functions
    https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-threadentry32
"""

from __future__ import annotations

from ctypes.wintypes import LONG
from enum import IntEnum
from typing import TYPE_CHECKING

from MemLib.Constants import INFINITE, THREAD_ALL_ACCESS, WAIT_FAILED, WAIT_OBJECT_0
from MemLib.windows import (
    CloseHandle, GetExitCodeThread, GetThreadPriority, OpenThread, ResumeThread, SetThreadPriority, SuspendThread,
    TerminateThread, WaitForSingleObject, Win32Exception,
)



if TYPE_CHECKING:
    from MemLib.Process import Process

class Priority(IntEnum):
    Idle: int = -15
    Lowest: int = -2
    BelowNormal: int = -1
    Normal: int = 0
    AboveNormal: int = 1
    Highest: int = 2
    TimeCritical: int = 15
    Realtime_Idle: int = 16
    Unknown17: int = 17
    Unknown18: int = 18
    Unknown19: int = 19
    Unknown20: int = 20
    Unknown21: int = 21
    Realtime_Lowest: int = 22
    Realtime_BelowNormal: int = 23
    Realtime_Normal: int = 24
    Realtime_AboveNormal: int = 25
    Realtime_Highest: int = 26
    Realtime_TimeCritical: int = 31

class Thread:
    """
    Represents a Windows thread handle and provides control over its lifecycle.

    Warning:
        Do not instantiate directly. Retrieve Thread objects via Process methods.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-threadentry32
    """

    def __init__(self, thread_id: int, process: Process, handle: int = 0) -> None:
        """
        Initialize a Thread object.

        Args:
            thread_id (int): The thread identifier.
            process (Process): Reference to the owning process.
            handle (int, optional): An optional thread handle. Defaults to 0.
        """
        self._process: Process = process
        self._threadId: int = thread_id
        self._handle: int = handle

    def __del__(self) -> None:
        """
        Destructor. Closes the thread handle if open.
        """
        self.close()

    def __enter__(self) -> Thread:
        """
        Context manager entry. Opens the thread handle if not already open.

        Returns:
            Thread: Self reference.
        """
        if not self._handle:
            self.open()

        return self

    def __exit__(self, exception_type, exception_value, exception_traceback) -> None:
        """
        Context manager exit. Closes the thread handle.
        """
        self.close()

    @property
    def id(self) -> int:
        """
        Returns the thread identifier.

        Returns:
            int: The thread ID, compatible with CreateProcess return value.
        """
        return self._threadId

    @property
    def handle(self) -> int:
        """
        Returns a valid thread handle, opening it if necessary.

        Returns:
            int: The OS thread handle.
        """
        if not self._handle:
            self.open()
        return self._handle

    @property
    def process(self) -> Process:
        """
        Returns a reference to the owning process.

        Returns:
            Process: The owning process.
        """
        return self._process

    def get_priority(self) -> Priority:
        """
        Gets the current thread priority level.

        Returns:
            Priority: The thread's priority.

        Raises:
            Win32Exception: If querying the priority fails.
        """
        level = GetThreadPriority(self.handle)
        if level == 0x7FFFFFFF:
            raise Win32Exception()

        return Priority(LONG(level).value)

    def set_priority(self, priority: Priority | int) -> int:
        """
        Sets the thread's priority.

        Args:
            priority (Priority or int): The priority to set.

        Returns:
            int: Non-zero if success, zero otherwise.
        """
        return SetThreadPriority(self.handle, priority)

    def open(self, access: int = THREAD_ALL_ACCESS, inherit: bool = False) -> int:
        """
        Opens the thread with the given access rights.

        Args:
            access (int, optional): Access mask. Defaults to THREAD_ALL_ACCESS.
            inherit (bool, optional): If child processes inherit this handle. Defaults to False.

        Returns:
            int: Non-zero if successful, zero otherwise.
        """
        if self._handle != 0:
            self.close()

        self._handle = OpenThread(self._threadId, inherit, access)

        return self._handle != 0

    def close(self) -> bool:
        """
        Closes the thread handle if it is open.

        Returns:
            bool: True if the handle was closed or already closed, False on error.
        """
        if self._handle == 0:
            return True

        if CloseHandle(self._handle):
            self._handle = 0
            return True

        raise False

    def suspend(self) -> bool:
        """
        Suspends the thread.

        Returns:
            bool: True if suspended successfully, False otherwise.
        """
        return SuspendThread(self.handle) != 0

    def resume(self, max_depth=50) -> bool:
        """
        Resumes the thread if it is suspended.

        Args:
            max_depth (int, optional): Maximum resume attempts. Defaults to 50.

        Returns:
            bool: True if resumed successfully, False otherwise.
        """
        depth: int = 0
        while ResumeThread(self.handle) != 0:
            depth += 1
            if depth >= max_depth:
                return False

        return True

    def join(self, timeout: int = INFINITE) -> int:
        """
        Waits for the thread to exit, resuming if suspended.

        Args:
            timeout (int, optional): Timeout in milliseconds. Defaults to INFINITE.

        Returns:
            int: Exit code if finished, -1 if timed out.

        Raises:
            Win32Exception: If waiting fails.
        """
        self.resume()

        result: int = WaitForSingleObject(self.handle, timeout)
        if result == WAIT_FAILED:
            raise Win32Exception()

        if result == WAIT_OBJECT_0:
            return GetExitCodeThread(self.handle)

        return -1

    def terminate(self, exit_code: int = 0) -> bool:
        """
        Forces the thread to terminate.

        Args:
            exit_code (int, optional): Exit code for the thread. Defaults to 0.

        Returns:
            bool: True if the thread was terminated, False otherwise.
        """
        return TerminateThread(self.handle, exit_code)

    def __eq__(self, other: Thread) -> bool:
        """
        Compares thread objects by ID and process.

        Args:
            other (Thread): The other Thread object.

        Returns:
            bool: True if both refer to the same OS thread in the same process.
        """
        same_id: bool = self._threadId == other.id
        same_process_id: bool = self._process.process_id == other._process.process_id

        return same_id and same_process_id

    def __str__(self) -> str:
        """
        Returns a debug string representation.

        Returns:
            str: Debug string.
        """
        return f"Thread(id={self.id}, process='{self.process.process_id}')"
