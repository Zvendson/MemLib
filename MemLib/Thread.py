"""
:platform: Windows

Describes an entry from a list of the modules belonging to the specified process.

.. warning::
  Don't instantiate this class.\n
  Use the methods inside :py:class:`~eve.MemLib.process.Process` to retrieve a Module object instead:\n
  - :py:meth:`~eve.MemLib.process.Process.GetModules`
  - :py:meth:`~eve.MemLib.process.Process.GetMainModule`
  - :py:meth:`~eve.MemLib.process.Process.GetModule`
"""

from __future__ import annotations

from ctypes.wintypes import LONG
from enum import IntEnum
from typing import TYPE_CHECKING

from MemLib.Constants import INFINITE, THREAD_ALL_ACCESS, WAIT_FAILED, WAIT_OBJECT_0
from MemLib.Kernel32 import (
    CloseHandle, GetExitCodeThread, GetThreadPriority, OpenThread, ResumeThread, SetThreadPriority, SuspendThread,
    TerminateThread, WaitForSingleObject, Win32Exception,
)


if TYPE_CHECKING:
    from MemLib.Process import Process


class Priority(IntEnum):
    Idle = -15
    Lowest = -2
    BelowNormal = -1
    Normal = 0
    AboveNormal = 1
    Highest = 2
    TimeCritical = 15
    Realtime_Idle = 16
    Unknown17 = 17
    Unknown18 = 18
    Unknown19 = 19
    Unknown20 = 20
    Unknown21 = 21
    Realtime_Lowest = 22
    Realtime_BelowNormal = 23
    Realtime_Normal = 24
    Realtime_AboveNormal = 25
    Realtime_Highest = 26
    Realtime_TimeCritical = 31


class Thread:
    """
    :param thread_id: The thread buffer struct
    :param process: The thread's process

    .. note:: **See also:**
        `THREADENTRY32 <https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-threadentry32>`_
    """

    def __init__(self, thread_id: int, process: Process, handle: int = 0):
        self._process: Process = process
        self._threadId: int    = thread_id
        self._handle: int      = handle

    def __del__(self):
        self.close()

    def __enter__(self):
        if not self._handle:
            self.open()

        return self

    def __exit__(self, exception_type, exception_value, exception_traceback):
        self.close()

    def get_id(self) -> int:
        """
        :returns: The thread identifier, compatible with the thread identifier returned by the CreateProcess function.
        """

        return self._threadId

    def get_handle(self) -> int:
        if not self._handle:
            self.open()
        return self._handle

    def get_priority(self) -> Priority:
        """
        :returns: The thread's priority level.
        """

        level = GetThreadPriority(self.get_handle())
        if level == 0x7FFFFFFF:
            raise Win32Exception()

        return Priority(LONG(level).value)

    def set_priority(self, priority: Priority | int) -> int:
        """
        :returns: True if priority could be changed. False otherwise.
        """

        return SetThreadPriority(self.get_handle(), priority)

    def get_process(self) -> Process:
        """
        :returns: a reference to its :py:class:`~process.Process`.
        """

        return self._process

    def open(self, access: int = THREAD_ALL_ACCESS, inherit: bool = False) -> int:
        """
        Opens the thread with the specified access rights.

        :param access: The access rights.
        :param inherit: Determines if processes created by this process will inherit the handle or not.
        :returns: True if the thread was opened successfully, False otherwise.
        """

        if self._handle != 0:
            self.close()

        self._handle = OpenThread(self._threadId, inherit, access)

        return self._handle != 0

    def close(self) -> bool:
        """
        Closes the thread handle.
        :returns: True if the thread was closed successfully, False otherwise.
        """

        if self._handle == 0:
            return True

        if CloseHandle(self._handle):
            self._handle = 0
            return True

        raise False

    def suspend(self) -> bool:
        """
        Resumes the thread.
        :returns: True if the thread was resumed successfully, False otherwise.
        """

        return SuspendThread(self.get_handle()) != 0

    def resume(self, max_depth = 50) -> bool:
        """
        Resumes the thread.
        :returns: True if the thread was resumed successfully, False otherwise.
        """

        depth: int = 0
        while ResumeThread(self.get_handle()) != 0:
            depth += 1
            if depth >= max_depth:
                return False

        return True

    def join(self, timeout: int = INFINITE) -> int:
        """
        Resumes the thread if suspended and waits until thread exited or the timout ran out.

        :param timeout: If waitExecution is True, this specifies the max wait time the function waits.
        :raises Win32Exception: If the wait failed.
        :returns: The exit code if successful waited for the thread, -1 otherwise (timeout as well).
        """

        self.resume()

        result: int = WaitForSingleObject(self.get_handle(), timeout)
        if result == WAIT_FAILED:
            raise Win32Exception()

        if result == WAIT_OBJECT_0:
            return GetExitCodeThread(self.get_handle())

        return -1

    def terminate(self, exit_code: int = 0) -> bool:
        return TerminateThread(self.get_handle(), exit_code)

    def __eq__(self, other: Thread) -> bool:
        same_id: bool         = self._threadId == other.get_id()
        same_process_id: bool = self._process.get_process_id() == other._process.get_process_id()

        return same_id and same_process_id

    def __repr__(self) -> str:
        return f"Thread(id={self.get_id()}, process='{self._process.get_process_id()}')"



