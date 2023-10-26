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

from MemLib.Constants import THREAD_ALL_ACCESS
from MemLib.Kernel32 import (
    CloseHandle, GetThreadPriority, OpenThread, ResumeThread, SetThreadPriority, SuspendThread,
    TerminateThread, Win32Exception,
)
from MemLib.Structs import THREADENTRY32



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
    :param thread: The thread buffer struct
    :param process: The thread's process

    .. note:: **See also:**
        `THREADENTRY32 <https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-threadentry32>`_
    """

    def __init__(self, thread: THREADENTRY32, process: Process, handle: int = 0):
        self._process: Process    = process
        self._threadId: int       = thread.th32ThreadID
        self._handle: int         = handle

        if not self._handle:
            self.Open()

    def __enter__(self):
        if not self._handle:
            self.Open()

        return self

    def __exit__(self, exception_type, exception_value, exception_traceback):
        self.Close()

    def GetId(self) -> int:
        """
        :returns: The thread identifier, compatible with the thread identifier returned by the CreateProcess function.
        """

        return self._threadId

    def GetPriority(self) -> Priority:
        """
        :returns: The thread's priority level.
        """

        level = GetThreadPriority(self._handle)
        if level == 0x7FFFFFFF:
            raise Win32Exception()

        return Priority(LONG(level).value)

    def SetPriority(self, priority: Priority | int) -> int:
        """
        :returns: True if priority could be changed. False otherwise.
        """

        return SetThreadPriority(self._handle, priority)

    def GetProcess(self) -> Process:
        """
        :returns: a reference to its :py:class:`~process.Process`.
        """

        return self._process

    def Open(self, access: int = THREAD_ALL_ACCESS) -> int:
        """
        Opens the thread with the specified access rights.

        :param access: The access rights.
        :returns: True if the thread was opened successfully, False otherwise.
        """

        if self._handle != 0:
            self.Close()

        self._handle = OpenThread(self._threadId, False, access)

        return self._handle != 0

    def Close(self) -> bool:
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

    def Suspend(self) -> bool:
        """
        Resumes the thread.
        :returns: True if the thread was resumed successfully, False otherwise.
        """

        return SuspendThread(self._handle) != 0

    def Resume(self, maxDepth = 50) -> bool:
        """
        Resumes the thread.
        :returns: True if the thread was resumed successfully, False otherwise.
        """

        depth = 0
        while ResumeThread(self._handle) != 0:
            depth += 1
            if depth >= maxDepth:
                return False

        return True

    def Terminate(self, exitCode: int = 0) -> bool:
        return TerminateThread(self._handle, exitCode)

    def __eq__(self, other: Thread) -> bool:
        sameId: bool        = (self._threadId == other.GetId())
        sameProcessId: bool = (self._process.GetProcessId() == other._process.GetProcessId())

        return sameId and sameProcessId

    def __repr__(self) -> str:
        return (f"Thread(id={self.GetId()}, priority={self.GetPriority().name}, process='"
                f"{self._process.GetProcessId()}')")
