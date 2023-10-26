"""
:platform: Windows
"""

from __future__ import annotations

from ctypes import WINFUNCTYPE
from ctypes.wintypes import (
    BYTE, CHAR, DWORD, HANDLE, HMODULE, HWND, INT, LONG, LPARAM, LPCSTR, LPSTR, LPVOID, MAX_PATH, PBYTE, UINT, ULONG,
    WORD, WPARAM,
)

from MemLib.Struct import Struct



class StartupInfoW(Struct):
    """
    Specifies the window station, desktop, standard handles, and appearance of the main window for a process at creation
    time.

    **See also:** `STARTUPINFOW <https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns
    -processthreadsapi-startupinfow>`_
    """

    _fields_ = [
        ('cb', DWORD),
        ('lpReserved', LPSTR),
        ('lpDesktop', LPSTR),
        ('lpTitle', LPSTR),
        ('dwX', DWORD),
        ('dwY', DWORD),
        ('dwXSize', DWORD),
        ('dwYSize', DWORD),
        ('dwXCountChars', DWORD),
        ('dwYCountChars', DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags', DWORD),
        ('wShowWindow', WORD),
        ('cbReserved2', WORD),
        ('lpReserved2', PBYTE),
        ('hStdInput', HANDLE),
        ('hStdOutput', HANDLE),
        ('hStdError', HANDLE)
    ]


class ProcessInfo(Struct):
    """
    Contains information about a newly created process and its primary thread. It is used with the CreateProcess.

    **See also:** `PROCESS_INFORMATION <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/
    ns-processthreadsapi-process_information>`_
    """

    _fields_ = [
        ('hProcess', HANDLE),
        ('hThread', HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId', DWORD)
    ]


class ProcessBasicInformation(Struct):
    """
    Contains basic information about a process.

    **See also:** `PROCESS_BASIC_INFORMATION
    <https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
    #process_basic_information>`_
    """

    _fields_ = [
        ('ExitStatus', DWORD),
        ('PebBaseAddress', LPVOID),
        ('AffinityMask', ULONG),
        ('BasePriority', DWORD),
        ('UniqueProcessId', ULONG),
        ('InheritedFromUniqueProcessId', ULONG)
    ]


class PEB(Struct):
    """
    Contains process information.

    **See also:** `PEB <https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb>`_
    """

    _fields_ = [
        ('InheritedAddressSpace', BYTE),
        ('ReadImageFileExecOptions', BYTE),
        ('BeingDebugged', BYTE),
        ('BitField', BYTE),
        ('Mutant', LPVOID),
        ('ImageBaseAddress', LPVOID)
        # And more but not interested in them
    ]


class PROCESSENTRY32(Struct):
    """
    Contains information about a process encountered by an application that traverses processes throughout the system.

    **See also:** `PROCESSENTRY32 <https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32
    -processentry32>`_
    """

    _fields_ = [
        ('dwSize', DWORD),
        ('cntUsage', DWORD),
        ('th32ProcessID', DWORD),
        ('th32DefaultHeapID', ULONG),
        ('th32ModuleID', DWORD),
        ('cntThreads', DWORD),
        ('th32ParentProcessID', DWORD),
        ('pcPriClassBase', LONG),
        ('dwFlags', DWORD),
        ('szExeFile', CHAR * MAX_PATH)
    ]


class MODULEENTRY32(Struct):
    """
    Contains information about a module in a process's address space.

    **See also:** `MODULEENTRY32 <https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32
    -moduleentry32>`_
    """

    _fields_ = [
        ('dwSize', DWORD),
        ('th32ModuleID', DWORD),
        ('th32ProcessID', DWORD),
        ('GlblcntUsage', DWORD),
        ('ProccntUsage', DWORD),
        ('modBaseAddr', ULONG),
        ('modBaseSize', DWORD),
        ('hModule', HMODULE),
        ('szModule', CHAR * 256),
        ('szExePath', CHAR * MAX_PATH)
    ]


class THREADENTRY32(Struct):
    """
    Describes an entry from a list of the threads executing in the system when a snapshot was taken.

    **See also:** `THREADENTRY32 <https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32
    -threadentry32>`_
    """

    _fields_ = [
        ('dwSize', DWORD),
        ('cntUsage', DWORD),
        ('th32ThreadID', DWORD),
        ('th32OwnerProcessID', DWORD),
        ('tpBasePri', LONG),
        ('tpDeltaPri', LONG),
        ('dwFlags', DWORD),
    ]


WNDPROC = WINFUNCTYPE(LONG, HWND, UINT, LONG, DWORD)

class WNDCLASS(Struct):
    """
    Contains the window class attributes that are registered by the RegisterClass function.

    This structure has been superseded by the WNDCLASSEX structure used with the RegisterClassEx function. You can
    still use WNDCLASS and RegisterClass if you do not need to set the small icon associated with the window class.

    **See also:** `WNDCLASS <https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-wndclassa>`_
    """

    _fields_ = [
        ('style', DWORD),
        ('lpfnWndProc', WNDPROC),
        ('cbClsExtra', INT),
        ('cbWndExtra', INT),
        ('hInstance', HANDLE),
        ('hIcon', HANDLE),
        ('hCursor', HANDLE),
        ('hbrBackground', HANDLE),
        ('lpszMenuName', LPCSTR),
        ('lpszClassName', LPCSTR)
    ]


class MSG(Struct):
    """
    Contains message information from a thread's message queue.

    **See also:** `MSG <https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-msg>`_
    """

    _fields_ = [
        ('hWnd', HWND),
        ('message', UINT),
        ('wParam', WPARAM),
        ('lParam', LPARAM),
        ('time', DWORD),
        ('pt', HANDLE),
        ('lprivate', DWORD),
    ]
