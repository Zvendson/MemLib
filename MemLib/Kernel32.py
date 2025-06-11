"""
High-level, Pythonic wrappers for selected Win32 and NT native API functions.

This module provides type-safe, exception-friendly bindings to many essential
Windows kernel functions for process, thread, memory, and module management,
using `ctypes` and best practices for cross-version compatibility.

Features:
    - Consistent, well-documented interfaces for major Win32/NT APIs.
    - Custom Win32Exception class with detailed error reporting.
    - Strong type hints for safety and IDE autocompletion.
    - Modern docstrings with links to Microsoft documentation.
    - Designed for both scripting and extension by power users.

Example:
    from Kernel32 import OpenProcess, ReadProcessMemory, Win32Exception

    try:
        handle = OpenProcess(PROCESS_ALL_ACCESS, False, 1234)
        # ... do something ...
    except Win32Exception as ex:
        print(f"Windows API Error: {ex}")

See also:
    - https://docs.microsoft.com/en-us/windows/win32/api/
    - https://docs.python.org/3/library/ctypes.html
"""

from __future__ import annotations

from ctypes import Array, POINTER, WINFUNCTYPE, byref, create_unicode_buffer, windll
from ctypes.wintypes import (
    BOOL, INT, LONG, DWORD,
    UINT, ULONG, PDWORD, PULONG,
    PLARGE_INTEGER,
    HANDLE, HMODULE, LPHANDLE, LPVOID,
    LPCSTR, LPCWSTR, LPWSTR, WCHAR,
)
from typing import Callable, Type

from MemLib.Constants import STATUS_SUCCESS


WaitOrTimerCallback = WINFUNCTYPE(None, LPVOID, BOOL)


def SUCCEEDED(hresult: int) -> bool:
    """
    Determines whether the given HRESULT value indicates success.

    Args:
        hresult (int): Status code to evaluate.

    Returns:
        bool: True if HRESULT is non-negative, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/winerror/nf-winerror-succeeded
    """
    value: LONG = LONG(hresult)
    return value.value >= 0


def FAILED(hresult: int) -> bool:
    """
    Determines whether the given HRESULT value indicates failure.

    Args:
        hresult (int): Status code to evaluate.

    Returns:
        bool: True if HRESULT is negative, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/winerror/nf-winerror-failed
    """
    value: LONG = LONG(hresult)
    return value.value < 0


def GetLastError() -> int:
    """
    Gets the last-error code value for the calling thread.

    Returns:
        int: Last-error code.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror
    """
    return _GetLastError()


def FormatMessageW(
        flags:       int,
        source:      object,
        message_id:  int,
        language_id: int,
        buffer:      Array,
        size:        int,
        arguments:   object) -> int:
    """
    Formats a message string for a system error or message definition.

    Args:
        flags (int): Formatting and source options.
        source (object): Location of the message definition.
        message_id (int): Message identifier.
        language_id (int): Language identifier.
        buffer (Array): Buffer to receive the formatted message.
        size (int): Size of the buffer.
        arguments (object): Arguments for inserts in the message.

    Returns:
        int: Number of TCHARs stored in buffer (excluding null), or 0 if failed.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-formatmessagew
    """
    return _FormatMessageW(flags, source, message_id, language_id, buffer, size, arguments)


def CreateProcessW(
        application_name: str | None,
        command_line:        str,
        process_attributes:  int,
        thread_attributes:   int,
        inherit_handles:     bool,
        creation_flags:      int,
        environment:         int,
        current_directory:   str | None,
        startup_info:        object,
        process_information: object) -> bool:
    """
    Creates a new process and its primary thread.

    Args:
        application_name (str | None): Path to executable.
        command_line (str): Command line string.
        process_attributes (int): SECURITY_ATTRIBUTES for process handle inheritance.
        thread_attributes (int): SECURITY_ATTRIBUTES for thread handle inheritance.
        inherit_handles (bool): If True, inheritable handles are inherited.
        creation_flags (int): Flags controlling process creation.
        environment (int): Pointer to environment block.
        current_directory (str | None): Working directory.
        startup_info (object): Pointer to STARTUPINFO struct.
        process_information (object): Pointer to PROCESS_INFORMATION struct.

    Returns:
        bool: True if the process was created successfully, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
    """
    return _CreateProcessW(
        application_name,
        command_line,
        process_attributes,
        thread_attributes,
        BOOL(inherit_handles),
        creation_flags,
        environment,
        current_directory,
        startup_info,
        process_information
    )


def GetPriorityClass(process_handle: int) -> int:
    """
    Retrieves the priority class of a process.

    Args:
        process_handle (int): Handle to the process.

    Returns:
        int: Priority class, or 0 if failed.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getpriorityclass
    """
    return _GetPriorityClass(process_handle)


def SetPriorityClass(process_handle: int, priority_class: int) -> bool:
    """
    Sets the priority class for a specified process.

    Args:
        process_handle (int): Handle to the process.
        priority_class (int): New priority class.

    Returns:
        bool: True if set successfully, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setpriorityclass
    """
    return _SetPriorityClass(process_handle, priority_class)


def GetExitCodeProcess(process_handle: int) -> int:
    """
    Gets the termination status code for a specified process.

    Args:
        process_handle (int): Handle to the process.

    Returns:
        int: Exit code on success, or -1 on failure.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess
    """
    exit_code: DWORD = DWORD()
    if _GetExitCodeProcess(process_handle, byref(exit_code)):
        return exit_code.value

    return -1


def CreateRemoteThread(
        process_handle:    int,
        thread_attributes: int,
        stack_size:        int,
        start_address:     int,
        parameter:         int,
        creation_flags:    int,
        thread_id:         POINTER) -> int:
    """
    Creates a thread that runs in another process's address space.

    Args:
        process_handle (int): Handle to the target process.
        thread_attributes (int): SECURITY_ATTRIBUTES pointer.
        stack_size (int): Initial stack size.
        start_address (int): Thread entry point address.
        parameter (int): Parameter to pass to thread.
        creation_flags (int): Creation flags.
        thread_id (POINTER): Pointer to receive the thread identifier.

    Returns:
        int: Handle to the new thread, or 0 if failed.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
    """
    return _CreateRemoteThread(
        process_handle,
        thread_attributes,
        stack_size,
        start_address,
        parameter,
        creation_flags,
        thread_id
    )


def OpenThread(thread_id: int, inherit_handle: bool, desired_access: int) -> int:
    """
    Opens an existing thread.

    Args:
        thread_id (int): Thread identifier.
        inherit_handle (bool): Whether the handle is inheritable.
        desired_access (int): Requested access rights.

    Returns:
        int: Handle to the thread, or 0 if failed.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread
    """
    handle: int | None = _OpenThread(desired_access, inherit_handle, thread_id)
    if handle is None:
        return 0

    return handle


def ResumeThread(thread_handle: int) -> int:
    """
    Decrements the suspend count of a thread, resuming it if the count reaches zero.

    Args:
        thread_handle (int): Handle to the thread.

    Returns:
        int: Previous suspend count, or -1 if failed.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread
    """
    return _ResumeThread(thread_handle)


def SuspendThread(thread_handle: int) -> int:
    """
    Increments the suspend count of a thread, suspending it if the count is greater than zero.

    Args:
        thread_handle (int): Handle to the thread.

    Returns:
        int: Previous suspend count, or -1 if failed.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread
    """
    return _SuspendThread(thread_handle)


def GetExitCodeThread(thread_handle: int) -> int:
    """
    Gets the exit code for a specified thread.

    Args:
        thread_handle (int): Handle to the thread.

    Returns:
        int: Thread exit code, or -1 if failed.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodethread
    """
    exit_code: DWORD = DWORD()
    if _GetExitCodeThread(thread_handle, byref(exit_code)):
        return exit_code.value

    return -1


def GetThreadDescription(thread_handle: int) -> str:
    """
    Retrieves the description for a specified thread.

    Args:
        thread_handle (int): Handle to the thread.

    Returns:
        str: Thread description, or empty string if unavailable.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreaddescription
    """
    name_buffer: Array = (WCHAR * 1024)()

    if SUCCEEDED(_GetThreadDescription(thread_handle, name_buffer)):
        return name_buffer.value[:-2]

    return ""


def SetThreadDescription(thread_handle: int, thread_description: str) -> bool:
    """
    Sets a description for a specified thread.

    Args:
        thread_handle (int): Handle to the thread.
        thread_description (str): Description to assign.

    Returns:
        bool: True if successful, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreaddescription
    """
    return _SetThreadDescription(thread_handle, thread_description)


def GetThreadPriority(thread_handle: int) -> int:
    """
    Gets the priority value of a thread.

    Args:
        thread_handle (int): Handle to the thread.

    Returns:
        int: Priority level, or THREAD_PRIORITY_ERROR_RETURN if failed.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadpriority
    """
    return _GetThreadPriority(thread_handle)


def SetThreadPriority(thread_handle: int, priority: int) -> bool:
    """
    Sets the priority value of a thread.

    Args:
        thread_handle (int): Handle to the thread.
        priority (int): New priority value.

    Returns:
        bool: True if successful, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadpriority
    """
    return _SetThreadPriority(thread_handle, priority)


def TerminateThread(thread_handle: int, exit_code: int) -> bool:
    """
    Terminates a thread.

    Args:
        thread_handle (int): Handle to the thread.
        exit_code (int): Exit code for the thread.

    Returns:
        bool: True if successful, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminatethread
    """
    return bool(_TerminateThread(thread_handle, exit_code))


def WaitForSingleObject(handle: int, milliseconds: int) -> int:
    """
    Waits until the specified object is signaled or a timeout occurs.

    Args:
        handle (int): Handle to the object.
        milliseconds (int): Timeout interval in milliseconds.

    Returns:
        int: Wait result (WAIT_OBJECT_0, WAIT_TIMEOUT, etc).

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
    """
    return _WaitForSingleObject(handle, milliseconds)


def CreateWaitOrTimerCallback(callback: Callable[[int, int], None]) -> WaitOrTimerCallback:
    """
    Creates a callback function suitable for wait/timer operations.

    Args:
        callback (Callable[[int, int], None]): Callback function.

    Returns:
        WaitOrTimerCallback: Wrapped callback.

    See also:
        https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms687066(v=vs.85)
    """
    return WaitOrTimerCallback(callback)


def RegisterWaitForSingleObject(
        obj_handle:    int,
        callback:      WaitOrTimerCallback,
        context:       int,
        milliseconds:  int,
        flags:         int) -> int:
    """
    Registers a wait operation for a specified object and callback.

    Args:
        obj_handle (int): Handle to the object.
        callback (WaitOrTimerCallback): Callback function.
        context (int): User-defined value passed to callback.
        milliseconds (int): Timeout interval.
        flags (int): Wait operation flags.

    Returns:
        int: Wait handle, or 0 if failed.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registerwaitforsingleobject
    """
    out_handle: HANDLE = HANDLE()
    if not _RegisterWaitForSingleObject(byref(out_handle), obj_handle, callback, context, milliseconds, flags):
        return 0

    if out_handle.value is None:
        return 0

    return out_handle.value


def UnregisterWait(wait_handle: int) -> bool:
    """
    Cancels a registered wait operation.

    Args:
        wait_handle (int): Handle from RegisterWaitForSingleObject.

    Returns:
        bool: True if successful, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-unregisterwait
    """
    return _UnregisterWait(wait_handle) != 0


def UnregisterWaitEx(wait_handle: int, completion_event: int) -> bool:
    """
    Cancels a registered wait operation and optionally signals an event on completion.

    Args:
        wait_handle (int): Wait handle.
        completion_event (int): Handle to event to signal, or 0.

    Returns:
        bool: True if successful, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/sync/unregisterwaitex
    """
    return _UnregisterWaitEx(wait_handle, completion_event) != 0


def OpenProcess(process_id: int, inherit_handle: bool, desired_access: int) -> int:
    """
    Opens an existing process.

    Args:
        process_id (int): Process identifier.
        inherit_handle (bool): Whether the handle is inheritable.
        desired_access (int): Access mask.

    Returns:
        int: Handle to the process, or 0 if failed.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
    """
    handle: int | None = _OpenProcess(desired_access, inherit_handle, process_id)
    if handle is None:
        return 0

    return handle


def CloseHandle(handle: int) -> bool:
    """
    Closes an open object handle.

    Args:
        handle (int): Handle to the object.

    Returns:
        bool: True if closed successfully, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
    """
    return _CloseHandle(handle)


def DuplicateHandle(
        source_process_handle: int,
        source_handle:         int,
        target_process_handle: int,
        target_handle:         Type[POINTER],
        desired_access:        int,
        inherit_handle:        bool,
        options:               int) -> bool:
    """
    Duplicates an object handle.

    Args:
        source_process_handle (int): Handle to source process.
        source_handle (int): Handle to duplicate.
        target_process_handle (int): Handle to target process.
        target_handle (Type[POINTER]): Receives the new handle.
        desired_access (int): Access mask for new handle.
        inherit_handle (bool): If True, new handle is inheritable.
        options (int): Duplication options.

    Returns:
        bool: True if duplicated successfully, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle
    """
    return _DuplicateHandle(
        source_process_handle,
        source_handle,
        target_process_handle,
        target_handle,
        desired_access,
        BOOL(inherit_handle),
        options
    )


def TerminateProcess(process_handle: int, exit_code: int) -> bool:
    """
    Terminates the specified process and all of its threads.

    Args:
        process_handle (int): Handle to the process.
        exit_code (int): Exit code for the process.

    Returns:
        bool: True if terminated successfully, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess
    """
    return _TerminateProcess(process_handle, exit_code)


def GetModuleHandleA(module_name: str | bytes) -> int:
    """
    Retrieves a handle to the specified module in the calling process (ANSI version).

    Args:
        module_name (str | bytes): Name of the loaded module (DLL or EXE). If a string is provided,
            it will be encoded to ANSI bytes.

    Returns:
        int: Handle to the specified module, or 0 if the module is not found.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea
    """
    if isinstance(module_name, str):
        module_name = module_name.encode('ascii')
    return _GetModuleHandleA(module_name)


def GetModuleHandleW(module_name: str | bytes) -> int:
    """
    Retrieves a handle to the specified module in the calling process (Unicode version).

    Args:
        module_name (str): Name of the loaded module (DLL or EXE). If given as bytes, it will be decoded to a string.

    Returns:
        int: Handle to the specified module, or 0 if the module is not found.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlew
    """
    if isinstance(module_name, bytes):
        module_name = module_name.decode('ascii')
    return _GetModuleHandleW(module_name)


def GetProcAddress(module_handle: int, process_name: str) -> int:
    """
    Retrieves the address of an exported function or variable from a DLL.

    Args:
        module_handle (int): Handle to the module.
        process_name (str): Function or variable name.

    Returns:
        int: Address of the exported function or variable, or 0 if failed.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
    """
    return _GetProcAddress(module_handle, process_name.encode('ascii'))


def ReadProcessMemory(
        process_handle:       int,
        base_address:         int,
        buffer:               object,
        size:                 int,
        number_of_bytes_read: object) -> bool:
    """
    Reads memory from another process.

    Args:
        process_handle (int): Handle to the process.
        base_address (int): Address to start reading from.
        buffer (object): Output buffer.
        size (int): Number of bytes to read.
        number_of_bytes_read (object): Variable to receive the number of bytes read.

    Returns:
        bool: True if read successfully, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory
    """
    return _ReadProcessMemory(process_handle, base_address, buffer, size, number_of_bytes_read)


def WriteProcessMemory(
        process_handle:          int,
        base_address:            int,
        buffer:                  object,
        size:                    int,
        number_of_bytes_written: object) -> bool:
    """
    Writes memory to another process.

    Args:
        process_handle (int): Handle to the process.
        base_address (int): Address to start writing to.
        buffer (object): Data buffer.
        size (int): Number of bytes to write.
        number_of_bytes_written (object): Variable to receive the number of bytes written.

    Returns:
        bool: True if written successfully, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
    """
    return _WriteProcessMemory(process_handle, base_address, buffer, size, number_of_bytes_written)


def VirtualAlloc(address: int, size: int, allocation_type: int, protect: int) -> int:
    """
    Allocates memory in the calling process.

    Args:
        address (int): Desired address (or 0).
        size (int): Size in bytes.
        allocation_type (int): Allocation type flags.
        protect (int): Memory protection flags.

    Returns:
        int: Address of allocated memory, or 0 if failed.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    """
    return _VirtualAlloc(address, size, allocation_type, protect)


def VirtualAllocEx(process_handle: int, address: int, size: int, allocation_type: int, protect: int) -> int:
    """
    Allocates memory in another process.

    Args:
        process_handle (int): Handle to the process.
        address (int): Desired address (or 0).
        size (int): Size in bytes.
        allocation_type (int): Allocation type flags.
        protect (int): Memory protection flags.

    Returns:
        int: Address of allocated memory, or 0 if failed.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
    """
    return _VirtualAllocEx(process_handle, address, size, allocation_type, protect)


def VirtualFree(address: int, size: int, free_type: int) -> bool:
    """
    Releases or decommits memory in the calling process.

    Args:
        address (int): Address to free.
        size (int): Size to free.
        free_type (int): Free operation flags.

    Returns:
        bool: True if successful, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree
    """
    return _VirtualFree(address, size, free_type)


def VirtualFreeEx(process_handle: int, address: int, size: int, free_type: int) -> bool:
    """
    Releases or decommits memory in the virtual address space of a specified process.

    Args:
        process_handle (int): Handle to the process whose memory is to be freed.
        address (int): Starting address of the region to be freed.
        size (int): Size of the region to free, in bytes.
        free_type (int): Type of free operation (e.g., MEM_RELEASE or MEM_DECOMMIT).

    Returns:
        bool: True if the memory was freed successfully, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfreeex
    """
    return _VirtualFreeEx(process_handle, address, size, free_type)


def VirtualProtectEx(process_handle: int, address: int, size: int, new_protect: int, old_protect: object) -> bool:
    """
    Changes the protection on a region of committed pages in the virtual address space of a specified process.

    Args:
        process_handle (int): Handle to the process.
        address (int): Base address of the region to change.
        size (int): Size of the region in bytes.
        new_protect (int): New memory protection option (e.g., PAGE_READWRITE).
        old_protect (object): Variable to receive the previous protection attributes.

    Returns:
        bool: True if the protection was changed successfully, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex
    """
    return _VirtualProtectEx(process_handle, address, size, new_protect, old_protect)


def CreateFileMappingW(
        file_handle:             int,
        file_mapping_attributes: int,
        protect:                 int,
        maximum_size_high:       int,
        maximum_size_low:        int,
        name:                    str | None) -> int:
    """
    Creates or opens a named or unnamed file mapping object for a specified file.

    Args:
        file_handle (int): Handle to the file to be mapped.
        file_mapping_attributes (int): Pointer to SECURITY_ATTRIBUTES for handle inheritance, or 0.
        protect (int): Memory protection for the mapping object.
        maximum_size_high (int): High-order DWORD of the maximum mapping size.
        maximum_size_low (int): Low-order DWORD of the maximum mapping size.
        name (str | None): Name of the file mapping object (optional).

    Returns:
        int: Handle to the file mapping object, or 0 if failed.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw
    """
    if name is None:
        _CreateFileMappingW.argtypes = [HANDLE, ULONG, DWORD, DWORD, DWORD, LPVOID]
        name: int = 0
    else:
        _CreateFileMappingW.argtypes = [HANDLE, ULONG, DWORD, DWORD, DWORD, LPWSTR]

    return _CreateFileMappingW(file_handle, file_mapping_attributes, protect, maximum_size_high, maximum_size_low, name)


def OpenFileMappingW(desired_access: int, inherit_handle: bool, name: str) -> int:
    """
    Opens a named file mapping object.

    Args:
        desired_access (int): Access rights for the mapping object.
        inherit_handle (bool): If True, handle can be inherited by child processes.
        name (str): Name of the file mapping object.

    Returns:
        int: Handle to the file mapping object, or 0 if not found.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-openfilemappingw
    """
    mapping = _OpenFileMappingW(desired_access, inherit_handle, name)
    if mapping is None:
        return 0

    return mapping


def MapViewOfFile(
        file_mapping_object:    int,
        desired_access:         int,
        file_offset_high:       int,
        file_offset_low:        int,
        number_of_bytes_to_map: int) -> int:
    """
    Maps a view of a file mapping object into the address space of the calling process.

    Args:
        file_mapping_object (int): Handle to the file mapping object.
        desired_access (int): Access type for the mapped view.
        file_offset_high (int): High-order DWORD of file offset where the view begins.
        file_offset_low (int): Low-order DWORD of file offset where the view begins.
        number_of_bytes_to_map (int): Number of bytes to map.

    Returns:
        int: Address of the mapped view, or 0 if failed.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile
    """
    return _MapViewOfFile(file_mapping_object, desired_access, file_offset_high, file_offset_low, number_of_bytes_to_map)


def UnmapViewOfFile(base_address: int) -> bool:
    """
    Unmaps a mapped view of a file from the calling process's address space.

    Args:
        base_address (int): Base address of the mapped view.

    Returns:
        bool: True if unmapped successfully, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile
    """
    return _UnmapViewOfFile(base_address)


def NtMapViewOfSection(
        section_handle:      int,
        process_handle:      int,
        base_address:        object,
        zero_bits:           int,
        commit_size:         int,
        section_offset:      object,
        view_size:           object,
        inherit_disposition: int,
        allocation_type:     int,
        win32_protect:       int) -> int:
    """
    Maps a view of a section object into the virtual address space of a specified process.

    Args:
        section_handle (int): Handle to the section object to map.
        process_handle (int): Handle to the target process.
        base_address (object): Receives the base address of the mapped view (output pointer).
        zero_bits (int): Number of high-order address bits that must be zero in the base address.
        commit_size (int): Size in bytes of the initially committed region.
        section_offset (object): Pointer to the offset, in bytes, from the start of the section.
        view_size (object): Pointer to the size of the view (input/output).
        inherit_disposition (int): Flags for sharing with child processes.
        allocation_type (int): Allocation flags for the view.
        win32_protect (int): Protection for the region of initially committed pages.

    Returns:
        bool: True if the section was mapped successfully, otherwise False.

    See also:
        https://ntdoc.m417z.com/ntmapviewofsection
        https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection
    """
    nt_status: int = _NtMapViewOfSection(
        section_handle,
        process_handle,
        base_address,
        zero_bits,
        commit_size,
        section_offset,
        view_size,
        inherit_disposition,
        allocation_type,
        win32_protect
    )

    return nt_status == STATUS_SUCCESS


def NtUnmapViewOfSection(process_handle: int, base_address: int) -> bool:
    """
    Unmaps a view of a section from the virtual address space of a process.

    Args:
        process_handle (int): Handle to the process whose view is to be unmapped.
        base_address (int): Base address of the mapped view.

    Returns:
        bool: True if the view was unmapped successfully, otherwise False.

    See also:
        https://malapi.io/winapi/NtUnmapViewOfSection
        https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwunmapviewofsection
    """
    nt_status: int = _NtUnmapViewOfSection(process_handle, base_address)
    return nt_status == STATUS_SUCCESS


def NtQueryInformationProcess(
        process_handle:             int,
        process_information_class:  object,
        process_information:        object,
        process_information_length: int,
        return_length:              int) -> bool:
    """
    Retrieves information about a specified process.

    Args:
        process_handle (int): Handle to the process.
        process_information_class (object): Type of process information to retrieve.
        process_information (object): Buffer to receive the requested information.
        process_information_length (int): Size of the buffer, in bytes.
        return_length (int): Variable that receives the number of bytes returned.

    Returns:
        bool: True if the information was retrieved successfully, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
    """
    nt_status: int = _NtQueryInformationProcess(
        process_handle,
        process_information_class,
        process_information,
        process_information_length,
        return_length
    )
    return nt_status == STATUS_SUCCESS


def NtSuspendProcess(process_handle: int) -> bool:
    """
    Suspends all threads in the specified process.

    Args:
        process_handle (int): Handle to the process to suspend.

    Returns:
        bool: True if the process was suspended successfully, otherwise False.

    See also:
        https://cyberstoph.org/posts/2021/05/fun-with-processes-suspend-and-resume/
    """
    nt_status: int = _NtSuspendProcess(process_handle)
    return nt_status == STATUS_SUCCESS


def NtResumeProcess(process_handle: int) -> bool:
    """
    Resumes all threads in the specified process.

    Args:
        process_handle (int): Handle to the process to resume.

    Returns:
        bool: True if the process was resumed successfully, otherwise False.

    See also:
        https://cyberstoph.org/posts/2021/05/fun-with-processes-suspend-and-resume/
    """
    nt_status: int = _NtResumeProcess(process_handle)
    return nt_status == STATUS_SUCCESS


def CreateToolhelp32Snapshot(flags: int, th32_process_id: int) -> int:
    """
    Takes a snapshot of the specified set of processes, including heaps, modules, and threads.

    Args:
        flags (int): Bitmask specifying what to include in the snapshot (e.g., TH32CS_SNAPPROCESS, TH32CS_SNAPMODULE).
        th32_process_id (int): Process ID to snapshot, or 0 to snapshot all processes.

    Returns:
        int: Handle to the snapshot on success, or 0 if the call fails.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
    """
    return _CreateToolhelp32Snapshot(flags, th32_process_id)


def Process32Next(snapshot_handle: int, lppe: object) -> bool:
    """
    Retrieves information about the next process in a system snapshot.

    Args:
        snapshot_handle (int): Handle to the snapshot from CreateToolhelp32Snapshot.
        lppe (object): Pointer to a PROCESSENTRY32 structure to receive process info.

    Returns:
        bool: True if the next process was retrieved, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next
    """
    return _Process32Next(snapshot_handle, lppe)


def Process32First(snapshot_handle: int, lppe: object) -> bool:
    """
    Retrieves information about the first process in a system snapshot.

    Args:
        snapshot_handle (int): Handle to the snapshot from CreateToolhelp32Snapshot.
        lppe (object): Pointer to a PROCESSENTRY32 structure to receive process info.

    Returns:
        bool: True if the first process was retrieved, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first
    """
    return _Process32First(snapshot_handle, lppe)


def Module32Next(snapshot_handle: int, lpme: object) -> bool:
    """
    Retrieves information about the next module associated with a process in a snapshot.

    Args:
        snapshot_handle (int): Handle to the snapshot from CreateToolhelp32Snapshot.
        lpme (object): Pointer to a MODULEENTRY32 structure to receive module info.

    Returns:
        bool: True if the next module was retrieved, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-module32next
    """
    return _Module32Next(snapshot_handle, lpme)


def Module32First(snapshot_handle: int, lpme: object) -> bool:
    """
    Retrieves information about the first module associated with a process in a snapshot.

    Args:
        snapshot_handle (int): Handle to the snapshot from CreateToolhelp32Snapshot.
        lpme (object): Pointer to a MODULEENTRY32 structure to receive module info.

    Returns:
        bool: True if the first module was retrieved, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-module32first
    """
    return _Module32First(snapshot_handle, lpme)


def Thread32Next(snapshot_handle: int, lpte: object) -> bool:
    """
    Retrieves information about the next thread in a system snapshot.

    Args:
        snapshot_handle (int): Handle to the snapshot from CreateToolhelp32Snapshot.
        lpte (object): Pointer to a THREADENTRY32 structure to receive thread info.

    Returns:
        bool: True if the next thread was retrieved, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32next
    """
    return _Thread32Next(snapshot_handle, lpte)


def Thread32First(snapshot_handle: int, lpte: object) -> bool:
    """
    Retrieves information about the first thread in a system snapshot.

    Args:
        snapshot_handle (int): Handle to the snapshot from CreateToolhelp32Snapshot.
        lpte (object): Pointer to a THREADENTRY32 structure to receive thread info.

    Returns:
        bool: True if the first thread was retrieved, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32first
    """
    return _Thread32First(snapshot_handle, lpte)


def GetStdHandle(std_handle: int) -> int:
    """
    Retrieves a handle to a specified standard device (input, output, or error).

    Args:
        std_handle (int): Identifier for the standard device (e.g., STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE).

    Returns:
        int: Handle to the specified device, or INVALID_HANDLE_VALUE on failure.

    See also:
        https://learn.microsoft.com/en-us/windows/console/getstdhandle
    """
    return _GetStdHandle(std_handle)


def QueryFullProcessImageNameW(process_handle: int, flags: int, exe_name: object, ptr_size: object) -> bool:
    """
    Retrieves the full path of the executable image for the specified process.

    Args:
        process_handle (int): Handle to the process.
        flags (int): Format flag for the path. Use 0 for Win32 path format, 1 for native system path format.
        exe_name (object): Buffer (writable) to receive the full path to the executable image.
        ptr_size (object): On input, specifies the size of exeName in characters. On success, receives the number of
            characters written (excluding the null terminator).

    Returns:
        bool: True if the full process image name was retrieved successfully, otherwise False.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew
    """
    return _QueryFullProcessImageNameW(process_handle, flags, exe_name, ptr_size)


class Win32Exception(RuntimeError):
    """
    Exception class representing a Windows API error.

    Args:
        error_code (int, optional): The Windows error code. If not provided, the last error from Windows will be used.
        custom_message (str, optional): A custom error message. If not provided, the message will be generated from Windows.

    Note:
        See also:
            - `GetLastError <https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror>`_
            - `FormatMessageW <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-formatmessagew>`_
    """

    def __init__(self, error_code: int = None, custom_message: str = None):
        """
        Initializes a Win32Exception with the provided error code and message.

        Args:
            error_code (int, optional): The Windows error code. If None, the result of GetLastError() will be used.
            custom_message (str, optional): A custom message. If None, a message will be retrieved using FormatMessageW.
        """
        self._error_code: int = GetLastError() if (error_code is None) else error_code
        self._message:   str = custom_message

        if custom_message is None:
            self.__format_message()

    @property
    def code(self) -> int:
        """
        Returns the Windows error code associated with this exception.

        Returns:
            int: The Windows error code.
        """
        return self._error_code

    @property
    def message(self) -> str:
        """
        Returns the descriptive error message for this exception.

        Returns:
            str: The error message string.
        """
        return self._message

    def __str__(self) -> str:
        """
        Returns a string representation of the exception.

        Returns:
            str: The error message and code in a formatted string.
        """
        return f"{self._message} (0x{self._error_code:08X})"

    def __repr__(self) -> str:
        """
        Returns a representation of the exception suitable for debugging.

        Returns:
            str: The exception as a string.
        """
        return 'Win32Exception(%s)' % str(self)

    def __format_message(self) -> None:
        """
        Retrieves the error message string for the error code using FormatMessageW.

        If the buffer is too small, it will be increased until the message fits
        or a maximum buffer size is reached. If the message cannot be retrieved,
        sets the message to 'Unknown Error'.
        """
        size: int = 256

        while size < 0x10000:  # Found 0x10000 in C# std lib
            msg_buffer: Array = create_unicode_buffer(size)

            result: int = FormatMessageW(0x200 | 0x1000 | 0x2000, None, self._error_code, 0, msg_buffer, size, None)

            if result > 0:
                self._message = msg_buffer.value
                return

            if GetLastError() != 0x7A:  # ERROR_INSUFFICIENT_BUFFER
                break

            size += 256

        self._message = 'Unknown Error'


# region Function bindings
_GetLastError          = windll.kernel32.GetLastError
_GetLastError.argtypes = []
_GetLastError.restype  = DWORD

_FormatMessageW          = windll.kernel32.FormatMessageW
_FormatMessageW.argtypes = [DWORD, LPVOID, DWORD, DWORD, LPWSTR, DWORD, LPVOID]
_FormatMessageW.restype  = DWORD

_CreateProcessW          = windll.kernel32.CreateProcessW
_CreateProcessW.argtypes = [LPCWSTR, LPWSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCWSTR, LPVOID, LPVOID]
_CreateProcessW.restype  = BOOL

_GetExitCodeProcess          = windll.kernel32.GetExitCodeProcess
_GetExitCodeProcess.argtypes = [HANDLE, PDWORD]
_GetExitCodeProcess.restype  = BOOL

_CreateRemoteThread          = windll.kernel32.CreateRemoteThread
_CreateRemoteThread.argtypes = [HANDLE, DWORD, LPVOID, DWORD, DWORD, DWORD, POINTER(DWORD)]
_CreateRemoteThread.restype  = HANDLE

_OpenThread          = windll.kernel32.OpenThread
_OpenThread.argtypes = [DWORD, BOOL, DWORD]
_OpenThread.restype  = HANDLE

_ResumeThread          = windll.kernel32.ResumeThread
_ResumeThread.argtypes = [HANDLE]
_ResumeThread.restype  = DWORD

_SuspendThread          = windll.kernel32.SuspendThread
_SuspendThread.argtypes = [HANDLE]
_SuspendThread.restype  = DWORD

_GetExitCodeThread          = windll.kernel32.GetExitCodeThread
_GetExitCodeThread.argtypes = [HANDLE, POINTER(DWORD)]
_GetExitCodeThread.restype  = BOOL

_GetThreadDescription          = windll.kernel32.GetThreadDescription
_GetThreadDescription.argtypes = [HANDLE, LPWSTR]
_GetThreadDescription.restype  = DWORD

_SetThreadDescription          = windll.kernel32.SetThreadDescription
_SetThreadDescription.argtypes = [HANDLE, LPCWSTR]
_SetThreadDescription.restype  = DWORD

_GetPriorityClass          = windll.kernel32.GetPriorityClass
_GetPriorityClass.argtypes = [HANDLE]
_GetPriorityClass.restype  = DWORD

_SetPriorityClass          = windll.kernel32.SetPriorityClass
_SetPriorityClass.argtypes = [HANDLE, DWORD]
_SetPriorityClass.restype  = BOOL

_GetThreadPriority          = windll.kernel32.GetThreadPriority
_GetThreadPriority.argtypes = [HANDLE]
_GetThreadPriority.restype  = DWORD

_SetThreadPriority          = windll.kernel32.SetThreadPriority
_SetThreadPriority.argtypes = [HANDLE, INT]
_SetThreadPriority.restype  = BOOL

_TerminateThread          = windll.kernel32.TerminateThread
_TerminateThread.argtypes = [HANDLE, DWORD]
_TerminateThread.restype  = BOOL

_WaitForSingleObject          = windll.kernel32.WaitForSingleObject
_WaitForSingleObject.argtypes = [HANDLE, DWORD]
_WaitForSingleObject.restype  = DWORD

_RegisterWaitForSingleObject          = windll.kernel32.RegisterWaitForSingleObject
_RegisterWaitForSingleObject.argtypes = [LPHANDLE, HANDLE, WaitOrTimerCallback, LPVOID, ULONG, ULONG]
_RegisterWaitForSingleObject.restype  = BOOL

_UnregisterWait          = windll.kernel32.UnregisterWait
_UnregisterWait.argtypes = [HANDLE]
_UnregisterWait.restype  = BOOL

_UnregisterWaitEx          = windll.kernel32.UnregisterWaitEx
_UnregisterWaitEx.argtypes = [HANDLE, HANDLE]
_UnregisterWaitEx.restype  = BOOL

_OpenProcess          = windll.kernel32.OpenProcess
_OpenProcess.argtypes = [DWORD, BOOL, DWORD]
_OpenProcess.restype  = HANDLE

_CloseHandle          = windll.kernel32.CloseHandle
_CloseHandle.argtypes = [HANDLE]
_CloseHandle.restype  = BOOL

_DuplicateHandle          = windll.kernel32.DuplicateHandle
_DuplicateHandle.argtypes = [HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD]
_DuplicateHandle.restype  = BOOL

_TerminateProcess          = windll.kernel32.TerminateProcess
_TerminateProcess.argtypes = [HANDLE, UINT]
_TerminateProcess.restype  = BOOL

_GetModuleHandleA          = windll.kernel32.GetModuleHandleA
_GetModuleHandleA.argtypes = [LPCSTR]
_GetModuleHandleA.restype  = HMODULE

_GetModuleHandleW          = windll.kernel32.GetModuleHandleW
_GetModuleHandleW.argtypes = [LPCWSTR]
_GetModuleHandleW.restype  = HMODULE

_GetProcAddress          = windll.kernel32.GetProcAddress
_GetProcAddress.argtypes = [HMODULE, LPCSTR]
_GetProcAddress.restype  = LPVOID

_ReadProcessMemory          = windll.kernel32.ReadProcessMemory
_ReadProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, DWORD, POINTER(DWORD)]
_ReadProcessMemory.restype  = BOOL

_WriteProcessMemory          = windll.kernel32.WriteProcessMemory
_WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, DWORD, POINTER(DWORD)]
_WriteProcessMemory.restype  = BOOL

_VirtualAlloc          = windll.kernel32.VirtualAlloc
_VirtualAlloc.argtypes = [LPVOID, DWORD, DWORD, DWORD]
_VirtualAlloc.restype  = LPVOID

_VirtualAllocEx          = windll.kernel32.VirtualAllocEx
_VirtualAllocEx.argtypes = [HANDLE, LPVOID, DWORD, DWORD, DWORD]
_VirtualAllocEx.restype  = LPVOID

_VirtualFree          = windll.kernel32.VirtualFree
_VirtualFree.argtypes = [LPVOID, DWORD, DWORD]
_VirtualFree.restype  = BOOL

_VirtualFreeEx          = windll.kernel32.VirtualFreeEx
_VirtualFreeEx.argtypes = [HANDLE, LPVOID, DWORD, DWORD]
_VirtualFreeEx.restype  = BOOL

_VirtualProtectEx          = windll.kernel32.VirtualProtectEx
_VirtualProtectEx.argtypes = [HANDLE, LPVOID, DWORD, DWORD, PDWORD]
_VirtualProtectEx.restype  = BOOL

_CreateFileMappingW          = windll.kernel32.CreateFileMappingW
_CreateFileMappingW.argtypes = [HANDLE, ULONG, DWORD, DWORD, DWORD, LPVOID]
_CreateFileMappingW.restype  = HANDLE

_OpenFileMappingW          = windll.kernel32.OpenFileMappingW
_OpenFileMappingW.argtypes = [DWORD, BOOL, LPCWSTR]
_OpenFileMappingW.restype  = HANDLE

_MapViewOfFile          = windll.kernel32.MapViewOfFile
_MapViewOfFile.argtypes = [HANDLE, DWORD, DWORD, DWORD, DWORD]
_MapViewOfFile.restype  = LPVOID

_UnmapViewOfFile          = windll.kernel32.UnmapViewOfFile
_UnmapViewOfFile.argtypes = [LPVOID]
_UnmapViewOfFile.restype  = BOOL

_NtQueryInformationProcess          = windll.ntdll.NtQueryInformationProcess
_NtQueryInformationProcess.argtypes = [HANDLE, DWORD, LPVOID, DWORD, DWORD]
_NtQueryInformationProcess.restype  = DWORD

_NtMapViewOfSection          = windll.ntdll.NtMapViewOfSection
_NtMapViewOfSection.argtypes = [HANDLE, HANDLE, LPVOID, ULONG, ULONG, PLARGE_INTEGER, PULONG, ULONG, ULONG, ULONG]
_NtMapViewOfSection.restype  = DWORD

_NtUnmapViewOfSection          = windll.ntdll.NtUnmapViewOfSection
_NtUnmapViewOfSection.argtypes = [HANDLE, LPVOID]
_NtUnmapViewOfSection.restype  = DWORD

_NtSuspendProcess          = windll.ntdll.NtSuspendProcess
_NtSuspendProcess.argtypes = [HANDLE]
_NtSuspendProcess.restype  = DWORD

_NtResumeProcess          = windll.ntdll.NtResumeProcess
_NtResumeProcess.argtypes = [HANDLE]
_NtResumeProcess.restype  = DWORD

_CreateToolhelp32Snapshot          = windll.kernel32.CreateToolhelp32Snapshot
_CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
_CreateToolhelp32Snapshot.restype  = HANDLE

_Process32Next          = windll.kernel32.Process32Next
_Process32Next.argtypes = [HANDLE, LPVOID]
_Process32Next.restype  = BOOL

_Process32First          = windll.kernel32.Process32First
_Process32First.argtypes = [HANDLE, LPVOID]
_Process32First.restype  = BOOL

_Module32Next          = windll.kernel32.Module32Next
_Module32Next.argtypes = [HANDLE, LPVOID]
_Module32Next.restype  = BOOL

_Module32First          = windll.kernel32.Module32First
_Module32First.argtypes = [HANDLE, LPVOID]
_Module32First.restype  = BOOL

_Thread32Next          = windll.kernel32.Thread32Next
_Thread32Next.argtypes = [HANDLE, LPVOID]
_Thread32Next.restype  = BOOL

_Thread32First          = windll.kernel32.Thread32First
_Thread32First.argtypes = [HANDLE, LPVOID]
_Thread32First.restype  = BOOL

_GetStdHandle          = windll.kernel32.GetStdHandle
_GetStdHandle.argtypes = [DWORD]
_GetStdHandle.restype  = HANDLE

_QueryFullProcessImageNameW          = windll.kernel32.QueryFullProcessImageNameW
_QueryFullProcessImageNameW.argtypes = [HANDLE, DWORD, LPWSTR, PDWORD]
_QueryFullProcessImageNameW.restype  = BOOL
# endregion
