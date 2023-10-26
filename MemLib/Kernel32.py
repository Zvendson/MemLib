"""
:platform: Windows
"""

from __future__ import annotations

from ctypes import Array, POINTER, byref, windll
from ctypes.wintypes import (
    BOOL, DWORD, HANDLE, HMODULE, INT, LONG, LPCSTR, LPCWSTR, LPHANDLE, LPVOID, LPWSTR, PDWORD,
    PLARGE_INTEGER, PULONG, UINT, ULONG, WCHAR,
)
from typing import Type

from MemLib.Constants import STATUS_SUCCESS


def SUCCEEDED(HRESULT: int) -> bool:
    """
    Generic test for success on any status value (non-negative numbers indicate success).
    """

    value = LONG(HRESULT)
    return value.value >= 0


def FAILED(HRESULT: int) -> bool:
    """
    Generic test for failure on any status value (non-negative numbers indicate success).
    """

    value = LONG(HRESULT)
    return value.value < 0


def GetLastError() -> int:
    """
    Retrieves the calling thread's last-error code value. The last-error code is maintained on a per-thread basis.

    :returns: The return value is the calling thread's last-error code.
    """

    return _GetLastError()


def FormatMessageW(
        flags: int,
        source: object,
        messageId: int,
        languageId: int,
        buffer: Array,
        size: int,
        arguments: object) -> int:
    """
    Formats a message string. The function requires a message definition as input. The message definition can come from
    a buffer passed into the function. It can come from a message table resource in an already-loaded module. Or the
    caller can ask the function to search the system's message table resource(s) for the message definition. The
    function finds the message definition in a message table resource based on a message identifier and a language
    identifier. The function copies the formatted message text to an output buffer, processing any embedded insert
    sequences if requested.

    :param flags: The formatting options, and how to interpret the lpSource parameter.
    :param source: The location of the message definition.
    :param messageId: The message identifier for the requested message.
    :param languageId: The language identifier for the requested message.
    :param buffer: A pointer to a buffer that receives the null-terminated string that specifies the formatted message.
    :param size: If the FORMAT_MESSAGE_ALLOCATE_BUFFER flag is not set, this parameter specifies the size of the
                 output buffer, in TCHARs. If FORMAT_MESSAGE_ALLOCATE_BUFFER is set, this parameter specifies the
                 minimum number of TCHARs to allocate for an output buffer.
    :param arguments: An array of values that are used as insert values in the formatted message.
    :returns: If the function succeeds, the return value is the number of TCHARs stored in the output buffer, excluding
              the terminating null character. If the function fails, the return value is zero. To get extended error
              information, call GetLastError.
    """

    return _FormatMessageW(flags, source, messageId, languageId, buffer, size, arguments)


def CreateProcessW(
        applicationName: str | None,
        commandLine: str,
        processAttributes: int,
        threadAttributes: int,
        inheritHandles: bool,
        creationFlags: int,
        environment: int,
        currentDirectory: str | None,
        startupInfo: object,
        processInformation: object) -> bool:
    """
    Creates a new process and its primary thread. The new process runs in the security context of the calling process.

    :param applicationName: The name of the module to be executed.
    :param commandLine: The command line to be executed.
    :param processAttributes: A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned handle
                              to the new process object can be inherited by child processes.
    :param threadAttributes: A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned handle to
                             the new thread object can be inherited by child processes.
    :param inheritHandles: If this parameter is TRUE, each inheritable handle in the calling process is inherited by the
                           new process.
    :param creationFlags: The flags that control the priority class and the creation of the process.
    :param environment: A pointer to the environment block for the new process.
    :param currentDirectory: The full path to the current directory for the process. f this parameter is NULL, the new
                             process will have the same current drive and directory as the calling process.
    :param startupInfo: A pointer to a StartupInfoW structure.
    :param processInformation: A pointer to a PROCESS_INFORMATION structure that receives identification information
                               about the new process.
    :returns: If the function succeeds, the return value is TRUE, False otherwise. If the function fails, the return
              value is zero. To get extended error information, call GetLastError.
    """

    return _CreateProcessW(
        applicationName,
        commandLine,
        processAttributes,
        threadAttributes,
        BOOL(inheritHandles),
        creationFlags,
        environment,
        currentDirectory,
        startupInfo,
        processInformation
    )


def GetPriorityClass(processHandle: int) -> int:
    """
    Retrieves the priority class for the specified process. This value, together with the priority value of each thread
    of the process, determines each thread's base priority level.

    :param processHandle: A handle to the process.
    :returns: If the function succeeds, the return value is the priority class of the specified process. If the
              function fails, the return value is zero. To get extended error information, call GetLastError.

    .. note:: **See also:**
        `GetPriorityClass <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi
        -getpriorityclass>`_
    """

    return _GetPriorityClass(processHandle)


def SetPriorityClass(processHandle: int, priorityClass: int) -> bool:
    """
    Sets the priority class for the specified process. This value together with the priority value of each thread of the
    process determines each thread's base priority level.

    :param processHandle: A handle to the process.
    :param priorityClass: The priority class for the process.
    :returns: If the function succeeds, the return value is the priority class of the specified process. If the
              function fails, the return value is zero. To get extended error information, call GetLastError.

    .. note:: **See also:**
        `GetPriorityClass <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi
        -getpriorityclass>`_
    """

    return _SetPriorityClass(processHandle, priorityClass)


def GetExitCodeProcess(processHandle: int) -> int:
    """
    Retrieves the termination status of the specified process.

    :param processHandle: A handle to the process.
    :returns: If the function succeeds, the return value is the termination status of the specified process. If the
              function fails, the return value is (DWORD) -1. To get extended error information, call GetLastError.
    """
    
    exitCode: DWORD = DWORD()
    if _GetExitCodeProcess(processHandle, byref(exitCode)):
        return exitCode.value

    return -1


def CreateRemoteThread(
        processHandle: int,
        threadAttributes: int,
        stackSize: int,
        startAddress: int,
        parameter: int,
        creationFlags: int) -> int:
    """
    Creates a thread that runs in the virtual address space of another process.

    :param processHandle: A handle to the process in which the thread is to be created.
    :param threadAttributes: A pointer to a SECURITY_ATTRIBUTES structure that specifies a security descriptor for the
                             new thread and determines whether child processes can inherit the returned handle.
    :param stackSize: The initial size of the stack, in bytes. The system rounds this value to the nearest page. If this
                      parameter is 0 (zero), the new thread uses the default size for the executable.
    :param startAddress: A pointer to the application-defined function of type LPTHREAD_START_ROUTINE to be executed by
                         the thread and represents the starting address of the thread in the remote process. The
                         function must exist in the remote process.
    :param parameter: A pointer to a variable to be passed to the thread function.
    :param creationFlags: The flags that control the creation of the thread.
    :returns: If the function succeeds, the return value is the termination status of the specified process. If the
              function fails, the return value is (DWORD) -1. To get extended error information, call GetLastError.
    """

    return _CreateRemoteThread(processHandle, threadAttributes, stackSize, startAddress, parameter, creationFlags, 0)


def OpenThread(threadId: int, inheritHandle: bool, desiredAccess: int) -> int:
    """
    Opens an existing local process object.

    :param threadId: The identifier of the local process to be opened.
    :param inheritHandle: If this value is TRUE, processes created by this process will inherit the handle. Otherwise,
                          the processes do not inherit this handle.
    :param desiredAccess: The access to the process object.
    :returns: If the function succeeds, the return value is an open handle to the specified process. If the function
              fails, the return value is NULL. To get extended error information, call GetLastError.
    """

    handle: int | None = _OpenThread(desiredAccess, inheritHandle, threadId)
    if handle is None:
        handle = 0

    return handle


def ResumeThread(threadHandle: int) -> int:
    """
    Decrements a thread's suspend count. When the suspend count is decremented to zero, the execution of the thread is
    resumed.

    :param threadHandle: A handle to the thread to be restarted.
    :returns: If the function succeeds, the return value is the thread's previous suspend count. If the function fails,
              the return value is (DWORD) -1. To get extended error information, use the GetLastError function.
    """

    return _ResumeThread(threadHandle)


def SuspendThread(threadHandle: int) -> int:
    """
    Suspends the specified thread.

    :param threadHandle: A handle to the thread that is to be suspended.
    :returns: If the function succeeds, the return value is the thread's previous suspend count. If the function fails,
              the return value is (DWORD) -1. To get extended error information, use the GetLastError function.
    """

    return _SuspendThread(threadHandle)


def GetExitCodeThread(threadHandle: int) -> int:
    """
    Retrieves the termination status of the specified thread.

    :param threadHandle: A handle to the thread.
    :returns: If the function succeeds, the return value is nonzero. If the function fails, the return value is
              (DWORD) -1. To get extended error information, call GetLastError.
    """

    exitCode: DWORD = DWORD()
    if _GetExitCodeThread(threadHandle, byref(exitCode)):
        return exitCode.value

    return -1


def GetThreadDescription(threadHandle: int) -> str:
    """
    Retrieves the description that was assigned to a thread by calling SetThreadDescription.

    :param threadHandle: A handle to the thread.
    :returns: If the function succeeds, the return value is the HRESULT that denotes a successful operation. If the
              function fails, the return value is an HRESULT that denotes the error.


    .. note:: **See also:**
        `HRESULT Values <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/705fb797-2175-4a90-b5a3
        -3918024b10b8>`_
    """

    nameBuffer = (WCHAR * 1024)()


    if SUCCEEDED(_GetThreadDescription(threadHandle, nameBuffer)):
        return nameBuffer.value[:-2]

    return ""


def SetThreadDescription(threadHandle: int, threadDescription: str) -> bool:
    """
    Retrieves the description that was assigned to a thread by calling SetThreadDescription.

    :param threadHandle: A handle to the thread.
    :param threadDescription: A string that specifies the description of the thread.
    :returns: If the function succeeds, the return value is the HRESULT that denotes a successful operation. If the
              function fails, the return value is an HRESULT that denotes the error.


    .. note:: **See also:**
        `HRESULT Values <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/705fb797-2175-4a90-b5a3
        -3918024b10b8>`_
    """

    return _SetThreadDescription(threadHandle, threadDescription)


def GetThreadPriority(threadHandle: int) -> int:
    """
    Retrieves the priority value for the specified thread. This value, together with the priority class of the thread's
    process, determines the thread's base-priority level.

    :param threadHandle: A handle to the thread.
    :returns: If the function succeeds, the return value is the thread's priority level. If the function fails,
              the return value is THREAD_PRIORITY_ERROR_RETURN. To get extended error information, call GetLastError.

    .. note:: **See also:**
        `GetThreadPriority <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi
        -getthreadpriority>`_
    """

    return _GetThreadPriority(threadHandle)


def SetThreadPriority(threadHandle: int, priority: int) -> bool:
    """
    Retrieves the priority value for the specified thread. This value, together with the priority class of the thread's
    process, determines the thread's base-priority level.

    :param threadHandle: A handle to the thread.
    :param priority: The priority value for the thread.
    :returns: If the function succeeds, the return value is nonzero. If the function fails, the return value is zero.
              To get extended error information, call GetLastError.

    .. note:: **See also:**
        `SetThreadPriority <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi
        -setthreadpriority>`_
    """

    return _SetThreadPriority(threadHandle, priority)


def TerminateThread(threadHandle: int, exitCode: int) -> bool:
    """
    Retrieves the termination status of the specified thread.

    :param threadHandle: A handle to the thread.
    :param exitCode: The exit code for the thread. Use the GetExitCodeThread function to retrieve a thread's exit value.
    :returns: If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
              get extended error information, call GetLastError.
    """

    return bool(_TerminateThread(threadHandle, exitCode))


def WaitForSingleObject(handle: int, milliseconds: int) -> int:
    return _WaitForSingleObject(handle, milliseconds)


def OpenProcess(processId: int, inheritHandle: bool, desiredAccess: int) -> int:
    """
    Opens an existing local process object.

    :param processId: The identifier of the local process to be opened.
    :param inheritHandle: If this value is TRUE, processes created by this process will inherit the handle. Otherwise,
                          the processes do not inherit this handle.
    :param desiredAccess: The access to the process object.
    :returns: If the function succeeds, the return value is an open handle to the specified process. If the function
              fails, the return value is NULL. To get extended error information, call GetLastError.
    """

    handle: int | None = _OpenProcess(desiredAccess, inheritHandle, processId)
    if handle is None:
        handle = 0

    return handle


def CloseHandle(handle: int) -> bool:
    """
    Closes an open object handle.

    :param handle: A valid handle to an open object.
    :returns: If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
              get extended error information, call GetLastError.
    """

    return _CloseHandle(handle)


def DuplicateHandle(
        sourceProcessHandle: int,
        sourceHandle: int,
        targetProcessHandle: int,
        targetHandle: Type[POINTER],
        desiredAccess: int,
        inheritHandle: bool,
        options: int) -> bool:
    """
    Duplicates an object handle.

    :param sourceProcessHandle: A handle to the process with the handle to duplicate.
    :param sourceHandle: The handle to be duplicated.
    :param targetProcessHandle: A handle to the process that is to receive the duplicated handle.
    :param targetHandle: A pointer to a variable that receives the duplicate handle.
    :param desiredAccess: The access requested for the new handle.
    :param inheritHandle: A variable that indicates whether the handle is inheritable.
    :param options: Optional actions.
    :returns: If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
              get extended error information, call GetLastError.
    """

    return _DuplicateHandle(
        sourceProcessHandle,
        sourceHandle,
        targetProcessHandle,
        targetHandle,
        desiredAccess,
        BOOL(inheritHandle),
        options
    )


def TerminateProcess(processHandle: int, exitCode: int) -> bool:
    """
    Terminates the specified process and all of its threads.

    :param processHandle: A handle to the process to be terminated.
    :param exitCode: The exit code to be used by the process and threads terminated as a result of this call.
    :returns: If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
              get extended error information, call GetLastError.
    """

    return _TerminateProcess(processHandle, exitCode)


def GetModuleHandleA(moduleName: str) -> int:
    """
    Retrieves a module handle for the specified module. The module must have been loaded by the calling process.

    :param moduleName: The name of the loaded module (either a .dll or .exe file).
    :returns: If the function succeeds, the return value is a handle to the specified module. If the function fails,
              the return value is NULL. To get extended error information, call GetLastError.
    """

    return _GetModuleHandleA(moduleName.encode())


def GetModuleHandleW(moduleName: str) -> int:
    """
    Retrieves a module handle for the specified module. The module must have been loaded by the calling process.

    :param moduleName: The name of the loaded module (either a .dll or .exe file).
    :returns: If the function succeeds, the return value is a handle to the specified module. If the function fails,
              the return value is NULL. To get extended error information, call GetLastError.
    """

    return _GetModuleHandleW(moduleName)


def GetProcAddress(moduleHandle: int, processName: str) -> int:
    """
    Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL).

    :param moduleHandle: A handle to the DLL module that contains the function or variable.
    :param processName: The function or variable name, or the function's ordinal value.
    :returns: If the function succeeds, the return value is the address of the exported function or variable. If the
              function fails, the return value is NULL. To get extended error information, call GetLastError.
    """

    return _GetProcAddress(moduleHandle, processName.encode('ascii'))


def ReadProcessMemory(
        processHandle: int,
        baseAddress: int,
        buffer: object,
        size: int,
        numberOfBytesRead: object) -> bool:
    """
    Reads data from an area of memory in a specified process. The entire area to be read must be accessible or the
    operation fails.

    :param processHandle: A handle to the process with memory that is being read.
    :param baseAddress: A pointer to the base address in the specified process from which to read.
    :param buffer: A pointer to a buffer that receives the contents from the address space of the specified process.
    :param size: The number of bytes to be read from the specified process.
    :param numberOfBytesRead: A pointer to a variable that receives the number of bytes transferred into the specified
                              buffer.
    :returns: If the function succeeds, the return value is nonzero. If the function fails, the return value is 0
              (zero). To get extended error information, call GetLastError. The function fails if the requested read
              operation crosses into an area of the process that is inaccessible.
    """

    return _ReadProcessMemory(processHandle, baseAddress, buffer, size, numberOfBytesRead)


def WriteProcessMemory(
        processHandle: int,
        baseAddress: int,
        buffer: object,
        size: int,
        numberOfBytesWritten: object) -> bool:
    """
    Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the
    operation fails.

    :param processHandle: A handle to the process with memory that is being read.
    :param baseAddress: A pointer to the base address in the specified process from which to read.
    :param buffer: A pointer to the buffer that contains data to be written in the address space of the specified
                   process.
    :param size: The number of bytes to be written to the specified process.
    :param numberOfBytesWritten: A pointer to a variable that receives the number of bytes transferred into the
                                 specified process.
    :returns: If the function fails, the return value is 0 (zero). To get extended error information, call GetLastError.
              The function fails if the requested read operation crosses into an area of the process that is
              inaccessible.
    """

    return _WriteProcessMemory(processHandle, baseAddress, buffer, size, numberOfBytesWritten)


def VirtualAlloc(address: int, size: int, allocationType: int, protect: int) -> int:
    """
    Reserves, commits, or changes the state of a region of pages in the virtual address space of the calling process.
    Memory allocated by this function is automatically initialized to zero. To allocate memory in the address space of
    another process, use the VirtualAllocEx function.

    :param address: The starting address of the region to allocate.
    :param size: The size of the region, in bytes. If the lpAddress parameter is NULL, this value is rounded up to the
                 next page boundary.
    :param allocationType: The type of memory allocation.
    :param protect: The memory protection for the region of pages to be allocated.
    :returns: If the function succeeds, the return value is the base address of the allocated region of pages. If the
              function fails, the return value is NULL. To get extended error information, call GetLastError.
    """

    return _VirtualAlloc(address, size, allocationType, protect)


def VirtualAllocEx(processHandle: int, address: int, size: int, allocationType: int, protect: int) -> int:
    """
    Reserves, commits, or changes the state of a region of memory within the virtual address space of a specified 
    process. The function initializes the memory it allocates to zero.
    
    :param processHandle: The handle to a process.
    :param address: The pointer that specifies a desired starting address for the region of pages that you want to
                    allocate.
    :param size: The size of the region of memory to allocate, in bytes.
    :param allocationType: The type of memory allocation.
    :param protect: The memory protection for the region of pages to be allocated.
    :returns: If the function succeeds, the return value is the base address of the allocated region of pages. If the
              function fails, the return value is NULL. To get extended error information, call GetLastError.
    """

    return _VirtualAllocEx(processHandle, address, size, allocationType, protect)


def VirtualFree(address: int, size: int, freeType: int) -> bool:
    """
    Releases, decommits, or releases and decommits a region of pages within the virtual address space of the calling
    process. To free memory allocated in another process by the VirtualAllocEx function, use the VirtualFreeEx function.
    
    :param address: A pointer to the base address of the region of pages to be freed.
    :param size: The size of the region of memory to be freed, in bytes.
    :param freeType: The type of free operation.
    :returns: If the function succeeds, the return value is nonzero. f the function fails, the return value is 0 (zero).
              To get extended error information, call GetLastError.
    """
    
    return _VirtualFree(address, size, freeType)


def VirtualFreeEx(processHandle: int, address: int, size: int, freeType: int) -> bool:
    """
    Reserves, commits, or changes the state of a region of memory within the virtual address space of a specified 
    process. The function initializes the memory it allocates to zero.
    
    :param processHandle: The handle to a process.
    :param address: The pointer that specifies a desired starting address for the region of pages that you want to
                    allocate.
    :param size: The size of the region of memory to allocate, in bytes.
    :param freeType: The type of memory allocation.
    :returns: If the function succeeds, the return value is the base address of the allocated region of pages. If the
              function fails, the return value is NULL. To get extended error information, call GetLastError.
    """

    return _VirtualFreeEx(processHandle, address, size, freeType)


def VirtualProtectEx(processHandle: int, address: int, size: int, newProtect: int, oldProtect: object) -> bool:
    """
    Changes the protection on a region of committed pages in the virtual address space of a specified process.
    
    :param processHandle: A handle to the process whose memory protection is to be changed.
    :param address: A pointer to the base address of the region of pages whose access protection attributes are to be
                    changed.
    :param size: The size of the region whose access protection attributes are changed, in bytes.
    :param newProtect: The memory protection option.
    :param oldProtect: A pointer to a variable that receives the previous access protection of the first page in the
                       specified region of pages.
    :returns: If the function succeeds, the return value is nonzero. If the function fails, the return value is zero.
              To get extended error information, call GetLastError.
    """

    return _VirtualProtectEx(processHandle, address, size, newProtect, oldProtect)


def CreateFileMappingW(
        fileHandle: int,
        fileMappingAttributes: int,
        protect: int,
        maximumSizeHigh: int,
        maximumSizeLow: int,
        name: str | None) -> int:
    """
    Creates or opens a named or unnamed file mapping object for a specified file.

    :param fileHandle: A handle to the file from which to create a file mapping object.
    :param fileMappingAttributes: A pointer to a SECURITY_ATTRIBUTES structure that determines whether a returned handle
                                  can be inherited by child processes.
    :param protect: Specifies the page protection of the file mapping object.
    :param maximumSizeHigh: The high-order DWORD of the maximum size of the file mapping object.
    :param maximumSizeLow: The low-order DWORD of the maximum size of the file mapping object.
    :param name: The name of the file mapping object.
    :returns: If the function succeeds, the return value is a handle to the newly created file mapping object. If the
              object exists before the function call, the function returns a handle to the existing object (with its
              current size, not the specified size), and GetLastError returns ERROR_ALREADY_EXISTS. If the function
              fails, the return value is 0. To get extended error information, call GetLastError.
    """

    if name is None:
        _CreateFileMappingW.argtypes = [HANDLE, ULONG, DWORD, DWORD, DWORD, LPVOID]
        name: int = 0
    else:
        _CreateFileMappingW.argtypes = [HANDLE, ULONG, DWORD, DWORD, DWORD, LPWSTR]

    return _CreateFileMappingW(fileHandle, fileMappingAttributes, protect, maximumSizeHigh, maximumSizeLow, name)


def MapViewOfFile(
        fileMappingObject: int,
        desiredAccess: int,
        fileOffsetHigh: int,
        fileOffsetLow: int,
        numberOfBytesToMap: int) -> int:
    """
    Maps a view of a file mapping into the address space of a calling process.

    :param fileMappingObject: A handle to a file mapping object.
    :param desiredAccess: The type of access to a file mapping object, which determines the page protection of the pages.
    :param fileOffsetHigh: A high-order DWORD of the file offset where the view begins.
    :param fileOffsetLow: A low-order DWORD of the file offset where the view is to begin.
    :param numberOfBytesToMap: The number of bytes of a file mapping to map to the view.
    :returns: If the function succeeds, the return value is the starting address of the mapped view. If the function
              fails, the return value is NULL. To get extended error information, call GetLastError.
    """

    return _MapViewOfFile(fileMappingObject, desiredAccess, fileOffsetHigh, fileOffsetLow, numberOfBytesToMap)


def UnmapViewOfFile(baseAddress: int) -> bool:
    """
    Unmaps a mapped view of a file from the calling process's address space.

    :param baseAddress: A pointer to the base address of the mapped view of a file that is to be unmapped.
    :returns: If the function succeeds, the return value is nonzero. If the function fails, the return value is zero.
              To get extended error information, call GetLastError.
    """

    return _UnmapViewOfFile(baseAddress)


def NtMapViewOfSection(
        sectionHandle: int,
        processHandle: int,
        baseAddress: object,
        zeroBits: int,
        commitSize: int,
        sectionOffset: object,
        viewSize: object,
        inheritDisposition: int,
        allocationType: int,
        win32Protect: int) -> int:
    """
    Maps a view of a section into the virtual address space of a subject process.

    :param sectionHandle: Handle to a section object.
    :param processHandle: Handle to the object that represents the process that the view should be mapped into.
    :param baseAddress: Pointer to a variable that receives the base address of the view.
    :param zeroBits: Specifies the number of high-order address bits that must be zero in the base address of the
                     section view.
    :param commitSize: Specifies the size, in bytes, of the initially committed region of the view.
    :param sectionOffset: A pointer to a variable that receives the offset, in bytes, from the beginning of the section
                          to the view.
    :param viewSize: A pointer to a SIZE_T variable.
    :param inheritDisposition: Specifies how the view is to be shared with child processes.
    :param allocationType: Specifies a set of flags that describes the type of allocation to be performed for the
                           specified region of pages.
    :param win32Protect: Specifies the type of protection for the region of initially committed pages.
    :returns: True if the function succeeds, False otherwise.
    """

    ntStatus: int = _NtMapViewOfSection(
        sectionHandle,
        processHandle,
        baseAddress,
        zeroBits,
        commitSize,
        sectionOffset,
        viewSize,
        inheritDisposition,
        allocationType,
        win32Protect
    )

    return ntStatus == STATUS_SUCCESS


def NtUnmapViewOfSection(processHandle: int, baseAddress: int) -> bool:
    """
    Unmaps a view of a section from the virtual address space of a subject process.

    :param processHandle: Handle to a process object that was previously passed to NtMapViewOfSection.
    :param baseAddress: Pointer to the base virtual address of the view to unmap.
    :returns: True if the function succeeds, False otherwise.
    """

    ntStatus: int = _NtUnmapViewOfSection(processHandle, baseAddress)
    return ntStatus == STATUS_SUCCESS


def NtQueryInformationProcess(
        processHandle: int,
        processInformationClass: object,
        processInformation: object,
        processInformationLength: int,
        returnLength: int) -> bool:
    """
    Retrieves information about the specified process.

    :param processHandle: A handle to the process for which information is to be retrieved.
    :param processInformationClass: The type of process information to be retrieved.
    :param processInformation: A pointer to a buffer supplied by the calling application into which the function writes
                               the requested information.
    :param processInformationLength: The size of the buffer pointed to by the ProcessInformation parameter, in bytes.
    :param returnLength: A pointer to a variable in which the function returns the size of the requested information.
    :returns: True if the function succeeds, False otherwise.
    """

    ntStatus: int = _NtQueryInformationProcess(
        processHandle,
        processInformationClass,
        processInformation,
        processInformationLength,
        returnLength
    )

    return ntStatus == STATUS_SUCCESS


def NtSuspendProcess(processHandle: int) -> bool:
    """
    Suspend the target process.

    :param processHandle: A handle to the process to be suspended.
    :returns: True if the function succeeds, False otherwise.
    """

    ntStatus: int = _NtSuspendProcess(processHandle)
    return ntStatus == STATUS_SUCCESS


def NtResumeProcess(processHandle: int) -> bool:
    """
    Resume the target process.

    :param processHandle: A handle to the process to be resumed.
    :returns: True if the function succeeds, False otherwise.
    """

    ntStatus: int = _NtResumeProcess(processHandle)
    return ntStatus == STATUS_SUCCESS


def CreateToolhelp32Snapshot(flags: int, th32ProcessId: int) -> int:
    """
    Takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.

    :param flags: The portions of the system to be included in the snapshot.
    :param th32ProcessId: The process identifier of the process to be included in the snapshot. This parameter can be
                          zero to indicate the current process.
    :returns: If the function succeeds, it returns an open handle to the specified snapshot.
    """

    return _CreateToolhelp32Snapshot(flags, th32ProcessId)


def Process32Next(snapshotHandle: int, lppe: object) -> bool:
    """
    Retrieves information about the next process recorded in a system snapshot.

    :param snapshotHandle: A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot
                           function.
    :param lppe: A pointer to a PROCESSENTRY32 structure.
    :returns: Returns TRUE if the next entry of the process list has been copied to the buffer or FALSE otherwise.
    """

    return _Process32Next(snapshotHandle, lppe)


def Process32First(snapshotHandle: int, lppe: object) -> bool:
    """
    Retrieves information about the first process encountered in a system snapshot.

    :param snapshotHandle: A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot
                           function.
    :param lppe: A pointer to a PROCESSENTRY32 structure.
    :returns: Returns TRUE if the first entry of the process list has been copied to the buffer or FALSE otherwise.
    """

    return _Process32First(snapshotHandle, lppe)


def Module32Next(snapshotHandle: int, lpme: object) -> bool:
    """
    Retrieves information about the next module associated with a process or thread.

    :param snapshotHandle: A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot
                           function.
    :param lpme: A pointer to a MODULEENTRY32 structure.
    :returns: Returns TRUE if the next entry of the module list has been copied to the buffer or FALSE otherwise.
    """

    return _Module32Next(snapshotHandle, lpme)


def Module32First(snapshotHandle: int, lpme: object) -> bool:
    """
    Retrieves information about the first module associated with a process.

    :param snapshotHandle: A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot
                           function.
    :param lpme: A pointer to a MODULEENTRY32 structure.
    :returns: Returns TRUE if the first entry of the module list has been copied to the buffer or FALSE otherwise.
    """

    return _Module32First(snapshotHandle, lpme)


def GetStdHandle(stdHandle: int) -> int:
    """
    Retrieves a handle to the specified standard device (standard input, standard output, or standard error).

    :param stdHandle: The standard device identifier. Can be STD_INPUT_HANDLE, STD_OUTPUT_HANDLE or STD_ERROR_HANDLE.
    """

    return _GetStdHandle(stdHandle)


def QueryFullProcessImageNameW(processHandle: int, flags: int, exeName: object, ptrSize: object) -> bool:
    """
    Retrieves the full name of the executable image for the specified process.

    :param processHandle: A handle to the process.
    :param flags: This parameter can be one of the following values:\n
                    0 - The name should use the Win32 path format.\n
                    1 - The name should use the native system path format.
    :param exeName: A pointer to a buffer that receives the full path to the executable image.
    :param ptrSize: On input, specifies the size of the lpExeName buffer, in characters. On success, receives the
                    number of characters written to the buffer, not including the null-terminating character.
    :returns: True if the function succeeds, False otherwise.
    """

    return _QueryFullProcessImageNameW(processHandle, flags, exeName, ptrSize)


class Win32Exception(RuntimeError):
    """
    Simple Exception-class to represent Windows Errors in python.

    :param errorCode:     Windows error code. if not provided, the windows last error will be used.
    :param customMessage: A customized message to show when raised. if not provided, the windows message
                          will be used.

    .. note:: **See also:** `GetLastError
          <https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror>`_ and
          `FormatMessageW <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-formatmessagew>`_
    """

    def __init__(self, errorCode: int = None, customMessage: str = None):
        self._errorCode: int = GetLastError() if (errorCode is None) else errorCode
        self._message: str = customMessage

        if customMessage is None:
            self.__FormatMessage()

    def GetErrorCode(self) -> int:
        """
        :returns: The error code.
        """

        return self._errorCode

    def GetErrorMessage(self) -> str:
        """
        :returns: The error message of the error code.
        """

        return self._message

    def __str__(self) -> str:
        return '%s (0x%08x)' % (self._message, self._errorCode)

    def __repr__(self) -> str:
        return 'Win32Exception(%s)' % str(self)

    def __FormatMessage(self) -> None:
        size = 256

        while size < 0x10000:  # Found 0x10000 in C# std lib
            msgBuffer = (WCHAR * size)()

            result = FormatMessageW(0x200 | 0x1000 | 0x2000, None, self._errorCode, 0, msgBuffer, size, None)

            if result > 0:
                self._message = msgBuffer[:result - 2]
                return

            if GetLastError() != 0x7A:  # ERROR_INSUFFICIENT_BUFFER
                break

        self._message = 'Unknown Error'


# region Function bindings
_GetLastError = windll.kernel32.GetLastError
_GetLastError.argtypes = []
_GetLastError.restype = DWORD

_FormatMessageW = windll.kernel32.FormatMessageW
_FormatMessageW.argtypes = [DWORD, LPVOID, DWORD, DWORD, LPWSTR, DWORD, LPVOID]
_FormatMessageW.restype = DWORD

_CreateProcessW = windll.kernel32.CreateProcessW
_CreateProcessW.argtypes = [LPCWSTR, LPWSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCWSTR, LPVOID, LPVOID]
_CreateProcessW.restype = BOOL

_GetExitCodeProcess = windll.kernel32.GetExitCodeProcess
_GetExitCodeProcess.argtypes = [HANDLE, PDWORD]
_GetExitCodeProcess.restype = BOOL

_CreateRemoteThread = windll.kernel32.CreateRemoteThread
_CreateRemoteThread.argtypes = [HANDLE, DWORD, LPVOID, DWORD, DWORD, DWORD, POINTER(DWORD)]
_CreateRemoteThread.restype = HANDLE

_OpenThread = windll.kernel32.OpenThread
_OpenThread.argtypes = [DWORD, BOOL, DWORD]
_OpenThread.restype = HANDLE

_ResumeThread = windll.kernel32.ResumeThread
_ResumeThread.argtypes = [HANDLE]
_ResumeThread.restype = DWORD

_SuspendThread = windll.kernel32.SuspendThread
_SuspendThread.argtypes = [HANDLE]
_SuspendThread.restype = DWORD

_GetExitCodeThread = windll.kernel32.GetExitCodeThread
_GetExitCodeThread.argtypes = [HANDLE, POINTER(DWORD)]
_GetExitCodeThread.restype = BOOL

_GetThreadDescription = windll.kernel32.GetThreadDescription
_GetThreadDescription.argtypes = [HANDLE, LPWSTR]
_GetThreadDescription.restype = DWORD

_SetThreadDescription = windll.kernel32.SetThreadDescription
_SetThreadDescription.argtypes = [HANDLE, LPCWSTR]
_SetThreadDescription.restype = DWORD

_GetPriorityClass = windll.kernel32.GetPriorityClass
_GetPriorityClass.argtypes = [HANDLE]
_GetPriorityClass.restype = DWORD

_SetPriorityClass = windll.kernel32.SetPriorityClass
_SetPriorityClass.argtypes = [HANDLE, DWORD]
_SetPriorityClass.restype = BOOL

_GetThreadPriority = windll.kernel32.GetThreadPriority
_GetThreadPriority.argtypes = [HANDLE]
_GetThreadPriority.restype = DWORD

_SetThreadPriority = windll.kernel32.SetThreadPriority
_SetThreadPriority.argtypes = [HANDLE, INT]
_SetThreadPriority.restype = BOOL

_TerminateThread = windll.kernel32.TerminateThread
_TerminateThread.argtypes = [HANDLE, DWORD]
_TerminateThread.restype = BOOL

_WaitForSingleObject = windll.kernel32.WaitForSingleObject
_WaitForSingleObject.argtypes = [HANDLE, DWORD]
_WaitForSingleObject.restype = DWORD

_OpenProcess = windll.kernel32.OpenProcess
_OpenProcess.argtypes = [DWORD, BOOL, DWORD]
_OpenProcess.restype = HANDLE

_CloseHandle = windll.kernel32.CloseHandle
_CloseHandle.argtypes = [HANDLE]
_CloseHandle.restype = BOOL

_DuplicateHandle = windll.kernel32.DuplicateHandle
_DuplicateHandle.argtypes = [HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD]
_DuplicateHandle.restype = BOOL

_TerminateProcess = windll.kernel32.TerminateProcess
_TerminateProcess.argtypes = [HANDLE, UINT]
_TerminateProcess.restype = BOOL

_GetModuleHandleA = windll.kernel32.GetModuleHandleA
_GetModuleHandleA.argtypes = [LPCSTR]
_GetModuleHandleA.restype = HMODULE

_GetModuleHandleW = windll.kernel32.GetModuleHandleW
_GetModuleHandleW.argtypes = [LPCWSTR]
_GetModuleHandleW.restype = HMODULE

_GetProcAddress = windll.kernel32.GetProcAddress
_GetProcAddress.argtypes = [HMODULE, LPCSTR]
_GetProcAddress.restype = LPVOID

_ReadProcessMemory = windll.kernel32.ReadProcessMemory
_ReadProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, DWORD, POINTER(DWORD)]
_ReadProcessMemory.restype = BOOL

_WriteProcessMemory = windll.kernel32.WriteProcessMemory
_WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, DWORD, POINTER(DWORD)]
_WriteProcessMemory.restype = BOOL

_VirtualAlloc = windll.kernel32.VirtualAlloc
_VirtualAlloc.argtypes = [LPVOID, DWORD, DWORD, DWORD]
_VirtualAlloc.restype = LPVOID

_VirtualAllocEx = windll.kernel32.VirtualAllocEx
_VirtualAllocEx.argtypes = [HANDLE, LPVOID, DWORD, DWORD, DWORD]
_VirtualAllocEx.restype = LPVOID

_VirtualFree = windll.kernel32.VirtualFree
_VirtualFree.argtypes = [LPVOID, DWORD, DWORD]
_VirtualFree.restype = BOOL

_VirtualFreeEx = windll.kernel32.VirtualFreeEx
_VirtualFreeEx.argtypes = [HANDLE, LPVOID, DWORD, DWORD]
_VirtualFreeEx.restype = BOOL

_VirtualProtectEx = windll.kernel32.VirtualProtectEx
_VirtualProtectEx.argtypes = [HANDLE, LPVOID, DWORD, DWORD, PDWORD]
_VirtualProtectEx.restype = BOOL

_CreateFileMappingW = windll.kernel32.CreateFileMappingW
_CreateFileMappingW.argtypes = [HANDLE, ULONG, DWORD, DWORD, DWORD, LPVOID]
_CreateFileMappingW.restype = HANDLE

_MapViewOfFile = windll.kernel32.MapViewOfFile
_MapViewOfFile.argtypes = [HANDLE, DWORD, DWORD, DWORD, DWORD]
_MapViewOfFile.restype = LPVOID

_UnmapViewOfFile = windll.kernel32.UnmapViewOfFile
_UnmapViewOfFile.argtypes = [LPVOID]
_UnmapViewOfFile.restype = BOOL

_NtQueryInformationProcess = windll.ntdll.NtQueryInformationProcess
_NtQueryInformationProcess.argtypes = [HANDLE, DWORD, LPVOID, DWORD, DWORD]
_NtQueryInformationProcess.restype = DWORD

_NtMapViewOfSection = windll.ntdll.NtMapViewOfSection
_NtMapViewOfSection.argtypes = [HANDLE, HANDLE, LPVOID, ULONG, ULONG, PLARGE_INTEGER, PULONG, ULONG, ULONG, ULONG]
_NtMapViewOfSection.restype = DWORD

_NtUnmapViewOfSection = windll.ntdll.NtUnmapViewOfSection
_NtUnmapViewOfSection.argtypes = [HANDLE, LPVOID]
_NtUnmapViewOfSection.restype = DWORD

_NtSuspendProcess = windll.ntdll.NtSuspendProcess
_NtSuspendProcess.argtypes = [HANDLE]
_NtSuspendProcess.restype = DWORD

_NtResumeProcess = windll.ntdll.NtResumeProcess
_NtResumeProcess.argtypes = [HANDLE]
_NtResumeProcess.restype = DWORD

_CreateToolhelp32Snapshot = windll.kernel32.CreateToolhelp32Snapshot
_CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
_CreateToolhelp32Snapshot.restype = HANDLE

_Process32Next = windll.kernel32.Process32Next
_Process32Next.argtypes = [HANDLE, LPVOID]
_Process32Next.restype = BOOL

_Process32First = windll.kernel32.Process32First
_Process32First.argtypes = [HANDLE, LPVOID]
_Process32First.restype = BOOL

_Module32Next = windll.kernel32.Module32Next
_Module32Next.argtypes = [HANDLE, LPVOID]
_Module32Next.restype = BOOL

_Module32First = windll.kernel32.Module32First
_Module32First.argtypes = [HANDLE, LPVOID]
_Module32First.restype = BOOL

_GetStdHandle = windll.kernel32.GetStdHandle
_GetStdHandle.argtypes = [DWORD]
_GetStdHandle.restype = HANDLE

_QueryFullProcessImageNameW = windll.kernel32.QueryFullProcessImageNameW
_QueryFullProcessImageNameW.argtypes = [HANDLE, DWORD, LPWSTR, PDWORD]
_QueryFullProcessImageNameW.restype = BOOL
# endregion
