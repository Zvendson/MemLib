"""
:platform: Windows
"""

from ctypes import Array, POINTER, byref, windll
from ctypes.wintypes import (
    BOOL, DWORD, HANDLE, HMODULE, LPCSTR, LPCWSTR, LPHANDLE, LPVOID, LPWSTR, PDWORD,
    PLARGE_INTEGER, PULONG, UINT, ULONG,
)
from typing import Type, Union

from memlib.structs import PROCESSENTRY32, MODULEENTRY32


def GetLastError() -> int:
    """
    Retrieves the calling thread's last-error code value. The last-error code is maintained on a per-thread basis.

    :returns: The return value is the calling thread's last-error code.
    """
    return _GetLastError()


def FormatMessageW(flags: int, src: object, msgId: int, langId: int, buffer: Array, size: int, args: object) -> int:
    """
    Formats a message string. The function requires a message definition as input. The message definition can come from
    a buffer passed into the function. It can come from a message table resource in an already-loaded module. Or the
    caller can ask the function to search the system's message table resource(s) for the message definition. The
    function finds the message definition in a message table resource based on a message identifier and a language
    identifier. The function copies the formatted message text to an output buffer, processing any embedded insert
    sequences if requested.

    :param flags: The formatting options, and how to interpret the lpSource parameter.
    :param src: The location of the message definition.
    :param msgId: The message identifier for the requested message.
    :param langId: The language identifier for the requested message.
    :param buffer: A pointer to a buffer that receives the null-terminated string that specifies the formatted message.
    :param size: If the FORMAT_MESSAGE_ALLOCATE_BUFFER flag is not set, this parameter specifies the size of the
                 output buffer, in TCHARs. If FORMAT_MESSAGE_ALLOCATE_BUFFER is set, this parameter specifies the
                 minimum number of TCHARs to allocate for an output buffer.
    :param args: An array of values that are used as insert values in the formatted message.
    :returns: If the function succeeds, the return value is the number of TCHARs stored in the output buffer, excluding
                the terminating null character. If the function fails, the return value is zero. To get extended error
                information, call GetLastError.
    """
    return _FormatMessageW(flags, src, msgId, langId, buffer, size, args)


def CreateProcessW(name: Union[str, None], cmdl: str, pAttr: int, tAttr: int, inherit: bool, flags: int,
                   env: int, currDir: Union[str, None], startupInfo: object, procInfo: object) -> bool:
    """
    Creates a new process and its primary thread. The new process runs in the security context of the calling process.

    :param name: The name of the module to be executed.
    :param cmdl: The command line to be executed.
    :param pAttr: A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned handle to the new
                  process object can be inherited by child processes.
    :param tAttr: A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned handle to the new
                  thread object can be inherited by child processes.
    :param inherit: If this parameter is TRUE, each inheritable handle in the calling process is inherited by the new
                    process.
    :param flags: The flags that control the priority class and the creation of the process.
    :param env: A pointer to the environment block for the new process.
    :param currDir: The full path to the current directory for the process. f this parameter is NULL, the new process
                    will have the same current drive and directory as the calling process.
    :param startupInfo: A pointer to a StartupInfoW structure.
    :param procInfo: A pointer to a PROCESS_INFORMATION structure that receives identification information about the new
                     process.
    :returns: If the function succeeds, the return value is TRUE, False otherwise. If the function fails, the return
              value is zero. To get extended error information, call GetLastError.
    """

    return _CreateProcessW(name, cmdl, pAttr, tAttr, BOOL(inherit), flags, env, currDir, startupInfo, procInfo)


def GetExitCodeProcess(hProc: int) -> int:
    """
    Retrieves the termination status of the specified process.

    :param hProc: A handle to the process.
    :returns: If the function succeeds, the return value is the termination status of the specified process. If the
              function fails, the return value is 0. To get extended error information, call GetLastError.
    """
    
    exitCode = DWORD()
    if _GetExitCodeProcess(hProc, byref(exitCode)):
        return exitCode.value

    return 0


def ResumeThread(hThread: int) -> int:
    """
    Decrements a thread's suspend count. When the suspend count is decremented to zero, the execution of the thread is
    resumed.

    :param hThread: A handle to the thread to be restarted.
    :returns: If the function succeeds, the return value is the thread's previous suspend count. If the function fails,
                the return value is (DWORD) -1. To get extended error information, use the GetLastError function.
    """
    return _ResumeThread(hThread)


def OpenProcess(processId: int, inherit: bool, access: int) -> int:
    """
    Opens an existing local process object.

    :param processId: The identifier of the local process to be opened.
    :param inherit: If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the
                    processes do not inherit this handle.
    :param access: The access to the process object.
    :returns: If the function succeeds, the return value is an open handle to the specified process. If the function
             fails, the return value is NULL. To get extended error information, call GetLastError.
    """

    return _OpenProcess(access, inherit, processId)


def CloseHandle(handle: int) -> bool:
    """
    Closes an open object handle.

    :param handle: A valid handle to an open object.
    :returns: If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
              get extended error information, call GetLastError.
    """

    return _CloseHandle(handle)


def DuplicateHandle(hProc: int, hSrc: int, hProc2: int, hTar: Type[POINTER], acc: int, inherit: bool, opt: int) -> bool:
    """
    Duplicates an object handle.

    :param hProc: A handle to the process with the handle to duplicate.
    :param hSrc: The handle to be duplicated.
    :param hProc2: A handle to the process that is to receive the duplicated handle.
    :param hTar: A pointer to a variable that receives the duplicate handle.
    :param acc: The access requested for the new handle.
    :param inherit: A variable that indicates whether the handle is inheritable.
    :param opt: Optional actions.
    :returns: If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
             get extended error information, call GetLastError.
    """

    return _DuplicateHandle(hProc, hSrc, hProc2, hTar, acc, BOOL(inherit), opt)


def TerminateProcess(hProc: int, uExitCode: int) -> bool:
    """
    Terminates the specified process and all of its threads.

    :param hProc: A handle to the process to be terminated.
    :param uExitCode: The exit code to be used by the process and threads terminated as a result of this call.
    :returns: If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
              get extended error information, call GetLastError.
    """

    return _TerminateProcess(hProc, uExitCode)


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


def GetProcAddress(hModule: int, procName: str) -> int:
    """
    Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL).

    :param hModule: A handle to the DLL module that contains the function or variable.
    :param procName: The function or variable name, or the function's ordinal value.
    :returns: If the function succeeds, the return value is the address of the exported function or variable. If the
              function fails, the return value is NULL. To get extended error information, call GetLastError.
    """

    return _GetProcAddress(hModule, procName.encode('ascii'))


def ReadProcessMemory(hProc: int, address: int, buffer: object, size: int, bytesRead: object) -> bool:
    """
    Reads data from an area of memory in a specified process. The entire area to be read must be accessible or the
    operation fails.

    :param hProc: A handle to the process with memory that is being read.
    :param address: A pointer to the base address in the specified process from which to read.
    :param buffer: A pointer to a buffer that receives the contents from the address space of the specified process.
    :param size: The number of bytes to be read from the specified process.
    :param bytesRead: A pointer to a variable that receives the number of bytes transferred into the specified buffer.
    :returns: If the function succeeds, the return value is nonzero. If the function fails, the return value is 0
              (zero). To get extended error information, call GetLastError. The function fails if the requested read
              operation crosses into an area of the process that is inaccessible.
    """
    return _ReadProcessMemory(hProc, address, buffer, size, bytesRead)


def WriteProcessMemory(hProc: int, address: int, buffer: object, size: int, bytesWritten: object) -> bool:
    """
    Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the
    operation fails.

    :param hProc: A handle to the process with memory that is being read.
    :param address: A pointer to the base address in the specified process from which to read.
    :param buffer: A pointer to the buffer that contains data to be written in the address space of the specified
                   process.
    :param size: The number of bytes to be written to the specified process.
    :param bytesWritten: A pointer to a variable that receives the number of bytes transferred into the specified
                         process.
    :returns: If the function fails, the return value is 0 (zero). To get extended error information, call GetLastError.
              The function fails if the requested read operation crosses into an area of the process that is
              inaccessible.
    """
    return _WriteProcessMemory(hProc, address, buffer, size, bytesWritten)


def VirtualAlloc(address: int, size: int, alloc: int, prot: int) -> int:
    """
    Reserves, commits, or changes the state of a region of pages in the virtual address space of the calling process.
    Memory allocated by this function is automatically initialized to zero. To allocate memory in the address space of
    another process, use the VirtualAllocEx function.

    :param address: The starting address of the region to allocate.
    :param size: The size of the region, in bytes. If the lpAddress parameter is NULL, this value is rounded up to the
                 next page boundary.
    :param alloc: The type of memory allocation.
    :param prot: The memory protection for the region of pages to be allocated.
    :returns: If the function succeeds, the return value is the base address of the allocated region of pages. If the
              function fails, the return value is NULL. To get extended error information, call GetLastError.
    """
    return _VirtualAlloc(address, size, alloc, prot)


def VirtualAllocEx(hProc: int, address: int, size: int, alloc: int, prot: int) -> int:
    """
    Reserves, commits, or changes the state of a region of memory within the virtual address space of a specified 
    process. The function initializes the memory it allocates to zero.
    
    :param hProc: The handle to a process.
    :param address: The pointer that specifies a desired starting address for the region of pages that you want to
                    allocate.
    :param size: The size of the region of memory to allocate, in bytes.
    :param alloc: The type of memory allocation.
    :param prot: The memory protection for the region of pages to be allocated.
    :returns: If the function succeeds, the return value is the base address of the allocated region of pages. If the
              function fails, the return value is NULL. To get extended error information, call GetLastError.
    """
    return _VirtualAllocEx(hProc, address, size, alloc, prot)


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


def VirtualFreeEx(hProc: int, address: int, size: int, freeType: int) -> bool:
    """
    Reserves, commits, or changes the state of a region of memory within the virtual address space of a specified 
    process. The function initializes the memory it allocates to zero.
    
    :param hProc: The handle to a process.
    :param address: The pointer that specifies a desired starting address for the region of pages that you want to
                    allocate.
    :param size: The size of the region of memory to allocate, in bytes.
    :param freeType: The type of memory allocation.
    :returns: If the function succeeds, the return value is the base address of the allocated region of pages. If the
              function fails, the return value is NULL. To get extended error information, call GetLastError.
    """

    return _VirtualFreeEx(hProc, address, size, freeType)


def VirtualProtectEx(hProc: int, address: int, size: int, newProt: int, oldProt: object) -> bool:
    """
    Changes the protection on a region of committed pages in the virtual address space of a specified process.
    
    :param hProc: A handle to the process whose memory protection is to be changed.
    :param address: A pointer to the base address of the region of pages whose access protection attributes are to be
                    changed.
    :param size: The size of the region whose access protection attributes are changed, in bytes.
    :param newProt: The memory protection option.
    :param oldProt: A pointer to a variable that receives the previous access protection of the first page in the
                    specified region of pages.
    :returns: If the function succeeds, the return value is nonzero. If the function fails, the return value is zero.
              To get extended error information, call GetLastError.
    """

    return _VirtualProtectEx(hProc, address, size, newProt, oldProt)


def CreateFileMappingW(hFile: int, attributes: int, prot: int, sizeHi: int, sizeLo: int, name: Union[str, None]) -> int:
    """
    Creates or opens a named or unnamed file mapping object for a specified file.

    :param hFile: A handle to the file from which to create a file mapping object.
    :param attributes: A pointer to a SECURITY_ATTRIBUTES structure that determines whether a returned handle can be
                       inherited by child processes.
    :param prot: Specifies the page protection of the file mapping object.
    :param sizeHi: The high-order DWORD of the maximum size of the file mapping object.
    :param sizeLo: The low-order DWORD of the maximum size of the file mapping object.
    :param name: The name of the file mapping object.
    :returns: If the function succeeds, the return value is a handle to the newly created file mapping object. If the
              object exists before the function call, the function returns a handle to the existing object (with its
              current size, not the specified size), and GetLastError returns ERROR_ALREADY_EXISTS. If the function
              fails, the return value is 0. To get extended error information, call GetLastError.
    """

    if name is None:
        _CreateFileMappingW.argtypes = [HANDLE, ULONG, DWORD, DWORD, DWORD, LPVOID]
        name = 0
    else:
        _CreateFileMappingW.argtypes = [HANDLE, ULONG, DWORD, DWORD, DWORD, LPWSTR]

    return _CreateFileMappingW(hFile, attributes, prot, sizeHi, sizeLo, name)


def MapViewOfFile(hFile: int, access: int, offsetHi: int, offsetLo: int, length: int) -> int:
    """
    Maps a view of a file mapping into the address space of a calling process.

    :param hFile: A handle to a file mapping object.
    :param access: The type of access to a file mapping object, which determines the page protection of the pages.
    :param offsetHi: A high-order DWORD of the file offset where the view begins.
    :param offsetLo: A low-order DWORD of the file offset where the view is to begin.
    :param length: The number of bytes of a file mapping to map to the view.
    :returns: If the function succeeds, the return value is the starting address of the mapped view. If the function
              fails, the return value is NULL. To get extended error information, call GetLastError.
    """

    return _MapViewOfFile(hFile, access, offsetHi, offsetLo, length)


def UnmapViewOfFile(address: int) -> bool:
    """
    Unmaps a mapped view of a file from the calling process's address space.

    :param address: A pointer to the base address of the mapped view of a file that is to be unmapped.
    :returns: If the function succeeds, the return value is nonzero. If the function fails, the return value is zero.
              To get extended error information, call GetLastError.
    """

    return _UnmapViewOfFile(address)


def NtMapViewOfSection(hSec: int, hProc: int, base: object, zeroBits: int, size: int,
                       offset: object, viewSize: object, inherit: int, alloc: int, prot: int) -> int:
    """
    Maps a view of a section into the virtual address space of a subject process.

    :param hSec: Handle to a section object.
    :param hProc: Handle to the object that represents the process that the view should be mapped into.
    :param base: Pointer to a variable that receives the base address of the view.
    :param zeroBits: Specifies the number of high-order address bits that must be zero in the base address of the
                     section view.
    :param size: Specifies the size, in bytes, of the initially committed region of the view.
    :param offset: A pointer to a variable that receives the offset, in bytes, from the beginning of the section to the
                   view.
    :param viewSize: A pointer to a SIZE_T variable.
    :param inherit: Specifies how the view is to be shared with child processes.
    :param alloc: Specifies a set of flags that describes the type of allocation to be performed for the specified
                  region of pages.
    :param prot: Specifies the type of protection for the region of initially committed pages.
    :returns: True if the function succeeds, False otherwise.
    """

    NtStatus = _NtMapViewOfSection(hSec, hProc, base, zeroBits, size, offset, viewSize, inherit, alloc, prot)
    return NtStatus == 0  # 0 is STATUS_SUCCESS


def NtUnmapViewOfSection(hSec: int, address: int) -> bool:
    """
    Unmaps a view of a section from the virtual address space of a subject process.

    :param hSec: Handle to a process object that was previously passed to NtMapViewOfSection.
    :param address: Pointer to the base virtual address of the view to unmap.
    :returns: True if the function succeeds, False otherwise.
    """

    NtStatus = _NtUnmapViewOfSection(hSec, address)
    return NtStatus == 0  # 0 is STATUS_SUCCESS


def NtQueryInformationProcess(hProc: int, procInfoClass: object, procInfo: object, infoLen: int, outLen: int) -> bool:
    """
    Retrieves information about the specified process.

    :param hProc: A handle to the process for which information is to be retrieved.
    :param procInfoClass: The type of process information to be retrieved.
    :param procInfo: A pointer to a buffer supplied by the calling application into which the function writes the
                     requested information.
    :param infoLen: The size of the buffer pointed to by the ProcessInformation parameter, in bytes.
    :param outLen: A pointer to a variable in which the function returns the size of the requested information.
    :returns: True if the function succeeds, False otherwise.
    """

    NtStatus = _NtQueryInformationProcess(hProc, procInfoClass, procInfo, infoLen, outLen)
    return NtStatus == 0


def NtSuspendProcess(hProc: int) -> bool:
    """
    Suspend the target process.

    :param hProc: A handle to the process to be suspended.
    :returns: True if the function succeeds, False otherwise.
    """

    NtStatus = _NtSuspendProcess(hProc)
    return NtStatus == 0


def NtResumeProcess(hProc: int) -> bool:
    """
    Resume the target process.

    :param hProc: A handle to the process to be resumed.
    :returns: True if the function succeeds, False otherwise.
    """

    NtStatus = _NtResumeProcess(hProc)
    return NtStatus == 0


def CreateToolhelp32Snapshot(flags: int, processId: int) -> int:
    """
    Takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.

    :param flags: The portions of the system to be included in the snapshot.
    :param processId: The process identifier of the process to be included in the snapshot.
    :returns: If the function succeeds, it returns an open handle to the specified snapshot.
    """

    return _CreateToolhelp32Snapshot(flags, processId)


def Process32Next(hSnapshot: int, lppe: object) -> bool:
    """
    Retrieves information about the next process recorded in a system snapshot.

    :param hSnapshot: A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.
    :param lppe: A pointer to a PROCESSENTRY32 structure.
    :returns: Returns TRUE if the next entry of the process list has been copied to the buffer or FALSE otherwise.
    """

    return _Process32Next(hSnapshot, lppe)


def Process32First(hSnapshot: int, lppe: object) -> bool:
    """
    Retrieves information about the first process encountered in a system snapshot.

    :param hSnapshot: A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.
    :param lppe: A pointer to a PROCESSENTRY32 structure.
    :returns: Returns TRUE if the first entry of the process list has been copied to the buffer or FALSE otherwise.
    """

    return _Process32First(hSnapshot, lppe)


def Module32Next(hSnapshot: int, lpme: object) -> bool:
    """
    Retrieves information about the next module associated with a process or thread.

    :param hSnapshot: A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.
    :param lpme: A pointer to a MODULEENTRY32 structure.
    :returns: Returns TRUE if the next entry of the module list has been copied to the buffer or FALSE otherwise.
    """

    return _Module32Next(hSnapshot, lpme)


def Module32First(hSnapshot: int, lpme: object) -> bool:
    """
    Retrieves information about the first module associated with a process.

    :param hSnapshot: A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.
    :param lpme: A pointer to a MODULEENTRY32 structure.
    :returns: Returns TRUE if the first entry of the module list has been copied to the buffer or FALSE otherwise.
    """

    return _Module32First(hSnapshot, lpme)


def GetStdHandle(stdIdentifier: int) -> int:
    """
    Retrieves a handle to the specified standard device (standard input, standard output, or standard error).

    :param stdIdentifier: The standard device identifier:\n
                          0 - Handle to the standard input device
                          1 - Handle to the standard output device
                          2 - Handle to the standard error device"""

    if not (0 <= stdIdentifier < 3):
        raise ValueError("stdIdentifier must be 0, 1 or 2.")

    return _GetStdHandle(stdIdentifier)


def QueryFullProcessImageNameW(hProc: int, dwFlags: int, lpExeName: object, lpdwSize: object) -> bool:
    """
    Retrieves the full name of the executable image for the specified process.

    :param hProc: A handle to the process.
    :param dwFlags: This parameter can be one of the following values:\n
                    0 - The name should use the Win32 path format.\n
                    1 - The name should use the native system path format.
    :param lpExeName: A pointer to a buffer that receives the full path to the executable image.
    :param lpdwSize: On input, specifies the size of the lpExeName buffer, in characters. On success, receives the
                     number of characters written to the buffer, not including the null-terminating character.
    :returns: True if the function succeeds, False otherwise.
    """

    return _QueryFullProcessImageNameW(hProc, dwFlags, lpExeName, lpdwSize)


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

_ResumeThread = windll.kernel32.ResumeThread
_ResumeThread.argtypes = [HANDLE]
_ResumeThread.restype = DWORD

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
_Process32Next.argtypes = [HANDLE, POINTER(PROCESSENTRY32)]
_Process32Next.restype = BOOL

_Process32First = windll.kernel32.Process32First
_Process32First.argtypes = [HANDLE, POINTER(PROCESSENTRY32)]
_Process32First.restype = BOOL

_Module32Next = windll.kernel32.Module32Next
_Module32Next.argtypes = [HANDLE, POINTER(MODULEENTRY32)]
_Module32Next.restype = BOOL

_Module32First = windll.kernel32.Module32First
_Module32First.argtypes = [HANDLE, POINTER(MODULEENTRY32)]
_Module32First.restype = BOOL

_GetStdHandle = windll.kernel32.GetStdHandle
_GetStdHandle.argtypes = [DWORD]
_GetStdHandle.restype = HANDLE

_QueryFullProcessImageNameW = windll.kernel32.QueryFullProcessImageNameW
_QueryFullProcessImageNameW.argtypes = [HANDLE, DWORD, LPWSTR, PDWORD]
_QueryFullProcessImageNameW.restype = BOOL
# endregion
