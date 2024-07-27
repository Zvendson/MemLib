"""
:platform: Windows
"""

from __future__ import annotations

from ctypes import WINFUNCTYPE
from ctypes.wintypes import (
    BYTE, CHAR, DWORD, HANDLE,
    HMODULE, HWND, INT, LONG,
    LPARAM, LPCSTR, LPSTR, LPVOID,
    LPWSTR, MAX_PATH, PBYTE, UINT, ULONG,
    USHORT, WORD, WPARAM,
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


class UNICODE_STRING(Struct):
    """
    The UNICODE_STRING structure is used by various Local Security Authority (LSA) functions to specify a Unicode string

    **See also:** `UNICODE_STRING
    <https://learn.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string>`_
    """

    _fields_ = [
        ('Length', USHORT),
        ('MaximumLength', USHORT),
        ('Buffer', LPWSTR),
    ]


class PEB(Struct):
    """
    Contains process information.

    **See also:** `PEB <https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb>`_ or
    `Exploring-PEB <https://void-stack.github.io/blog/post-Exploring-PEB/>`_
    """

    _fields_ = [
        ('InheritedAddressSpace', BYTE),
        ('ReadImageFileExecOptions', BYTE),
        ('BeingDebugged', BYTE),
        ('BitField', BYTE),
        ('Mutant', LPVOID),
        ('ImageBaseAddress', LPVOID),
        ('Ldr', LPVOID),
        ('ProcessParameters', LPVOID),
        ('SubSystemData', LPVOID),
        ('ProcessHeap', LPVOID),
        ('FastPebLock', LPVOID),
        ('AtlThunkSListPtr', LPVOID),
        ('IFEOKey', LPVOID),
        ('CrossProcessFlags', DWORD),
        ('UserSharedInfoPtr', LPVOID),
        ('SystemReserved', DWORD),
        ('SpareUlong', DWORD),
        ('FreeList', LPVOID),
        ('TlsExpansionCounter', DWORD),
        ('TlsBitmap', LPVOID),
        ('TlsBitmapBits', DWORD * 2),
        ('ReadOnlySharedMemoryBase', LPVOID),
        ('HotpatchInformation', LPVOID),
        ('ReadOnlyStaticServerData', LPVOID),
        ('AnsiCodePageData', LPVOID),
        ('OemCodePageData', LPVOID),
        ('UnicodeCaseTableData', LPVOID),
        ('NumberOfProcessors', DWORD),
        ('NtGlobalFlag', DWORD),

        # Actually QWORD but for some reason LARGE_INTEGER has a size of 0xC in structs ???
        ('CriticalSectionTimeout1', DWORD),
        ('CriticalSectionTimeout2', DWORD),
        ('HeapSegmentReserve', DWORD),
        ('HeapSegmentCommit', DWORD),
        ('HeapDeCommitTotalFreeThreshold', DWORD),
        ('HeapDeCommitFreeBlockThreshold', DWORD),
        ('NumberOfHeaps', DWORD),
        ('MaximumNumberOfHeaps', DWORD),
        ('ProcessHeaps', LPVOID),
        ('GdiSharedHandleTable', LPVOID),
        ('ProcessStarterHelper', LPVOID),
        ('GdiDCAttributeList', LPVOID),
        ('LoaderLock', LPVOID),
        ('OSMajorVersion', DWORD),
        ('OSMinorVersion', DWORD),
        ('OSBuildNumber', WORD),
        ('OSCSDVersion', WORD),
        ('OSPlatformId', DWORD),
        ('ImageSubsystem', DWORD),
        ('ImageSubsystemMajorVersion', DWORD),
        ('ImageSubsystemMinorVersion', DWORD),
        ('ImageProcessAffinityMask', DWORD),
        ('GdiHandleBuffer', DWORD * 34),
        ('PostProcessInitRoutine', LPVOID),
        ('TlsExpansionBitmap', LPVOID),
        ('TlsExpansionBitmapBits', DWORD * 32),
        ('SessionId', DWORD),

        # Actually QWORDs but for some reason LARGE_INTEGER has a size of 0xC in structs ???
        ('AppCompatFlags1', DWORD),
        ('AppCompatFlags2', DWORD),
        ('AppCompatFlagsUser1', DWORD),
        ('AppCompatFlagsUser2', DWORD),

        ('pShimData', LPVOID),
        ('AppCompatInfo', LPVOID),
        ('CSDVersion', UNICODE_STRING),
        ('ActivationContextData', LPVOID),
        ('ProcessAssemblyStorageMap', LPVOID),
        ('SystemDefaultActivationContextData', LPVOID),
        ('SystemAssemblyStorageMap', LPVOID),
        ('MinimumStackCommit', DWORD),
        ('FlsCallback', LPVOID),
        ('FlsListHeadNext', LPVOID),
        ('FlsListHeadFirst', LPVOID),
        ('FlsBitmap', LPVOID),
        ('FlsBitmapBits', DWORD * 4),
        ('FlsHighIndex', DWORD),
        ('WerRegistrationData', LPVOID),
        ('WerShipAssertPtr', LPVOID),
    ]


class IMAGE_FILE_HEADER(Struct):
    """
    Contains process information.

    **See also:** `IMAGE_FILE_HEADER
    <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header>`_
    """

    _fields_ = [
        ('Machine', WORD),
        ('NumberOfSections', WORD),
        ('TimeDateStamp', DWORD),
        ('PointerToSymbolTable', DWORD),
        ('NumberOfSymbols', DWORD),
        ('SizeOfOptionalHeader', WORD),
        ('Characteristics', WORD),
    ]


class IMAGE_OPTIONAL_HEADER32(Struct):
    """
    Contains process information.

    **See also:** `IMAGE_OPTIONAL_HEADER32
    <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32>`_
    """

    _fields_ = [
        ('Magic', WORD),
        ('MajorLinkerVersion', BYTE),
        ('MinorLinkerVersion', BYTE),
        ('SizeOfCode', DWORD),
        ('SizeOfInitializedData', DWORD),
        ('SizeOfUninitializedData', DWORD),
        ('AddressOfEntryPoint', DWORD),
        ('BaseOfCode', DWORD),
        ('BaseOfData', DWORD),
        ('ImageBase', DWORD),
        ('SectionAlignment', DWORD),
        ('FileAlignment', DWORD),
        ('MajorOperatingSystemVersion', WORD),
        ('MinorOperatingSystemVersion', WORD),
        ('MajorImageVersion', WORD),
        ('MinorImageVersion', WORD),
        ('MajorSubsystemVersion', WORD),
        ('MinorSubsystemVersion', WORD),
        ('Win32VersionValue', DWORD),
        ('SizeOfImage', DWORD),
        ('SizeOfHeaders', DWORD),
        ('CheckSum', DWORD),
        ('Subsystem', WORD),
        ('DllCharacteristics', WORD),
        ('SizeOfStackReserve', DWORD),
        ('SizeOfStackCommit', DWORD),
        ('SizeOfHeapReserve', DWORD),
        ('SizeOfHeapCommit', DWORD),
        ('LoaderFlags', DWORD),
        ('NumberOfRvaAndSizes', DWORD),
        ('DataDirectory', LPVOID),  # is an array of pointers including 0 sized array (no DataDirectory at all).
    ]


class IMAGE_SECTION_HEADER(Struct):
    """
    Contains process information.

    **See also:** `IMAGE_NT_HEADERS32
    <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32>`_
    """

    _fields_ = [
        ('Name', CHAR * 8),
        ('VirtualSize', DWORD),
        ('VirtualAddress', DWORD),
        ('SizeOfRawData', DWORD),
        ('PointerToRawData', DWORD),
        ('PointerToRelocations', DWORD),
        ('PointerToLinenumbers', DWORD),
        ('NumberOfRelocations', WORD),
        ('NumberOfLinenumbers', WORD),
        ('Characteristics', DWORD),
    ]


class IMAGE_NT_HEADERS32(Struct):
    """
    Contains process information.

    **See also:** `IMAGE_NT_HEADERS32
    <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32>`_
    """

    _fields_ = [
        ('Signature', DWORD),
        ('FileHeader', IMAGE_FILE_HEADER),
        ('OptionalHeader', IMAGE_OPTIONAL_HEADER32),
    ]

    def GetSectionsOffset(self) -> int:
        return IMAGE_NT_HEADERS32.OptionalHeader.offset + self.FileHeader.SizeOfOptionalHeader


class MZ_FILEHEADER(Struct):
    """
    The MS-DOS EXE format, also known as MZ after its signature.

    **See also:** `PE_FILEHEADER <https://wiki.osdev.org/MZ>`_
    """

    _fields_ = [
        ('Signature', WORD),
        ('ExtraBytes', WORD),
        ('Pages', WORD),
        ('RelocationItems', WORD),
        ('HeaderSize', WORD),
        ('MinAllow', WORD),
        ('MaxAllow', WORD),
        ('InitialSS', WORD),
        ('InitialSP', WORD),
        ('Checksum', WORD),
        ('InitialIS', WORD),
        ('InitialCS', WORD),
        ('RelocationTable', WORD),
        ('Overlay', WORD),
        ('OverlayInfo1', DWORD),  # Actually QWORD but for some reason LARGE_INTEGER has a size of 0xC in structs ???
        ('OverlayInfo2', DWORD),
        ('OEMIdentifier', WORD),
        ('OEMInfo', WORD),
        ('Reserved', BYTE * 20),
        ('PEHeaderOffset', DWORD),
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



