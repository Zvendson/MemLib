"""
Windows native structure definitions for process, thread, PE, and GUI data.

This module provides Python ctypes-based structures that map to Windows native
types used for process management, Portable Executable (PE) parsing, thread and
module enumeration, and GUI programming.

Features:
    * Process/thread structures (PROCESS_INFORMATION, PROCESSENTRY32, THREADENTRY32)
    * PE/COFF/NT/section/image headers for PE file parsing (IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32, etc.)
    * Windows message and GUI-related structures (MSG, WNDCLASS)
    * Unicode and ANSI variants where appropriate
    * Structs extend a common Struct base class for enhanced inspection

Example:
    dos = IMAGE_DOS_HEADER()
    print(dos)

References:
    https://learn.microsoft.com/en-us/windows/win32/api/
    https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    https://docs.python.org/3/library/ctypes.html
"""

from ctypes import WINFUNCTYPE
from ctypes.wintypes import (
    BYTE, CHAR, DWORD, HANDLE, HMODULE, HWND, INT, LONG, LPARAM, LPCSTR, LPSTR, LPVOID, LPWSTR,
    MAX_PATH, PBYTE, UINT, ULONG, USHORT, WORD, WPARAM,
)
from typing import Any

from _ctypes import Array

from MemLib.Struct import Struct



class STARTUPINFOA(Struct):
    """
    Specifies window station, desktop, standard handles, and window appearance for a process at creation time (ANSI version).

    This structure is used with process creation functions such as CreateProcessW to define various properties of the main window and standard I/O handles for the new process.

    Fields:
        cb              (DWORD): Size of this structure, in bytes.
        lpReserved      (LPSTR): Reserved; must be NULL.
        lpDesktop       (LPSTR): Name of the desktop (as a byte string) associated with the process.
        lpTitle         (LPSTR): Title for the main window.
        dwX             (DWORD): Initial X position of the window.
        dwY             (DWORD): Initial Y position of the window.
        dwXSize         (DWORD): Width of the window.
        dwYSize         (DWORD): Height of the window.
        dwXCountChars   (DWORD): Screen buffer width (in characters) for console applications.
        dwYCountChars   (DWORD): Screen buffer height (in characters) for console applications.
        dwFillAttribute (DWORD): Initial text and background colors for console applications.
        dwFlags         (DWORD): Flags that control window appearance and handle usage.
        wShowWindow     (WORD) : ShowWindow value for the process’s main window.
        cbReserved2     (WORD) : Size of the lpReserved2 buffer.
        lpReserved2     (PBYTE): Reserved; must be NULL.
        hStdInput       (HANDLE): Standard input handle for the process.
        hStdOutput      (HANDLE): Standard output handle for the process.
        hStdError       (HANDLE): Standard error handle for the process.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    """
    cb: int
    lpReserved: bytes | None
    lpDesktop: bytes | None
    lpTitle: bytes | None
    dwX: int
    dwY: int
    dwXSize: int
    dwYSize: int
    dwXCountChars: int
    dwYCountChars: int
    dwFillAttribute: int
    dwFlags: int
    wShowWindow: int
    cbReserved2: int
    lpReserved2: PBYTE
    hStdInput: int | None
    hStdOutput: int | None
    hStdError: int | None

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

class STARTUPINFOW(Struct):
    """
    Specifies window station, desktop, standard handles, and window appearance for a process at creation time (Unicode version).

    This structure is used with process creation functions such as CreateProcessW to define various properties of the main window and standard I/O handles for the new process.

    Fields:
        cb              (DWORD): Size of this structure, in bytes.
        lpReserved      (LPWSTR): Reserved; must be NULL.
        lpDesktop       (LPWSTR): Name of the desktop (as a string) associated with the process.
        lpTitle         (LPWSTR): Title for the main window.
        dwX             (DWORD): Initial X position of the window.
        dwY             (DWORD): Initial Y position of the window.
        dwXSize         (DWORD): Width of the window.
        dwYSize         (DWORD): Height of the window.
        dwXCountChars   (DWORD): Screen buffer width (in characters) for console applications.
        dwYCountChars   (DWORD): Screen buffer height (in characters) for console applications.
        dwFillAttribute (DWORD): Initial text and background colors for console applications.
        dwFlags         (DWORD): Flags that control window appearance and handle usage.
        wShowWindow     (WORD) : ShowWindow value for the process’s main window.
        cbReserved2     (WORD) : Size of the lpReserved2 buffer.
        lpReserved2     (PBYTE): Reserved; must be NULL.
        hStdInput       (HANDLE): Standard input handle for the process.
        hStdOutput      (HANDLE): Standard output handle for the process.
        hStdError       (HANDLE): Standard error handle for the process.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfow
    """
    cb: int
    lpReserved: str | None
    lpDesktop: str | None
    lpTitle: str | None
    dwX: int
    dwY: int
    dwXSize: int
    dwYSize: int
    dwXCountChars: int
    dwYCountChars: int
    dwFillAttribute: int
    dwFlags: int
    wShowWindow: int
    cbReserved2: int
    lpReserved2: PBYTE
    hStdInput: int | None
    hStdOutput: int | None
    hStdError: int | None

    _fields_ = [
        ('cb', DWORD),
        ('lpReserved', LPWSTR),
        ('lpDesktop', LPWSTR),
        ('lpTitle', LPWSTR),
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

# noinspection PyPep8Naming
# pylint: disable=invalid-name
class PROCESS_INFORMATION(Struct):
    """
    Contains information about a newly created process and its primary thread.

    This structure is filled by functions such as CreateProcess, holding handles and identifiers for the created process and thread.

    Fields:
        hProcess    (HANDLE): Handle to the newly created process.
        hThread     (HANDLE): Handle to the primary thread of the new process.
        dwProcessId (DWORD) : Unique identifier for the new process.
        dwThreadId  (DWORD) : Unique identifier for the new thread.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
    """
    hProcess: int | None
    hThread: int | None
    dwProcessId: int
    dwThreadId: int

    _fields_ = [
        ('hProcess', HANDLE),
        ('hThread', HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId', DWORD)
    ]

# noinspection PyPep8Naming
# pylint: disable=invalid-name
class PROCESS_BASIC_INFORMATION(Struct):
    """
    Holds basic information about a process, typically filled by the NtQueryInformationProcess API.

    Fields:
        ExitStatus                   (DWORD): Process exit code.
        PebBaseAddress               (LPVOID): Address of the process environment block (PEB).
        AffinityMask                 (ULONG): Process affinity mask.
        BasePriority                 (DWORD): Base priority level.
        UniqueProcessId              (ULONG): Unique process identifier.
        InheritedFromUniqueProcessId (ULONG): Parent process identifier.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#process_basic_information
    """
    ExitStatus: int
    PebBaseAddress: int | None
    AffinityMask: int
    BasePriority: int
    UniqueProcessId: int
    InheritedFromUniqueProcessId: int

    _fields_ = [
        ('ExitStatus', DWORD),
        ('PebBaseAddress', LPVOID),
        ('AffinityMask', ULONG),
        ('BasePriority', DWORD),
        ('UniqueProcessId', ULONG),
        ('InheritedFromUniqueProcessId', ULONG)
    ]

# noinspection PyPep8Naming
# pylint: disable=invalid-name
class UNICODE_STRING(Struct):
    """
    Represents a counted Unicode string used by Windows NT system structures.

    Fields:
        Length        (USHORT): Length of the string in bytes.
        MaximumLength (USHORT): Maximum length of the string buffer in bytes.
        Buffer        (LPWSTR): Pointer to the string buffer (wide characters).

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string
    """
    Length: int
    MaximumLength: int
    Buffer: str | None

    _fields_ = [
        ('Length', USHORT),
        ('MaximumLength', USHORT),
        ('Buffer', LPWSTR),
    ]

class PEB(Struct):
    """
    Represents the Process Environment Block (PEB), a structure containing information about a specific process.

    The PEB contains data used by the operating system loader, memory manager, and other core components.

    Note:
        The exact layout of the PEB is undocumented and may change between Windows versions. This definition covers the most common fields.

    For details on individual fields, see the Windows Internals documentation or the ReactOS source code.

    See also:
        https://void-stack.github.io/blog/post-Exploring-PEB/
        https://en.wikipedia.org/wiki/Process_Environment_Block
        https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
    """

    InheritedAddressSpace: int
    ReadImageFileExecOptions: int
    BeingDebugged: int
    BitField: int
    Mutant: int | None
    ImageBaseAddress: int | None
    Ldr: int | None
    ProcessParameters: int | None
    SubSystemData: int | None
    ProcessHeap: int | None
    FastPebLock: int | None
    AtlThunkSListPtr: int | None
    IFEOKey: int | None
    CrossProcessFlags: int
    UserSharedInfoPtr: int | None
    SystemReserved: int
    SpareUlong: int
    FreeList: int | None
    TlsExpansionCounter: int
    TlsBitmap: int | None
    TlsBitmapBits: Array
    ReadOnlySharedMemoryBase: int | None
    HotpatchInformation: int | None
    ReadOnlyStaticServerData: int | None
    AnsiCodePageData: int | None
    OemCodePageData: int | None
    UnicodeCaseTableData: int | None
    NumberOfProcessors: int
    NtGlobalFlag: int
    CriticalSectionTimeout1: int
    CriticalSectionTimeout2: int
    HeapSegmentReserve: int
    HeapSegmentCommit: int
    HeapDeCommitTotalFreeThreshold: int
    HeapDeCommitFreeBlockThreshold: int
    NumberOfHeaps: int
    MaximumNumberOfHeaps: int
    ProcessHeaps: int | None
    GdiSharedHandleTable: int | None
    ProcessStarterHelper: int | None
    GdiDCAttributeList: int | None
    LoaderLock: int | None
    OSMajorVersion: int
    OSMinorVersion: int
    OSBuildNumber: WORD
    OSCSDVersion: WORD
    OSPlatformId: int
    ImageSubsystem: int
    ImageSubsystemMajorVersion: int
    ImageSubsystemMinorVersion: int
    ImageProcessAffinityMask: int
    GdiHandleBuffer: Array
    PostProcessInitRoutine: int | None
    TlsExpansionBitmap: int | None
    TlsExpansionBitmapBits: Array
    SessionId: int
    AppCompatFlags1: int
    AppCompatFlags2: int
    AppCompatFlagsUser1: int
    AppCompatFlagsUser2: int
    pShimData: int | None
    AppCompatInfo: int | None
    CSDVersion: UNICODE_STRING
    ActivationContextData: int | None
    ProcessAssemblyStorageMap: int | None
    SystemDefaultActivationContextData: int | None
    SystemAssemblyStorageMap: int | None
    MinimumStackCommit: int
    FlsCallback: int | None
    FlsListHeadNext: int | None
    FlsListHeadFirst: int | None
    FlsBitmap: int | None
    FlsBitmapBits: Array
    FlsHighIndex: int
    WerRegistrationData: int | None
    WerShipAssertPtr: int | None

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
        ('TlsBitmapBits', DWORD * 2),  # type: ignore
        ('ReadOnlySharedMemoryBase', LPVOID),
        ('HotpatchInformation', LPVOID),
        ('ReadOnlyStaticServerData', LPVOID),
        ('AnsiCodePageData', LPVOID),
        ('OemCodePageData', LPVOID),
        ('UnicodeCaseTableData', LPVOID),
        ('NumberOfProcessors', DWORD),
        ('NtGlobalFlag', DWORD),
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
        ('GdiHandleBuffer', DWORD * 34),  # type: ignore
        ('PostProcessInitRoutine', LPVOID),
        ('TlsExpansionBitmap', LPVOID),
        ('TlsExpansionBitmapBits', DWORD * 32),  # type: ignore
        ('SessionId', DWORD),
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
        ('FlsBitmapBits', DWORD * 4),  # type: ignore
        ('FlsHighIndex', DWORD),
        ('WerRegistrationData', LPVOID),
        ('WerShipAssertPtr', LPVOID),
    ]

# noinspection PyPep8Naming
# pylint: disable=invalid-name
class IMAGE_DOS_HEADER(Struct):
    """
    Represents the MS-DOS (MZ) header at the start of all PE files.

    This structure is found at the very beginning of any Portable Executable (PE) and contains information for legacy DOS execution, as well as a pointer to the PE header.

    Fields:
        e_magic     (WORD)      : Magic number ("MZ").
        e_cblp      (WORD)      : Bytes on last page of file.
        e_cp        (WORD)      : Pages in file.
        e_crlc      (WORD)      : Relocations.
        e_cparhdr   (WORD)      : Size of header in paragraphs.
        e_minalloc  (WORD)      : Minimum extra paragraphs needed.
        e_maxalloc  (WORD)      : Maximum extra paragraphs needed.
        e_ss        (WORD)      : Initial (relative) SS value.
        e_sp        (WORD)      : Initial SP value.
        e_csum      (WORD)      : Checksum.
        e_ip        (WORD)      : Initial IP value.
        e_cs        (WORD)      : Initial (relative) CS value.
        e_lfarlc    (WORD)      : File address of relocation table.
        e_ovno      (WORD)      : Overlay number.
        e_res       (WORD * 4)  : Reserved words.
        e_oemid     (WORD)      : OEM identifier (for e_oeminfo).
        e_oeminfo   (WORD)      : OEM information; e_oemid specific.
        e_res2      (WORD * 10) : Reserved words.
        e_lfanew    (LONG)      : File address of the new exe header (PE header offset).

    See also:
        https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#ms-dos-stub-image-only
    """
    e_magic: int
    e_cblp: int
    e_cp: int
    e_crlc: int
    e_cparhdr: int
    e_minalloc: int
    e_maxalloc: int
    e_ss: int
    e_sp: int
    e_csum: int
    e_ip: int
    e_cs: int
    e_lfarlc: int
    e_ovno: int
    e_res: Array
    e_oemid: int
    e_oeminfo: int
    e_res2: Array
    e_lfanew: int

    _fields_ = [
        ('e_magic', WORD),
        ('e_cblp', WORD),
        ('e_cp', WORD),
        ('e_crlc', WORD),
        ('e_cparhdr', WORD),
        ('e_minalloc', WORD),
        ('e_maxalloc', WORD),
        ('e_ss', WORD),
        ('e_sp', WORD),
        ('e_csum', WORD),
        ('e_ip', WORD),
        ('e_cs', WORD),
        ('e_lfarlc', WORD),
        ('e_ovno', WORD),
        ('e_res', WORD * 4),  # type: ignore
        ('e_oemid', WORD),
        ('e_oeminfo', WORD),
        ('e_res2', WORD * 10),  # type: ignore
        ('e_lfanew', LONG)
    ]

# noinspection PyPep8Naming
# pylint: disable=invalid-name
class IMAGE_FILE_HEADER(Struct):
    """
    COFF file header found in PE files, sometimes called the PE "file header".

    Fields:
        Machine              (WORD): The architecture type of the computer.
        NumberOfSections     (WORD): Number of sections.
        TimeDateStamp        (DWORD): Time and date stamp.
        PointerToSymbolTable (DWORD): File offset of the COFF symbol table, or zero if none.
        NumberOfSymbols      (DWORD): Number of entries in the symbol table.
        SizeOfOptionalHeader (WORD): Size of the optional header.
        Characteristics      (WORD): Flags indicating attributes of the file.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
        https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
        https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics
    """
    Machine: int
    NumberOfSections: int
    TimeDateStamp: int
    PointerToSymbolTable: int
    NumberOfSymbols: int
    SizeOfOptionalHeader: int
    Characteristics: int

    _fields_ = [
        ('Machine', WORD),
        ('NumberOfSections', WORD),
        ('TimeDateStamp', DWORD),
        ('PointerToSymbolTable', DWORD),
        ('NumberOfSymbols', DWORD),
        ('SizeOfOptionalHeader', WORD),
        ('Characteristics', WORD),
    ]

# noinspection PyPep8Naming
# pylint: disable=invalid-name
class IMAGE_DATA_DIRECTORY(Struct):
    """
    Describes the location and size of a data directory (e.g., import table, export table) within the PE file.

    Fields:
        VirtualAddress (DWORD): RVA of the table.
        Size           (DWORD): Size of the table, in bytes.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only
    """
    VirtualAddress: int
    Size: int

    _fields_ = [
        ('VirtualAddress', DWORD),
        ('Size', DWORD)
    ]

# noinspection PyPep8Naming
# pylint: disable=invalid-name
class IMAGE_OPTIONAL_HEADER32(Struct):
    """
    Contains the optional header for a 32-bit PE file, which provides important information required for loading the program.

    Fields:
        Magic                        (WORD): Identifies the type of image (PE32).
        MajorLinkerVersion           (BYTE): Major version number of the linker.
        MinorLinkerVersion           (BYTE): Minor version number of the linker.
        SizeOfCode                   (DWORD): Size of the code section.
        SizeOfInitializedData        (DWORD): Size of the initialized data section.
        SizeOfUninitializedData      (DWORD): Size of the uninitialized data section.
        AddressOfEntryPoint          (DWORD): RVA of the entry point.
        BaseOfCode                   (DWORD): RVA of the code section.
        BaseOfData                   (DWORD): RVA of the data section.
        ImageBase                    (DWORD): Preferred address to load the image.
        SectionAlignment             (DWORD): Section alignment in memory.
        FileAlignment                (DWORD): File alignment on disk.
        MajorOperatingSystemVersion  (WORD): Major OS version required.
        MinorOperatingSystemVersion  (WORD): Minor OS version required.
        MajorImageVersion            (WORD): Major image version.
        MinorImageVersion            (WORD): Minor image version.
        MajorSubsystemVersion        (WORD): Major subsystem version.
        MinorSubsystemVersion        (WORD): Minor subsystem version.
        Win32VersionValue            (DWORD): Reserved.
        SizeOfImage                  (DWORD): Size of the image, including all headers.
        SizeOfHeaders                (DWORD): Combined size of MS-DOS stub, PE header, and section headers.
        CheckSum                     (DWORD): Image checksum.
        Subsystem                    (WORD): Subsystem required to run this image.
        DllCharacteristics           (WORD): DLL characteristics flags.
        SizeOfStackReserve           (DWORD): Size of stack to reserve.
        SizeOfStackCommit            (DWORD): Size of stack to commit.
        SizeOfHeapReserve            (DWORD): Size of heap to reserve.
        SizeOfHeapCommit             (DWORD): Size of heap to commit.
        LoaderFlags                  (DWORD): Loader flags.
        NumberOfRvaAndSizes          (DWORD): Number of data-directory entries.
        DataDirectory                (IMAGE_DATA_DIRECTORY * 16): Array of data directories.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
    """
    Magic: int
    MajorLinkerVersion: int
    MinorLinkerVersion: int
    SizeOfCode: int
    SizeOfInitializedData: int
    SizeOfUninitializedData: int
    AddressOfEntryPoint: int
    BaseOfCode: int
    BaseOfData: int
    ImageBase: int
    SectionAlignment: int
    FileAlignment: int
    MajorOperatingSystemVersion: int
    MinorOperatingSystemVersion: int
    MajorImageVersion: int
    MinorImageVersion: int
    MajorSubsystemVersion: int
    MinorSubsystemVersion: int
    Win32VersionValue: int
    SizeOfImage: int
    SizeOfHeaders: int
    CheckSum: int
    Subsystem: int
    DllCharacteristics: int
    SizeOfStackReserve: int
    SizeOfStackCommit: int
    SizeOfHeapReserve: int
    SizeOfHeapCommit: int
    LoaderFlags: int
    NumberOfRvaAndSizes: int
    DataDirectory: IMAGE_DATA_DIRECTORY * 16  # type: ignore

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
        ('DataDirectory', IMAGE_DATA_DIRECTORY * 16),  # IMAGE_NUMBEROF_DIRECTORY_ENTRIES
    ]

# noinspection PyPep8Naming
# pylint: disable=invalid-name
class IMAGE_SECTION_HEADER(Struct):
    """
    Describes a section table entry in a PE file, also known as a section header.

    Fields:
        Name                 (CHAR * 8): Section name.
        VirtualSize          (DWORD): Virtual size of the section.
        VirtualAddress       (DWORD): RVA of the section.
        SizeOfRawData        (DWORD): Size of the section's data on disk.
        PointerToRawData     (DWORD): File pointer to the section's data.
        PointerToRelocations (DWORD): File pointer to the relocation table.
        PointerToLinenumbers (DWORD): File pointer to the line-number table.
        NumberOfRelocations  (WORD): Number of relocations.
        NumberOfLinenumbers  (WORD): Number of line numbers.
        Characteristics      (DWORD): Flags describing characteristics of the section.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header
    """
    Name: bytes
    VirtualSize: int
    VirtualAddress: int
    SizeOfRawData: int
    PointerToRawData: int
    PointerToRelocations: int
    PointerToLinenumbers: int
    NumberOfRelocations: int
    NumberOfLinenumbers: int
    Characteristics: int

    _fields_ = [
        ('Name', CHAR * 8),  # type: ignore
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

# noinspection PyPep8Naming
# pylint: disable=invalid-name
class IMAGE_NT_HEADERS32(Struct):
    """
    Represents the NT headers for a 32-bit Portable Executable (PE) file.

    This structure combines the PE signature, file header, and optional header, and forms the starting point
    for parsing the rest of the PE file structure after the DOS header.

    Fields:
        Signature       (DWORD)                  : PE file signature ('PE\0\0' as 0x00004550).
        FileHeader      (IMAGE_FILE_HEADER)      : Standard COFF file header.
        OptionalHeader  (IMAGE_OPTIONAL_HEADER32): Optional header with detailed information for loading.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#pe-format
    """
    Signature: int
    FileHeader: IMAGE_FILE_HEADER
    OptionalHeader: IMAGE_OPTIONAL_HEADER32

    _fields_ = [
        ('Signature', DWORD),
        ('FileHeader', IMAGE_FILE_HEADER),
        ('OptionalHeader', IMAGE_OPTIONAL_HEADER32),
    ]

    def get_sections_offset(self) -> int:
        """
        Returns the file offset to the first section header in the PE file.

        Returns:
            int: Offset (in bytes) to the start of the section headers.
        """
        return IMAGE_NT_HEADERS32.OptionalHeader.offset + self.FileHeader.SizeOfOptionalHeader

# noinspection PyPep8Naming
# pylint: disable=invalid-name
class IMAGE_EXPORT_DIRECTORY(Struct):
    """
    Represents the export directory table of a PE (Portable Executable) file.

    This structure provides information about the exported functions of a Windows module (DLL or EXE).
    It includes addresses, name pointers, ordinals, and other metadata required to enumerate or resolve exports.

    Fields:
        Characteristics        (DWORD): Reserved; set to 0.
        TimeDateStamp          (DWORD): The time and date the export data was created.
        MajorVersion           (WORD) : Major version number (user-defined).
        MinorVersion           (WORD) : Minor version number (user-defined).
        Name                   (DWORD): RVA of the ASCII string containing the DLL name.
        Base                   (DWORD): Starting ordinal number for exports.
        NumberOfFunctions      (DWORD): Number of entries in the export address table.
        NumberOfNames          (DWORD): Number of entries in the name pointer table.
        AddressOfFunctions     (DWORD): RVA of the export address table.
        AddressOfNames         (DWORD): RVA of the export name pointer table.
        AddressOfNameOrdinals  (DWORD): RVA of the export ordinal table.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-export-directory-table
    """
    Characteristics: int
    TimeDateStamp: int
    MajorVersion: int
    MinorVersion: int
    Name: int
    Base: int
    NumberOfFunctions: int
    NumberOfNames: int
    AddressOfFunctions: int
    AddressOfNames: int
    AddressOfNameOrdinals: int

    _fields_ = [
        ('Characteristics', DWORD),
        ('TimeDateStamp', DWORD),
        ('MajorVersion', WORD),
        ('MinorVersion', WORD),
        ('Name', DWORD),
        ('Base', DWORD),
        ('NumberOfFunctions', DWORD),
        ('NumberOfNames', DWORD),
        ('AddressOfFunctions', DWORD),
        ('AddressOfNames', DWORD),
        ('AddressOfNameOrdinals', DWORD)
    ]

# noinspection PyPep8Naming
# pylint: disable=invalid-name
class MZ_FILEHEADER(Struct):
    """
    Represents the header of a legacy MS-DOS executable (MZ format).

    This structure forms the very beginning of every DOS or Windows PE file and contains information for the DOS loader,
    as well as a pointer to the PE (NT) header for modern Windows systems.

    Fields:
        Signature       (WORD)      : Magic number ("MZ").
        ExtraBytes      (WORD)      : Bytes on last page of file.
        Pages           (WORD)      : Pages in file.
        RelocationItems (WORD)      : Number of relocation entries.
        HeaderSize      (WORD)      : Size of the header in paragraphs.
        MinAllow        (WORD)      : Minimum extra paragraphs needed.
        MaxAllow        (WORD)      : Maximum extra paragraphs needed.
        InitialSS       (WORD)      : Initial (relative) SS value.
        InitialSP       (WORD)      : Initial SP value.
        Checksum        (WORD)      : Checksum.
        InitialIS       (WORD)      : Initial IP value.
        InitialCS       (WORD)      : Initial (relative) CS value.
        RelocationTable (WORD)      : File address of relocation table.
        Overlay         (WORD)      : Overlay number.
        OverlayInfo1    (DWORD)     : Reserved or overlay-specific.
        OverlayInfo2    (DWORD)     : Reserved or overlay-specific.
        OEMIdentifier   (WORD)      : OEM identifier.
        OEMInfo         (WORD)      : OEM information.
        Reserved        (BYTE * 20) : Reserved.
        PEHeaderOffset  (DWORD)     : File offset to the PE header (e_lfanew).

    See also:
        https://wiki.osdev.org/MZ
    """
    Signature: int
    ExtraBytes: int
    Pages: int
    RelocationItems: int
    HeaderSize: int
    MinAllow: int
    MaxAllow: int
    InitialSS: int
    InitialSP: int
    Checksum: int
    InitialIS: int
    InitialCS: int
    RelocationTable: int
    Overlay: int
    OverlayInfo1: int
    OverlayInfo2: int
    OEMIdentifier: int
    OEMInfo: int
    Reserved: Array
    PEHeaderOffset: int

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
        ('OverlayInfo1', DWORD),
        ('OverlayInfo2', DWORD),
        ('OEMIdentifier', WORD),
        ('OEMInfo', WORD),
        ('Reserved', BYTE * 20),  # type: ignore
        ('PEHeaderOffset', DWORD),
    ]

class PROCESSENTRY32(Struct):
    """
    Describes an entry for a process as returned when taking a system snapshot with the Tool Help library.

    Fields:
        dwSize              (DWORD): Size of the structure, in bytes.
        cntUsage            (DWORD): Number of references to the process.
        th32ProcessID       (DWORD): Process identifier.
        th32DefaultHeapID   (ULONG): Default heap identifier.
        th32ModuleID        (DWORD): Module identifier.
        cntThreads          (DWORD): Number of execution threads started by the process.
        th32ParentProcessID (DWORD): Process identifier of the parent process.
        pcPriClassBase      (LONG) : Base priority of any threads created by the process.
        dwFlags             (DWORD): Flags.
        szExeFile           (CHAR * MAX_PATH): Executable file name.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32
    """
    dwSize: int
    cntUsage: int
    th32ProcessID: int
    th32DefaultHeapID: int
    th32ModuleID: int
    cntThreads: int
    th32ParentProcessID: int
    pcPriClassBase: int
    dwFlags: int
    szExeFile: bytes

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
        ('szExeFile', CHAR * MAX_PATH)  # type: ignore
    ]

    def __init__(self, *args: Any, **kw: Any):
        super().__init__(*args, **kw)
        if self.dwSize == 0:
            self.dwSize = self.get_size()

class MODULEENTRY32(Struct):
    """
    Contains information about a module (DLL or EXE) in the address space of a process.

    Fields:
        dwSize        (DWORD): Size of the structure, in bytes.
        th32ModuleID  (DWORD): Module identifier.
        th32ProcessID (DWORD): Identifier of the process containing the module.
        GlblcntUsage  (DWORD): Global usage count.
        ProccntUsage  (DWORD): Process usage count.
        modBaseAddr   (ULONG): Base address of the module.
        modBaseSize   (DWORD): Size of the module, in bytes.
        hModule       (HMODULE): Handle to the module.
        szModule      (CHAR * 256): Module name.
        szExePath     (CHAR * MAX_PATH): Path to the executable file for the module.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-moduleentry32
    """
    dwSize: int
    th32ModuleID: int
    th32ProcessID: int
    GlblcntUsage: int
    ProccntUsage: int
    modBaseAddr: int
    modBaseSize: int
    hModule: int | None
    szModule: bytes
    szExePath: bytes

    _fields_ = [
        ('dwSize', DWORD),
        ('th32ModuleID', DWORD),
        ('th32ProcessID', DWORD),
        ('GlblcntUsage', DWORD),
        ('ProccntUsage', DWORD),
        ('modBaseAddr', ULONG),
        ('modBaseSize', DWORD),
        ('hModule', HMODULE),
        ('szModule', CHAR * 256),  # type: ignore
        ('szExePath', CHAR * MAX_PATH)  # type: ignore
    ]

    def __init__(self, *args: Any, **kw: Any):
        super().__init__(*args, **kw)
        if self.dwSize == 0:
            self.dwSize = self.get_size()

class THREADENTRY32(Struct):
    """
    Contains information about a thread in the system as returned by a snapshot enumeration.

    This structure is filled by the Thread32First and Thread32Next functions when enumerating all threads on the system.

    Fields:
        dwSize             (DWORD): Size of the structure, in bytes.
        cntUsage           (DWORD): Usage count for the thread (not typically used).
        th32ThreadID       (DWORD): Thread identifier.
        th32OwnerProcessID (DWORD): Identifier of the process that created the thread.
        tpBasePri          (LONG) : Base priority level assigned to the thread.
        tpDeltaPri         (LONG) : Priority delta.
        dwFlags            (DWORD): Flags (reserved).

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-threadentry32
    """
    dwSize: int
    cntUsage: int
    th32ThreadID: int
    th32OwnerProcessID: int
    tpBasePri: int
    tpDeltaPri: int
    dwFlags: int

    _fields_ = [
        ('dwSize', DWORD),
        ('cntUsage', DWORD),
        ('th32ThreadID', DWORD),
        ('th32OwnerProcessID', DWORD),
        ('tpBasePri', LONG),
        ('tpDeltaPri', LONG),
        ('dwFlags', DWORD),
    ]

    def __init__(self, *args: Any, **kw: Any):
        super().__init__(*args, **kw)
        if self.dwSize == 0:
            self.dwSize = self.get_size()

WNDPROC = WINFUNCTYPE(LONG, HWND, UINT, LONG, DWORD)

class WNDCLASS(Struct):
    """
    Contains the attributes of a window class registered with RegisterClass.

    This structure is used with RegisterClass to define window properties such as style, icon, cursor, background brush, and menu.

    Note:
        WNDCLASS is superseded by WNDCLASSEX, which provides support for a small icon. Use WNDCLASS if you do not need this feature.

    Fields:
        style         (DWORD): Class style flags.
        lpfnWndProc   (WNDPROC): Pointer to the window procedure.
        cbClsExtra    (INT)  : Number of extra bytes to allocate after the class structure.
        cbWndExtra    (INT)  : Number of extra bytes to allocate after the window instance.
        hInstance     (HANDLE): Handle to the application instance.
        hIcon         (HANDLE): Handle to the class icon.
        hCursor       (HANDLE): Handle to the class cursor.
        hbrBackground (HANDLE): Handle to the class background brush.
        lpszMenuName  (LPCSTR): Resource name of the class menu.
        lpszClassName (LPCSTR): Name of the window class.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-wndclassa
    """
    style: int
    lpfnWndProc: WNDPROC
    cbClsExtra: int
    cbWndExtra: int
    hInstance: int | None
    hIcon: int | None
    hCursor: int | None
    hbrBackground: int | None
    lpszMenuName: bytes | None
    lpszClassName: bytes | None

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
    Represents a message retrieved from a thread's message queue.

    This structure corresponds to the Windows MSG struct and contains all information
    about a message sent to a window or retrieved from a message queue. It is commonly
    used for GUI event/message handling.

    Attributes:
        hWnd (HWND): Handle to the window receiving the message, or None.
        message (UINT): The message identifier (e.g., WM_PAINT, WM_KEYDOWN).
        wParam (WPARAM): Additional message information (message-specific).
        lParam (LPARAM): Additional message information (message-specific).
        time (DWORD): The time at which the message was posted (milliseconds since system start).
        pt (HANDLE): Handle or pointer to additional information (e.g., mouse position), or None.
        lprivate (DWORD): Additional private information.

    See Also:
        https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-msg
    """

    hWnd: int | None
    message: int
    wParam: int
    lParam: int
    time: int
    pt: int | None
    lprivate: int

    _fields_ = [
        ('hWnd', HWND),
        ('message', UINT),
        ('wParam', WPARAM),
        ('lParam', LPARAM),
        ('time', DWORD),
        ('pt', HANDLE),
        ('lprivate', DWORD),
    ]
