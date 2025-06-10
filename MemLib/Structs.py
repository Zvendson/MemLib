"""
:platform: Windows
"""

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
    Specifies window station, desktop, standard handles, and window appearance for a process at creation time (Unicode version).

    This structure is used with process creation functions such as CreateProcessW to define various properties of the main window and standard I/O handles for the new process.

    Fields:
        cb              (DWORD): Size of this structure, in bytes.
        lpReserved      (LPSTR): Reserved; must be NULL.
        lpDesktop       (LPSTR): Name of the desktop (as a string) associated with the process.
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
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfow
    """
    cb:              DWORD
    lpReserved:      LPSTR
    lpDesktop:       LPSTR
    lpTitle:         LPSTR
    dwX:             DWORD
    dwY:             DWORD
    dwXSize:         DWORD
    dwYSize:         DWORD
    dwXCountChars:   DWORD
    dwYCountChars:   DWORD
    dwFillAttribute: DWORD
    dwFlags:         DWORD
    wShowWindow:     WORD
    cbReserved2:     WORD
    lpReserved2:     PBYTE
    hStdInput:       HANDLE
    hStdOutput:      HANDLE
    hStdError:       HANDLE


class ProcessInfo(Struct):
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
    hProcess:    HANDLE
    hThread:     HANDLE
    dwProcessId: DWORD
    dwThreadId:  DWORD


class ProcessBasicInformation(Struct):
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
    ExitStatus:                   DWORD
    PebBaseAddress:               LPVOID
    AffinityMask:                 ULONG
    BasePriority:                 DWORD
    UniqueProcessId:              ULONG
    InheritedFromUniqueProcessId: ULONG



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
    Length:        USHORT
    MaximumLength: USHORT
    Buffer:        LPWSTR



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
    InheritedAddressSpace:              BYTE
    ReadImageFileExecOptions:           BYTE
    BeingDebugged:                      BYTE
    BitField:                           BYTE
    Mutant:                             LPVOID
    ImageBaseAddress:                   LPVOID
    Ldr:                                LPVOID
    ProcessParameters:                  LPVOID
    SubSystemData:                      LPVOID
    ProcessHeap:                        LPVOID
    FastPebLock:                        LPVOID
    AtlThunkSListPtr:                   LPVOID
    IFEOKey:                            LPVOID
    CrossProcessFlags:                  DWORD
    UserSharedInfoPtr:                  LPVOID
    SystemReserved:                     DWORD
    SpareUlong:                         DWORD
    FreeList:                           LPVOID
    TlsExpansionCounter:                DWORD
    TlsBitmap:                          LPVOID
    TlsBitmapBits:                      DWORD * 2
    ReadOnlySharedMemoryBase:           LPVOID
    HotpatchInformation:                LPVOID
    ReadOnlyStaticServerData:           LPVOID
    AnsiCodePageData:                   LPVOID
    OemCodePageData:                    LPVOID
    UnicodeCaseTableData:               LPVOID
    NumberOfProcessors:                 DWORD
    NtGlobalFlag:                       DWORD
    CriticalSectionTimeout1:            DWORD
    CriticalSectionTimeout2:            DWORD
    HeapSegmentReserve:                 DWORD
    HeapSegmentCommit:                  DWORD
    HeapDeCommitTotalFreeThreshold:     DWORD
    HeapDeCommitFreeBlockThreshold:     DWORD
    NumberOfHeaps:                      DWORD
    MaximumNumberOfHeaps:               DWORD
    ProcessHeaps:                       LPVOID
    GdiSharedHandleTable:               LPVOID
    ProcessStarterHelper:               LPVOID
    GdiDCAttributeList:                 LPVOID
    LoaderLock:                         LPVOID
    OSMajorVersion:                     DWORD
    OSMinorVersion:                     DWORD
    OSBuildNumber:                      WORD
    OSCSDVersion:                       WORD
    OSPlatformId:                       DWORD
    ImageSubsystem:                     DWORD
    ImageSubsystemMajorVersion:         DWORD
    ImageSubsystemMinorVersion:         DWORD
    ImageProcessAffinityMask:           DWORD
    GdiHandleBuffer:                    DWORD * 34
    PostProcessInitRoutine:             LPVOID
    TlsExpansionBitmap:                 LPVOID
    TlsExpansionBitmapBits:             DWORD * 32
    SessionId:                          DWORD
    AppCompatFlags1:                    DWORD
    AppCompatFlags2:                    DWORD
    AppCompatFlagsUser1:                DWORD
    AppCompatFlagsUser2:                DWORD
    pShimData:                          LPVOID
    AppCompatInfo:                      LPVOID
    CSDVersion:                         UNICODE_STRING
    ActivationContextData:              LPVOID
    ProcessAssemblyStorageMap:          LPVOID
    SystemDefaultActivationContextData: LPVOID
    SystemAssemblyStorageMap:           LPVOID
    MinimumStackCommit:                 DWORD
    FlsCallback:                        LPVOID
    FlsListHeadNext:                    LPVOID
    FlsListHeadFirst:                   LPVOID
    FlsBitmap:                          LPVOID
    FlsBitmapBits:                      DWORD * 4
    FlsHighIndex:                       DWORD
    WerRegistrationData:                LPVOID
    WerShipAssertPtr:                   LPVOID


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
    e_magic:    WORD
    e_cblp:     WORD
    e_cp:       WORD
    e_crlc:     WORD
    e_cparhdr:  WORD
    e_minalloc: WORD
    e_maxalloc: WORD
    e_ss:       WORD
    e_sp:       WORD
    e_csum:     WORD
    e_ip:       WORD
    e_cs:       WORD
    e_lfarlc:   WORD
    e_ovno:     WORD
    e_res:      WORD * 4
    e_oemid:    WORD
    e_oeminfo:  WORD
    e_res2:     WORD * 10
    e_lfanew:   LONG


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
    """
    Machine:              WORD
    NumberOfSections:     WORD
    TimeDateStamp:        DWORD
    PointerToSymbolTable: DWORD
    NumberOfSymbols:      DWORD
    SizeOfOptionalHeader: WORD
    Characteristics:      WORD


class IMAGE_DATA_DIRECTORY(Struct):
    """
    Describes the location and size of a data directory (e.g., import table, export table) within the PE file.

    Fields:
        VirtualAddress (DWORD): RVA of the table.
        Size           (DWORD): Size of the table, in bytes.

    See also:
        https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only
    """
    VirtualAddress: DWORD
    Size:           DWORD


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
    Magic:                       WORD
    MajorLinkerVersion:          BYTE
    MinorLinkerVersion:          BYTE
    SizeOfCode:                  DWORD
    SizeOfInitializedData:       DWORD
    SizeOfUninitializedData:     DWORD
    AddressOfEntryPoint:         DWORD
    BaseOfCode:                  DWORD
    BaseOfData:                  DWORD
    ImageBase:                   DWORD
    SectionAlignment:            DWORD
    FileAlignment:               DWORD
    MajorOperatingSystemVersion: WORD
    MinorOperatingSystemVersion: WORD
    MajorImageVersion:           WORD
    MinorImageVersion:           WORD
    MajorSubsystemVersion:       WORD
    MinorSubsystemVersion:       WORD
    Win32VersionValue:           DWORD
    SizeOfImage:                 DWORD
    SizeOfHeaders:               DWORD
    CheckSum:                    DWORD
    Subsystem:                   WORD
    DllCharacteristics:          WORD
    SizeOfStackReserve:          DWORD
    SizeOfStackCommit:           DWORD
    SizeOfHeapReserve:           DWORD
    SizeOfHeapCommit:            DWORD
    LoaderFlags:                 DWORD
    NumberOfRvaAndSizes:         DWORD
    DataDirectory:               IMAGE_DATA_DIRECTORY * 16


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
    Name:                 CHAR * 8
    VirtualSize:          DWORD
    VirtualAddress:       DWORD
    SizeOfRawData:        DWORD
    PointerToRawData:     DWORD
    PointerToRelocations: DWORD
    PointerToLinenumbers: DWORD
    NumberOfRelocations:  WORD
    NumberOfLinenumbers:  WORD
    Characteristics:      DWORD


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

    Signature:      DWORD
    FileHeader:     IMAGE_FILE_HEADER
    OptionalHeader: IMAGE_OPTIONAL_HEADER32

    def get_sections_offset(self) -> int:
        """
        Returns the file offset to the first section header in the PE file.

        Returns:
            int: Offset (in bytes) to the start of the section headers.
        """
        return IMAGE_NT_HEADERS32.OptionalHeader.offset + self.FileHeader.SizeOfOptionalHeader


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

    Characteristics:       DWORD
    TimeDateStamp:         DWORD
    MajorVersion:          WORD
    MinorVersion:          WORD
    Name:                  DWORD
    Base:                  DWORD
    NumberOfFunctions:     DWORD
    NumberOfNames:         DWORD
    AddressOfFunctions:    DWORD
    AddressOfNames:        DWORD
    AddressOfNameOrdinals: DWORD


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
    Signature:       WORD
    ExtraBytes:      WORD
    Pages:           WORD
    RelocationItems: WORD
    HeaderSize:      WORD
    MinAllow:        WORD
    MaxAllow:        WORD
    InitialSS:       WORD
    InitialSP:       WORD
    Checksum:        WORD
    InitialIS:       WORD
    InitialCS:       WORD
    RelocationTable: WORD
    Overlay:         WORD
    OverlayInfo1:    DWORD
    OverlayInfo2:    DWORD
    OEMIdentifier:   WORD
    OEMInfo:         WORD
    Reserved:        BYTE * 20
    PEHeaderOffset:  DWORD


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
    dwSize:              DWORD
    cntUsage:            DWORD
    th32ProcessID:       DWORD
    th32DefaultHeapID:   ULONG
    th32ModuleID:        DWORD
    cntThreads:          DWORD
    th32ParentProcessID: DWORD
    pcPriClassBase:      LONG
    dwFlags:             DWORD
    szExeFile:           CHAR * MAX_PATH


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
    dwSize:        DWORD
    th32ModuleID:  DWORD
    th32ProcessID: DWORD
    GlblcntUsage:  DWORD
    ProccntUsage:  DWORD
    modBaseAddr:   ULONG
    modBaseSize:   DWORD
    hModule:       HMODULE
    szModule:      CHAR * 256
    szExePath:     CHAR * MAX_PATH


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
    dwSize:             DWORD
    cntUsage:           DWORD
    th32ThreadID:       DWORD
    th32OwnerProcessID: DWORD
    tpBasePri:          LONG
    tpDeltaPri:         LONG
    dwFlags:            DWORD


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
    style:         DWORD
    lpfnWndProc:   WNDPROC
    cbClsExtra:    INT
    cbWndExtra:    INT
    hInstance:     HANDLE
    hIcon:         HANDLE
    hCursor:       HANDLE
    hbrBackground: HANDLE
    lpszMenuName:  LPCSTR
    lpszClassName: LPCSTR


class MSG(Struct):
    """
    Contains message information retrieved from a thread's message queue.

    This structure is filled by functions such as GetMessage and PeekMessage.

    Fields:
        hWnd     (HWND) : Handle to the window receiving the message.
        message  (UINT) : Message identifier.
        wParam   (WPARAM): Additional message information.
        lParam   (LPARAM): Additional message information.
        time     (DWORD): Time the message was posted.
        pt       (HANDLE): Pointer to a POINT structure with the cursor position (typically should be POINT, not HANDLE).
        lprivate (DWORD): Additional private data (may not be present in all Windows versions).

    See also:
        https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-msg
    """
    hWnd:     HWND
    message:  UINT
    wParam:   WPARAM
    lParam:   LPARAM
    time:     DWORD
    pt:       HANDLE
    lprivate: DWORD
