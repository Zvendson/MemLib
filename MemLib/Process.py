"""
:platform: Windows
"""

from __future__ import annotations

from typing import Callable, List, Literal, TYPE_CHECKING, Type, TypeVar

from ctypes import Array, byref, pointer
from ctypes.wintypes import BYTE, DWORD, WCHAR

from pathlib import Path

from _ctypes import sizeof
from psutil import pid_exists


from MemLib.Constants import (
    CREATE_SUSPENDED, INFINITE, MEM_COMMIT, MEM_RELEASE,
    NORMAL_PRIORITY_CLASS, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, WT_EXECUTEONLYONCE,
)
from MemLib.Scanner import BinaryScanner
from MemLib.Structs import (
    IMAGE_NT_HEADERS32, IMAGE_SECTION_HEADER, MODULEENTRY32, MZ_FILEHEADER, PEB, PROCESSENTRY32,
    ProcessBasicInformation, Struct,
    THREADENTRY32,
)
from MemLib.Module import Module
from MemLib.Thread import Thread
from MemLib.Kernel32 import (
    CloseHandle, CreateRemoteThread, CreateToolhelp32Snapshot, CreateWaitOrTimerCallback,
    GetPriorityClass, Module32First, Module32Next, NtQueryInformationProcess,
    NtResumeProcess, NtSuspendProcess, OpenProcess, Process32First,
    Process32Next, QueryFullProcessImageNameW, ReadProcessMemory, RegisterWaitForSingleObject,
    SetPriorityClass, TerminateProcess, Thread32First, Thread32Next,
    UnregisterWait, VirtualAllocEx, VirtualFreeEx, VirtualProtectEx,
    WaitOrTimerCallback, Win32Exception, WriteProcessMemory,
)


if TYPE_CHECKING:
    T = TypeVar('T')


class Process:
    """
    Represents an interactable process.

    :raises ValueError: If the process does not exist.
    :param processId: The process id of the process.
    :param processHandle: The process handle of the process. If 0, the process will be opened.
    """

    def __init__(self, processId: int, processHandle: int = 0):
        if not processId:
            raise ValueError("processId cannot be 0.")

        self._processId:    int                       = processId
        self._handle:       int                       = processHandle
        self._callbacks:    list                      = list()
        self._wait:         int                       = 0
        self._waitCallback: WaitOrTimerCallback       = CreateWaitOrTimerCallback(self.__OnProcessTerminate)
        self._peb:          PEB | None                = None
        self._mzheader:     MZ_FILEHEADER | None      = None
        self._imgheader:    IMAGE_NT_HEADERS32 | None = None

        if not self._handle:
            self.Open(self._processId)

        if not self.Exists():
            raise ValueError(f"Process {self._processId} does not exist.")

    def __del__(self):
        self._callbacks.clear()
        self._UnregisterWait()

        if self._handle:
            self.Close()

    def __str__(self) -> str:
        return f"Process(Name={self.GetName()}, PID={self._processId}, Handle={self._handle}, Path={self.GetPath()})"

    def __repr__(self) -> str:
        return str(self)

    def __eq__(self, other: Process | int) -> bool:
        if self is None or other is None:
            return False

        if isinstance(other, Process):
            return self._processId == other._processId

        return self._processId == other

    def Exists(self) -> bool:
        """
        Checks if the process exists.

        :returns: True if the process exists, False otherwise.
        """

        return pid_exists(self._processId)

    def Open(self, processId: int, access: int = PROCESS_ALL_ACCESS, inherit: bool = False) -> bool:
        """
        Opens the process with the given process id with `PROCESS_ALL_ACCESS`.

        :param processId: The process id of the process.
        :param access: The access rights to open the process.
        :param inherit: Determines processes created by this process will inherit the handle or not.

        :returns: True if the process was opened successfully, False otherwise.
        """

        if self._handle != 0:
            self.Close()

        self._processId = processId
        self._handle    = OpenProcess(processId, inherit, access)

        return self._handle != 0

    def Close(self) -> bool:
        """
        Closes the process handle.

        :returns: True if the process was closed successfully, False otherwise.
        """

        self._UnregisterWait()

        if CloseHandle(self._handle):
            self._processId = 0
            self._handle    = 0
            return True

        raise False

    def Suspend(self) -> bool:
        """
        Suspends the process. In other words, it freezes the process.
        :returns: True if the process was suspended successfully, False otherwise.
        """

        return NtSuspendProcess(self._handle)

    def Resume(self) -> bool:
        """
        Resumes the process. In other words, it unfreezes the process.
        :returns: True if the process was resumed successfully, False otherwise.
        """

        return NtResumeProcess(self._handle)

    def RegisterOnExitCallback(self, callback: Callable[[int, int], None]):
        self._callbacks.append(callback)
        self._RegisterWait()

    def UnregisterOnExitCallback(self, callback: Callable[[int, int], None]):
        self._callbacks.remove(callback)

        if self._wait and len(self._callbacks) == 0:
            UnregisterWait(self._wait)
            self._wait = 0

    def CreateThread(self,
                     startAddress:     int,
                     parameter:        int = 0,
                     creationFlags:    int = CREATE_SUSPENDED,
                     threadAttributes: int = 0,
                     stackSize:        int = 0) -> Thread:
        """
        Creates a thread that runs in the virtual address space of this process.

        :param startAddress: A pointer to the application-defined function of type LPTHREAD_START_ROUTINE to be executed
                             by the thread and represents the starting address of the thread in the remote process. The
                             function must exist in the remote process.
        :param parameter: A pointer to a variable to be passed to the thread function.
        :param creationFlags: The flags that control the creation of the thread.
        :param threadAttributes: A pointer to a SECURITY_ATTRIBUTES structure that specifies a security descriptor for
                                 the new thread and determines whether child processes can inherit the returned handle.
        :param stackSize: The initial size of the stack, in bytes. The system rounds this value to the nearest page. If
                          this parameter is 0 (zero), the new thread uses the default size for the executable.
        :returns: if waitExecution is set to False, it returns the thread handle. If set to True, it returns the
                  thread's exit code.
        """

        threadId: DWORD = DWORD()
        threadHandle: int = CreateRemoteThread(
            self._handle,
            threadAttributes,
            stackSize,
            startAddress,
            parameter,
            creationFlags,
            byref(threadId)
        )

        return Thread(threadId.value, self, threadHandle)

    def GetProcessId(self) -> int:
        """
        :returns: The process id of the targeted process.
        """

        return self._processId

    def GetHandle(self) -> int:
        """
        :returns: The process handle of the opened process. 0 if not opened.
        """

        return self._handle

    def GetName(self) -> str:
        """
        :returns: The name of the process. Empty string if the process is not opened.
        """

        try:
            module: Module = self.GetMainModule()
        except Win32Exception:
            return ""
        else:
            return module.GetName()

    def GetPath(self) -> Path | None:
        """
        :returns: The local path of the process. Empty string if the process is not opened.
        """

        nameBuffer: Array      = (WCHAR * 4096)()
        sizeBuffer: DWORD      = DWORD(4096)
        path:       str | None = None

        if QueryFullProcessImageNameW(self._handle, 0, nameBuffer, pointer(sizeBuffer)):
            path = nameBuffer.value

        if isinstance(path, str):
            return Path(path)

        return None

    def GetPriorityClass(self) -> int:
        """
        :returns: the priority class.
        """

        return GetPriorityClass(self._handle)

    def SetPriorityClass(self, priority: int = NORMAL_PRIORITY_CLASS) -> bool:
        """
        Sets the priority class

        :param priority: The priority class for the process.
        :returns: True if the priority class has been set. False otherwise.
        """

        return SetPriorityClass(self._handle, priority)

    def GetModules(self) -> List[Module]:
        """
        :raises Win32Exception: If the process is not opened or if the snapshot could not be created.
        :returns: A list of Modules of the process. Empty list if the process is not opened.
        """

        snapshot: int = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self._processId)

        if not snapshot:
            raise Win32Exception()

        moduleBuffer: MODULEENTRY32 = MODULEENTRY32()
        moduleBuffer.dwSize         = moduleBuffer.GetSize()

        if not Module32First(snapshot, byref(moduleBuffer)):
            CloseHandle(snapshot)
            raise Win32Exception()

        moduleList: List[Module] = list()

        while Module32Next(snapshot, byref(moduleBuffer)):
            module: Module = Module(moduleBuffer, self)

            moduleList.append(module)

        CloseHandle(snapshot)
        return moduleList

    def GetMainModule(self) -> Module:
        """
        :raises Win32Exception: If the process is not opened, if the snapshot could not be created or if the main module
                               could not be found.
        :returns: The main module of the process. None if the process is not opened.
        """

        return self.GetModule(None)

    def GetModule(self, name: str | None) -> Module | None:
        """
        :param name: The name of the module. If None, the main module will be returned.
        :raises Win32Exception: If the process is not opened, if the snapshot could not be created or if the main module
                               could not be found.
        :returns: The module with the given name. None if the process is not opened or the module was not found.
        """

        moduleBuffer: MODULEENTRY32 = MODULEENTRY32()
        moduleBuffer.dwSize         = moduleBuffer.GetSize()
        snapshot:     int           = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self._processId)

        if not snapshot:
            raise Win32Exception()

        if name is None:
            if not Module32First(snapshot, byref(moduleBuffer)):
                raise Win32Exception()

            module: Module = Module(moduleBuffer, self)

            CloseHandle(snapshot)
            return module

        name: bytes = name.encode('ascii')

        while Module32Next(snapshot, byref(moduleBuffer)):
            if moduleBuffer.szModule.lower() == name.lower():
                module: Module = Module(moduleBuffer, self)

                CloseHandle(snapshot)
                return module

        CloseHandle(snapshot)
        return None

    def GetThreads(self) -> List[Thread]:
        """
        :raises Win32Exception: If the process is not opened or if the snapshot could not be created.
        :returns: A list of Threads of the process. Empty list if the process is not opened.
        """

        snapshot: int = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self._processId)
        if not snapshot:
            raise Win32Exception()

        threadBuffer: THREADENTRY32 = THREADENTRY32()
        threadBuffer.dwSize         = threadBuffer.GetSize()

        if not Thread32First(snapshot, byref(threadBuffer)):
            err = Win32Exception()
            CloseHandle(snapshot)
            raise err

        threadList: List[Thread] = list()

        while Thread32Next(snapshot, byref(threadBuffer)):
            if threadBuffer.th32OwnerProcessID != self._processId:
                continue

            thread: Thread = Thread(threadBuffer.th32ThreadID, self)
            threadList.append(thread)

        CloseHandle(snapshot)
        return threadList

    def GetMainThread(self) -> Thread | None:
        """
        :raises Win32Exception: If the process is not opened, if the snapshot could not be created or if the main thread
                               could not be found.
        :returns: The main thread of the process. None if the process is not opened.
        """

        snapshot: int = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self._processId)
        if not snapshot:
            raise Win32Exception()

        threadBuffer: THREADENTRY32 = THREADENTRY32()
        threadBuffer.dwSize         = threadBuffer.GetSize()

        if not Thread32First(snapshot, byref(threadBuffer)):
            err = Win32Exception()
            CloseHandle(snapshot)
            raise err

        thread: Thread | None = None

        while Thread32Next(snapshot, byref(threadBuffer)):
            if threadBuffer.th32OwnerProcessID == self._processId:
                thread = Thread(threadBuffer.th32ThreadID, self)
                break

        CloseHandle(snapshot)
        return thread

    def GetPEB(self) -> PEB | None:
        """
        :returns: The PEB struct.
        """

        if self._peb is not None:
            return self._peb

        processInfo: ProcessBasicInformation = ProcessBasicInformation()
        if not NtQueryInformationProcess(self._handle, 0, byref(processInfo), processInfo.GetSize(), 0):
            return None

        self._peb = self.ReadStruct(processInfo.PebBaseAddress, PEB)
        return self._peb

    def GetFileHeader(self) -> MZ_FILEHEADER | None:
        """
        :returns: The MZ_FILEHEADER struct.
        """

        if self._mzheader is not None:
            return self._mzheader

        self._mzheader = self.ReadStruct(self.GetBase(), MZ_FILEHEADER)

        return self._mzheader

    def GetImageHeader(self) -> IMAGE_NT_HEADERS32 | None:
        """
        :returns: The IMAGE_NT_HEADERS32 struct.
        """

        if self._imgheader is not None:
            return self._imgheader

        mzheader: MZ_FILEHEADER = self.GetFileHeader()
        self._imgheader         = self.ReadStruct(self.GetBase() + mzheader.PEHeaderOffset, IMAGE_NT_HEADERS32)

        return self._imgheader

    def GetBase(self) -> int:
        """
        :returns: The base address of the process core module. 0 if the process is not opened.
        """

        peb = self.GetPEB()
        if peb is None:
            return 0

        return peb.ImageBaseAddress

    def GetSize(self) -> int:
        """
        :returns: The size of the process core module. 0 if the process is not opened.
        """

        img = self.GetImageHeader()
        if img is None:
            return 0

        return img.SizeOfImage

    def GetSections(self) -> list[IMAGE_SECTION_HEADER]:
        mz = self.GetFileHeader()
        pe = self.GetImageHeader()

        sectionBase: int = self.GetBase() + mz.PEHeaderOffset + pe.GetSectionsOffset()
        sectionSize: int = pe.FileHeader.NumberOfSections
        sections:    list[IMAGE_SECTION_HEADER] = list()

        for i in range(sectionSize):
            section: IMAGE_SECTION_HEADER = self.ReadStruct(sectionBase, IMAGE_SECTION_HEADER)
            section.VirtualAddress += self.GetBase()

            restsize = section.VirtualSize % pe.OptionalHeader.SectionAlignment
            if restsize:
                section.VirtualSize += pe.OptionalHeader.SectionAlignment - restsize

            sections.append(section)
            sectionBase += sizeof(IMAGE_SECTION_HEADER)

        return sections

    def Terminate(self, exitCode: int = 0) -> bool:
        """
        Terminates the process. In other words, it kills the process.

        :param exitCode: The exit code of the process.
        :returns: True if the process was terminated successfully, False otherwise.
        """

        return TerminateProcess(self._handle, exitCode)

    def Read(self, address: int, length: int) -> bytes:
        """
        Reads data from the process. This method is a wrapper for `ReadProcessMemory`.

        :param address: 4-Byte address of the data you want to read
        :param length: Data length you want to read from the address. 1 = 1 Byte
        :returns: Data on success or an empty byte string on failure
        """

        if not self.Exists():
            return b''

        buffer: Array = (BYTE * length)()

        if ReadProcessMemory(self._handle, address, byref(buffer), length, None):
            return bytes(buffer)

        raise b''

    def ReadStruct(self, address: int, structClass: Type[T: Struct]) -> T | None:
        """
        Reads data from the process into your struct.

        :param address: 4-Byte address of the data you want to read
        :param structClass: Your struct class
        :returns: Your struct filled with data on success or None on failure
        """

        if not self.Exists():
            return None

        buffer: T = structClass()

        if ReadProcessMemory(self._handle, address, byref(buffer), buffer.GetSize(), None):
            buffer.ADRESS_EX = address
            return buffer

        return None

    def ReadDWORD(self, address: int, endianess: Literal["little", "big"] = "little") -> int:
        """
        Reads a DWORD from the process.

        :param address: 4-Byte address of the data DWORD you want to read
        :param endianess: The endianess of the DWORD ("little" or "big")
        :returns: The DWORD as int
        """

        if not self.Exists():
            return 0

        result: bytes = self.Read(address, 4)
        return int.from_bytes(result, endianess)

    def ReadWORD(self, address: int, endianess: Literal["little", "big"] = "little") -> int:
        """
        Reads a WORD from the process.

        :param address: 4-Byte address of the data WORD you want to read
        :param endianess: The endianess of the WORD ("little" or "big")
        :returns: The WORD as int
        """

        if not self.Exists():
            return 0

        result: bytes = self.Read(address, 2)
        return int.from_bytes(result, endianess)

    def ReadBYTE(self, address: int, endianess: Literal["little", "big"] = "little") -> int:
        """
        Reads a BYTE from the process.

        :param address: 4-Byte address of the data BYTE you want to read
        :param endianess: The endianess of the BYTE ("little" or "big")
        :returns: The BYTE as int
        """

        if not self.Exists():
            return 0

        result: bytes = self.Read(address, 1)
        return int.from_bytes(result, endianess)

    def ReadString(self, address: int, length: int, strip: bool = True) -> bytes:
        """
        Reads a string from the process. The string will be encoded in UTF-8.

        :param address: 4-Byte address of the string you want to read
        :param length: The length of the string
        :param strip: If True, the string will be stripped of null-bytes
        :returns: The string in UTF-8.
        """

        if not self.Exists():
            return b''

        result: bytes = self.Read(address, length)
        if strip:
            termination = result.find(b'\x00')
            if termination != -1:
                result = result[:termination + 1]

        return result

    def ReadWideString(self, address: int, length: int, strip: bool = True) -> str:
        """
        Reads a wide string from the process. The string will be encoded in UTF-16.

        :param address: 4-Byte address of the string you want to read
        :param length: The length of the string
        :param strip: If True, the string will be stripped of null-bytes
        :returns: the wide string in UTF-16.
        """

        if not self.Exists():
            return ""

        result: bytes = self.Read(address, length * 2)
        if strip:
            termination = result.find(b'\x00\x00')
            if termination != -1:
                result = result[:termination + 1]

        return result.decode(encoding="utf-16")

    def Write(self, address: int, *data: bytes) -> bool:
        """
        Writes data to the process at the specified address.

        :param address: 4-Byte address of the data you want to write to
        :param data: The data you want to write
        :returns: True on success and False on failure
        """

        if not self.Exists():
            return False

        binary_data:   bytes = b''.join(data)
        size:          int   = len(binary_data)
        oldProtection: int   = self.Protect(address, size, PAGE_EXECUTE_READWRITE)
        success:       bool  = WriteProcessMemory(self._handle, address, binary_data, size, None)

        self.Protect(address, size, oldProtection)

        return success

    def WriteStruct(self, address: int, data: Type[T: Struct]) -> bool:
        """
        Writes the data of the struct to the process at the specified address.

        :param address: 4-Byte address of the data you want to write to
        :param data: your struct
        :returns: True on success and False on failure
        """

        if not self.Exists():
            return False

        size:          int  = data.GetSize()
        oldProtection: int  = self.Protect(address, size, PAGE_EXECUTE_READWRITE)
        success:       bool = WriteProcessMemory(self._handle, address, byref(data), size, None)

        self.Protect(address, size, oldProtection)

        return success

    def ZeroMemory(self, address: int, size: int) -> bool:
        """
        Fills the memory at the specified address with 0x00.

        :param address: 4-Byte address of the data you want to zero
        :param size: the size of the memory you want to zero
        :returns: True on success and False on failure
        """

        if not self.Exists():
            return False

        oldProtection: int  = self.Protect(address, size, PAGE_EXECUTE_READWRITE)
        success:       bool = self.Write(address, b'\x00' * size)

        self.Protect(address, size, oldProtection)

        return success

    def Allocate(self,
                 size:           int,
                 address:        int = 0,
                 allocationType: int = MEM_COMMIT,
                 protect:        int = PAGE_EXECUTE_READWRITE) -> int:
        """
        Allocates memory in the process.

        :param size: the size of the memory you want to allocate
        :param address: the address you want to allocate the memory at
        :param allocationType: the allocation type
        :param protect: the protection type
        :returns: the address of the allocated memory on success and 0 on failure
        """

        if not self.Exists():
            return 0

        return VirtualAllocEx(self._handle, address, size, allocationType, protect)

    def Free(self, address: int, size: int = 0, freeType: int = MEM_RELEASE) -> bool:
        """
        Frees previously allocated memory in the process.

        :param address: 4-Byte address of the memory you want to free
        :param size: the size of the memory you want to free
        :param freeType: the free type
        :returns: True on success and False on failure
        """

        return VirtualFreeEx(self._handle, address, size, freeType)

    def Protect(self, address, size, newProtection: int) -> int:
        """
        Changes the protection of the memory at the specified address.

        :param address: 4-Byte address of the memory you want to change the protection of
        :param size: the size of the memory you want to change the protection of
        :param newProtection: the new protection type
        :returns: the old protection type on success and 0 on failure
        """

        oldProtection: DWORD = DWORD()
        if not VirtualProtectEx(int(self._handle), address, size, newProtection, oldProtection):
            return 0

        return oldProtection.value

    @staticmethod
    def GetProcessList(processName: str = "") -> List[Process]:
        """
        :param processName: the name of the processes to filter
        :returns: a list of all processes found
        """

        processName: bytes         = processName.encode('ascii')
        processList: List[Process] = list()
        snapshot:    int           = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

        if not snapshot:
            return processList

        processBuffer: PROCESSENTRY32 = PROCESSENTRY32()
        processBuffer.dwSize          = processBuffer.GetSize()

        if not Process32First(snapshot, byref(processBuffer)):
            CloseHandle(snapshot)
            return processList

        while Process32Next(snapshot, byref(processBuffer)):
            if processName != "" and processBuffer.szExeFile.lower() != processName.lower():
                continue

            processList.append(Process(processBuffer.th32ProcessID))

        CloseHandle(snapshot)
        return processList

    @staticmethod
    def GetFirstProcess(processName: str = "") -> Process | None:
        """
        :param processName: the name of the process
        :returns: a process by its name
        """

        snapshot: int = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not snapshot:
            return None

        processBuffer: PROCESSENTRY32 = PROCESSENTRY32()
        processBuffer.dwSize          = processBuffer.GetSize()

        if not Process32First(snapshot, byref(processBuffer)):
            CloseHandle(snapshot)
            return None

        while Process32Next(snapshot, byref(processBuffer)):
            if processName != "" and processBuffer.szExeFile.lower() != processName.lower():
                continue

            CloseHandle(snapshot)
            return Process(processBuffer.th32ProcessID)

        CloseHandle(snapshot)
        return None

    def _RegisterWait(self) -> None:
        if not self._wait:
            self._wait = RegisterWaitForSingleObject(
                self._handle,
                self._waitCallback,
                self._processId,
                INFINITE,
                WT_EXECUTEONLYONCE
            )

    def _UnregisterWait(self) -> None:
        if self._wait:
            UnregisterWait(self._wait)
            self._wait = 0

    def __OnProcessTerminate(self, processId: int, timerOrWaitFired: int) -> None:
        for callback in self._callbacks:
            callback(processId, timerOrWaitFired)



