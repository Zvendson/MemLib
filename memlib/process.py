"""
:platform: Windows
"""

from __future__ import annotations

from ctypes import byref, pointer
from ctypes.wintypes import BYTE, DWORD, WCHAR
from typing import List, Literal, TYPE_CHECKING, Type, TypeVar, Union


import memlib.constants
import memlib.exceptions
import memlib.kernel32
import memlib.module
import memlib.structs

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

        self._processId = 0
        self._handle = 0

        if not processHandle:
            self.Open(processId)
        else:
            self._handle = processHandle

    def __del__(self):
        if self._handle:
            self.Close()

    def __int__(self):
        return self._handle

    def __str__(self) -> str:
        return f"Process(Name={self.GetName()}, PID={self._processId}, Handle={self._handle}, Path={self.GetPath()})"

    def __repr__(self) -> str:
        return str(self)

    def __eq__(self, other: Union[Process, int]) -> bool:
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

        return memlib.kernel32.GetExitCodeProcess(self._handle) == memlib.constants.STILL_ACTIVE

    def Open(self, processId: int) -> bool:
        """
        Opens the process with the given process id with `PROCESS_ALL_ACCESS`.

        :param processId: The process id of the process.
        :param desiredAccess: The access to the process object.
        :returns: True if the process was opened successfully, False otherwise.
        """

        if self._handle != 0:
            self.Close()

        self._processId = processId
        self._handle = memlib.kernel32.OpenProcess(processId, False, memlib.constants.PROCESS_ALL_ACCESS)

        return self._handle != 0

    def Close(self) -> bool:
        """
        Closes the process handle.
        :returns: True if the process was closed successfully, False otherwise.
        """

        if memlib.kernel32.CloseHandle(self._handle):
            self._processId = 0
            self._handle = 0
            return True

        raise False

    def Suspend(self) -> bool:
        """
        Suspends the process. In other words, it freezes the process.
        :returns: True if the process was suspended successfully, False otherwise.
        """

        return memlib.kernel32.NtSuspendProcess(self._handle)

    def Resume(self) -> bool:
        """
        Resumes the process. In other words, it unfreezes the process.
        :returns: True if the process was resumed successfully, False otherwise.
        """

        return memlib.kernel32.NtResumeProcess(self._handle)

    def GetProcessId(self):
        """
        :returns: The process id of the process. 0 if the process is not opened.
        """

        return self._processId

    def GetHandle(self):
        """
        :returns: The process handle of the process. 0 if the process is not opened.
        """

        return self._handle

    def GetName(self) -> str:
        """
        :returns: The name of the process. Empty string if the process is not opened.
        """

        try:
            module: memlib.module.Module = self.GetMainModule()
        except memlib.exceptions.Win32Exception:
            return ""
        else:
            return module.GetName()

    def GetPath(self) -> str:
        """
        :returns: The local path of the process. Empty string if the process is not opened.
        """

        nameBuffer = (WCHAR * 4096)()
        sizeBuffer = DWORD(4096)

        if memlib.kernel32.QueryFullProcessImageNameW(self._handle, 0, nameBuffer, pointer(sizeBuffer)):
            return nameBuffer.value

        return ""

    def GetModules(self) -> List[memlib.module.Module]:
        """
        :raises Win32Exception: If the process is not opened or if the snapshot could not be created.
        :returns: A list of Modules of the process. Empty list if the process is not opened.
        """

        moduleList = list()

        snapshot = memlib.kernel32.CreateToolhelp32Snapshot(
            memlib.constants.TH32CS_SNAPMODULE | memlib.constants.TH32CS_SNAPMODULE32,
            self._processId
        )

        if not snapshot:
            raise memlib.exceptions.Win32Exception()

        moduleBuffer = memlib.structs.MODULEENTRY32()

        while memlib.kernel32.Module32Next(snapshot, byref(moduleBuffer)):
            module = memlib.module.Module(moduleBuffer, self)
            moduleList.append(module)

        memlib.kernel32.CloseHandle(snapshot)

        return moduleList

    def GetMainModule(self) -> memlib.module.Module:
        """
        :raises Win32Exception: If the process is not opened, if the snapshot could not be created or if the main module
                               could not be found.
        :returns: The main module of the process. None if the process is not opened.
        """

        return self.GetModule(None)

    def GetModule(self, name: Union[str, None]) -> memlib.module.Module:
        """
        :param name: The name of the module. If None, the main module will be returned.
        :raises Win32Exception: If the process is not opened, if the snapshot could not be created or if the main module
                               could not be found.
        :returns: The module with the given name. None if the process is not opened or the module was not found.
        """

        moduleBuffer = memlib.structs.MODULEENTRY32()
        moduleBuffer.dwSize = moduleBuffer.GetSize()

        snapshot = memlib.kernel32.CreateToolhelp32Snapshot(
            memlib.constants.TH32CS_SNAPMODULE | memlib.constants.TH32CS_SNAPMODULE32,
            self._processId
        )

        if not snapshot:
            raise memlib.exceptions.Win32Exception()

        module = None

        if name is None:
            if not memlib.kernel32.Module32First(snapshot, byref(moduleBuffer)):
                raise memlib.exceptions.Win32Exception()

            module = memlib.module.Module(moduleBuffer, self)
            memlib.kernel32.CloseHandle(snapshot)

            return module

        name = name.encode('ascii')

        while memlib.kernel32.Module32Next(snapshot, byref(moduleBuffer)):
            if moduleBuffer.szModule.lower() == name.lower():
                module = memlib.module.Module(moduleBuffer, self)
                memlib.kernel32.CloseHandle(snapshot)

                return module

        assert module is None, f"Module '{name}' not found."

    def GetBase(self) -> int:
        """
        :returns: The base address of the process. 0 if the process is not opened.
        """

        processInfo = memlib.structs.ProcessBasicInformation()

        if not memlib.kernel32.NtQueryInformationProcess(self._handle, 0, byref(processInfo), processInfo.GetSize(), 0):
            return 0

        peb = self.ReadStruct(processInfo.PebBaseAddress, memlib.structs.PEB)

        return peb.ImageBaseAddress

    def Terminate(self, exitCode: int = 0) -> bool:
        """
        Terminates the process. In other words, it kills the process.

        :param exitCode: The exit code of the process.
        :returns: True if the process was terminated successfully, False otherwise.
        """

        return memlib.kernel32.TerminateProcess(self._handle, exitCode)

    def Read(self, address: int, length: int) -> bytes:
        """
        Reads data from the process. This method is a wrapper for `ReadProcessMemory`.

        :param address: 4-Byte address of the data you want to read
        :param length: Data length you want to read from the address. 1 = 1 Byte
        :returns: Data on success or an empty byte string on failure
        """

        buffer = (BYTE * length)()

        if memlib.kernel32.ReadProcessMemory(self._handle, address, byref(buffer), length, None):
            return bytes(buffer)

        raise b''

    def ReadStruct(self, address: int, structClass: Type[T: memlib.structs.Struct]) -> T:
        """
        Reads data from the process into your struct.

        :param address: 4-Byte address of the data you want to read
        :param structClass: Your struct class
        :returns: Your struct filled with data on success or None on failure
        """

        buffer: T = structClass()

        if memlib.kernel32.ReadProcessMemory(self._handle, address, byref(buffer), buffer.GetSize(), None):
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

        result = self.Read(address, 4)
        return int.from_bytes(result, endianess)

    def ReadWORD(self, address: int, endianess: Literal["little", "big"] = "little") -> int:
        """
        Reads a WORD from the process.

        :param address: 4-Byte address of the data WORD you want to read
        :param endianess: The endianess of the WORD ("little" or "big")
        :returns: The WORD as int
        """

        result = self.Read(address, 2)
        return int.from_bytes(result, endianess)

    def ReadBYTE(self, address: int, endianess: Literal["little", "big"] = "little") -> int:
        """
        Reads a BYTE from the process.

        :param address: 4-Byte address of the data BYTE you want to read
        :param endianess: The endianess of the BYTE ("little" or "big")
        :returns: The BYTE as int
        """

        result = self.Read(address, 1)
        return int.from_bytes(result, endianess)

    def ReadString(self, address: int, length: int, strip: bool = True) -> bytes:
        """
        Reads a string from the process. The string will be encoded in UTF-8.

        :param address: 4-Byte address of the string you want to read
        :param length: The length of the string
        :param strip: If True, the string will be stripped of null-bytes
        :returns: The string in UTF-8.
        """

        result: bytes = self.Read(address, length)
        if strip:
            result = result.rstrip(b'\x00') + b'\x00'

        return result

    def ReadWideString(self, address: int, length: int, strip: bool = True) -> str:
        """
        Reads a wide string from the process. The string will be encoded in UTF-16.

        :param address: 4-Byte address of the string you want to read
        :param length: The length of the string
        :param strip: If True, the string will be stripped of null-bytes
        :returns: the wide string in UTF-16.
        """

        result: bytes = self.Read(address, length * 2)
        if strip:
            result = result.rstrip(b'\x00') + b'\x00'
        return result.decode(encoding="utf-16")

    def Write(self, address: int, *data: bytes) -> bool:
        """
        Writes data to the process at the specified address.

        :param address: 4-Byte address of the data you want to write to
        :param data: The data you want to write
        :returns: True on success and False on failure
        """

        binary_data = b''.join(data)
        size = len(binary_data)

        oldProtection = self.Protect(address, size, memlib.constants.PAGE_EXECUTE_READWRITE)
        success = memlib.kernel32.WriteProcessMemory(self._handle, address, binary_data, size, None)
        self.Protect(address, size, oldProtection)

        return success

    def WriteStruct(self, address: int, data: Type[T: memlib.structs.Struct]) -> bool:
        """
        Writes the data of the struct to the process at the specified address.

        :param address: 4-Byte address of the data you want to write to
        :param data: your struct
        :returns: True on success and False on failure
        """

        size = data.GetSize()

        oldProtection = self.Protect(address, size, memlib.constants.PAGE_EXECUTE_READWRITE)
        success = memlib.kernel32.WriteProcessMemory(self._handle, address, byref(data), size, None)
        self.Protect(address, size, oldProtection)

        return success

    def ZeroMemory(self, address: int, size: int) -> bool:
        """
        Fills the memory at the specified address with 0x00.

        :param address: 4-Byte address of the data you want to zero
        :param size: the size of the memory you want to zero
        :returns: True on success and False on failure
        """

        oldProtection = self.Protect(address, size, memlib.constants.PAGE_EXECUTE_READWRITE)
        success = self.Write(address, b'\x00' * size)
        self.Protect(address, size, oldProtection)

        return success

    def Allocate(self,
                 size: int,
                 address: int = 0,
                 alloc: int = memlib.constants.MEM_COMMIT,
                 prot: int = memlib.constants.PAGE_EXECUTE_READWRITE) -> int:
        """
        Allocates memory in the process.

        :param size: the size of the memory you want to allocate
        :param address: the address you want to allocate the memory at
        :param allocationType: the allocation type
        :param protect: the protection type
        :returns: the address of the allocated memory on success and 0 on failure
        """

        return memlib.kernel32.VirtualAllocEx(self._handle, address, size, alloc, prot)

    def Free(self, address: int, size: int = 0, freeType: int = memlib.constants.MEM_RELEASE) -> bool:
        """
        Frees previously allocated memory in the process.

        :param address: 4-Byte address of the memory you want to free
        :param size: the size of the memory you want to free
        :param freeType: the free type
        :returns: True on success and False on failure
        """

        return memlib.kernel32.VirtualFreeEx(self._handle, address, size, freeType)

    def Protect(self, address, size, newProtection: int) -> int:
        """
        Changes the protection of the memory at the specified address.

        :param address: 4-Byte address of the memory you want to change the protection of
        :param size: the size of the memory you want to change the protection of
        :param newProtection: the new protection type
        :returns: the old protection type on success and 0 on failure
        """
        oldProtection = DWORD()
        if not memlib.kernel32.VirtualProtectEx(int(self._handle), address, size, newProtection, oldProtection):

            return 0

        return oldProtection.value

    @staticmethod
    def GetProcessList(processName: str = "") -> List[Process]:
        """
        :param processName: the name of the processes to filter
        :returns: a list of all processes found
        """

        processName = processName.encode('ascii')
        processList = list()

        snapshot = memlib.kernel32.CreateToolhelp32Snapshot(memlib.constants.TH32CS_SNAPPROCESS, 0)
        if not snapshot:
            return processList

        processBuffer = memlib.structs.PROCESSENTRY32()
        processBuffer.dwSize = processBuffer.GetSize()

        if not memlib.kernel32.Process32First(snapshot, byref(processBuffer)):
            memlib.kernel32.CloseHandle(snapshot)
            return processList

        while memlib.kernel32.Process32Next(snapshot, byref(processBuffer)):
            # print(processBuffer.szExeFile.lower(), "!=", processName.lower(), "=", processBuffer.szExeFile.lower() !=
            #       processName.lower())
            if processName != "" and processBuffer.szExeFile.lower() != processName.lower():
                continue

            processList.append(Process(processBuffer.th32ProcessID))

        memlib.kernel32.CloseHandle(snapshot)

        return processList

    @staticmethod
    def GetFirstProcess(processName: str = "") -> Union[Process, None]:
        """
        :param processName: the name of the process
        :returns: a process by its name
        """

        snapshot = memlib.kernel32.CreateToolhelp32Snapshot(memlib.constants.TH32CS_SNAPPROCESS, 0)
        if not snapshot:
            return None

        processBuffer = memlib.structs.PROCESSENTRY32()
        processBuffer.dwSize = processBuffer.GetSize()

        if not memlib.kernel32.Process32First(snapshot, byref(processBuffer)):
            memlib.kernel32.CloseHandle(snapshot)
            return None

        while memlib.kernel32.Process32Next(snapshot, byref(processBuffer)):
            if processName != "" and processBuffer.szExeFile.lower() != processName.lower():
                continue

            memlib.kernel32.CloseHandle(snapshot)
            return Process(processBuffer.th32ProcessID)

        memlib.kernel32.CloseHandle(snapshot)
        return None
