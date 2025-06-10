"""
:platform: Windows
"""

from __future__ import annotations
from typing import TYPE_CHECKING, Callable, Literal, Type, TypeVar

import psutil
from pathlib import Path

from ctypes import Array, byref, pointer, sizeof
from ctypes.wintypes import BYTE, DWORD, WCHAR

from MemLib import Kernel32
from MemLib.Constants import (
    CREATE_SUSPENDED, INFINITE, MEM_COMMIT, MEM_RELEASE,
    NORMAL_PRIORITY_CLASS, PAGE_EXECUTE_READWRITE,
    PROCESS_ALL_ACCESS, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ, PROCESS_VM_WRITE, SYNCHRONIZE,
    TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
    TH32CS_SNAPTHREAD, WT_EXECUTEONLYONCE,
)
from MemLib.Decorators import require_32bit
from MemLib.Scanner import BinaryScanner
from MemLib.Structs import (
    IMAGE_NT_HEADERS32, IMAGE_SECTION_HEADER, MODULEENTRY32, MZ_FILEHEADER, PEB, PROCESSENTRY32,
    ProcessBasicInformation, Struct,
    THREADENTRY32,
)
from MemLib.Module import Module
from MemLib.Thread import Thread


if TYPE_CHECKING:
    T = TypeVar('T')
    WaitCallback = Kernel32.WaitOrTimerCallback


class Process:
    """
    Represents an interactable process. 64 bit not supported (yet?).

    :raises ValueError: If the process does not exist.
    :param process_id: The process id of the process.
    :param process_handle: The process handle of the process. If 0, the process will be opened.
    """

    @require_32bit
    def __init__(self, process_id: int, process_handle: int = 0, access: int = PROCESS_ALL_ACCESS,
                 inherit: bool = False):
        if not process_id:
            raise ValueError("processId cannot be 0.")

        self._process_id: int                      = process_id
        self._handle: int                          = process_handle
        self._access: int                          = access
        self._inherit: bool                        = inherit
        self._name: str | None                     = None
        self._path: Path | None                    = None
        self._callbacks: list                      = list()
        self._wait: int                            = 0
        self._wait_callback: WaitCallback          = Kernel32.CreateWaitOrTimerCallback(self.__on_process_terminate)
        self._peb: PEB | None                      = None
        self._mzheader: MZ_FILEHEADER | None       = None
        self._imgheader: IMAGE_NT_HEADERS32 | None = None

        if not self._handle:
            self.open(access, self._inherit, self._process_id)

        if not self.exists():
            raise ValueError(f"Process {self._process_id} does not exist.")

    def __del__(self):
        self._callbacks.clear()
        self._unregister_wait()

        if self._handle:
            self.close()

    def __str__(self) -> str:
        return (f"Process(Name={self.get_name()}, PID={self._process_id}, Handle={self._handle}, Path="
                f"{self.get_path()}, AccessRights=0x{self._access:X})")

    def __repr__(self) -> str:
        return str(self)

    def __eq__(self, other: Process | int) -> bool:
        if self is None or other is None:
            return False

        if isinstance(other, Process):
            return self == other

        return self._process_id == other

    def exists(self) -> bool:
        """
        Checks if the process exists.

        :returns: True if the process exists, False otherwise.
        """

        return psutil.pid_exists(self._process_id)

    def open(self, access: int = PROCESS_ALL_ACCESS, inherit: bool = False, process_id: int = 0) -> bool:
        """
        Opens the process with the given process id with `PROCESS_ALL_ACCESS`.

        :param process_id: The process id of the process. If 0, will take self._process_id.
        :param access: The access rights to open the process.
        :param inherit: Determines processes created by this process will inherit the handle or not.

        :raises Win32Exception: If the process vould not be opened with the desicered access rights.

        :returns: True if the process was opened successfully, False otherwise.
        """

        if self._handle != 0:
            self.close()

        if process_id != 0:
            self._process_id = process_id

        self._access  = access
        self._inherit = inherit
        self._handle  = Kernel32.OpenProcess(self._process_id, self._inherit, self._access)

        if not self._handle:
            raise Kernel32.Win32Exception()

        return self._handle != 0

    def close(self) -> bool:
        """
        Closes the process handle.

        :returns: True if the process was closed successfully, False otherwise.
        """

        self._unregister_wait()

        if Kernel32.CloseHandle(self._handle):
            self._handle = 0
            return True

        raise False

    def suspend(self) -> bool:
        """
        Suspends the process. In other words, it freezes the process.
        :returns: True if the process was suspended successfully, False otherwise.
        """

        return Kernel32.NtSuspendProcess(self._handle)

    def resume(self) -> bool:
        """
        Resumes the process. In other words, it unfreezes the process.
        :returns: True if the process was resumed successfully, False otherwise.
        """

        return Kernel32.NtResumeProcess(self._handle)

    def register_on_exit_callback(self, callback: Callable[[int, int], None]) -> bool:
        """
        Registers a callback that gets called when the process terminates.
        The callback takes 2 params:
        VOID CALLBACK WaitOrTimerCallback(
            _In_ PVOID   lpParameter,
            _In_ BOOLEAN TimerOrWaitFired
        );

        :returns: True if registered successfully, False otherwise.
        """

        self._callbacks.append(callback)
        return self._register_wait()

    def unregister_on_exit_callback(self, callback: Callable[[int, int], None]) -> bool:
        """
        Unregisters a callback was previously registered through 'RegisterOnExitCallback'.

        :returns: True if unregistered successfully, False otherwise.
        """

        self._callbacks.remove(callback)

        if self._wait and len(self._callbacks) == 0:
            success = Kernel32.UnregisterWait(self._wait)
            self._wait = 0
            return success

        return True

    def create_thread(self, start_address: int, parameter: int = 0, creation_flags: int = CREATE_SUSPENDED,
                      thread_attributes: int = 0, stack_size: int = 0) -> Thread:
        """
        Creates a thread that runs in the virtual address space of this process.

        :param start_address: A pointer to the application-defined function of type LPTHREAD_START_ROUTINE to be executed
                             by the thread and represents the starting address of the thread in the remote process. The
                             function must exist in the remote process.
        :param parameter: A pointer to a variable to be passed to the thread function.
        :param creation_flags: The flags that control the creation of the thread.
        :param thread_attributes: A pointer to a SECURITY_ATTRIBUTES structure that specifies a security descriptor for
                                 the new thread and determines whether child processes can inherit the returned handle.
        :param stack_size: The initial size of the stack, in bytes. The system rounds this value to the nearest page. If
                          this parameter is 0 (zero), the new thread uses the default size for the executable.
        :returns: if waitExecution is set to False, it returns the thread handle. If set to True, it returns the
                  thread's exit code.
        """

        thread_id: DWORD = DWORD()
        thread_handle: int = Kernel32.CreateRemoteThread(
            self._handle,
            thread_attributes,
            stack_size,
            start_address,
            parameter,
            creation_flags,
            byref(thread_id)
        )

        return Thread(thread_id.value, self, thread_handle)

    def get_process_id(self) -> int:
        """
        :returns: The process id of the targeted process.
        """

        return self._process_id

    def get_handle(self) -> int:
        """
        :returns: The process handle of the opened process. 0 if not opened.
        """

        return self._handle

    def get_access_rights(self) -> int:
        """
        :returns: The access rights the process is or will be opened with.
        """

        return self._access

    def get_name(self) -> str:
        """
        :returns: The name of the process. Empty string if the process is not opened.
        """

        if self._name is not None:
            return self._name

        try:
            module: Module = self.get_main_module()
        except Kernel32.Win32Exception as e:
            self._name = None
        else:
            self._name = module.name()

        return self._name

    def get_path(self) -> Path | None:
        """
        :returns: The local path of the process. Empty string if the process is not opened.
        """

        if self._path is not None:
            return self._path

        name_buffer: Array = (WCHAR * 4096)()
        size_buffer: DWORD = DWORD(4096)
        path: str | None   = None

        if Kernel32.QueryFullProcessImageNameW(self._handle, 0, name_buffer, pointer(size_buffer)):
            path = name_buffer.value

        if isinstance(path, str):
            self._path = Path(path)

        return self._path

    def get_priority_class(self) -> int:
        """
        :returns: the priority class.
        """

        return Kernel32.GetPriorityClass(self._handle)

    def set_priority_class(self, priority: int = NORMAL_PRIORITY_CLASS) -> bool:
        """
        Sets the priority class

        :param priority: The priority class for the process.
        :returns: True if the priority class has been set. False otherwise.
        """

        return Kernel32.SetPriorityClass(self._handle, priority)

    def get_modules(self) -> list[Module]:
        """
        :raises Win32Exception: If the process is not opened or if the snapshot could not be created.
        :returns: A list of Modules of the process. Empty list if the process is not opened.
        """

        snapshot: int = Kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self._process_id)

        if not snapshot:
            raise Kernel32.Win32Exception()

        module_buffer: MODULEENTRY32 = MODULEENTRY32()
        module_buffer.dwSize         = module_buffer.get_size()

        if not Kernel32.Module32First(snapshot, byref(module_buffer)):
            Kernel32.CloseHandle(snapshot)
            raise Kernel32.Win32Exception()

        module_list: list[Module] = list()

        while Kernel32.Module32Next(snapshot, byref(module_buffer)):
            module: Module = Module(module_buffer, self)

            module_list.append(module)

        Kernel32.CloseHandle(snapshot)
        return module_list

    def get_main_module(self) -> Module:
        """
        :raises Win32Exception: If the process is not opened, if the snapshot could not be created or if the main module
                               could not be found.
        :returns: The main module of the process. None if the process is not opened.
        """

        return self.get_module(None)

    def get_module(self, name: str | None) -> Module | None:
        """
        :param name: The name of the module. If None, the main module will be returned.
        :raises Win32Exception: If the process is not opened, if the snapshot could not be created or if the main module
                               could not be found.
        :returns: The module with the given name. None if the process is not opened or the module was not found.
        """

        module_buffer: MODULEENTRY32 = MODULEENTRY32()
        module_buffer.dwSize         = module_buffer.get_size()

        snapshot: int = Kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self._process_id)

        if not snapshot:
            raise Kernel32.Win32Exception()

        if name is None:
            if not Kernel32.Module32First(snapshot, byref(module_buffer)):
                raise Kernel32.Win32Exception()

            module: Module = Module(module_buffer, self)

            Kernel32.CloseHandle(snapshot)
            return module

        name: bytes = name.encode('ascii').lower()

        while Kernel32.Module32Next(snapshot, byref(module_buffer)):
            if module_buffer.szModule.lower() == name:
                module: Module = Module(module_buffer, self)

                Kernel32.CloseHandle(snapshot)
                return module

        Kernel32.CloseHandle(snapshot)
        return None

    def get_threads(self) -> list[Thread]:
        """
        :raises Win32Exception: If the process is not opened or if the snapshot could not be created.
        :returns: A list of Threads of the process. Empty list if the process is not opened.
        """

        snapshot: int = Kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self._process_id)
        if not snapshot:
            raise Kernel32.Win32Exception()

        thread_buffer: THREADENTRY32 = THREADENTRY32()
        thread_buffer.dwSize         = thread_buffer.get_size()

        if not Kernel32.Thread32First(snapshot, byref(thread_buffer)):
            err = Kernel32.Win32Exception()
            Kernel32.CloseHandle(snapshot)
            raise err

        thread_list: list[Thread] = list()
        thread_found: bool        = True

        while thread_found:
            if thread_buffer.th32OwnerProcessID == self._process_id:
                thread: Thread = Thread(thread_buffer.th32ThreadID, self)
                thread_list.append(thread)

            thread_found = Kernel32.Thread32Next(snapshot, byref(thread_buffer))

        Kernel32.CloseHandle(snapshot)
        return thread_list

    def get_main_thread(self) -> Thread | None:
        """
        :raises Win32Exception: If the process is not opened, if the snapshot could not be created or if the main thread
                               could not be found.
        :returns: The main thread of the process. None if the process is not opened.
        """

        snapshot: int = Kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self._process_id)
        if not snapshot:
            raise Kernel32.Win32Exception()

        thread_buffer: THREADENTRY32 = THREADENTRY32()
        thread_buffer.dwSize         = thread_buffer.get_size()
        thread: Thread | None        = None

        if not Kernel32.Thread32First(snapshot, byref(thread_buffer)):
            err = Kernel32.Win32Exception()
            Kernel32.CloseHandle(snapshot)
            raise err

        thread_found: bool = True

        while thread_found:
            if thread_buffer.th32OwnerProcessID == self._process_id:
                thread = Thread(thread_buffer.th32ThreadID, self)
                break

            thread_found = Kernel32.Thread32Next(snapshot, byref(thread_buffer))

        Kernel32.CloseHandle(snapshot)
        return thread

    def get_peb(self) -> PEB | None:
        """
        :returns: The PEB struct.
        """

        if self._peb is not None:
            return self._peb

        process_info: ProcessBasicInformation = ProcessBasicInformation()
        if not Kernel32.NtQueryInformationProcess(self._handle, 0, byref(process_info), process_info.get_size(), 0):
            return None

        self._peb = self.read_struct(process_info.PebBaseAddress, PEB)
        return self._peb

    def get_file_header(self) -> MZ_FILEHEADER | None:
        """
        :returns: The MZ_FILEHEADER struct.
        """

        if self._mzheader is not None:
            return self._mzheader

        self._mzheader = self.read_struct(self.get_base(), MZ_FILEHEADER)

        return self._mzheader

    def get_image_header(self) -> IMAGE_NT_HEADERS32 | None:
        """
        :returns: The IMAGE_NT_HEADERS32 struct.
        """

        if self._imgheader is not None:
            return self._imgheader

        mzheader: MZ_FILEHEADER = self.get_file_header()
        self._imgheader         = self.read_struct(self.get_base() + mzheader.PEHeaderOffset, IMAGE_NT_HEADERS32)

        return self._imgheader

    def get_base(self) -> int:
        """
        :returns: The base address of the process core module. 0 if the process is not opened.
        """

        peb = self.get_peb()
        if peb is None:
            return 0

        return peb.ImageBaseAddress

    def get_size(self) -> int:
        """
        :returns: The size of the process core module. 0 if the process is not opened.
        """

        img: IMAGE_NT_HEADERS32 = self.get_image_header()
        if img is None:
            return 0

        return img.SizeOfImage

    def get_sections(self) -> list[IMAGE_SECTION_HEADER]:
        """
        :returns: The core module sections of the process, even if the process was created in suspended mode.
        """

        mz: MZ_FILEHEADER      = self.get_file_header()
        pe: IMAGE_NT_HEADERS32 = self.get_image_header()

        section_base: int = self.get_base() + mz.PEHeaderOffset + pe.get_sections_offset()
        section_size: int = pe.FileHeader.NumberOfSections

        sections: list[IMAGE_SECTION_HEADER] = list()

        for i in range(section_size):
            section: IMAGE_SECTION_HEADER = self.read_struct(section_base, IMAGE_SECTION_HEADER)

            section.VirtualAddress += self.get_base()

            rest_size = section.VirtualSize % pe.OptionalHeader.SectionAlignment
            if rest_size:
                section.VirtualSize += pe.OptionalHeader.SectionAlignment - rest_size

            sections.append(section)
            section_base += sizeof(IMAGE_SECTION_HEADER)

        return sections

    def get_section(self, name: str) -> IMAGE_SECTION_HEADER | None:
        """
        :returns: A core module section by name of the process, even if the process was created in suspended mode.
        """

        b_name: bytes = name.encode()

        sections: list[IMAGE_SECTION_HEADER] = self.get_sections()
        for section in sections:
            if section.Name == b_name:
                return section

        return None

    def get_scanner(self, section_name: str = None) -> BinaryScanner | None:
        """
        :returns: A scanner object of the core module by section name. Picks first section if none specified.
        """

        if not self.can_read_memory():
            raise RuntimeError(f"Invalid access rights. PROCESS_VM_READ required, got: 0x{self._access:X}")

        if section_name is None:
            sections = self.get_sections()
            if not len(sections):
                return None
            wanted_section: IMAGE_SECTION_HEADER = sections[0]
        else:
            wanted_section: IMAGE_SECTION_HEADER = self.get_section(section_name)

        if wanted_section is None:
            return None

        buffer: bytes = self.read(wanted_section.VirtualAddress, wanted_section.VirtualSize)
        if len(buffer):
            return BinaryScanner(buffer, wanted_section.VirtualAddress)

        return None

    def can_read_memory(self) -> bool:
        """
        :returns: True if the access rights can read memory.
        """

        return self._access & PROCESS_VM_READ == PROCESS_VM_READ

    def can_write_memory(self) -> bool:
        """
        :returns: True if the access rights can write memory.
        """

        return self._access & PROCESS_VM_WRITE == PROCESS_VM_WRITE

    def terminate(self, exit_code: int = 0) -> bool:
        """
        Terminates the process. In other words, it kills the process.

        :param exit_code: The exit code of the process.
        :returns: True if the process was terminated successfully, False otherwise.
        """

        return Kernel32.TerminateProcess(self._handle, exit_code)

    def read(self, address: int, length: int) -> bytes:
        """
        Reads data from the process. This method is a wrapper for `ReadProcessMemory`.

        :param address: 4-Byte address of the data you want to read
        :param length: Data length you want to read from the address. 1 = 1 Byte
        :returns: Data on success or an empty byte string on failure
        """

        if not self.exists():
            return b''

        buffer: Array = (BYTE * length)()
        if Kernel32.ReadProcessMemory(self._handle, address, byref(buffer), length, None):
            return bytes(buffer)

        return b''

    def read_struct(self, address: int, struct_class: Type[T: Struct]) -> T | None:
        """
        Reads data from the process into your struct.

        :param address: 4-Byte address of the data you want to read
        :param struct_class: Your struct type class
        :returns: Your struct filled with data on success or None on failure
        """

        if not self.exists():
            return None

        buffer: T = struct_class()

        if Kernel32.ReadProcessMemory(self._handle, address, byref(buffer), buffer.get_size(), None):
            buffer.ADDRESS_EX = address
            return buffer

        return None

    def read_dword(self, address: int, endian: Literal["little", "big"] = "little") -> int:
        """
        Reads a DWORD from the process.

        :param address: 4-Byte address of the data DWORD you want to read
        :param endian: The endianess of the DWORD ("little" or "big")
        :returns: The DWORD as int
        """

        if not self.exists():
            return 0

        result: bytes = self.read(address, 4)
        return int.from_bytes(result, endian)

    def read_word(self, address: int, endian: Literal["little", "big"] = "little") -> int:
        """
        Reads a WORD from the process.

        :param address: 4-Byte address of the data WORD you want to read
        :param endian: The endianess of the WORD ("little" or "big")
        :returns: The WORD as int
        """

        if not self.exists():
            return 0

        result: bytes = self.read(address, 2)
        return int.from_bytes(result, endian)

    def read_byte(self, address: int, endian: Literal["little", "big"] = "little") -> int:
        """
        Reads a BYTE from the process.

        :param address: 4-Byte address of the data BYTE you want to read
        :param endian: The endianess of the BYTE ("little" or "big")
        :returns: The BYTE as int
        """

        if not self.exists():
            return 0

        result: bytes = self.read(address, 1)
        return int.from_bytes(result, endian)

    def read_string(self, address: int, length: int, strip: bool = True) -> bytes:
        """
        Reads a string from the process. The string will be encoded in UTF-8.

        :param address: 4-Byte address of the string you want to read
        :param length: The length of the string
        :param strip: If True, the string will be stripped of null-bytes
        :returns: The string in UTF-8.
        """

        if not self.exists():
            return b''

        result: bytes = self.read(address, length)
        if strip:
            termination = result.find(b'\x00')
            if termination != -1:
                result = result[:termination]

        return result

    def read_wide_string(self, address: int, length: int, strip: bool = True) -> str:
        """
        Reads a wide string from the process. The string will be encoded in UTF-16.

        :param address: 4-Byte address of the string you want to read
        :param length: The length of the string
        :param strip: If True, the string will be stripped of null-bytes
        :returns: the wide string in UTF-16.
        """

        if not self.exists():
            return ""

        result: bytes = self.read(address, length * 2)
        if strip:
            termination = result.find(b'\x00\x00')
            if termination != -1:
                result = result[:termination + 1]

        return result.decode(encoding="utf-16")

    def write(self, address: int, binary_data: bytes) -> bool:
        """
        Writes data to the process at the specified address.

        :param address: 4-Byte address of the data you want to write to
        :param binary_data: The data you want to write
        :returns: True on success and False on failure
        """

        if not self.exists():
            return False

        size: int           = len(binary_data)
        old_protection: int = self.protect(address, size, PAGE_EXECUTE_READWRITE)

        success: bool = Kernel32.WriteProcessMemory(self._handle, address, binary_data, size, None)

        self.protect(address, size, old_protection)

        return success

    def write_struct(self, address: int, data: Type[T: Struct]) -> bool:
        """
        Writes the data of the struct to the process at the specified address.

        :param address: 4-Byte address of the data you want to write to
        :param data: your struct
        :returns: True on success and False on failure
        """

        if not self.exists():
            return False

        size: int           = data.get_size()
        old_protection: int = self.protect(address, size, PAGE_EXECUTE_READWRITE)
        success: bool       = Kernel32.WriteProcessMemory(self._handle, address, byref(data), size, None)

        self.protect(address, size, old_protection)

        return success

    def zero_memory(self, address: int, size: int) -> bool:
        """
        Fills the memory at the specified address with 0x00.

        :param address: 4-Byte address of the data you want to zero
        :param size: the size of the memory you want to zero
        :returns: True on success and False on failure
        """

        if not self.exists():
            return False

        old_protection: int = self.protect(address, size, PAGE_EXECUTE_READWRITE)
        success: bool       = self.write(address, b'\x00' * size)

        self.protect(address, size, old_protection)

        return success

    def allocate(self, size: int, address: int = 0, allocation_type: int = MEM_COMMIT,
                 protect: int = PAGE_EXECUTE_READWRITE) -> int:
        """
        Allocates memory in the process.

        :param size: the size of the memory you want to allocate
        :param address: the address you want to allocate the memory at
        :param allocation_type: the allocation type
        :param protect: the protection type
        :returns: the address of the allocated memory on success and 0 on failure
        """

        if not self.exists():
            return 0

        return Kernel32.VirtualAllocEx(self._handle, address, size, allocation_type, protect)

    def free(self, address: int, size: int = 0, free_type: int = MEM_RELEASE) -> bool:
        """
        Frees previously allocated memory in the process.

        :param address: 4-Byte address of the memory you want to free
        :param size: the size of the memory you want to free
        :param free_type: the free type
        :returns: True on success and False on failure
        """

        return Kernel32.VirtualFreeEx(self._handle, address, size, free_type)

    def protect(self, address, size, new_protection: int) -> int:
        """
        Changes the protection of the memory at the specified address.

        :param address: 4-Byte address of the memory you want to change the protection of
        :param size: the size of the memory you want to change the protection of
        :param new_protection: the new protection type
        :returns: the old protection type on success and 0 on failure
        """

        old_protection: DWORD = DWORD()
        if not Kernel32.VirtualProtectEx(int(self._handle), address, size, new_protection, old_protection):
            return 0

        return old_protection.value

    @staticmethod
    def get_process_list(process_name: str = "") -> list[Process]:
        """
        :param process_name: the name of the processes to filter
        :returns: a list of all processes found
        """

        process_list: list[Process] = list()

        snapshot: int = Kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not snapshot:
            return process_list

        process_buffer: PROCESSENTRY32 = PROCESSENTRY32()
        process_buffer.dwSize          = process_buffer.get_size()

        if not Kernel32.Process32First(snapshot, byref(process_buffer)):
            Kernel32.CloseHandle(snapshot)
            return process_list

        process_name: bytes = process_name.encode('ascii').lower()
        process_found: bool = True

        process: Process

        while process_found:
            if process_buffer.th32ProcessID and (process_name == b"" or process_buffer.szExeFile.lower() == process_name):
                try:
                    process = Process(process_buffer.th32ProcessID)
                except Kernel32.Win32Exception:
                    process = Process(process_buffer.th32ProcessID, 0, PROCESS_QUERY_LIMITED_INFORMATION)

                process._name = process_buffer.szExeFile.decode('ascii')
                process_list.append(process)

            process_found = Kernel32.Process32Next(snapshot, byref(process_buffer))

        Kernel32.CloseHandle(snapshot)
        return process_list

    @staticmethod
    def get_first_process(process_name: str = "") -> Process | None:
        """
        :param process_name: the name of the process
        :returns: a process by its name
        """

        snapshot: int = Kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not snapshot:
            return None

        process_buffer: PROCESSENTRY32 = PROCESSENTRY32()
        process_buffer.dwSize          = process_buffer.get_size()

        if not Kernel32.Process32First(snapshot, byref(process_buffer)):
            Kernel32.CloseHandle(snapshot)
            return None

        process_name:  bytes    = process_name.encode('ascii').lower()
        process: Process | None = None
        process_found: bool     = True

        while process_found:
            if process_buffer.th32ProcessID and (process_name == b"" or process_buffer.szExeFile.lower() == process_name):
                try:
                    process = Process(process_buffer.th32ProcessID)
                except Kernel32.Win32Exception:
                    process = Process(process_buffer.th32ProcessID, 0, PROCESS_QUERY_LIMITED_INFORMATION)

                process._name = process_buffer.szExeFile
                break

            process_found = Kernel32.Process32Next(snapshot, byref(process_buffer))

        Kernel32.CloseHandle(snapshot)
        return process

    def _register_wait(self) -> bool:
        if not self._wait:
            self._wait = Kernel32.RegisterWaitForSingleObject(
                self._handle,
                self._wait_callback,
                self._process_id,
                INFINITE,
                WT_EXECUTEONLYONCE
            )

        return self._wait != 0

    def _unregister_wait(self) -> bool:
        if self._wait:
            success: bool = Kernel32.UnregisterWait(self._wait)
            self._wait = 0
            return success

        return True

    def __on_process_terminate(self, process_id: int, timer_or_wait_fired: int) -> None:
        for callback in self._callbacks:
            callback(process_id, timer_or_wait_fired)
