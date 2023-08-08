"""
:platform: Windows

.. note:: **Learn more about** `Shared Memory <https://learn.microsoft.com/en-us/windows/win32/memory/creating-named
    -shared-memory>`_
"""

from ctypes import byref
from ctypes.wintypes import DWORD, HANDLE, LARGE_INTEGER, LPVOID, ULONG
from typing import List

from MemLib.Constants import (
    DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, FILE_MAP_EXECUTE, FILE_MAP_WRITE, PAGE_EXECUTE_READWRITE,
    SECTION_INHERIT_VIEW_UNMAP,
)
from MemLib.Kernel32 import (
    CloseHandle, CreateFileMappingW, DuplicateHandle, MapViewOfFile, NtMapViewOfSection,
    NtUnmapViewOfSection, UnmapViewOfFile, Win32Exception,
)
from MemLib.Process import Process
from MemLib.Structs import Struct



class SharedMemoryBuffer(Struct):
    """
    SharedMemoryBuffer is a structure that contains the information about the shared memory.

    +---------------+---------------------------------------------------------------+
    | **Fields**                                                                    |
    +---------------+---------------------------------------------------------------+
    | Handle        | File mapping handle of python.                                |
    +---------------+---------------------------------------------------------------+
    | HandleEx      | File mapping handle of target process.                        |
    +---------------+---------------------------------------------------------------+
    | BaseAddress   | Address of shared memory in python.                           |
    +---------------+---------------------------------------------------------------+
    | BaseAddressEx | Address of shared memory in target process.                   |
    +---------------+---------------------------------------------------------------+
    | SizeHigh      | The high-order DWORD of the maximum size of the file mapping. |
    +---------------+---------------------------------------------------------------+
    | SizeLow       | The low-order DWORD of the maximum size of the file mapping.  |
    +---------------+---------------------------------------------------------------+
    """

    _fields_ = [
        ('Handle', HANDLE),
        ('HandleEx', HANDLE),
        ('BaseAddress', LPVOID),
        ('BaseAddressEx', LPVOID),
        ('SizeHigh', DWORD),
        ('SizeLow', DWORD),
    ]

    def IsValid(self):
        """
        :returns: True if the SharedMemoryBuffer is valid, False otherwise.
        """

        if not self.HandleEx:
            return False
        if not self.BaseAddressEx:
            return False

        return True


class SharedMemory:

    def __init__(self, process: Process):
        """
        Allows to create a shared memory between two processes. The shared memory is created in the target process and
        then it is mapped in the current process. A shared memory can be stored in the target process, so another process
        can reconnect to it if it knows the address where the shared memory is stored.

        :param process: The process that will be used to create the shared memory.
        :raises ValueError: If the process is None.
        """

        if process is None:
            raise ValueError("'process' cannot be None.")

        self._process: Process                        = process
        self._memoryBuffer: SharedMemoryBuffer | None = None
        self._bufferAddress: int                      = 0

    def CanReconnect(self, address: int) -> bool:
        """
        Checks if the shared memory stored at the specified address is valid. If the shared memory is valid, it can be
        reconnected. If the shared memory is not valid, it cannot be reconnected. If the shared memory is not stored
        at the specified address, it cannot be reconnected.

        :param address: The address where the shared memory is stored.
        :returns: True if the shared memory can be reconnected, False otherwise.
        """

        mapping: SharedMemoryBuffer = self._process.ReadStruct(address, SharedMemoryBuffer)

        return mapping.IsValid()

    def Create(self, size: int) -> None:
        """
        Creates the shared memory and maps target process to the shared memory.

        :param size: The size of the shared memory. The size must be greater than 0.
        :raises ValueError: If the size is less than 0.
        :raises Win32Exception: If an error occurs while creating the shared memory.
        :returns: None
        """

        if size < 0:
            raise ValueError(f"invalid size: 0x{size:X}")

        mapping: SharedMemoryBuffer = SharedMemoryBuffer()
        mapping.SizeHigh            = size >> 32 & 0xFFFFFFFF
        mapping.SizeLow             = size & 0xFFFFFFFF

        mapping.Handle = CreateFileMappingW(-1, 0, PAGE_EXECUTE_READWRITE, mapping.SizeHigh, mapping.SizeLow, None)
        if not mapping.Handle:
            raise Win32Exception()

        mapping.BaseAddress = MapViewOfFile(mapping.Handle, FILE_MAP_EXECUTE | FILE_MAP_WRITE, 0, 0, 0)
        if not mapping.BaseAddress:
            error: Win32Exception = Win32Exception()
            CloseHandle(mapping.Handle)
            raise error

        # BaseAddressEx
        procHandle: int = self._process.GetHandle()
        void: LPVOID    = LPVOID(0)

        NtMapViewOfSection(
            mapping.Handle,
            procHandle,
            byref(void),
            0,
            0,
            byref(LARGE_INTEGER()),
            byref(ULONG()),
            SECTION_INHERIT_VIEW_UNMAP,
            0,
            PAGE_EXECUTE_READWRITE
        )
        if not void.value:
            error: Win32Exception = Win32Exception()
            UnmapViewOfFile(mapping.BaseAddress)
            CloseHandle(mapping.Handle)
            raise error
        mapping.BaseAddressEx = void.value

        handleEx: HANDLE = HANDLE()
        duplicated: bool = DuplicateHandle(-1, mapping.Handle, procHandle, handleEx, 0, False, DUPLICATE_SAME_ACCESS)
        if not handleEx or not duplicated:
            error: Win32Exception = Win32Exception()
            NtUnmapViewOfSection(procHandle, mapping.BaseAddressEx)
            UnmapViewOfFile(mapping.BaseAddress)
            CloseHandle(mapping.Handle)
            raise error

        mapping.HandleEx = handleEx

        self._memoryBuffer = mapping

    def Connect(self, address: int) -> None:
        """
        Connects to an existing shared memory stored at the address. The shared memory must be valid and stored
        at the specified address. If the shared memory is not valid or it is not stored at the specified address, an
        exception is raised.

        :param address: The address where the shared memory buffer is stored.
        :raises ValueError: If the shared memory buffer is not valid at the specified address.
        :raises Win32Exception: If an error occurs while connecting to the shared memory.
        :returns: None
        """

        # Read buffer
        mapping: SharedMemoryBuffer = self._process.ReadStruct(address, SharedMemoryBuffer)
        if not mapping.IsValid():
            raise ValueError(f"Invalid SharedMemory stored at address 0x{address:X}.")

        # Handle
        handle: HANDLE = HANDLE()
        duplicated: bool = DuplicateHandle(self._process.GetHandle(), mapping.HandleEx, -1, handle, 0, False, DUPLICATE_SAME_ACCESS)
        if not handle or not duplicated:
            raise Win32Exception()
        mapping.Handle = handle.value

        # BaseAddress
        base: int = MapViewOfFile(mapping.Handle, FILE_MAP_EXECUTE | FILE_MAP_WRITE, 0, 0, 0)
        if not base:
            error: Win32Exception = Win32Exception()
            CloseHandle(mapping.Handle)
            raise error
        mapping.BaseAddress = base

        self._memoryBuffer  = mapping
        self._bufferAddress = address

    def Destroy(self) -> None:
        """
        Disconnects from the shared memory.

        :raises Exception: If an error occurs while disconnecting from the shared memory. The exception represents the
                           list of errors that occurred. The list of errors is formatted as follows::
                               [Error 1] -> <error 1>
                               [Error 2] -> <error 2>
                               ...
                               [Error n] -> <error n>
        :returns: None
        """

        errors: List[Win32Exception] = list()
        procHandle: int              = self._process.GetHandle()
        handle: int                  = self._memoryBuffer.Handle
        handleEx: int                = self._memoryBuffer.HandleEx
        baseAddr: int                = self._memoryBuffer.BaseAddress
        baseAddrEx: int              = self._memoryBuffer.BaseAddressEx

        if baseAddr and not UnmapViewOfFile(self._memoryBuffer.BaseAddress):
            errors.append(Win32Exception())

        if handle and not CloseHandle(self._memoryBuffer.Handle):
            errors.append(Win32Exception())

        if baseAddrEx and self._memoryBuffer.BaseAddressEx and not NtUnmapViewOfSection(procHandle, baseAddrEx):
            errors.append(Win32Exception())

        closed: bool = DuplicateHandle(procHandle, handleEx, -1, None, 0, False, DUPLICATE_CLOSE_SOURCE)
        if handleEx and not closed:
            errors.append(Win32Exception())

        if len(errors):
            fmtError = [f'[Error {i + 1}] -> ' + str(error) for i, error in enumerate(errors)]
            raise Exception(f'Catched {len(errors)} Win32Exception:\n' + '\n-> '.join(fmtError))

        self._memoryBuffer.Handle        = 0
        self._memoryBuffer.HandleEx      = 0
        self._memoryBuffer.BaseAddress   = 0
        self._memoryBuffer.BaseAddressEx = 0

    def Store(self, address: int) -> bool:
        """
        Stores the shared memory at the specified address.

        :param address: The address where the shared memory will be stored.
        :returns: True if the shared memory was stored successfully, False otherwise.
        """

        if self._process.WriteStruct(address, self.GetBuffer()):
            self._bufferAddress = address
            return True

        return False

    def Free(self) -> bool:
        """
        Frees the shared memory buffer in target process.

        :returns: True if the shared memory buffer was freed successfully, False otherwise.
        """

        return self._process.ZeroMemory(self._bufferAddress, self._memoryBuffer.GetSize())

    def GetHandle(self) -> int:
        """
        :returns: The handle of the shared memory of the python process.
        """

        return self._memoryBuffer.Handle

    def GetHandleEx(self) -> int:
        """
        :returns: The handle of the shared memory of the target process.
        """

        return self._memoryBuffer.HandleEx

    def GetBaseAddress(self) -> int:
        """
        :returns: The base address of the shared memory of the python process.
        """

        return self._memoryBuffer.BaseAddress

    def GetBaseAddressEx(self) -> int:
        """
        :returns: The base address of the shared memory of the target process.
        """

        return self._memoryBuffer.BaseAddressEx

    def GetSizeHigh(self) -> int:
        """
        :returns: The high size of the shared memory.
        """

        return self._memoryBuffer.SizeHigh

    def GetSizeLow(self) -> int:
        """
        :returns: The low size of the shared memory.
        """

        return self._memoryBuffer.SizeLow

    def GetBuffer(self) -> SharedMemoryBuffer:
        """
        :returns: A reference to the shared memory buffer.
        """

        return self._memoryBuffer

    def GetProcess(self) -> Process:
        """
        :returns: A reference to the target process.
        """

        return self._process

    def __str__(self) -> str:
        return f'SharedMemory(Address=0x{self._memoryBuffer.BaseAddress:X} ' \
               f'Process={self._process.GetProcessId()} ' \
               f'at 0x{self.GetBaseAddressEx():X})'

    def __repr__(self) -> str:
        return str(self)
