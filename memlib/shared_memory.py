"""
:platform: Windows

.. note:: **Learn more about** `Shared Memory <https://learn.microsoft.com/en-us/windows/win32/memory/creating-named
    -shared-memory>`_
"""
from ctypes import byref
from ctypes.wintypes import DWORD, HANDLE, LARGE_INTEGER, LPVOID, ULONG
from typing import Union

import memlib.constants
import memlib.exceptions
import memlib.kernel32
import memlib.process
import memlib.structs


class SharedMemoryBuffer(memlib.structs.Struct):
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

        if self.Handle is None:
            return False
        if self.HandleEx is None:
            return False
        if self.BaseAddress is None:
            return False
        if self.BaseAddressEx is None:
            return False

        return True


class SharedMemory:
    """
    Allows to create a shared memory between two processes. The shared memory is created in the target process and
    then it is mapped in the current process. A shared memory can be stored in the target process, so another process
    can reconnect to it if it knows the address where the shared memory is stored.

    :param process: The process that will be used to create the shared memory.
    :raises ValueError: If the process is None.
    """

    def __init__(self, process: memlib.process.Process):
        if process is None:
            raise ValueError("'process' cannot be None.")

        self._process = process
        self._memBuffer: Union[SharedMemoryBuffer, None] = None
        self._storedAt = None

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

        mapping = SharedMemoryBuffer()
        mapping.SizeHigh = size >> 32 & 0xFFFFFFFF
        mapping.SizeLow = size & 0xFFFFFFFF

        # Handle
        handle = memlib.kernel32.CreateFileMappingW(
            -1,
            0,
            memlib.constants.PAGE_EXECUTE_READWRITE,
            mapping.SizeHigh,
            mapping.SizeLow,
            None
        )

        if not handle:
            raise memlib.exceptions.Win32Exception()
        mapping.Handle = handle

        # BaseAddress
        mapping.BaseAddress = memlib.kernel32.MapViewOfFile(
            mapping.Handle,
            memlib.constants.FILE_MAP_EXECUTE | memlib.constants.FILE_MAP_WRITE,
            0,
            0,
            0
        )

        if not mapping.BaseAddress:
            memlib.kernel32.CloseHandle(mapping.Handle)
            raise memlib.exceptions.Win32Exception()

        # BaseAddressEx
        procHandle = self._process.GetHandle()
        void = LPVOID(0)
        memlib.kernel32.NtMapViewOfSection(
            mapping.Handle,
            procHandle,
            byref(void),
            0,
            0,
            byref(LARGE_INTEGER()),
            byref(ULONG()),
            memlib.constants.SECTION_INHERIT_VIEW_UNMAP,
            0,
            memlib.constants.PAGE_EXECUTE_READWRITE
        )

        if not void.value:
            error = memlib.exceptions.Win32Exception()
            memlib.kernel32.UnmapViewOfFile(mapping.BaseAddress)
            memlib.kernel32.CloseHandle(mapping.Handle)
            raise error
        mapping.BaseAddressEx = void.value

        # HandleEx
        handleEx = HANDLE()
        memlib.kernel32.DuplicateHandle(
            -1,
            mapping.Handle,
            procHandle,
            handleEx,
            0,
            False,
            memlib.constants.DUPLICATE_SAME_ACCESS
        )

        if not handleEx:
            error = memlib.exceptions.Win32Exception()
            memlib.kernel32.NtUnmapViewOfSection(procHandle, mapping.BaseAddressEx)
            memlib.kernel32.UnmapViewOfFile(mapping.BaseAddress)
            memlib.kernel32.CloseHandle(mapping.Handle)
            raise error

        mapping.HandleEx = handleEx

        self._memBuffer = mapping

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
        handle = HANDLE()
        memlib.kernel32.DuplicateHandle(
            self._process.GetHandle(),
            mapping.HandleEx,
            -1,
            handle,
            0,
            False,
            memlib.constants.DUPLICATE_SAME_ACCESS
        )

        if not handle:
            raise memlib.exceptions.Win32Exception()
        mapping.Handle = handle.value

        # BaseAddress
        base = memlib.kernel32.MapViewOfFile(
            mapping.Handle,
            memlib.constants.FILE_MAP_EXECUTE | memlib.constants.FILE_MAP_WRITE,
            0,
            0,
            0
        )

        if not base:
            error = memlib.exceptions.Win32Exception()
            memlib.kernel32.CloseHandle(mapping.Handle)
            raise error
        mapping.BaseAddress = base

        self._memBuffer = mapping
        self._storedAt = address

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

        errors = []
        procHandle = self._process.GetHandle()
        handle = self._memBuffer.Handle
        handleEx = self._memBuffer.HandleEx
        baseAddr = self._memBuffer.BaseAddress
        baseAddrEx = self._memBuffer.BaseAddressEx

        if baseAddr and not memlib.kernel32.UnmapViewOfFile(self._memBuffer.BaseAddress):
            errors.append(memlib.exceptions.Win32Exception())
            print("err1")

        if handle and not memlib.kernel32.CloseHandle(self._memBuffer.Handle):
            errors.append(memlib.exceptions.Win32Exception())

        if baseAddrEx and self._memBuffer.BaseAddressEx and not memlib.kernel32.NtUnmapViewOfSection(procHandle, baseAddrEx):
            errors.append(memlib.exceptions.Win32Exception())

        closed = memlib.kernel32.DuplicateHandle(
            procHandle,
            handleEx,
            -1,
            None,
            0,
            False,
            memlib.constants.DUPLICATE_CLOSE_SOURCE
        )

        if handleEx and not closed:
            errors.append(memlib.exceptions.Win32Exception())

        if len(errors):
            fmtError = [f'[Error {i + 1}] -> ' + str(error) for i, error in enumerate(errors)]
            raise Exception(f'Catched {len(errors)} Win32Exception:\n' + '\n-> '.join(fmtError))

    def Store(self, address: int) -> bool:
        """
        Stores the shared memory at the specified address.

        :param address: The address where the shared memory will be stored.
        :returns: True if the shared memory was stored successfully, False otherwise.
        """

        if self._process.WriteStruct(address, self.GetBuffer()):
            self._storedAt = address
            return True

        return False

    def Free(self) -> bool:
        """
        Frees the shared memory buffer in target process.

        :returns: True if the shared memory buffer was freed successfully, False otherwise.
        """

        return self._process.ZeroMemory(self._storedAt, self._memBuffer.GetSize())

    def GetHandle(self) -> int:
        """
        :returns: The handle of the shared memory of the python process.
        """

        return self._memBuffer.Handle

    def GetHandleEx(self) -> int:
        """
        :returns: The handle of the shared memory of the target process.
        """
        return self._memBuffer.HandleEx

    def GetBaseAddress(self) -> int:
        """
        :returns: The base address of the shared memory of the python process.
        """

        return self._memBuffer.BaseAddress

    def GetBaseAddressEx(self) -> int:
        """
        :returns: The base address of the shared memory of the target process.
        """

        return self._memBuffer.BaseAddressEx

    def GetSizeHigh(self) -> int:
        """
        :returns: The high size of the shared memory.
        """

        return self._memBuffer.SizeHigh

    def GetSizeLow(self) -> int:
        """
        :returns: The low size of the shared memory.
        """

        return self._memBuffer.SizeLow

    def GetBuffer(self) -> SharedMemoryBuffer:
        """
        :returns: A reference to the shared memory buffer.
        """

        return self._memBuffer

    def GetProcess(self) -> memlib.process.Process:
        """
        :returns: A reference to the target process.
        """

        return self._process

    def __str__(self) -> str:
        return f'SharedMemory(Address=0x{self._memBuffer.BaseAddress:X} ' \
               f'Process={self._process.GetProcessId()} ' \
               f'at 0x{self.GetBaseAddressEx():X})'

    def __repr__(self) -> str:
        return str(self)
