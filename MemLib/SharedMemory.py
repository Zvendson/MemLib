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

    +-----------------+---------------------------------------------------------------+
    | **Fields**                                                                      |
    +-----------------+---------------------------------------------------------------+
    | handle          | File mapping handle of python.                                |
    +-----------------+---------------------------------------------------------------+
    | handle_ex       | File mapping handle of target process.                        |
    +-----------------+---------------------------------------------------------------+
    | base_address    | Address of shared memory in python.                           |
    +-----------------+---------------------------------------------------------------+
    | base_address_ex | Address of shared memory in target process.                   |
    +-----------------+---------------------------------------------------------------+
    | size_high        | The high-order DWORD of the maximum size of the file mapping. |
    +-----------------+---------------------------------------------------------------+
    | size_low         | The low-order DWORD of the maximum size of the file mapping.  |
    +-----------------+---------------------------------------------------------------+
    """

    _fields_ = [
        ('handle', HANDLE),
        ('handle_ex', HANDLE),
        ('base_address', LPVOID),
        ('base_address_ex', LPVOID),
        ('size_high', DWORD),
        ('size_low', DWORD),
    ]

    def is_valid(self):
        """
        :returns: True if the SharedMemoryBuffer is valid, False otherwise.
        """

        if not self.handle_ex:
            return False
        if not self.base_address_ex:
            return False

        return True


def close_shared_memory_connection(handle: int, base_addr: int) -> None:
        """
        Disconnects from the shared memory.

        :param handle: The handle
        :param base_addr: The address of the mapfile
        :raises Exception: If an error occurs while disconnecting from the shared memory. The exception represents the
                           list of errors that occurred. The list of errors is formatted as follows::
                               [Error 1] -> <error 1>
                               [Error 2] -> <error 2>
                               ...
                               [Error n] -> <error n>
        :returns: None
        """

        errors: List[Win32Exception] = list()
        if base_addr and not UnmapViewOfFile(base_addr):
            errors.append(Win32Exception())

        if handle and not CloseHandle(handle):
            errors.append(Win32Exception())

        if len(errors):
            fmt_error: list[str] = [f'[Error {i + 1}] -> ' + str(error) for i, error in enumerate(errors)]
            raise Exception(f'Caught {len(errors)} Win32Exception:\n' + '\n-> '.join(fmt_error))


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

        self._process: Process                         = process
        self._memory_buffer: SharedMemoryBuffer | None = None
        self._buffer_address: int                      = 0

    def can_reconnect(self, address: int) -> bool:
        """
        Checks if the shared memory stored at the specified address is valid. If the shared memory is valid, it can be
        reconnected. If the shared memory is not valid, it cannot be reconnected. If the shared memory is not stored
        at the specified address, it cannot be reconnected.

        :param address: The address where the shared memory is stored.
        :returns: True if the shared memory can be reconnected, False otherwise.
        """

        mapping: SharedMemoryBuffer = self._process.read_struct(address, SharedMemoryBuffer)

        return mapping.is_valid()

    def create(self, size: int) -> None:
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
        mapping.size_high           = size >> 32 & 0xFFFFFFFF
        mapping.size_low            = size & 0xFFFFFFFF

        mapping.handle = CreateFileMappingW(
            -1,
            0,
            PAGE_EXECUTE_READWRITE,
            mapping.size_high,
            mapping.size_low,
            None
        )

        if not mapping.handle:
            raise Win32Exception()

        mapping.base_address = MapViewOfFile(
            mapping.handle,
            FILE_MAP_EXECUTE | FILE_MAP_WRITE,
            0,
            0,
            0
        )

        if not mapping.base_address:
            error: Win32Exception = Win32Exception()
            CloseHandle(mapping.handle)
            raise error

        # base_address_ex
        proc_handle: int       = self._process.get_handle()
        address_buffer: LPVOID = LPVOID(0)

        NtMapViewOfSection(
            mapping.handle,
            proc_handle,
            byref(address_buffer),
            0,
            0,
            byref(LARGE_INTEGER()),
            byref(ULONG()),
            SECTION_INHERIT_VIEW_UNMAP,
            0,
            PAGE_EXECUTE_READWRITE
        )

        if not address_buffer.value:
            error: Win32Exception = Win32Exception()

            UnmapViewOfFile(mapping.base_address)
            CloseHandle(mapping.handle)

            raise error

        mapping.base_address_ex = address_buffer.value

        handle_ex: HANDLE = HANDLE()
        duplicated: bool  = DuplicateHandle(
            -1,
            mapping.handle,
            proc_handle,
            handle_ex,
            0,
            False,
            DUPLICATE_SAME_ACCESS
        )

        if not handle_ex or not duplicated:
            error: Win32Exception = Win32Exception()

            NtUnmapViewOfSection(proc_handle, mapping.base_address_ex)
            UnmapViewOfFile(mapping.base_address)
            CloseHandle(mapping.handle)

            raise error

        mapping.handle_ex   = handle_ex
        self._memory_buffer = mapping

    def destroy(self) -> None:
        """
        Disconnects from the shared memory and frees it.

        :raises Exception: If an error occurs while disconnecting from the shared memory. The exception represents the
                           list of errors that occurred. The list of errors is formatted as follows::
                               [Error 1] -> <error 1>
                               [Error 2] -> <error 2>
                               ...
                               [Error n] -> <error n>
        :returns: None
        """

        errors: List[Win32Exception] = list()
        proc_handle: int             = self._process.get_handle()
        handle: int                  = self._memory_buffer.handle
        handle_ex: int               = self._memory_buffer.handle_ex
        base_addr: int               = self._memory_buffer.base_address
        base_addr_ex: int            = self._memory_buffer.base_address_ex

        if base_addr and not UnmapViewOfFile(self._memory_buffer.base_address):
            errors.append(Win32Exception())

        if handle and not CloseHandle(self._memory_buffer.handle):
            errors.append(Win32Exception())

        if base_addr_ex and self._memory_buffer.base_address_ex and not NtUnmapViewOfSection(proc_handle, base_addr_ex):
            errors.append(Win32Exception())

        closed: bool = DuplicateHandle(proc_handle, handle_ex, -1, None, 0, False, DUPLICATE_CLOSE_SOURCE)
        if handle_ex and not closed:
            errors.append(Win32Exception())

        if len(errors):
            fmt_error: list[str] = [f'[Error {i + 1}] -> ' + str(error) for i, error in enumerate(errors)]
            raise Exception(f'Catched {len(errors)} Win32Exception:\n' + '\n-> '.join(fmt_error))

        self._memory_buffer.handle          = 0
        self._memory_buffer.handle_ex       = 0
        self._memory_buffer.base_address    = 0
        self._memory_buffer.base_address_ex = 0

    def connect(self, mem_handle: int, mem_address: int) -> None:
        """
        Connects to an existing shared memory stored at the address. The shared memory must be valid and stored
        at the specified address. If the shared memory is not valid or it is not stored at the specified address, an
        exception is raised.

        :param mem_handle: The handle of the shared memory.
        :param mem_address: The address of the shared memory.
        :raises ValueError: If the shared memory buffer is not valid at the specified address.
        :raises Win32Exception: If an error occurs while connecting to the shared memory.
        :returns: None
        """

        # Create buffer
        mapping: SharedMemoryBuffer = SharedMemoryBuffer()
        mapping.handle_ex           = mem_handle
        mapping.base_address_ex     = mem_address

        # Handle
        handle: HANDLE   = HANDLE()
        duplicated: bool = DuplicateHandle(
            self.get_process().get_handle(),
            mem_handle,
            -1,
            handle,
            0,
            False,
            DUPLICATE_SAME_ACCESS
        )

        if not duplicated or handle.value == 0:
            raise Win32Exception()

        mapping.handle = handle.value

        # base_address
        base: int = MapViewOfFile(
            mapping.handle,
            FILE_MAP_EXECUTE | FILE_MAP_WRITE,
            0,
            0,
            0
        )

        if not base:
            error: Win32Exception = Win32Exception()

            CloseHandle(mapping.handle)

            raise error

        mapping.base_address = base
        self._memory_buffer  = mapping
        self._buffer_address = 0

    def connect_from_buffer(self, buffer_address: int) -> None:
        """
        Connects to an existing shared memory stored at the address. The shared memory must be valid and stored
        at the specified address. If the shared memory is not valid or it is not stored at the specified address, an
        exception is raised.

        :param buffer_address: The address where the shared memory buffer is stored.
        :raises ValueError: If the shared memory buffer is not valid at the specified address.
        :raises Win32Exception: If an error occurs while connecting to the shared memory.
        :returns: None
        """

        # Read buffer
        mapping: SharedMemoryBuffer = self._process.read_struct(buffer_address, SharedMemoryBuffer)
        if not mapping.is_valid():
            raise ValueError(f"Invalid SharedMemory stored at address 0x{buffer_address:X}.")

        # Handle
        handle: HANDLE   = HANDLE()
        duplicated: bool = DuplicateHandle(
            self._process.get_handle(),
            mapping.handle_ex,
            -1,
            handle,
            0,
            False,
            DUPLICATE_SAME_ACCESS
        )

        if not handle or not duplicated:
            raise Win32Exception()

        mapping.handle = handle.value

        # base_address
        base: int = MapViewOfFile(
            mapping.handle,
            FILE_MAP_EXECUTE | FILE_MAP_WRITE,
            0,
            0,
            0
        )

        if not base:
            error: Win32Exception = Win32Exception()

            CloseHandle(mapping.handle)

            raise error

        mapping.base_address = base
        self._memory_buffer  = mapping
        self._buffer_address = buffer_address

    def disconnect(self) -> None:
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

        close_shared_memory_connection(self._memory_buffer.handle, self._memory_buffer.base_address)

        self._memory_buffer.handle       = 0
        self._memory_buffer.base_address = 0

    def store(self, address: int) -> bool:
        """
        Stores the shared memory at the specified address.

        :param address: The address where the shared memory will be stored.
        :returns: True if the shared memory was stored successfully, False otherwise.
        """

        if self._process.write_struct(address, self.get_buffer()):
            self._buffer_address = address
            return True

        return False

    def free(self) -> bool:
        """
        Frees the shared memory buffer in target process.

        :returns: True if the shared memory buffer was freed successfully, False otherwise.
        """

        return self._process.zero_memory(self._buffer_address, self._memory_buffer.get_size())

    def get_handle(self) -> int:
        """
        :returns: The handle of the shared memory of the python process.
        """

        return self._memory_buffer.handle

    def get_handle_ex(self) -> int:
        """
        :returns: The handle of the shared memory of the target process.
        """

        return self._memory_buffer.handle_ex

    def get_base_address(self) -> int:
        """
        :returns: The base address of the shared memory of the python process.
        """

        return self._memory_buffer.base_address

    def get_base_address_ex(self) -> int:
        """
        :returns: The base address of the shared memory of the target process.
        """

        return self._memory_buffer.base_address_ex

    def get_size_high(self) -> int:
        """
        :returns: The high size of the shared memory.
        """

        return self._memory_buffer.size_high

    def get_size_low(self) -> int:
        """
        :returns: The low size of the shared memory.
        """

        return self._memory_buffer.size_low

    def get_buffer(self) -> SharedMemoryBuffer:
        """
        :returns: A reference to the shared memory buffer.
        """

        return self._memory_buffer

    def get_process(self) -> Process:
        """
        :returns: A reference to the target process.
        """

        return self._process

    def __str__(self) -> str:
        return f'SharedMemory(Address=0x{self._memory_buffer.base_address:X} ' \
               f'Process={self._process.get_process_id()} ' \
               f'at 0x{self.get_base_address_ex():X})'

    def __repr__(self) -> str:
        return str(self)
