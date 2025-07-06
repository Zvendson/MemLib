"""
Cross-process shared memory interface for Windows.

This module provides classes and functions for creating, connecting, and cleaning up named or anonymous
shared memory mappings between Python and remote processes, using the Windows API (VirtualAlloc, MapViewOfFile,
NtMapViewOfSection, etc.).

Features:
    * SharedMemoryBuffer structure for tracking mapping state and addresses in both processes
    * SharedMemory class for allocation, connection, destruction, and storage of shared regions
    * Robust cleanup and error handling for handles and memory views

Example:
    shm = SharedMemory(target_process)
    shm.create(4096)
    print(f"Shared memory at 0x{shm.base_address:X} in Python, 0x{shm.base_address_ex:X} in target process")
    # or print(repr(shm))

References:
    https://learn.microsoft.com/en-us/windows/win32/memory/creating-named-shared-memory
"""

import os
from ctypes import byref
from ctypes.wintypes import DWORD, HANDLE, LARGE_INTEGER, LPVOID, ULONG
from typing import List

from MemLib.Constants import (
    DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, FILE_MAP_EXECUTE, FILE_MAP_WRITE, PAGE_EXECUTE_READWRITE,
    SECTION_INHERIT_VIEW_UNMAP,
)
from MemLib.windows import (
    CloseHandle, CreateFileMappingW, DuplicateHandle, MapViewOfFile, NtMapViewOfSection,
    NtUnmapViewOfSection, UnmapViewOfFile, Win32Exception,
)
from MemLib.Process import Process
from MemLib.Structs import Struct



class SharedMemoryBuffer(Struct):
    """
    Structure representing the state of a shared memory region between two processes.

    Fields:
        handle (int): File mapping handle in the current process.
        handle_ex (int): File mapping handle in the target process.
        base_address (int): Address of the mapped memory in the current process.
        base_address_ex (int): Address of the mapped memory in the target process.
        size_high (int): High-order DWORD of the mapping size.
        size_low (int): Low-order DWORD of the mapping size.
    """

    handle: int
    handle_ex: int
    base_address: int
    base_address_ex: int
    size_high: int
    size_low: int

    _fields_ = [
        ('handle', HANDLE),
        ('handle_ex', HANDLE),
        ('base_address', LPVOID),
        ('base_address_ex', LPVOID),
        ('size_high', DWORD),
        ('size_low', DWORD)
    ]

    def is_valid(self):
        """
        Checks if the shared memory buffer references are valid.

        Returns:
            bool: True if the buffer is valid, False otherwise.
        """
        if not self.handle_ex:
            return False
        if not self.base_address_ex:
            return False

        return True

def close_shared_memory_connection(handle: int, base_addr: int) -> None:
    """
    Disconnects and cleans up resources for a shared memory region.

    Args:
        handle (int): Handle to the shared memory object.
        base_addr (int): Base address of the mapped view.

    Raises:
        Exception: Aggregated Win32Exception(s) if cleanup fails.
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
    """
    Facilitates creation, connection, and cleanup of cross-process shared memory.

    This class manages mapping the same memory region into both the calling and remote process,
    and provides utility methods for storing and retrieving shared memory buffers.
    """

    def __init__(self, process: Process):
        """
        Initialize a SharedMemory object for the given process.

        Args:
            process (Process): Target process for shared memory mapping.

        Raises:
            ValueError: If process is None.
        """
        if process is None:
            raise ValueError("'process' cannot be None.")

        self._process: Process = process
        self._memory_buffer: SharedMemoryBuffer | None = None
        self._buffer_address: int = 0

    def can_reconnect(self, address: int) -> bool:
        """
        Check if a valid shared memory buffer exists at a given address in the remote process.

        Args:
            address (int): Address to check.

        Returns:
            bool: True if a valid buffer is present and reconnectable, False otherwise.
        """
        mapping: SharedMemoryBuffer = self._process.read_struct(address, SharedMemoryBuffer)

        return mapping.is_valid()

    def create(self, size: int) -> None:
        """
        Creates a new shared memory region of the given size and maps it into both processes.

        Args:
            size (int): Size in bytes. Must be positive.

        Raises:
            ValueError: If size is less than zero.
            Win32Exception: If allocation or mapping fails.
        """
        if size < 0:
            raise ValueError(f"invalid size: 0x{size:X}")

        mapping: SharedMemoryBuffer = SharedMemoryBuffer()
        mapping.size_high = DWORD(size >> 32 & 0xFFFFFFFF)
        mapping.size_low = DWORD(size & 0xFFFFFFFF)

        mapping.handle = HANDLE(
            CreateFileMappingW(
                -1,
                0,
                PAGE_EXECUTE_READWRITE,
                mapping.size_high,
                mapping.size_low,
                None
            )
        )

        if not mapping.handle:
            raise Win32Exception()

        mapping.base_address = LPVOID(
            MapViewOfFile(
                mapping.handle,
                FILE_MAP_EXECUTE | FILE_MAP_WRITE,
                0,
                0,
                0
            )
        )

        if not mapping.base_address:
            error: Win32Exception = Win32Exception()
            CloseHandle(mapping.handle)
            raise error

        # base_address_ex
        proc_handle: int = self._process.handle
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
        duplicated: bool = DuplicateHandle(
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

        mapping.handle_ex = handle_ex
        self._memory_buffer = mapping

    def destroy(self) -> None:
        """
        Disconnects and releases all resources associated with the shared memory.

        Raises:
            Exception: Aggregated Win32Exception(s) if cleanup fails.
        """
        errors: List[Win32Exception] = list()

        proc_handle: int = self._process.handle
        handle: int = self._memory_buffer.handle
        handle_ex: int = self._memory_buffer.handle_ex
        base_addr: int = self._memory_buffer.base_address
        base_addr_ex: int = self._memory_buffer.base_address_ex

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

        self._memory_buffer.handle = HANDLE(0)
        self._memory_buffer.handle_ex = HANDLE(0)
        self._memory_buffer.base_address = LPVOID(0)
        self._memory_buffer.base_address_ex = LPVOID(0)

    def connect(self, mem_handle: int, mem_address: int) -> None:
        """
        Connects to an existing shared memory region given its handle and address.

        Args:
            mem_handle (int): Handle to the memory mapping in the remote process.
            mem_address (int): Base address of the mapping.

        Raises:
            ValueError: If the buffer at the address is invalid.
            Win32Exception: On failure to duplicate or map handles.
        """
        # Create buffer
        mapping: SharedMemoryBuffer = SharedMemoryBuffer()
        mapping.handle_ex = HANDLE(mem_handle)
        mapping.base_address_ex = LPVOID(mem_address)

        # Handle
        handle: HANDLE = HANDLE()
        duplicated: bool = DuplicateHandle(
            self.process.handle,
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

        mapping.base_address = LPVOID(base)
        self._memory_buffer = mapping
        self._buffer_address = 0

    def connect_from_buffer(self, buffer_address: int) -> None:
        """
        Connects to a shared memory buffer by reading its struct from a specified address.

        Args:
            buffer_address (int): Address of the SharedMemoryBuffer struct.

        Raises:
            ValueError: If the buffer is invalid at the given address.
            Win32Exception: On failure to duplicate handle or map view.
        """
        # Read buffer
        mapping: SharedMemoryBuffer = self._process.read_struct(buffer_address, SharedMemoryBuffer)
        if not mapping.is_valid():
            raise ValueError(f"Invalid SharedMemory stored at address 0x{buffer_address:X}.")

        # Handle
        handle: HANDLE = HANDLE()
        duplicated: bool = DuplicateHandle(
            self._process.handle,
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

        mapping.base_address = LPVOID(base)
        self._memory_buffer = mapping
        self._buffer_address = buffer_address

    def disconnect(self) -> None:
        """
        Disconnects only the calling process's view from the shared memory.

        Raises:
            Exception: Aggregated Win32Exception(s) if cleanup fails.
        """
        close_shared_memory_connection(self._memory_buffer.handle, self._memory_buffer.base_address)

        self._memory_buffer.handle = HANDLE(0)
        self._memory_buffer.base_address = LPVOID(0)

    def store(self, address: int) -> bool:
        """
        Stores the shared memory buffer struct at the specified address in the target process.

        Args:
            address (int): Where to write the buffer.

        Returns:
            bool: True if the buffer was successfully written, False otherwise.
        """
        if self._process.write_struct(address, self.buffer):
            self._buffer_address = address
            return True

        return False

    def free(self) -> bool:
        """
        Zeroes out (frees) the shared memory buffer struct in the target process.

        Returns:
            bool: True if memory was zeroed successfully, False otherwise.
        """
        return self._process.zero_memory(self._buffer_address, self._memory_buffer.get_size())

    @property
    def handle(self) -> int:
        """
        Get the handle of the shared memory mapping in the current (Python) process.

        Returns:
            int: Handle to the shared memory in the Python process.
        """
        return self._memory_buffer.handle

    @property
    def handle_ex(self) -> int:
        """
        Get the handle of the shared memory in the target process.

        Returns:
            int: Handle to the shared memory as seen by the target process.
        """
        return self._memory_buffer.handle_ex

    @property
    def base_address(self) -> int:
        """
        Get the base address of the shared memory mapping in the current (Python) process.

        Returns:
            int: Base address of the shared memory in the Python process.
        """
        return self._memory_buffer.base_address

    @property
    def base_address_ex(self) -> int:
        """
        Get the base address of the shared memory mapping in the target process.

        Returns:
            int: Base address of the shared memory in the target process.
        """
        return self._memory_buffer.base_address_ex

    @property
    def size_high(self) -> int:
        """
        Get the high-order DWORD of the shared memory size.

        Returns:
            int: High 32 bits of the mapping size.
        """
        return self._memory_buffer.size_high

    @property
    def size_low(self) -> int:
        """
        Get the low-order DWORD of the shared memory size.

        Returns:
            int: Low 32 bits of the mapping size.
        """
        return self._memory_buffer.size_low

    @property
    def buffer(self) -> SharedMemoryBuffer:
        """
        Get the `SharedMemoryBuffer` structure associated with this shared memory.

        Returns:
            SharedMemoryBuffer: The buffer struct with handles and addresses.
        """
        return self._memory_buffer

    @property
    def process(self) -> Process:
        """
        Get the `Process` instance associated with this shared memory.

        Returns:
            Process: The target process object.
        """
        return self._process

    def __str__(self) -> str:
        """
        Returns a small string summary of the shared memory mapping.

        Returns:
            str: Human-readable description.
        """
        return (f'SharedMemory(Address=0x{self.base_address:X} Process={self.process.process_id} at '
                f'0x{self.base_address_ex:X})')

    def __repr__(self) -> str:
        """
        Returns a detailed string representation of the shared memory mapping, suitable for debugging.

        Returns:
            str: Full state including process IDs, addresses, and handles.
        """
        return (f'SharedMemory(PyProc={os.getpid()}, PyAddr=0x{self.base_address:X}, PyHandle=0x{self.handle}, Proc='
                f'{self.process.process_id}, ProcAddr=0x{self.base_address_ex:X}, ProcHandle=0x{self.handle_ex:X})')
