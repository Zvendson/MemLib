"""
Provides an object-oriented, high-level interface for interacting with Windows processes.

Supports querying, opening, suspending/resuming, terminating, memory reading/writing,
module/thread enumeration, and memory management in remote processes via the Win32 API.

Note:
    - The package is Windows-only.
    - Requires sufficient permissions to access the target process.

Raises:
    ValueError: If a process does not exist or parameters are invalid.
    windows.Win32Exception: If a Windows API call fails.
"""

from __future__ import annotations

from contextlib import contextmanager
from ctypes import Array, byref, create_unicode_buffer, pointer, sizeof
from ctypes.wintypes import BYTE, DWORD
from pathlib import Path
from typing import Callable, Literal, TYPE_CHECKING, Type, TypeVar

from MemLib import windows
from MemLib.Constants import (
    CREATE_SUSPENDED, ERROR_INVALID_HANDLE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM,
    IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_IA64, INFINITE, INVALID_HANDLE_VALUE, MEM_COMMIT,
    MEM_RELEASE,
    NORMAL_PRIORITY_CLASS,
    PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE, STILL_ACTIVE, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
    TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, WAIT_FAILED, WAIT_OBJECT_0, WT_EXECUTEONLYONCE,
)
from MemLib.Module import Module
from MemLib.Scanner import BinaryScanner
from MemLib.Structs import (
    IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, MODULEENTRY32, MZ_FILEHEADER, PEB, PROCESSENTRY32,
    PROCESS_BASIC_INFORMATION, Struct, THREADENTRY32,
)
from MemLib.Thread import Thread
from MemLib.windows import IsWow64Process2, Win32Exception, is_32bit


def _decode_snapshot_text(raw_value: bytes) -> str:
    """Decode ANSI snapshot text using the active Windows code page."""
    return raw_value.decode("mbcs", errors="replace")


T = TypeVar('T', bound=Struct)

if TYPE_CHECKING:
    WaitCallback = windows.WaitOrTimerCallback


class MemoryWindow:
    """
    An immutable local snapshot of a remote memory region.

    Returned by :meth:`Process.read_window`. Field accessors take an offset relative to
    the window base and read from the local copy, so a structure walk costs one remote
    read instead of one per field.

    Attributes:
        address (int): Base address the snapshot was taken from, in the target process.
        data (bytes): The snapshot bytes.
    """

    __slots__ = ("address", "data")

    def __init__(self, address: int, data: bytes) -> None:
        self.address: int = address
        self.data: bytes = data

    def __len__(self) -> int:
        return len(self.data)

    def __contains__(self, offset: int) -> bool:
        return 0 <= offset < len(self.data)

    def _slice(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0:
            raise ValueError(f"offset and size must be non-negative, got {offset}, {size}")

        end: int = offset + size
        if end > len(self.data):
            raise IndexError(
                f"offset 0x{offset:X}+0x{size:X} exceeds window size 0x{len(self.data):X} "
                f"at base 0x{self.address:X}"
            )

        return self.data[offset:end]

    def bytes(self, offset: int, size: int) -> bytes:
        """Returns `size` raw bytes at `offset` within the window."""
        return self._slice(offset, size)

    def integer(
            self,
            offset: int,
            size: int,
            endian: Literal["little", "big"] = "little",
            signed: bool = False,
    ) -> int:
        """Returns an integer of `size` bytes at `offset` within the window.

        Raises:
            ValueError: If `size` is not positive; a 0-byte integer would decode to 0 and
                hide an offset or size bug.
        """
        if size <= 0:
            raise ValueError(f"size must be positive: {size}")

        return int.from_bytes(self._slice(offset, size), endian, signed=signed)

    def byte(self, offset: int) -> int:
        """Returns the BYTE at `offset` within the window."""
        return self._slice(offset, 1)[0]

    def word(self, offset: int, endian: Literal["little", "big"] = "little") -> int:
        """Returns the WORD at `offset` within the window."""
        return self.integer(offset, 2, endian)

    def dword(self, offset: int, endian: Literal["little", "big"] = "little") -> int:
        """Returns the DWORD at `offset` within the window."""
        return self.integer(offset, 4, endian)

    def qword(self, offset: int, endian: Literal["little", "big"] = "little") -> int:
        """Returns the QWORD at `offset` within the window."""
        return self.integer(offset, 8, endian)

    def string(self, offset: int, size: int, strip: bool = True) -> bytes:
        """Returns raw bytes at `offset`, truncated at the first null when `strip`."""
        raw: bytes = self._slice(offset, size)
        if strip:
            termination: int = raw.find(b'\x00')
            if termination != -1:
                raw = raw[:termination]

        return raw

    def wide_string(self, offset: int, length: int, strip: bool = True) -> str:
        """Returns a UTF-16-LE string of `length` characters at `offset`."""
        raw: bytes = self._slice(offset, length * 2)
        if strip:
            for index in range(0, len(raw) - 1, 2):
                if raw[index:index + 2] == b'\x00\x00':
                    raw = raw[:index]
                    break

        return raw.decode(encoding="utf-16-le", errors="ignore")

    def struct(self, offset: int, struct_class: type[T]) -> T:
        """Materialises `struct_class` from the snapshot at `offset`."""
        instance: T = struct_class.from_buffer_copy(self._slice(offset, sizeof(struct_class)))
        instance.ADDRESS_EX = self.address + offset
        return instance

    def __repr__(self) -> str:
        return f"MemoryWindow(Address=0x{self.address:X}, Size=0x{len(self.data):X})"

class Process:
    """
    High-level, object-oriented wrapper for interacting with a Windows process.

    Provides process handle management, memory operations, thread and module enumeration,
    and related Windows API features via `ctypes`.

    Attributes:
        _process_id (int): Process ID.
        _handle (int): Windows handle for the opened process.
        _access (int): Access mask used for opening the process.
        _inherit (bool): Whether the handle is inheritable.
        _name (str | None): Name of the process (cached).
        _path (Path | None): Path to the executable (cached).
        ...
    """

    def __init__(self, process_id: int, process_handle: int = 0, access: int = PROCESS_ALL_ACCESS,
                 inherit: bool = False, owns_handle: bool | None = None):
        """
        Initializes the Process object and opens the process handle if not provided.

        Args:
            process_id (int): The target process ID.
            process_handle (int): An existing process handle (optional).
            access (int): Desired access mask (default: PROCESS_ALL_ACCESS).
            inherit (bool): Whether the handle is inheritable.
            owns_handle (bool | None): Whether this instance is responsible for closing
                `process_handle`. Defaults to None, meaning "own it only if we opened
                it ourselves". Pass False to borrow a handle whose lifetime is managed
                elsewhere; the handle is then never closed by this instance.

        Raises:
            ValueError: If process_id is 0 or the process does not exist.
            windows.Win32Exception: If opening the process fails.
        """
        if not process_id:
            raise ValueError("processId cannot be 0.")

        self._process_id: int = process_id
        self._handle: int = process_handle
        self._access: int = access
        self._inherit: bool = inherit
        self._name: str | None = None
        self._path: Path | None = None
        self._callbacks: list = list()
        self._wait: int = 0
        self._wait_callback: WaitCallback = windows.CreateWaitOrTimerCallback(self.__on_process_terminate)
        self._peb: PEB | None = None
        self._main_module: Module | None = None
        self._is64bit: bool | None = None
        # A handle passed in belongs to the caller unless they say otherwise; closing a
        # borrowed handle invalidates it for whoever else still holds it.
        self._owns_handle: bool = (not process_handle) if owns_handle is None else bool(owns_handle)

        if not self._handle:
            self.open(access, self._inherit, self._process_id)

        if not self.exists:
            raise ValueError(f"Process {self._process_id} does not exist.")

    @property
    def owns_handle(self) -> bool:
        """Whether this instance will close its process handle."""
        return self._owns_handle

    def __del__(self):
        """
        Destructor. Cleans up resources associated with the process.

        Clears registered callbacks, unregisters process wait callbacks,
        and closes the process handle if it is still open.
        """
        try:
            callbacks = getattr(self, "_callbacks", None)
            if callbacks is not None:
                callbacks.clear()

            self._unregister_wait()

            if getattr(self, "_handle", 0):
                self.close(raise_on_error=False)
        except Exception:
            pass

    def __str__(self) -> str:
        """
        Returns a human-readable string representation of the Process instance.

        Returns:
            str: A string summarizing the process name and PID.
        """
        return f"Process(Name={self.name}, PID={self.process_id}, 64Bit={self.is_64bit})"

    def __repr__(self) -> str:
        """
        Returns a more detailed human-readable string representation of the Process instance.

        Returns:
            str: A string summarizing the process name, PID, handle, path, and access rights.
        """
        return (f"Process(Name={self.name}, PID={self.process_id}, Handle={self.handle}, Path="
                f"{self.path}, AccessRights=0x{self.access_rights:X})")

    def __eq__(self, other: object) -> bool:
        """
        Compares this Process instance to another Process or process ID.

        Comparing equal to a bare PID is pre-existing, deliberate behaviour. It stays
        container-safe because :meth:`__hash__` hashes the same process id, so
        `hash(Process(pid)) == hash(pid)`: a set or dict sees the two as one key rather
        than storing both. Types that are neither Process nor int yield `NotImplemented`
        so Python falls back to the reflected comparison.

        Args:
            other (object): Another Process instance, a process ID, or anything else.

        Returns:
            bool: True if both refer to the same process ID, otherwise False.
        """
        if other is None:
            return False

        if isinstance(other, Process):
            return self._process_id == other.process_id

        if isinstance(other, int):
            return self._process_id == other

        return NotImplemented

    def __hash__(self) -> int:
        """
        Hashes on the process id, consistent with `__eq__`.

        Defining `__eq__` without `__hash__` sets `__hash__` to None, which makes the
        class unusable in sets and as a dict key.

        Returns:
            int: Hash of the process id.
        """
        return hash(self._process_id)

    def __enter__(self) -> Process:
        """
        Context manager entry. Opens the handle if it is not already open.

        Returns:
            Process: Self reference.
        """
        if not self._handle:
            self.open(self._access, self._inherit, self._process_id)

        return self

    def __exit__(self, exception_type, exception_value, exception_traceback) -> None:
        """Context manager exit. Closes the process handle."""
        self.close()

    @property
    def is_32bit(self) -> bool:
        return not self.is_64bit

    @property
    def is_64bit(self) -> bool:
        if self._is64bit is None:
            machine, native_machine = self.is_wow64()

            # If process is native (machine==0), use native_machine
            effective_machine = machine if machine != 0 else native_machine

            # All 64-bit architectures
            if effective_machine in (IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_IA64, IMAGE_FILE_MACHINE_ARM64):
                self._is64bit = True
            # All 32-bit architectures
            elif effective_machine in (IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_ARM):
                self._is64bit = False
            else:
                raise Win32Exception()

        return self._is64bit

    @property
    def exists(self) -> bool:
        """
        Checks whether the process is still running.

        Tests the *handle* rather than the process id: PIDs are recycled by Windows, so
        a live PID does not imply this handle still refers to the process it was opened
        for. A signalled process object means the process has exited.

        Returns:
            bool: True if the process is still running, False otherwise.
        """
        if not self._handle:
            return False

        state: int = windows.WaitForSingleObject(self._handle, 0)
        if state == WAIT_OBJECT_0:
            return False

        if state != WAIT_FAILED:
            return True

        # WAIT_FAILED covers two very different cases. An invalid or stale handle is not
        # a live process, so report it as gone rather than falling through to the exit
        # code, which cannot be read either and would look like "still alive".
        if windows.GetLastError() == ERROR_INVALID_HANDLE:
            return False

        # Otherwise the handle most likely lacks SYNCHRONIZE (e.g. opened with
        # PROCESS_QUERY_LIMITED_INFORMATION); fall back to the exit code, which only
        # needs query access. GetExitCodeProcess returns -1 when it cannot be read, so
        # only a real, non-pending exit code counts as "gone".
        exit_code: int = windows.GetExitCodeProcess(self._handle)
        if exit_code == -1:
            return True

        return exit_code == STILL_ACTIVE

    def open(self, access: int = PROCESS_ALL_ACCESS, inherit: bool = False, process_id: int = 0) -> bool:
        """
        Opens the process with the specified access rights and obtains a process handle.

        Args:
            access (int): Desired access rights for the process (see PROCESS_* constants). Defaults to PROCESS_ALL_ACCESS.
            inherit (bool): Whether child processes can inherit the handle.
            process_id (int): Process ID to open. If 0, uses self._process_id.

        Returns:
            bool: True if the process was opened successfully, False otherwise.

        Raises:
            windows.Win32Exception: If the process could not be opened with the desired access rights.
        """
        if self._handle != 0:
            self.close()

        if process_id != 0:
            self._process_id = process_id

        self._access = access
        self._inherit = inherit
        self._handle = windows.OpenProcess(self._access, self._inherit, self._process_id)

        if not self._handle:
            raise windows.Win32Exception()

        # We opened it, so we are responsible for closing it.
        self._owns_handle = True

        return self._handle != 0

    def close(self, raise_on_error: bool = True) -> bool:
        """
        Closes the process handle and unregisters any wait callbacks.

        A handle that was borrowed (passed to `__init__` with `owns_handle=False`) is
        released from this instance but not closed, since its lifetime belongs to
        whoever created it.

        Args:
            raise_on_error (bool, optional): Raise `Win32Exception` when CloseHandle
                fails. Set to False on teardown paths, where raising is unhelpful and
                may not even be possible. Defaults to True.

        Returns:
            bool: True if the process was closed successfully, False otherwise.

        Raises:
            windows.Win32Exception: If the handle could not be closed and `raise_on_error`.
        """
        self._unregister_wait()

        if not self._handle:
            return True

        if not self._owns_handle:
            self._handle = 0
            return True

        if windows.CloseHandle(self._handle):
            self._handle = 0
            return True

        # Drop the reference either way: retrying a handle that will not close just
        # repeats the failure.
        self._handle = 0

        if raise_on_error:
            raise windows.Win32Exception()

        return False

    def suspend(self) -> bool:
        """
        Suspends the process (freezes execution of all its threads).

        Returns:
            bool: True if the process was suspended successfully, False otherwise.
        """
        return windows.NtSuspendProcess(self._handle)

    def resume(self) -> bool:
        """
        Resumes the process (restores execution of all its threads).

        Returns:
            bool: True if the process was resumed successfully, False otherwise.
        """
        return windows.NtResumeProcess(self._handle)

    def register_on_exit_callback(self, callback: Callable[[int, int], None]) -> bool:
        """
        Registers a callback to be invoked when the process terminates.

        The callback must accept two arguments:
            - process_id (int): The process ID.
            - timer_or_wait_fired (int): Indicates if the wait was due to a timer or process termination.

        Args:
            callback (Callable[[int, int], None]): The function to call upon process termination.

        Returns:
            bool: True if the callback was registered successfully, False otherwise.
        """
        self._callbacks.append(callback)
        return self._register_wait()

    def unregister_on_exit_callback(self, callback: Callable[[int, int], None]) -> bool:
        """
        Unregisters a previously registered process exit callback.

        Args:
            callback (Callable[[int, int], None]): The callback to unregister.

        Returns:
            bool: True if unregistered successfully, False otherwise.
        """
        self._callbacks.remove(callback)

        if self._wait and len(self._callbacks) == 0:
            success = windows.UnregisterWait(self._wait)
            self._wait = 0
            return success

        return True

    def create_thread(self, start_address: int, parameter: int = 0, creation_flags: int = CREATE_SUSPENDED,
                      thread_attributes: int = 0, stack_size: int = 0) -> Thread:
        """
        Creates a new thread in the remote process.

        Args:
            start_address (int): Address of the function to execute in the remote process.
            parameter (int, optional): Value to pass to the thread function.
            creation_flags (int, optional): Creation flags, e.g. CREATE_SUSPENDED.
            thread_attributes (int, optional): Security attributes or 0.
            stack_size (int, optional): Initial stack size in bytes. 0 means default.

        Returns:
            Thread: The created Thread object.

        Raises:
            windows.Win32Exception: If thread creation fails.
        """
        thread_id: DWORD = DWORD()
        thread_handle: int = windows.CreateRemoteThread(
            self._handle,
            thread_attributes,
            stack_size,
            start_address,
            parameter,
            creation_flags,
            byref(thread_id)
        )

        return Thread(thread_id.value, self, thread_handle)

    @property
    def process_id(self) -> int:
        """
        Gets the process ID of the target process.

        Returns:
            int: The process ID.
        """
        return self._process_id

    @property
    def handle(self) -> int:
        """
        Gets the handle to the opened process.

        Returns:
            int: The process handle, or 0 if not opened.
        """
        return self._handle

    @property
    def access_rights(self) -> int:
        """
        Gets the access rights used to open the process.

        Returns:
            int: The access mask.
        """
        return self._access

    @property
    def name(self) -> str:
        """
        Gets the name of the process executable.

        Returns:
            str: The process name, or an empty string if not available.
        """
        if self._name is not None:
            return self._name

        try:
            module: Module = self.get_main_module()
        except windows.Win32Exception:
            # Not cached: the module list may become readable later (for example once
            # the target finishes initialising), and the declared return type is str.
            return ""

        self._name = module.name
        return self._name

    @property
    def path(self) -> Path | None:
        """
        Gets the file system path of the process executable.

        Returns:
            Path | None: The path to the executable, or None if unavailable.
        """
        if self._path is not None:
            return self._path

        name_buffer: Array = create_unicode_buffer(4096)
        size_buffer: DWORD = DWORD(4096)
        path: str | None = None

        if windows.QueryFullProcessImageNameW(self._handle, 0, name_buffer, pointer(size_buffer)):
            path = name_buffer.value

        if isinstance(path, str):
            self._path = Path(path)

        return self._path

    def get_priority_class(self) -> int:
        """
        Gets the process priority class.

        Returns:
            int: The current priority class of the process (see Windows API priority class constants).
        """
        return windows.GetPriorityClass(self._handle)

    def set_priority_class(self, priority: int = NORMAL_PRIORITY_CLASS) -> bool:
        """
        Sets the process priority class.

        Args:
            priority (int): The desired priority class (see Windows API priority class constants).

        Returns:
            bool: True if the priority class was set successfully, False otherwise.
        """
        return windows.SetPriorityClass(self._handle, priority)

    def get_modules(self) -> list[Module]:
        """
        Enumerates all modules loaded in the process.

        Returns:
            list[Module]: List of Module objects. Empty if process is not opened.

        Raises:
            windows.Win32Exception: If the process is not opened or if the snapshot could not be created.
        """
        snapshot: int = windows.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self._process_id)

        if snapshot in (0, INVALID_HANDLE_VALUE):
            raise windows.Win32Exception()

        module_buffer: MODULEENTRY32 = MODULEENTRY32()
        module_buffer.dwSize = module_buffer.get_size()

        if not windows.Module32First(snapshot, byref(module_buffer)):
            windows.CloseHandle(snapshot)
            raise windows.Win32Exception()

        module_list: list[Module] = [Module(module_buffer, self)]

        while windows.Module32Next(snapshot, byref(module_buffer)):
            module: Module = Module(module_buffer, self)

            module_list.append(module)

        windows.CloseHandle(snapshot)
        return module_list

    def get_main_module(self) -> Module:
        """
        Gets the main module of the process (the executable itself).

        Returns:
            Module: The main module object.

        Raises:
            windows.Win32Exception: If the process is not opened, if the snapshot could not be created,
                or if the main module could not be found.
        """
        if self._main_module is None:
            self._main_module = self.get_module(None)
        return self._main_module


    def get_module(self, name: str | None) -> Module | None:
        """
        Gets a module by name, or the main module when `name` is `None`.

        Returns:
            Module | None: The matching module, or `None` if it is not loaded.

        Raises:
            windows.Win32Exception: If the process is not opened, if the snapshot could not be created,
                or if the main module could not be found.
        """
        module_buffer: MODULEENTRY32 = MODULEENTRY32()
        module_buffer.dwSize = module_buffer.get_size()

        snapshot: int = windows.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self._process_id)

        if snapshot in (0, INVALID_HANDLE_VALUE):
            raise windows.Win32Exception()

        if not windows.Module32First(snapshot, byref(module_buffer)):
            err: windows.Win32Exception = windows.Win32Exception()
            windows.CloseHandle(snapshot)
            raise err

        if name is None:
            module: Module = Module(module_buffer, self)

            windows.CloseHandle(snapshot)
            return module

        name: bytes = name.encode('ascii').lower()
        module_found: bool = True

        while module_found:
            if module_buffer.szModule.lower() == name:
                module: Module = Module(module_buffer, self)

                windows.CloseHandle(snapshot)
                return module
            module_found = windows.Module32Next(snapshot, byref(module_buffer))

        windows.CloseHandle(snapshot)
        return None

    def get_threads(self) -> list[Thread]:
        """
        Enumerates all threads belonging to this process.

        Returns:
            list[Thread]: List of Thread objects. Empty if process is not opened.

        Raises:
            windows.Win32Exception: If the process is not opened or if the snapshot could not be created.
        """
        snapshot: int = windows.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self._process_id)
        if snapshot in (0, INVALID_HANDLE_VALUE):
            raise windows.Win32Exception()

        thread_buffer: THREADENTRY32 = THREADENTRY32()
        thread_buffer.dwSize = thread_buffer.get_size()

        if not windows.Thread32First(snapshot, byref(thread_buffer)):
            err = windows.Win32Exception()
            windows.CloseHandle(snapshot)
            raise err

        thread_list: list[Thread] = list()
        thread_found: bool = True

        while thread_found:
            if thread_buffer.th32OwnerProcessID == self._process_id:
                thread: Thread = Thread(thread_buffer.th32ThreadID, self)
                thread_list.append(thread)

            thread_found = windows.Thread32Next(snapshot, byref(thread_buffer))

        windows.CloseHandle(snapshot)
        return thread_list

    def get_main_thread(self) -> Thread | None:
        """
        Gets the first (main) thread belonging to this process.

        Returns:
            Thread | None: The main Thread object, or None if not found.

        Raises:
            windows.Win32Exception: If the process is not opened, if the snapshot could not be created,
                or if the main thread could not be found.
        """
        snapshot: int = windows.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self._process_id)
        if snapshot in (0, INVALID_HANDLE_VALUE):
            raise windows.Win32Exception()

        thread_buffer: THREADENTRY32 = THREADENTRY32()
        thread_buffer.dwSize = thread_buffer.get_size()
        thread: Thread | None = None

        if not windows.Thread32First(snapshot, byref(thread_buffer)):
            err = windows.Win32Exception()
            windows.CloseHandle(snapshot)
            raise err

        thread_found: bool = True

        while thread_found:
            if thread_buffer.th32OwnerProcessID == self._process_id:
                thread = Thread(thread_buffer.th32ThreadID, self)
                break

            thread_found = windows.Thread32Next(snapshot, byref(thread_buffer))

        windows.CloseHandle(snapshot)
        return thread

    @property
    def peb(self) -> PEB | None:
        """
        Retrieves the Process Environment Block (PEB) structure of the process.

        Returns:
            PEB | None: The PEB structure, or None if not available.
        """
        if self._peb is not None:
            return self._peb

        process_info: PROCESS_BASIC_INFORMATION = PROCESS_BASIC_INFORMATION()
        if not windows.NtQueryInformationProcess(self._handle, 0, byref(process_info), process_info.get_size()):
            return None

        self._peb = self.read_struct(process_info.PebBaseAddress, PEB)
        return self._peb

    @property
    def base(self) -> int:
        """
        Gets the base address of the process core module.

        Returns:
            int: The base address, or 0 if not available.
        """

        peb = self.peb
        if peb is None:
            return 0

        return peb.ImageBaseAddress

    @property
    def size(self) -> int:
        """
        Gets the size of the process core module.

        Returns:
            int: The module size in bytes, or 0 if not available.
        """
        img: IMAGE_NT_HEADERS32 | IMAGE_NT_HEADERS64 = self.get_main_module().nt_headers
        if img is None:
            return 0

        return img.SizeOfImage

    def is_wow64(self) -> tuple[int, int]:
        """
        Determines the architecture of the process using IsWow64Process2.

        Returns:
            tuple[int, int]: A tuple containing (process_machine, native_machine) values.
                - process_machine: The architecture the process is running under (IMAGE_FILE_MACHINE_*).
                - native_machine: The native architecture of the host system (IMAGE_FILE_MACHINE_*).

        Note:
            - If process_machine is 0, the process is running natively (not under WOW64).
            - Use the returned codes to distinguish between 32-bit (WOW64) and 64-bit (native) processes.
            - Requires Windows 10 or later.
        """
        return IsWow64Process2(self._handle)

    def get_scanner(self, section_name: str = None) -> BinaryScanner | None:
        """
        Returns a BinaryScanner for a section of the process core module.

        Args:
            section_name (str, optional): Name of the section. If None, uses the first section.

        Returns:
            BinaryScanner | None: A scanner for the section, or None if unavailable.

        Raises:
            RuntimeError: If the process lacks PROCESS_VM_READ access rights.
        """
        if not self.can_read_memory():
            raise RuntimeError(f"Invalid access rights. PROCESS_VM_READ required, got: 0x{self._access:X}")

        if section_name is None:
            base: int = self.base
            size: int = self.size
        else:
            wanted_section: IMAGE_SECTION_HEADER = self.get_main_module().get_section(section_name)

            base: int = self.base + wanted_section.VirtualAddress
            size: int = wanted_section.VirtualSize

        buffer: bytes = self.read(base, size)
        if len(buffer):
            return BinaryScanner(buffer, base)

        return None

    def can_read_memory(self) -> bool:
        """
        Checks if the current access rights allow reading process memory.

        Returns:
            bool: True if reading memory is permitted, False otherwise.
        """
        return self._access & PROCESS_VM_READ == PROCESS_VM_READ

    def can_write_memory(self) -> bool:
        """
        Checks if the current access rights allow writing to process memory.

        Returns:
            bool: True if writing memory is permitted, False otherwise.
        """
        return self._access & PROCESS_VM_WRITE == PROCESS_VM_WRITE

    def terminate(self, exit_code: int = 0) -> bool:
        """
        Terminates (kills) the process.

        Args:
            exit_code (int, optional): Exit code to use when terminating.

        Returns:
            bool: True if the process was terminated successfully, False otherwise.
        """
        return windows.TerminateProcess(self._handle, exit_code)

    def read(self, address: int, length: int) -> bytes:
        """
        Reads raw bytes from the process memory at the specified address.

        Args:
            address (int): Address to read from.
            length (int): Number of bytes to read.

        Returns:
            bytes: The data read, or an empty byte string on failure.

        Note:
            An empty result is ambiguous: it means either "the read failed" or
            "zero bytes requested". Use :meth:`try_read` when the caller needs to
            tell a failed read from valid data.
        """
        if length <= 0:
            return b''

        data: bytes | None = self.try_read(address, length)
        if data is None:
            return b''

        return data

    def try_read(self, address: int, length: int) -> bytes | None:
        """
        Reads raw bytes, returning None when the read fails.

        The `read*` methods report failure with a value that is also a legitimate
        result (`b''`, `0`, `""`), which makes a failed read indistinguishable from
        real data. That matters when walking pointer chains, where 0 is a meaningful
        value: "this pointer is NULL" and "the read failed" demand different handling.

        Args:
            address (int): Address to read from.
            length (int): Number of bytes to read.

        Returns:
            bytes | None: The bytes read, or None if the read failed.

        Raises:
            ValueError: If `length` is negative.
        """
        if length < 0:
            raise ValueError(f"length cannot be negative: {length}")

        if length == 0:
            return b''

        # No liveness pre-check: ReadProcessMemory fails on a dead process anyway, and
        # probing first would double the cost of every read.
        # noinspection PyCallingNonCallable
        buffer: Array = (BYTE * length)()  # type: ignore
        if windows.ReadProcessMemory(self._handle, address, byref(buffer), length, None):
            return bytes(buffer)

        return None

    def try_read_integer(
            self,
            address: int,
            size: int,
            endian: Literal["little", "big"] = "little",
            signed: bool = False,
    ) -> int | None:
        """
        Reads an integer of `size` bytes, returning None when the read fails.

        Args:
            address (int): Address to read from.
            size (int): Width of the integer in bytes.
            endian (Literal["little", "big"], optional): Byte order. Defaults to "little".
            signed (bool, optional): Interpret the value as two's-complement. Defaults to False.

        Returns:
            int | None: The value, or None if the read failed.

        Raises:
            ValueError: If `size` is not positive. A 0-byte integer is not meaningful and
                would otherwise decode to 0, hiding an offset or size bug.
        """
        if size <= 0:
            raise ValueError(f"size must be positive: {size}")

        data: bytes | None = self.try_read(address, size)
        if data is None:
            return None

        return int.from_bytes(data, endian, signed=signed)

    def try_read_dword(self, address: int, endian: Literal["little", "big"] = "little") -> int | None:
        """Reads a DWORD, returning None when the read fails (0 is then a real value)."""
        return self.try_read_integer(address, 4, endian)

    def try_read_word(self, address: int, endian: Literal["little", "big"] = "little") -> int | None:
        """Reads a WORD, returning None when the read fails (0 is then a real value)."""
        return self.try_read_integer(address, 2, endian)

    def try_read_byte(self, address: int, endian: Literal["little", "big"] = "little") -> int | None:
        """Reads a BYTE, returning None when the read fails (0 is then a real value)."""
        return self.try_read_integer(address, 1, endian)

    def is_readable(self, address: int, length: int = 1) -> bool:
        """
        Checks whether a region can currently be read from the target process.

        Useful for validating a pointer before dereferencing it, without having to
        interpret an ambiguous zero result.

        Args:
            address (int): Address to probe.
            length (int, optional): Number of bytes that must be readable. Defaults to 1.

        Returns:
            bool: True if the whole region could be read, False otherwise.
        """
        if not address or length <= 0:
            return False

        return self.try_read(address, length) is not None

    def read_into(self, address: int, buffer, size: int = 0) -> int:
        """
        Reads memory directly into a caller-owned ctypes buffer.

        Avoids the per-call buffer allocation and the `bytes()` copy that :meth:`read`
        performs, so a buffer can be reused across a polling loop. Combined with one
        wide read instead of many narrow ones, this is the cheapest way to snapshot a
        remote structure: reading 64 DWORD fields individually costs ~84x more than a
        single 256-byte read.

        Args:
            address (int): Address to read from.
            buffer: A ctypes instance, array or buffer to fill (anything `byref`
                accepts, e.g. `create_string_buffer(...)` or a `Struct`).
            size (int, optional): Bytes to read. Defaults to `sizeof(buffer)`.

        Returns:
            int: Number of bytes read; 0 if the read failed.

        Raises:
            ValueError: If `size` is negative or larger than the buffer.
        """
        capacity: int = sizeof(buffer)
        if size == 0:
            size = capacity

        if size < 0:
            raise ValueError(f"size cannot be negative: {size}")

        if size > capacity:
            raise ValueError(f"size 0x{size:X} exceeds buffer capacity 0x{capacity:X}")

        if size == 0:
            return 0

        bytes_read: DWORD = DWORD(0)
        if windows.ReadProcessMemory(self._handle, address, byref(buffer), size, byref(bytes_read)):
            # Report what Windows actually wrote. Substituting `size` here would claim a
            # full read from a call that reported none.
            return bytes_read.value

        return 0

    def read_struct_into(self, address: int, struct_instance: T) -> T | None:
        """
        Refills an existing Struct instance from remote memory.

        Like :meth:`read_struct` but reuses the caller's instance instead of allocating
        a new one, which matters when re-reading the same structure every frame.

        Args:
            address (int): Address to read from.
            struct_instance (T): The Struct instance to fill in place.

        Returns:
            T | None: The same instance on success, or None if the read failed.
        """
        if not self.read_into(address, struct_instance):
            return None

        struct_instance.ADDRESS_EX = address
        return struct_instance

    def read_window(self, address: int, size: int) -> MemoryWindow | None:
        """
        Reads a block of memory once and serves field access from the local copy.

        Walking a remote structure field by field costs one `ReadProcessMemory` per
        field. Reading the whole span once and slicing locally is dramatically cheaper:
        64 DWORD fields measured ~84x slower read individually than as a single
        256-byte block.

            window = process.read_window(unit_address, 0x100)
            if window is not None:
                unit_type = window.dword(0x00)
                unit_id   = window.dword(0x0C)

        Args:
            address (int): Base address of the region.
            size (int): Number of bytes to snapshot.

        Returns:
            MemoryWindow | None: The snapshot, or None if the read failed.
        """
        data: bytes | None = self.try_read(address, size)
        if data is None:
            return None

        return MemoryWindow(address, data)

    def read_struct(self, address: int, struct_class: type[T]) -> T | None:
        """
        Reads a structure from the process memory.

        Args:
            address (int): Address to read from.
            struct_class (type[T]): The struct type (must inherit from Struct).

        Returns:
            T | None: An instance of struct_class filled with data, or None on failure.
        """
        buffer: T = struct_class()

        if windows.ReadProcessMemory(self._handle, address, byref(buffer), buffer.get_size(), None):
            buffer.ADDRESS_EX = address
            return buffer

        return None

    def read_dword(self, address: int, endian: Literal["little", "big"] = "little") -> int:
        """
        Reads a DWORD (4 bytes) from the process memory.

        Args:
            address (int): Address to read from.
            endian (Literal["little", "big"], optional): Byte order. Defaults to "little".

        Returns:
            int: The value as an int, or 0 on failure.

        Note:
            0 is indistinguishable from a successful read of a zero DWORD. When walking
            pointer chains, prefer :meth:`try_read_dword`, which returns None on failure.
        """
        value: int | None = self.try_read_integer(address, 4, endian)
        return 0 if value is None else value

    def read_word(self, address: int, endian: Literal["little", "big"] = "little") -> int:
        """
        Reads a WORD (2 bytes) from the process memory.

        Args:
            address (int): Address to read from.
            endian (Literal["little", "big"], optional): Byte order. Defaults to "little".

        Returns:
            int: The value as an int, or 0 on failure.

        Note:
            0 is indistinguishable from a successful read of a zero WORD. See
            :meth:`try_read_word`.
        """
        value: int | None = self.try_read_integer(address, 2, endian)
        return 0 if value is None else value

    def read_byte(self, address: int, endian: Literal["little", "big"] = "little") -> int:
        """
        Reads a BYTE (1 byte) from the process memory.

        Args:
            address (int): Address to read from.
            endian (Literal["little", "big"], optional): Byte order. Defaults to "little".

        Returns:
            int: The value as an int, or 0 on failure.

        Note:
            0 is indistinguishable from a successful read of a zero byte. See
            :meth:`try_read_byte`.
        """
        value: int | None = self.try_read_integer(address, 1, endian)
        return 0 if value is None else value

    def read_string(self, address: int, length: int, strip: bool = True) -> bytes:
        """
        Reads raw bytes from process memory and optionally strips the first null terminator.

        Args:
            address (int): Address to read from.
            length (int): Number of bytes to read.
            strip (bool, optional): If True, strip at first null byte.

        Returns:
            bytes: The bytes read, or an empty byte string on failure.

        Note:
            `b''` is also what a legitimately empty string reads as. Use
            :meth:`try_read_string` to tell the two apart.
        """
        # Stay tolerant of non-positive lengths like :meth:`read` does; try_read_string
        # raises for those, and this lossy API is documented to return b'' on failure.
        if length <= 0:
            return b''

        result: bytes | None = self.try_read_string(address, length, strip)
        if result is None:
            return b''

        return result

    def try_read_string(self, address: int, length: int, strip: bool = True) -> bytes | None:
        """
        Reads raw bytes, returning None when the read fails rather than `b''`.

        Args:
            address (int): Address to read from.
            length (int): Number of bytes to read.
            strip (bool, optional): If True, strip at first null byte.

        Returns:
            bytes | None: The bytes read, or None if the read failed.
        """
        result: bytes | None = self.try_read(address, length)
        if result is None:
            return None

        if strip:
            termination = result.find(b'\x00')
            if termination != -1:
                result = result[:termination]

        return result

    def read_wide_string(self, address: int, length: int, strip: bool = True) -> str:
        """
        Reads a UTF-16-LE string from process memory.

        Args:
            address (int): Address to read from.
            length (int): Number of characters to read.
            strip (bool, optional): If True, strip at first null wide character.

        Returns:
            str: The decoded string, or an empty string on failure.

        Note:
            `""` is also what a legitimately empty string reads as. Use
            :meth:`try_read_wide_string` to tell the two apart.
        """
        # Stay tolerant of non-positive lengths like :meth:`read` does; the try_* variant
        # raises for those, and this lossy API is documented to return "" on failure.
        if length <= 0:
            return ""

        result: str | None = self.try_read_wide_string(address, length, strip)
        if result is None:
            return ""

        return result

    def try_read_wide_string(self, address: int, length: int, strip: bool = True) -> str | None:
        """
        Reads a UTF-16-LE string, returning None when the read fails rather than `""`.

        Args:
            address (int): Address to read from.
            length (int): Number of characters to read.
            strip (bool, optional): If True, strip at first null wide character.

        Returns:
            str | None: The decoded string, or None if the read failed.
        """
        result: bytes | None = self.try_read(address, length * 2)
        if result is None:
            return None

        if strip:
            for i in range(0, len(result) - 1, 2):
                if result[i:i + 2] == b'\x00\x00':
                    result = result[:i]
                    break

        return result.decode(encoding="utf-16-le", errors="ignore")

    def write(self, address: int, binary_data: bytes) -> bool:
        """
        Writes raw bytes to the process at the specified address.

        Temporarily grants write access if the target pages are not already writable,
        and restores the previous protection afterwards.

        Args:
            address (int): The address to write to.
            binary_data (bytes): The data to write.

        Returns:
            bool: True if successful, False otherwise.
        """
        if not self.exists:
            return False

        size: int = len(binary_data)
        with self._writable(address, size):
            return windows.WriteProcessMemory(self._handle, address, binary_data, size, None)

    def write_raw(self, address: int, binary_data: bytes) -> bool:
        """
        Writes raw bytes without touching page protection.

        Use this when the target pages are known to be writable already (for example a
        shared-memory region or a previously allocated RW buffer). Avoids two
        `VirtualProtectEx` round trips per write.

        Args:
            address (int): The address to write to.
            binary_data (bytes): The data to write.

        Returns:
            bool: True if successful, False otherwise.
        """
        if not self.exists:
            return False

        return windows.WriteProcessMemory(self._handle, address, binary_data, len(binary_data), None)

    def write_struct(self, address: int, data: Struct) -> bool:
        """
        Writes a structure to the process at the specified address.

        Args:
            address (int): The address to write to.
            data (Struct): The structure instance to write.

        Returns:
            bool: True if successful, False otherwise.
        """
        if not self.exists:
            return False

        size: int = data.get_size()
        with self._writable(address, size):
            return windows.WriteProcessMemory(self._handle, address, byref(data), size, None)

    def zero_memory(self, address: int, size: int) -> bool:
        """
        Sets a memory region in the process to zero.

        Args:
            address (int): The address to zero.
            size (int): Number of bytes to zero.

        Returns:
            bool: True if successful, False otherwise.
        """
        if not self.exists:
            return False

        # One protection window for the whole operation: write_raw does not add its own.
        with self._writable(address, size):
            return self.write_raw(address, b'\x00' * size)

    @contextmanager
    def _writable(self, address: int, size: int):
        """
        Temporarily makes a region writable, restoring the original protection on exit.

        Always requests write access rather than probing first: the query would cost an
        extra syscall per write, and `VirtualProtectEx` is cheap when the protection is
        already what we ask for. Only a protection value that was actually captured gets
        restored — passing the `0` that :meth:`protect` returns on failure back to
        `VirtualProtectEx` would fail and silently leave the pages
        readable/writable/executable.

        Args:
            address (int): Start of the region.
            size (int): Size of the region in bytes.

        Raises:
            Win32Exception: If the original protection could not be restored. When the
                wrapped operation also failed, that error is chained as the cause so
                neither failure is lost.
        """
        if size <= 0:
            yield
            return

        old_protection: int = self.protect(address, size, PAGE_EXECUTE_READWRITE)
        body_error: BaseException | None = None
        try:
            yield
        except BaseException as error:
            body_error = error
            raise
        finally:
            # 0 means VirtualProtectEx failed; there is no previous value to restore
            # and re-applying 0 is an invalid protection constant.
            if old_protection:
                restored: int = self.protect(address, size, old_protection)
                if not restored:
                    # Chain rather than replace: raising bare here would swallow an
                    # exception from the write itself.
                    raise Win32Exception(
                        custom_message=(
                            f"Failed to restore page protection 0x{old_protection:X} at "
                            f"0x{address:X} (size 0x{size:X}); the region may still be writable."
                        )
                    ) from body_error

    def allocate(self, size: int, address: int = 0, allocation_type: int = MEM_COMMIT,
                 protect: int = PAGE_EXECUTE_READWRITE) -> int:
        """
        Allocates memory in the target process.

        Args:
            size (int): The size of memory to allocate.
            address (int, optional): The address to allocate at, or 0 for automatic.
            allocation_type (int, optional): Allocation type flags.
            protect (int, optional): Protection flags.

        Returns:
            int: The address of the allocated memory on success, 0 on failure.
        """
        if not self.exists:
            return 0

        return windows.VirtualAllocEx(self._handle, address, size, allocation_type, protect)

    def free(self, address: int, size: int = 0, free_type: int = MEM_RELEASE) -> bool:
        """
        Frees memory previously allocated in the process.

        Args:
            address (int): The address of the memory to free.
            size (int, optional): The size to free (often 0).
            free_type (int, optional): The free type (e.g., MEM_RELEASE).

        Returns:
            bool: True if successful, False otherwise.
        """
        return windows.VirtualFreeEx(self._handle, address, size, free_type)

    def load_library(self, lib_path: Path, timeout: int = INFINITE) -> Module | None:
        """
        Loads a DLL into the remote process using LoadLibraryW.

        This method allocates memory in the remote process, writes the full
        DLL path (as a UTF-16LE encoded string), and creates a remote thread
        that calls LoadLibraryW to load the specified library.

        Args:
            lib_path (Path): Path to the DLL to be injected into the target process.
            timeout (int, optional): Maximum time in milliseconds to wait for the remote thread to finish.
                                     Defaults to INFINITE.

        Returns:
            Module | None: A Module object representing the loaded DLL if successful, or None otherwise.

        Raises:
            ValueError: If the specified DLL path does not exist.
            RuntimeError: If memory allocation or writing fails.
        """
        if not lib_path.exists() or not lib_path.is_file():
            raise ValueError("Lib does not exist.")

        full_path: str = str(lib_path.resolve())

        kernel32: int = windows.GetModuleHandle("kernel32.dll")
        load_library: int = windows.GetProcAddress(kernel32, "LoadLibraryW")
        mem_lib_path: int = self.allocate(4096)
        if mem_lib_path == 0:
            raise RuntimeError("Could not allocate memory in process.")

        if not self.write(mem_lib_path, full_path.encode("utf-16-le")):
            self.free(mem_lib_path)
            raise RuntimeError("Could not write path to process.")

        thread: Thread = self.create_thread(load_library, mem_lib_path, 0)
        thread.join(timeout)
        thread.close()
        self.free(mem_lib_path)

        return self.get_module(lib_path.name)

    def free_library(self, lib: str | Module, timeout: int = INFINITE) -> bool:
        """
        Unloads a DLL from the remote process using FreeLibrary.

        This method creates a remote thread in the target process that calls
        FreeLibrary on the specified module handle. The module can be provided
        as either a string (DLL name) or a Module object.

        Args:
            lib (str | Module): The name of the DLL to unload, or a Module instance returned by `get_module()`.
            timeout (int, optional): Maximum time in milliseconds to wait for the remote thread to finish.
                                     Defaults to INFINITE.

        Returns:
            bool: True if the library was successfully unloaded or handle changed; False otherwise.

        Raises:
            ValueError: If the module cannot be found or is None.
        """
        if isinstance(lib, str):
            name: str = lib
            lib: Module = self.get_module(lib)
        else:
            name: str = lib.name

        if lib is None:
            raise ValueError("module cannot be None.")

        kernel32: int = windows.GetModuleHandle("kernel32.dll")
        free_library: int = windows.GetProcAddress(kernel32, "FreeLibrary")
        handle: int = lib.handle
        thread: Thread = self.create_thread(free_library, handle, 0)
        thread.join(timeout)
        thread.close()

        found: Module = self.get_module(name)
        if found is None:
            return True

        return found.handle != handle

    def protect(self, address, size, new_protection: int) -> int:
        """
        Changes memory protection on a region of the process.

        Args:
            address (int): Address of the memory region.
            size (int): Size of the region.
            new_protection (int): The new protection flags.

        Returns:
            int: The old protection type on success, 0 on failure.
        """
        old_protection: DWORD = DWORD()
        if not windows.VirtualProtectEx(int(self._handle), address, size, new_protection, byref(old_protection)):
            return 0

        return old_protection.value

    @staticmethod
    def get_process_list(process_name: str = "", exclude_32bit: bool = False) -> list[Process]:
        """
        Gets a list of all running processes (optionally filtered by name).

        Args:
            process_name (str, optional): Filter for process executable name (ASCII, case-insensitive).
            exclude_32bit (bool, optional): If `True`, excludes 32-bit processes from the output.

        Returns:
            list[Process]: List of Process objects matching the filter.
        """
        process_list: list[Process] = list()

        snapshot: int = windows.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot in (0, INVALID_HANDLE_VALUE):
            raise Win32Exception()

        process_buffer: PROCESSENTRY32 = PROCESSENTRY32()
        assert process_buffer.dwSize > 0

        if not windows.Process32First(snapshot, byref(process_buffer)):
            windows.CloseHandle(snapshot)
            return process_list

        process_name: bytes = process_name.encode('ascii').lower()
        process_found: bool = True

        process: Process

        while process_found:
            if process_buffer.th32ProcessID and (
                    process_name == b"" or process_buffer.szExeFile.lower() == process_name):
                process = Process._open_discovered_process(process_buffer.th32ProcessID)
                if process is None:
                    process_found = windows.Process32Next(snapshot, byref(process_buffer))
                    continue

                process._name = _decode_snapshot_text(process_buffer.szExeFile)

                if process.is_64bit:
                    process_list.append(process)
                elif not exclude_32bit:
                    process_list.append(process)

            process_found = windows.Process32Next(snapshot, byref(process_buffer))

        windows.CloseHandle(snapshot)
        return process_list

    @staticmethod
    def get_first_process(process_name: str = "") -> Process | None:
        """
        Gets the first process matching the given name.

        Args:
            process_name (str, optional): Process executable name (ASCII, case-insensitive).

        Returns:
            Process | None: The matching process, or None if not found.
        """
        snapshot: int = windows.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot in (0, INVALID_HANDLE_VALUE):
            return None

        process_buffer: PROCESSENTRY32 = PROCESSENTRY32()
        process_buffer.dwSize = process_buffer.get_size()

        if not windows.Process32First(snapshot, byref(process_buffer)):
            windows.CloseHandle(snapshot)
            return None

        process_name: bytes = process_name.encode('ascii').lower()
        process: Process | None = None
        process_found: bool = True

        while process_found:
            if process_buffer.th32ProcessID and (
                    process_name == b"" or process_buffer.szExeFile.lower() == process_name):
                process = Process._open_discovered_process(process_buffer.th32ProcessID)
                if process is None:
                    process_found = windows.Process32Next(snapshot, byref(process_buffer))
                    continue

                process._name = _decode_snapshot_text(process_buffer.szExeFile)
                break

            process_found = windows.Process32Next(snapshot, byref(process_buffer))

        windows.CloseHandle(snapshot)
        return process

    def _register_wait(self) -> bool:
        """
        Internal helper to register the wait callback for process termination.

        Returns:
            bool: True if the wait was registered, False otherwise.
        """
        if not self._wait:
            self._wait = windows.RegisterWaitForSingleObject(
                self._handle,
                self._wait_callback,
                self._process_id,
                INFINITE,
                WT_EXECUTEONLYONCE
            )

        return self._wait != 0

    @staticmethod
    def _open_discovered_process(process_id: int) -> Process | None:
        """Open a discovered process, skipping entries that remain inaccessible."""
        try:
            return Process(process_id)
        except windows.Win32Exception:
            try:
                return Process(process_id, 0, PROCESS_QUERY_LIMITED_INFORMATION)
            except windows.Win32Exception:
                return None

    def _unregister_wait(self) -> bool:
        """
        Internal helper to unregister the wait callback for process termination.

        Returns:
            bool: True if unregistered or not set, False otherwise.
        """
        if self._wait:
            success: bool = windows.UnregisterWait(self._wait)
            self._wait = 0
            return success

        return True

    def __on_process_terminate(self, process_id: int, timer_or_wait_fired: int) -> None:
        """
        Internal handler invoked when the process terminates.

        Args:
            process_id (int): The process ID.
            timer_or_wait_fired (int): Indicates timer or process exit.
        """
        for callback in self._callbacks:
            callback(process_id, timer_or_wait_fired)
