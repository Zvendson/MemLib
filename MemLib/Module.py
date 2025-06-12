"""
Represents a loaded module (DLL or EXE) in a remote process.

This module defines the `Module` class, which wraps Windows module information and provides
methods to access headers, exported functions (by name or ordinal), and metadata for a module
loaded in another process. Intended to be used via methods in the `Process` class.

Features:
    * Query module base address, size, path, and handle
    * Read DOS, NT, and optional headers, and data directories
    * Retrieve export addresses by name or ordinal
    * Compare module instances for equality (handle and process)

Example:
    mod = process.GetMainModule()
    print(f"Main module base address: 0x{mod.base:X}")
    address = mod.get_export_by_name("SomeExportedFunc")

References:
    https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-moduleentry32
    https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
    https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from MemLib.Constants import IMAGE_DIRECTORY_ENTRY_EXPORT, MAX_MODULE_NAME32
from MemLib.Structs import (
    IMAGE_DATA_DIRECTORY, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64,
    IMAGE_OPTIONAL_HEADER32,
    IMAGE_OPTIONAL_HEADER64, MODULEENTRY32,
)
from MemLib.windows import GetProcAddress, Win32Exception



if TYPE_CHECKING:
    from MemLib.Process import Process


class Module:
    """
    Represents a loaded module (DLL or EXE) within a remote process.

    Provides access to the module's metadata, memory addresses, PE headers,
    export table, and process context. This class enables parsing and inspection
    of the loaded module's structure, exports, and header fields.

    Attributes:
        _handle (int):
            The Windows handle of the loaded module.
        _process (Process):
            Reference to the owning process.
        _name (str):
            The module's name (e.g., 'kernel32.dll').
        _path (str):
            The full file path to the module on disk.
        _base (int):
            The base memory address where the module is loaded.
        _size (int):
            The size of the module in bytes.
        _dos (IMAGE_DOS_HEADER | None):
            Cached DOS header structure (optional).
        _nt_headers (IMAGE_NT_HEADERS32 | IMAGE_NT_HEADERS64 | None):
            Cached NT headers structure (optional).
        _expo_dir (IMAGE_EXPORT_DIRECTORY | None):
            Cached export directory structure (optional).
        _exports (dict[str, int]):
            Cached exports dictionary, mapping names or ordinals to addresses.

    Args:
        module (MODULEENTRY32):
            The Windows MODULEENTRY32 structure representing the module.
        process (Process):
            The parent process in which the module is loaded.
    """

    def __init__(self, module: MODULEENTRY32, process: Process):
        """
        Initializes a new Module object from a MODULEENTRY32 structure and its parent process.

        Parses and stores basic metadata about the module, such as its handle, name, path,
        base address, and size. Caches for PE header structures and exports are initialized as empty.

        Args:
            module (MODULEENTRY32):
                The MODULEENTRY32 structure containing metadata about the loaded module.
            process (Process):
                The parent process instance in which the module is loaded.

        Attributes Initialized:
            _handle (int): The module's Windows handle.
            _process (Process): The parent process object.
            _name (str): The module's name (e.g., "user32.dll").
            _path (str): The module's file path on disk.
            _base (int): The module's base memory address.
            _size (int): The module's size in bytes.
            _dos (IMAGE_DOS_HEADER | None): Cached DOS header (None until loaded).
            _nt_headers (IMAGE_NT_HEADERS32 | IMAGE_NT_HEADERS64 | None): Cached NT headers (None until loaded).
            _expo_dir (IMAGE_EXPORT_DIRECTORY | None): Cached export directory (None until loaded).
            _exports (dict[str, int]): Dictionary mapping export names/ordinals to addresses (empty initially).
        """
        self._handle: int = module.hModule
        self._process: Process = process
        self._name: str = module.szModule.decode('ascii')
        self._path: str = module.szExePath.decode('ascii')
        self._base: int = module.modBaseAddr
        self._size: int = module.modBaseSize
        self._dos: IMAGE_DOS_HEADER | None = None
        self._nt_headers: IMAGE_NT_HEADERS32 | IMAGE_NT_HEADERS64 | None = None
        self._expo_dir: IMAGE_EXPORT_DIRECTORY | None = None
        self._exports: dict[str, int] = dict()

    @property
    def base(self) -> int:
        """
        Returns the base memory address where the module is loaded.

        Returns:
            int: The module's base address in the remote process.
        """
        return self._base

    @property
    def handle(self) -> int:
        """
        Returns the Windows handle of the loaded module.

        Returns:
            int: The module handle as returned by the operating system.
        """
        return self._handle

    @property
    def name(self) -> str:
        """
        Returns the module's name (e.g., 'kernel32.dll').

        Returns:
            str: The short name of the module.
        """
        return self._name

    @property
    def path(self) -> Path | None:
        """
        Returns the full file path to the module on disk as a Path object.

        Returns:
            Path | None: The absolute file path, or None if the path is not a valid string.
        """
        if isinstance(self._path, str):
            return Path(self._path)

        return None

    @property
    def process(self) -> Process:
        """
        Returns the parent process object in which the module is loaded.

        Returns:
            Process: The process associated with this module.
        """
        return self._process

    @property
    def size(self) -> int:
        """
        Returns the size of the module in bytes.

        Returns:
            int: The size of the module image in memory.
        """
        return self._size

    @property
    def dos_header(self) -> IMAGE_DOS_HEADER:
        """
        Returns the IMAGE_DOS_HEADER structure for the loaded module.

        Reads and caches the DOS header from the module's base address in memory.
        This header marks the beginning of any DOS or Windows PE executable and contains
        essential information used to locate other headers in the PE file.

        Returns:
            IMAGE_DOS_HEADER:
                The parsed DOS header structure for the loaded module.
        """
        if self._dos is None:
            self._dos = self._process.read_struct(self._base, IMAGE_DOS_HEADER)
        return self._dos

    @property
    def nt_headers(self) -> IMAGE_NT_HEADERS32 | IMAGE_NT_HEADERS64:
        """
        Returns the IMAGE_NT_HEADERS structure for the loaded module.

        This property reads and caches the NT headers structure from the module in memory.
        Depending on whether the process is 32-bit or 64-bit, either an `IMAGE_NT_HEADERS32`
        or `IMAGE_NT_HEADERS64` instance is returned. The signature field is asserted to ensure
        the structure is valid.

        Returns:
            IMAGE_NT_HEADERS32 | IMAGE_NT_HEADERS64:
                The parsed NT headers structure for the loaded module, matching the module's architecture.

        Raises:
            AssertionError:
                If the NT headers signature does not match the expected value (0x4550, 'PE\0\0').
        """
        if self._nt_headers is None:
            address: int = self._base + self.dos_header.e_lfanew
            if self._process.is_64bit:
                nt_headers: IMAGE_NT_HEADERS64 = self._process.read_struct(address, IMAGE_NT_HEADERS64)
            else:
                nt_headers: IMAGE_NT_HEADERS32 = self._process.read_struct(address, IMAGE_NT_HEADERS32)
            assert nt_headers.Signature == 0x4550

            self._nt_headers = nt_headers

        return self._nt_headers

    @property
    def optional_header(self) -> IMAGE_OPTIONAL_HEADER32 | IMAGE_OPTIONAL_HEADER64:
        """
        Returns the IMAGE_OPTIONAL_HEADER structure for the loaded module.

        Depending on whether the process is 32-bit or 64-bit, this property returns
        either an `IMAGE_OPTIONAL_HEADER32` or `IMAGE_OPTIONAL_HEADER64` instance.
        It asserts that the header's magic value matches the expected value for the
        architecture.

        Returns:
            IMAGE_OPTIONAL_HEADER32 | IMAGE_OPTIONAL_HEADER64:
                The parsed optional header structure for the module, corresponding
                to the module's architecture (32-bit or 64-bit).

        Raises:
            AssertionError:
                If the header magic does not match the expected value.
        """
        if self._process.is_64bit:
            opt_headers: IMAGE_OPTIONAL_HEADER64 = self.nt_headers.OptionalHeader
            assert opt_headers.Magic == 0x20B
        else:
            opt_headers: IMAGE_OPTIONAL_HEADER32 = self.nt_headers.OptionalHeader
            assert opt_headers.Magic == 0x10B
        return opt_headers

    def data_directory(self, index: int) -> IMAGE_DATA_DIRECTORY:
        """
        Retrieves the IMAGE_DATA_DIRECTORY structure at the specified index from the optional header.

        This method accesses the PE optional header's data directories and returns the structure
        at the given index. It raises an IndexError if the index is out of bounds.

        Args:
            index (int):
                The zero-based index of the desired data directory.

        Returns:
            IMAGE_DATA_DIRECTORY:
                The data directory structure at the specified index.

        Raises:
            IndexError:
                If the specified index is not within the valid range.
        """
        opt_headers: IMAGE_OPTIONAL_HEADER32 = self.optional_header
        if 0 <= index < opt_headers.NumberOfRvaAndSizes:
            return opt_headers.DataDirectory[index]
        raise IndexError("DataDirectory index out of bounds")

    @property
    def export_directory(self) -> IMAGE_EXPORT_DIRECTORY:
        """
        Returns the IMAGE_EXPORT_DIRECTORY structure for the loaded module.

        Reads and caches the export directory from the PE data directories if not already cached.
        This property provides access to the parsed export directory, which contains
        metadata about all exported functions and symbols.

        Returns:
            IMAGE_EXPORT_DIRECTORY:
                The export directory structure of the loaded module.
        """
        if self._expo_dir is None:
            export_dir_entry: IMAGE_DATA_DIRECTORY = self.data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT)
            address: int = self._base + export_dir_entry.VirtualAddress
            self._expo_dir = self._process.read_struct(address, IMAGE_EXPORT_DIRECTORY)

        return self._expo_dir

    def get_proc_address(self, name: str) -> int:
        """
        Retrieves the address of an exported function or variable by name from the loaded module.

        This method uses the Win32 API `GetProcAddress` to obtain the address of the specified
        exported function or symbol. If the export is not found, a `Win32Exception` is raised.

        Args:
            name (str):
                The name of the exported function or variable.

        Returns:
            int:
                The address of the exported function or variable.

        Raises:
            Win32Exception:
                If the specified name could not be found in the module's exports.
        """
        handle: int = GetProcAddress(self._handle, name)
        if not handle:
            raise Win32Exception()

        return handle

    def get_export_by_ordinal(self, ordinal: int) -> int:
        """
        Retrieves the absolute address of an exported function by its ordinal.

        Args:
            ordinal (int): The export ordinal value.

        Returns:
            int: The absolute address of the exported function.

        Raises:
            IndexError: If the ordinal is not within the valid export range.
            AssertionError: If the export directory or function address table is invalid, or the function does not exist.
        """
        export_dir = self.export_directory
        assert export_dir.NumberOfFunctions > 0, "ExportDirectory has no function exports"
        assert export_dir.AddressOfFunctions > 0, "ExportDirectory has no function address"
        func_index = ordinal - export_dir.Base
        if not (0 <= func_index < export_dir.NumberOfFunctions):
            raise IndexError(f"Ordinal {ordinal} (0x{ordinal:X}) (index {func_index}) is out of range")

        func_rva: int = self._process.read_dword(self._base + export_dir.AddressOfFunctions + func_index * 0x0004)
        assert func_rva > 0, "Function ordinal does not exist"

        return self._base + func_rva

    def get_export_by_name(self, name: str) -> int:
        """
        Retrieves the absolute address of an exported function by its name.

        Args:
            name (str): The export name (ASCII).

        Returns:
            int: The absolute address of the exported function.

        Raises:
            ValueError: If the function is not found or has an invalid RVA.
            AssertionError: If the export directory is invalid or contains no names.
        """
        export: int | None = self._exports.get(name, None)
        if export is not None:
            return export

        export_dir: IMAGE_EXPORT_DIRECTORY = self.export_directory
        name_count: int = export_dir.NumberOfNames
        name_addr: int = export_dir.AddressOfNames

        assert name_count > 0, "ExportDirectory has no name exports"
        assert name_addr > 0, "ExportDirectory has no name address"

        name_enc: bytes = name.encode("ascii")
        name_len: int = len(name_enc) + 1

        for i in range(name_count):
            name_rva: int = self._process.read_dword(self._base + name_addr + i * 0x0004)
            func_name: bytes = self._process.read_string(self._base + name_rva, name_len)
            if func_name != name_enc:
                continue

            ordinal_index_addr: int = self._base + export_dir.AddressOfNameOrdinals + i * 0x0002
            ordinal_index: int = self._process.read_word(ordinal_index_addr)

            func_rva_addr: int = self._base + export_dir.AddressOfFunctions + ordinal_index * 0x0004
            func_rva: int = self._process.read_dword(func_rva_addr)
            if func_rva == 0:
                raise ValueError(f"Function '{name}' RVA is 0")

            self._exports[name] = self._base + func_rva
            return self._base + func_rva

        raise ValueError(f"Exported function '{name}' not found")

    def get_exports(self) -> dict[str, int]:
        """
        Parses and retrieves all exported functions from the module's export directory.

        This method reads both named and ordinal-only exports from the PE export directory
        of the loaded module. The result is a dictionary mapping export names (or ordinals
        for unnamed exports) to their corresponding virtual addresses.

        Returns:
            dict[str, int]:
                A dictionary mapping each export name (or ordinal as "Ordinal#<number>")
                to its absolute virtual address.

        Raises:
            AssertionError:
                If the number of discovered exports does not match the expected count from the export directory.
        """
        export_dir: IMAGE_EXPORT_DIRECTORY = self.export_directory
        total_count: int = export_dir.NumberOfFunctions
        if len(self._exports) >= total_count:
            return self._exports

        name_count: int = export_dir.NumberOfNames
        name_addr: int = export_dir.AddressOfNames
        ord_addr: int = export_dir.AddressOfNameOrdinals
        func_addr: int = export_dir.AddressOfFunctions
        names_seen = set()

        # Read named exports
        for i in range(name_count):
            name_rva: int = self._process.read_dword(self._base + name_addr + i * 4)
            func_name: str = self._process.read_string(self._base + name_rva, 2048).decode("ascii", errors="replace")

            ordinal_index_addr: int = self._base + ord_addr + i * 2
            ordinal_index: int = self._process.read_word(ordinal_index_addr)

            func_rva_addr: int = self._base + func_addr + ordinal_index * 4
            func_rva: int = self._process.read_dword(func_rva_addr)
            if func_rva == 0:
                continue

            self._exports[func_name] = self._base + func_rva
            names_seen.add(ordinal_index)

        # Read ordinal-only exports (no name)
        for ordinal_index in range(total_count):
            if ordinal_index in names_seen:
                continue  # Already mapped by name

            func_rva_addr: int = self._base + func_addr + ordinal_index * 4
            func_rva: int = self._process.read_dword(func_rva_addr)
            if func_rva == 0:
                continue

            func_ordinal = export_dir.Base + ordinal_index
            self._exports[f"Ordinal#{func_ordinal}"] = self._base + func_rva

        assert len(self._exports) == total_count

        return self._exports

    def __eq__(self, other: Module) -> bool:
        """
        Checks if two Module objects refer to the same loaded module in the same process.

        :param other: Module to compare.
        :return: True if both modules have the same handle and parent process, else False.
        """
        same_handle: bool = self._handle == other.handle
        same_process_id: bool = self._process.process_id == other._process.process_id

        return same_handle and same_process_id

    def __str__(self) -> str:
        """
        Returns a readable string representation of the module and its process.

        :return: String representation.
        """
        return f"Module('{self.name}' in Process '{self._process.process_id}')"

    def __repr__(self) -> str:
        """
        Returns the string representation (same as __str__).

        :return: String representation.
        """
        return str(self)
