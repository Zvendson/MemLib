from __future__ import annotations

from pathlib import Path
from typing import Optional, TYPE_CHECKING

from MemLib.Kernel32 import GetProcAddress, Win32Exception
from MemLib.Structs import (
    IMAGE_DATA_DIRECTORY, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS32, IMAGE_OPTIONAL_HEADER32,
    MODULEENTRY32,
)


if TYPE_CHECKING:
    from MemLib.Process import Process


class Module:
    """
    Represents a module (DLL or EXE) loaded in a remote process.

    Do not instantiate this class directly.
    Use the methods in :py:class:`~eve.MemLib.process.Process` to obtain Module instances:
      - :py:meth:`~eve.MemLib.process.Process.GetModules`
      - :py:meth:`~eve.MemLib.process.Process.GetMainModule`
      - :py:meth:`~eve.MemLib.process.Process.GetModule`

    .. seealso::
        `MODULEENTRY32 <https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-moduleentry32>`_
    """

    def __init__(self, module: MODULEENTRY32, process: Process):
        """
        Initializes a Module object from a MODULEENTRY32 struct and its parent process.

        :param module: The MODULEENTRY32 struct containing module info.
        :param process: The parent :py:class:`~process.Process` object.
        """
        self._handle:  int                    = module.hModule
        self._process: Process                = process
        self._name: str                    = module.szModule.decode('ascii')
        self._path: str                    = module.szExePath.decode('ascii')
        self._base: int                    = module.modBaseAddr
        self._size: int                    = module.modBaseSize
        self._dos: Optional[IMAGE_DOS_HEADER]          = None
        self._nt_headers: Optional[IMAGE_NT_HEADERS32] = None
        self._expo_dir: Optional[IMAGE_EXPORT_DIRECTORY] = None

    @property
    def base(self) -> int:
        """
        Returns the base address of the module in the process's memory.

        :return: Module base address.
        """
        return self._base

    @property
    def handle(self) -> int:
        """
        Returns the OS handle to the module.

        :return: Module handle.
        """
        return self._handle

    @property
    def name(self) -> str:
        """
        Returns the filename (with extension) of the module.

        :return: Module filename, e.g. ``kernel32.dll``.
        """
        return self._name

    @property
    def path(self) -> Path | None:
        """
        Returns the full local filesystem path of the module, if available.

        :return: Path object for the module's file, or None.
        """
        if isinstance(self._path, str):
            return Path(self._path)

        return None

    @property
    def process(self) -> Process:
        """
        Returns a reference to the parent process object.

        :return: The :py:class:`~process.Process` this module belongs to.
        """
        return self._process

    @property
    def size(self) -> int:
        """
        Returns the size of the module in bytes.

        :return: Size of the module in memory.
        """
        return self._size

    @property
    def dos_header(self) -> IMAGE_DOS_HEADER:
        """
        Returns the DOS header (``IMAGE_DOS_HEADER``) of the module.

        The header is read from the module's base address and cached on first access.

        :return: Parsed ``IMAGE_DOS_HEADER`` struct.
        """
        if self._dos is None:
            self._dos = self._process.read_struct(self._base, IMAGE_DOS_HEADER)
        return self._dos

    @property
    def nt_headers(self) -> IMAGE_NT_HEADERS32:
        """
        Returns the NT headers (``IMAGE_NT_HEADERS32``) of the module.

        The address is computed using ``e_lfanew`` from the DOS header.
        Asserts that the NT signature is valid.

        :return: Parsed ``IMAGE_NT_HEADERS32`` struct.
        """
        if self._nt_headers is None:
            address: int = self._base + self.dos_header.e_lfanew
            nt_headers: IMAGE_NT_HEADERS32 = self._process.read_struct(address, IMAGE_NT_HEADERS32)
            assert nt_headers.Signature == 0x4550
            self._nt_headers = nt_headers

        return self._nt_headers

    @property
    def optional_header(self) -> IMAGE_OPTIONAL_HEADER32:
        """
        Returns the optional header (``IMAGE_OPTIONAL_HEADER32``) of the module.

        Asserts that the header has the correct PE32 magic value.

        :return: Parsed ``IMAGE_OPTIONAL_HEADER32`` struct.
        """
        opt_headers: IMAGE_OPTIONAL_HEADER32 = self.nt_headers.OptionalHeader
        assert opt_headers.Magic == 0x10B
        return opt_headers

    def data_directory(self, index: int) -> IMAGE_DATA_DIRECTORY:
        """
        Returns the ``IMAGE_DATA_DIRECTORY`` at the specified index from the optional header.

        :param index: Index in the data directory array.
        :return: The requested data directory.
        :raises IndexError: If index is out of range.
        """
        opt_headers: IMAGE_OPTIONAL_HEADER32 = self.optional_header
        if 0 <= index < opt_headers.NumberOfRvaAndSizes:
            return opt_headers.DataDirectory[index]
        raise IndexError("DataDirectory index out of bounds")

    @property
    def export_directory(self) -> IMAGE_EXPORT_DIRECTORY:
        if self._expo_dir is None:
            export_dir_entry: IMAGE_DATA_DIRECTORY = self.data_directory(0)
            address: int = self._base + export_dir_entry.VirtualAddress
            self._expo_dir = self._process.read_struct(address, IMAGE_EXPORT_DIRECTORY)

        return self._expo_dir


    def get_proc_address(self, name: str) -> int:
        """
        Retrieves the address of an exported function or variable by name.

        :param name: The export's name.
        :return: Address of the exported function or variable.
        :raises Win32Exception: If the export is not found.

        .. seealso::
            `GetProcAddress <https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress>`_
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
        export_dir: IMAGE_EXPORT_DIRECTORY = self.export_directory
        name_count: int = export_dir.NumberOfNames
        name_addr: int = export_dir.AddressOfNames

        assert name_count > 0, "ExportDirectory has no name exports"
        assert name_addr > 0, "ExportDirectory has no name address"

        name_enc: bytes = name.encode("ascii")
        name_len: int   = len(name_enc) + 1

        for i in range(name_count):
            name_rva: int    = self._process.read_dword(self._base + name_addr + i * 0x0004)
            func_name: bytes = self._process.read_string(self._base + name_rva, name_len)
            if func_name != name_enc:
                continue

            ordinal_index_addr: int = self._base + export_dir.AddressOfNameOrdinals + i * 0x0002
            ordinal_index: int      = self._process.read_word(ordinal_index_addr)

            func_rva_addr = self._base + export_dir.AddressOfFunctions + ordinal_index * 0x0004
            func_rva = self._process.read_dword(func_rva_addr)
            if func_rva == 0:
                raise ValueError(f"Function '{name}' RVA is 0")

            return self._base + func_rva

        raise ValueError(f"Exported function '{name}' not found")

    def __eq__(self, other: Module) -> bool:
        """
        Checks if two Module objects refer to the same loaded module in the same process.

        :param other: Module to compare.
        :return: True if both modules have the same handle and parent process, else False.
        """
        same_handle: bool     = self._handle == other.handle
        same_process_id: bool = self._process.get_process_id() == other._process.get_process_id()

        return same_handle and same_process_id

    def __str__(self) -> str:
        """
        Returns a readable string representation of the module and its process.

        :return: String representation.
        """
        return f"Module('{self.name}' in Process '{self._process.get_process_id()}')"

    def __repr__(self) -> str:
        """
        Returns the string representation (same as __str__).

        :return: String representation.
        """
        return str(self)



