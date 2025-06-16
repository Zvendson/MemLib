"""
FasmWrapper.py

High-level Python wrapper for Flat Assembler (FASM) using the MemLib backend.

This module provides a `FASM` class for generating, compiling, and managing
assembly source code at runtime, supporting both 32-bit and 64-bit modes.

Classes:
    FASM: Provides an interface for writing and compiling FASM code,
          injecting strings and symbols, and retrieving exported addresses.
"""

from __future__ import annotations

from typing import Any

from MemLib import windows
from MemLib.FlatAssembler import compile_asm, get_version, get_version_string


class FASM:
    """
    Provides a simple high-level interface for generating and compiling Flat Assembler (FASM) code.

    Supports dynamic definition of strings, Unicode strings, constants, variables, labels
    and handles export symbol tracking and binary retrieval.
    """

    def __init__(self):
        self._32bit: bool = windows.is_32bit()
        self._fmt: str = "format binary"
        self._org: int = 0
        self._unique_symbols: set[str] = set()
        self._assembly: str = ""
        self._bytes: dict[str, int] = dict()
        self._words: dict[str, int] = dict()
        self._dwords: dict[str, int] = dict()
        self._qwords: dict[str, int] = dict()
        self._byte_arrays: dict[str, int] = dict()
        self._word_arrays: dict[str, int] = dict()
        self._dword_arrays: dict[str, int] = dict()
        self._qword_arrays: dict[str, int] = dict()
        self._buffers: dict[str, int | bytes | bytearray] = dict()
        self._strings: dict[str, str] = dict()
        self._wstrings: dict[str, str] = dict()
        self._definitions: dict[str, Any] = dict()
        self._exports: set[str] = set()
        self._export_map: dict[str, int] = dict()
        self._binary: bytes = b""

    def use32(self) -> FASM:
        """
        Sets the output mode to 32-bit assembly.

        Returns:
            FASM: Self (for chaining).
        """
        self._32bit = True
        return self

    def use64(self) -> FASM:
        """
        Sets the output mode to 64-bit assembly.

        Returns:
            FASM: Self (for chaining).
        """
        self._32bit = False
        return self

    def org(self, base_address: int) -> FASM:
        """
        Sets the origin address for the assembled code.

        Args:
            base_address (int): Base address to set as ORG.

        Returns:
            FASM: Self (for chaining).
        """
        self._org = base_address
        return self

    def format(self, fmt: str) -> FASM:
        """
        Sets the output binary format for FASM.

        Args:
            fmt (str): FASM format string (e.g., 'binary', 'pe').

        Returns:
            FASM: Self (for chaining).
        """
        self._fmt = f"format {fmt}"
        return self

    @property
    def version(self) -> tuple[int, int]:
        """
        Retrieves the version of the linked FASM library.

        Returns:
            tuple[int, int]: The (major, minor) version.
        """
        return get_version()

    @property
    def version_string(self) -> str:
        """
        Returns the version string of the linked FASM library.

        Returns:
            str: The version in the format 'Flat Assembler vMAJOR.MINOR'.
        """
        return get_version_string()

    def write(self, code: str) -> None:
        """
        Appends a block of raw assembly source code to the internal buffer.

        Args:
            code (str): Assembly code to append.
        """
        code = code.strip()
        if self._assembly and not self._assembly.endswith('\n'):
            self._assembly += '\n'
        self._assembly += code

    def add_byte(self, key: str, value: int) -> None:
        """
        Adds a single byte variable to the assembly.

        Args:
            key (str): Symbol name.
            value (int): Byte value (0–255).

        Raises:
            KeyError: If the symbol already exists.
        """
        if key in self._unique_symbols:
            raise KeyError(f"Key already exist: {key}")
        self._bytes[key] = value
        self._unique_symbols.add(key)

    def add_word(self, key: str, value: int) -> None:
        """
        Adds a single 2-byte word variable to the assembly.

        Args:
            key (str): Symbol name.
            value (int): Word value (0–65535).

        Raises:
            KeyError: If the symbol already exists.
        """
        if key in self._unique_symbols:
            raise KeyError(f"Key already exist: {key}")
        self._words[key] = value
        self._unique_symbols.add(key)

    def add_dword(self, key: str, value: int) -> None:
        """
        Adds a single 4-byte doubleword variable to the assembly.

        Args:
            key (str): Symbol name.
            value (int): 32-bit value.

        Raises:
            KeyError: If the symbol already exists.
        """
        if key in self._unique_symbols:
            raise KeyError(f"Key already exist: {key}")
        self._dwords[key] = value
        self._unique_symbols.add(key)

    def add_qword(self, key: str, value: int) -> None:
        """
        Adds a single 8-byte quadword variable to the assembly.

        Args:
            key (str): Symbol name.
            value (int): 64-bit value.

        Raises:
            KeyError: If the symbol already exists.
        """
        if key in self._unique_symbols:
            raise KeyError(f"Key already exist: {key}")
        self._qwords[key] = value
        self._unique_symbols.add(key)

    def add_byte_array(self, key: str, size: int) -> None:
        """
        Reserves a block of uninitialized memory for a byte array.

        Args:
            key (str): Symbol name.
            size (int): Number of bytes to reserve.

        Raises:
            KeyError: If the symbol already exists.
        """
        if key in self._unique_symbols:
            raise KeyError(f"Key already exist: {key}")
        self._byte_arrays[key] = size
        self._unique_symbols.add(key)

    def add_word_array(self, key: str, size: int) -> None:
        """
        Reserves a block of uninitialized memory for a word (2-byte) array.

        Args:
            key (str): Symbol name.
            size (int): Number of words to reserve.

        Raises:
            KeyError: If the symbol already exists.
        """
        if key in self._unique_symbols:
            raise KeyError(f"Key already exist: {key}")
        self._word_arrays[key] = size
        self._unique_symbols.add(key)

    def add_dword_array(self, key: str, size: int) -> None:
        """
        Reserves a block of uninitialized memory for a doubleword (4-byte) array.

        Args:
            key (str): Symbol name.
            size (int): Number of dwords to reserve.

        Raises:
            KeyError: If the symbol already exists.
        """
        if key in self._unique_symbols:
            raise KeyError(f"Key already exist: {key}")
        self._dword_arrays[key] = size
        self._unique_symbols.add(key)

    def add_qword_array(self, key: str, size: int) -> None:
        """
        Reserves a block of uninitialized memory for a quadword (8-byte) array.

        Args:
            key (str): Symbol name.
            size (int): Number of qwords to reserve.

        Raises:
            KeyError: If the symbol already exists.
        """
        if key in self._unique_symbols:
            raise KeyError(f"Key already exist: {key}")
        self._qword_arrays[key] = size
        self._unique_symbols.add(key)

    def add_buffer(self, key: str, data: bytes | bytearray) -> None:
        """
        Adds a raw binary buffer as a named symbol in the generated assembly.

        Args:
            key (str): The symbol name for the buffer.
            data (bytes | bytearray): The binary data to inject.

        Raises:
            KeyError: If the symbol already exists.
        """
        if key in self._unique_symbols:
            raise KeyError(f"Key already exist: {key}")
        self._buffers[key] = data
        self._unique_symbols.add(key)

    def add_string(self, key: str, string: str) -> None:
        """
        Adds a null-terminated ASCII string to the assembly.

        Args:
            key (str): Symbol name.
            string (str): ASCII string content.

        Raises:
            KeyError: If the key already exists.
        """
        if key in self._unique_symbols:
            raise KeyError(f"Key already exist: {key}")
        self._strings[key] = string
        self._unique_symbols.add(key)

    def add_wstring(self, key: str, string: str) -> None:
        """
        Adds a null-terminated Unicode string to the assembly.

        Args:
            key (str): Symbol name.
            string (str): Unicode string content.

        Raises:
            KeyError: If the key already exists.
        """
        if key in self._unique_symbols:
            raise KeyError(f"Key already exist: {key}")
        self._wstrings[key] = string
        self._unique_symbols.add(key)

    def define(self, key: str, value: int | str) -> None:
        """
        Defines a constant or label in the assembly.

        Args:
            key (str): Symbol name.
            value (int | str): Constant value.

        Raises:
            KeyError: If the key already exists.
        """
        if key in self._unique_symbols:
            raise KeyError(f"Key already exist: {key}")
        self._definitions[key] = value
        self._unique_symbols.add(key)

    def export(self, key: str) -> None:
        """
        Marks a label to be exported and tracked.

        Args:
            key (str): Label to export.

        Raises:
            KeyError: If the export key already exists.
        """
        if key in self._exports:
            raise KeyError(f"Key already exist: {key}")
        self._exports.add(key)

    def generate_assembly(self) -> str:
        """
        Constructs the final assembly source code including headers, strings, definitions,
        labels, and exports.

        Returns:
            str: Full assembly source text ready for compilation.
        """
        assembly: str = ""

        assembly += self._fmt + '\n'

        if self._32bit:
            ptr_decl: str = "dd"
            ptr_size: int = 4
            assembly += "use32\n"
        else:
            ptr_decl: str = "dq"
            ptr_size: int = 8
            assembly += "use64\n"

        if self._org:
            assembly += f"org {self._org}\n"

        assembly += "\n"

        for key, value in self._definitions.items():
            assembly += f"{key} = {value}\n"

        assembly += "\n"
        assembly += "nop\n" * 6
        assembly += "align 8\n"
        assembly += "\n"
        assembly += self._assembly
        assembly += "\n"
        assembly += "nop\n" * 6
        assembly += "align 8\n"
        assembly += "\n"

        for key, value in self._bytes.items():
            assembly += f"{key} db {value}\n"

        for key, size in self._byte_arrays.items():
            assembly += f"{key} rb {size}\n"

        assembly += "align 2\n"

        for key, value in self._words.items():
            assembly += f"{key} dw {value}\n"

        for key, size in self._word_arrays.items():
            assembly += f"{key} rw {size}\n"

        assembly += "align 4\n"

        for key, value in self._dwords.items():
            assembly += f"{key} dd {value}\n"

        for key, size in self._dword_arrays.items():
            assembly += f"{key} rd {size}\n"

        assembly += "align 8\n"

        for key, value in self._qwords.items():
            assembly += f"{key} dq {value}\n"

        for key, size in self._qword_arrays.items():
            assembly += f"{key} rq {size}\n"

        assembly += "align 8\n"

        for key, buf in self._buffers.items():
            byte_list = ", ".join(f"0x{b:X}" for b in buf)
            assembly += f"{key} db {byte_list}\n"

        assembly += "db 0\n"  # to generate if last line was reserving bytes (just in case)
        assembly += "align 4\n"

        for key, string in self._strings.items():
            assembly += f"{key} db '{string}', 0\n"

        assembly += "\n"

        for key, wstring in self._wstrings.items():
            assembly += f"{key} du '{wstring}', 0\n"

        self._export_map.clear()

        i = 0
        for symbol in self._exports:
            if symbol in self._definitions:
                continue
            self._export_map[symbol] = i

            assembly += f"{ptr_decl} {symbol}  ; {i}\n"
            i += 1

        total_count = len(self._export_map)
        for symbol, idx in self._export_map.items():
            self._export_map[symbol] = (total_count - idx) * ptr_size

        return assembly

    def compile(self, max_memory_size: int = 0, max_iterations: int = 100) -> bytes:
        """
        Compiles the generated FASM source code into binary using the linked assembler.

        Args:
            max_memory_size (int): Max buffer size for compilation (default scales with source length).
            max_iterations (int): Max number of passes FASM is allowed (default: 100).

        Returns:
            bytes: The compiled machine code binary.
        """
        self._binary = b""
        src_txt = self.generate_assembly()
        if not len(src_txt):
            return b""

        self._binary = compile_asm(src_txt, max_memory_size, max_iterations)
        return self._binary

    def get_export(self, name: str):
        """
        Retrieves the absolute address or value of a previously exported symbol.

        Args:
            name (str): Export symbol name.

        Returns:
            int: The dereferenced value (e.g., function address) of the export.

        Raises:
            RuntimeError: If no binary was compiled yet.
            KeyError: If the symbol was not exported.
        """
        if not len(self._binary):
            raise RuntimeError("You have not compiled any code yet.")

        rva: int = self._export_map[name]
        offset: int = len(self._binary) - rva
        size: int = 0x0008 if not self._32bit else 0x0004
        return int.from_bytes(self._binary[offset:offset + size], "little")
