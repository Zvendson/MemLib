"""
Binary pattern scanner with masked matching using embedded 32-bit and 64-bit assembly.

This module provides tools for fast, masked binary scanning of memory buffers using an injected
FASM-compiled assembly routine. Supports custom pattern definitions, efficient memory management,
and compatibility with Windows process memory (VirtualAlloc/VirtualFree).

Features:
    * FASM-powered payload generation for custom binary scanners
    * Pattern class for flexible masked byte sequence search
    * BinaryScanner for high-speed masked scanning using native assembly
    * All memory operations compatible with Windows process memory management

Example:
    scanner = BinaryScanner(buffer=b"...")
    addr = scanner.find("55 8B EC ?? 33 C0")
    print(f"Pattern found at virtual address: 0x{addr:X}")
"""

from ctypes import CFUNCTYPE, POINTER, byref, c_uint32, c_uint64, create_string_buffer
from ctypes.wintypes import BYTE, CHAR, DWORD, LPVOID
from typing import Callable, Literal

from _ctypes import Array

from MemLib.Constants import MEM_COMMIT, MEM_RELEASE, PAGE_EXECUTE_READWRITE
from MemLib.FlatAssembler import compile_asm
from MemLib.Structs import Struct
from MemLib.windows import VirtualAlloc, VirtualFree, Win32Exception, is_32bit



def generate_assembly_payload(file_path: str) -> str:
    """
    Compiles assembly code from a file using FASM and returns a prettified string of its opcodes.

    The output is formatted for readability (max 120 chars per line including indentation),
    as suitable for Python byte assignments.

    Args:
        file_path (str): Path to the assembly source file.

    Returns:
        str: Prettified opcode bytes as a Python-formatted string.

    Raises:
        FileNotFoundError: If the file does not exist.
        Win32Exception: If FASM compilation fails.
    """
    with open(file_path) as asm:
        text = asm.read()
        binary: bytes = compile_asm(text)

        opcode: str = binary.hex().upper()
        out: str = ""

        while len(opcode):
            temp: str = opcode[:74]
            temp = ' '.join(a + b for a, b in zip(temp[::2], temp[1::2]))
            out += f"'{temp}'\n"
            opcode = opcode[74::]

        return out

class Pattern(Struct):
    """
    Represents a binary pattern for scanning with mask support.

    Accepts combo patterns containing wildcards (?).

    Example:
        Pattern("55 8B EC ?? 33 C0")
    """

    length: int
    binary: bytes
    mask: bytes
    offset: int

    _fields_ = [
        ("length", DWORD),
        ("binary", BYTE * 256),
        ("mask", BYTE * 256),
        ("offset", DWORD),
    ]

    def __init__(self, combo_pattern: str, offset: int = 0):
        """
        Initializes a Pattern from a combo pattern string.

        Args:
            combo_pattern (str): Pattern string, e.g. "A1 ?? B2 ??".
            offset (int, optional): Offset to add to scan result. Defaults to 0.

        Raises:
            ValueError: If the pattern string has invalid length or unsupported format.
        """
        combo_pattern = combo_pattern.replace(" ", "")

        if len(combo_pattern) % 2 != 0:
            raise ValueError("Pattern has an invalid length!")

        binary: str = ""
        mask: str = ""

        for a, b in zip(combo_pattern[::2], combo_pattern[1::2]):
            if '?' in (a + b):
                binary += '00'
                mask += '?'
            else:
                binary += a + b
                mask += 'x'

        buffer_type: Callable = (BYTE * 256)  # type: ignore
        # noinspection PyCallingNonCallable
        super().__init__(
            len(mask),
            buffer_type(*bytes.fromhex(binary)),
            buffer_type(*mask.encode()),
            offset
        )

    def is_valid(self):
        """
        Check if the pattern is valid.

        Returns:
            bool: True if valid (length > 0), False otherwise.
        """
        return self.length > 0

class BinaryScanner:
    """
    Binary scanner using embedded 32-bit or 64-bit assembly for masked pattern matching.

    Can scan a provided byte buffer for binary patterns with wildcard masks.
    Automatically selects the appropriate routine based on architecture.
    """

    __PAYLOAD32 = bytes.fromhex(
        '55 89 E5 83 EC 08 53 51 52 56 57 8B 55 08 8B 02 85 C0 74 51 48 8B 9A 04 02 00 00 89 5D FC 8D 72 04 8D BA 04 01'
        '00 00 8B 55 0C 8B 1A 8B 4A 04 89 5D F8 29 C1 8A 14 06 39 CB 73 28 38 14 03 75 20 50 48 80 3C 07 78 75 08 8A 34'
        '06 38 34 03 75 04 85 C0 75 ED 58 75 09 89 D8 8B 5D F8 29 D8 EB 05 43 EB D4 31 C0 85 C0 74 03 03 45 FC 5F 5E 5A'
        '59 5B 83 C4 08 C9 C2 08 00'
    )

    __PAYLOAD64 = bytes.fromhex(
        '55 48 89 E5 48 83 EC 10 53 56 57 48 31 C0 48 31 DB 8B 01 48 85 C0 74 63 48 FF C8 8B 99 04 02 00 00 48 89 5D F8'
        '48 8D 71 04 48 8D B9 04 01 00 00 48 8B 1A 48 8B 4A 04 48 89 5D F0 48 29 C1 48 0F B6 14 06 48 39 CB 73 30 38 14'
        '03 75 26 50 48 FF C8 80 3C 07 78 75 08 8A 34 06 38 34 03 75 05 48 85 C0 75 EA 58 75 0C 48 89 D8 48 8B 5D F0 48'
        '29 D8 EB 08 48 FF C3 EB CB 48 31 C0 48 85 C0 74 04 48 03 45 F8 5F 5E 5B 48 89 EC 5D C3'
    )

    class _Buffer(Struct):

        base: int
        end: int

        _fields_ = [
            ("base", LPVOID),
            ("end", LPVOID),
        ]

    def __init__(self, buffer: bytes | None = None, base: int = 0, arch: Literal["32", "64"] = None):
        """
        Initializes the BinaryScanner, allocating memory for the scan routine and buffer.

        Args:
            buffer (bytes, optional): Buffer to scan.
            base (int, optional): Base address for virtual address calculations.

        Raises:
            Win32Exception: On memory allocation failure.
        """
        if arch is None:
            arch = "32" if is_32bit() else "64"

        self._buffer: BinaryScanner._Buffer = BinaryScanner._Buffer(0, 0)
        self._base: int = base

        # Writing payload to py memory
        if arch == "32":
            payload: bytes = BinaryScanner.__PAYLOAD32
            functype: CFUNCTYPE = CFUNCTYPE(c_uint32, POINTER(Pattern), POINTER(BinaryScanner._Buffer))
        else:
            payload: bytes = BinaryScanner.__PAYLOAD64
            functype: CFUNCTYPE = CFUNCTYPE(c_uint64, POINTER(Pattern), POINTER(BinaryScanner._Buffer))

        self._handler_address: int = VirtualAlloc(0, len(payload), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        if not self._handler_address:
            raise Win32Exception()

        binary: Array = (CHAR * len(payload)).from_address(self._handler_address)  # type: ignore
        binary.value = payload

        self._handler: Callable[[str, str], int] = functype(self._handler_address)

        # Writing buffer to py memory
        if buffer is not None:
            self.set_buffer(buffer, base)

    def __del__(self):
        self.close()

    @property
    def base(self) -> int:
        """
        Returns the base address used for virtual address calculations.

        Returns:
            int: Base address.
        """
        return self._base

    def close(self) -> None:
        """
        Frees all allocated memory for the scanner.
        """
        if self._handler_address:
            VirtualFree(self._handler_address, 0, MEM_RELEASE)
            self._handler_address = 0

    def set_buffer(self, new_buffer: bytes, base: int = 0) -> None:
        """
        Sets the buffer to scan and its associated base address.

        Args:
            new_buffer (bytes): The new buffer to scan.
            base (int, optional): New base address.

        Raises:
            Win32Exception: On memory allocation failure.
        """
        size: int = len(new_buffer)

        if self._buffer.base:
            VirtualFree(self._buffer.base, 0, MEM_RELEASE)

        self._base = base
        self._buffer.base = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)  # type: ignore
        if not self._buffer.base:
            raise Win32Exception()

        buffer: Array = (CHAR * size).from_address(self._buffer.base)  # type: ignore
        buffer.value = new_buffer

        self._buffer.end = self._buffer.base + size  # type: ignore

    def find_rva(self, pattern: str | Pattern) -> int:
        """
        Finds a pattern in the buffer and returns its RVA (offset from buffer base).

        Args:
            pattern (str | Pattern): Pattern string or Pattern object.

        Returns:
            int: RVA (offset) where the pattern is found, or 0 if not found.

        Raises:
            RuntimeError: If scanner is uninitialized.
            ValueError: If the pattern is invalid.
        """
        if not self._handler_address:
            raise RuntimeError("Scanner is not initialized!")

        if isinstance(pattern, str):
            pattern = Pattern(pattern)

        if not isinstance(pattern, Pattern) or not pattern.is_valid():
            raise ValueError("Invalid Pattern: " + str(pattern))

        return self._handler(byref(pattern), byref(self._buffer))

    def find(self, pattern: str | Pattern) -> int:
        """
        Finds a pattern and returns the absolute (virtual) address.

        Args:
            pattern (str | Pattern): Pattern string or Pattern object.

        Returns:
            int: Virtual address (base + offset), or 0 if not found.
        """
        rva = self.find_rva(pattern)
        return self._base + rva

if __name__ == '__main__':
    if is_32bit():
        scanner_opcode: str = generate_assembly_payload("Scanner32.asm")
    else:
        scanner_opcode: str = generate_assembly_payload("Scanner64.asm")
    print(scanner_opcode)
