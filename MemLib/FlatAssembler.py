"""
FASM assembler wrapper for runtime x86/x64 assembly compilation using FASM.dll.

This module provides high-level Python bindings to the FASM assembler via a DLL,
allowing you to compile assembly source code at runtime, query the FASM version,
and handle compilation errors with detailed diagnostics.

Features:
    * Compile assembly source to machine code with Python (using FASM.dll)
    * Retrieve FASM library version
    * Raise and display detailed error messages, including error context and faulty assembly lines

Typical usage example:
    machine_code = compile_asm("mov eax, 1", max_memory_size=4096)
    print(machine_code)

References:
    https://flatassembler.net/
"""

from ctypes import Array, byref, WinDLL, addressof, c_void_p, create_string_buffer, memmove, windll
from ctypes.wintypes import BOOL, CHAR, DWORD, INT, LPSTR, LPVOID, PDWORD
from enum import IntEnum
from os import path
from struct import calcsize, unpack_from
from typing import Any

from MemLib.Constants import MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE
from MemLib.windows import VirtualAlloc, VirtualFree



__FASM_DIRECTORY: str = path.dirname(__file__)
if calcsize("P") * 8 == 32:
    __FASM_PATH: str = path.join(__FASM_DIRECTORY, 'fasm32.dll')
else:
    __FASM_PATH: str = path.join(__FASM_DIRECTORY, 'fasm64.dll')

_FASM: WinDLL = WinDLL(__FASM_PATH)


def allocate_in_32bit_space(
        size: int,
        alloc_type: int = MEM_COMMIT | MEM_RESERVE,
        prot: int = PAGE_EXECUTE_READWRITE,
        min_addr: int = 0x10000,
        max_addr: int = 0x100000000
    ) -> int:
    if max_addr > 0x100000000:
        raise ValueError("max_addr cannot be higher than 0x100000000!")

    for base in range(min_addr, max_addr, 0x10000):
        addr = VirtualAlloc(base, size, alloc_type, prot)
        if not addr:
            continue

        if addr < max_addr:
            return addr

        VirtualFree(addr, 0, MEM_RELEASE)
    raise MemoryError("Could not allocate buffer in low 4GB of address space")


def get_version() -> str:
    """
    Returns the version string of the linked FASM library.

    Returns:
        str: The version in the format 'FASM vMAJOR.MINOR'.
    """

    fasm_version: int = _FASM.fasm_GetVersion()
    major: str = str(fasm_version & 0xFFFF)
    minor: str = str(fasm_version >> 16)

    return f'FASM v{major}.{minor}'


def compile_asm(source_code: str, max_memory_size: int = 0x5E8000, max_iterations: int = 1000) -> bytes:
    """
    Compiles assembly source code using the FASM DLL at runtime.

    Args:
        source_code (str): The assembly code to compile (ASCII-encoded).
        max_memory_size (int, optional): Maximum size of the output buffer (default: 0x5E8000).
        max_iterations (int, optional): Maximum number of recursion iterations FASM may perform (default: 100).

    Returns:
        bytes: The compiled machine code as a bytes object.

    Raises:
        FasmError: If assembly fails or FASM returns an error code.
    """

    src_txt = source_code.encode('ascii') + b"\x00"
    # max_memory_size = len(src_txt) * 8
    src = allocate_in_32bit_space(len(src_txt) + max_memory_size)
    dst = src + len(src_txt)
    memmove(src, src_txt, len(src_txt))

    error_code: int = _FASM.fasm_Assemble(src, dst, max_memory_size, max_iterations, 0)

    if error_code:
        raise FasmError(dst, source_code)

    size: int = DWORD.from_address(dst + 0x0004).value
    address: int = DWORD.from_address(dst + 0x0008).value
    offset: int =  address - dst

    return bytes((CHAR * max_memory_size).from_address(dst))[offset:offset + size]

class ErrorState(IntEnum):
    FASMERR_FILE_NOT_FOUND = -101
    FASMERR_ERROR_READING_FILE = -102
    FASMERR_INVALID_FILE_FORMAT = -103
    FASMERR_INVALID_MACRO_ARGUMENTS = -104
    FASMERR_INCOMPLETE_MACRO = -105
    FASMERR_UNEXPECTED_CHARACTERS = -106
    FASMERR_INVALID_ARGUMENT = -107
    FASMERR_ILLEGAL_INSTRUCTION = -108
    FASMERR_INVALID_OPERAND = -109
    FASMERR_INVALID_OPERAND_SIZE = -110
    FASMERR_OPERAND_SIZE_NOT_SPECIFIED = -111
    FASMERR_OPERAND_SIZES_DO_NOT_MATCH = -112
    FASMERR_INVALID_ADDRESS_SIZE = -113
    FASMERR_ADDRESS_SIZES_DO_NOT_AGREE = -114
    FASMERR_DISALLOWED_COMBINATION_OF_REGISTERS = -115
    FASMERR_LONG_IMMEDIATE_NOT_ENCODABLE = -116
    FASMERR_RELATIVE_JUMP_OUT_OF_RANGE = -117
    FASMERR_INVALID_EXPRESSION = -118
    FASMERR_INVALID_ADDRESS = -119
    FASMERR_INVALID_VALUE = -120
    FASMERR_VALUE_OUT_OF_RANGE = -121
    FASMERR_UNDEFINED_SYMBOL = -122
    FASMERR_INVALID_USE_OF_SYMBOL = -123
    FASMERR_NAME_TOO_LONG = -124
    FASMERR_INVALID_NAME = -125
    FASMERR_RESERVED_WORD_USED_AS_SYMBOL = -126
    FASMERR_SYMBOL_ALREADY_DEFINED = -127
    FASMERR_MISSING_END_QUOTE = -128
    FASMERR_MISSING_END_DIRECTIVE = -129
    FASMERR_UNEXPECTED_INSTRUCTION = -130
    FASMERR_EXTRA_CHARACTERS_ON_LINE = -131
    FASMERR_SECTION_NOT_ALIGNED_ENOUGH = -132
    FASMERR_SETTING_ALREADY_SPECIFIED = -133
    FASMERR_DATA_ALREADY_DEFINED = -134
    FASMERR_TOO_MANY_REPEATS = -135
    FASMERR_SYMBOL_OUT_OF_SCOPE = -136
    FASMERR_USER_ERROR = -140
    FASMERR_ASSERTION_FAILED = -141

class FasmError(Exception):
    """
    Exception raised when FASM compilation fails.

    Attributes:
        CODE_NAMES (tuple): Names for standard FASM error codes.
        ERROR_NAMES (tuple): Names for extended FASM error codes.
        _fasm_buffer (Array): Raw output buffer returned by FASM.dll.
        _source_code (str): The original assembly source code.
        _error_code (int): Numeric FASM error code.
        _error_name (str): Error name string (short).
        _error_msg (str): Full error message with context, if available.

    Methods:
        get_message() -> str: Retrieves detailed error information (if available).

    Example:
        try:
            compile_asm("invalid code")
        except FasmError as e:
            print(e)
    """

    CODE_NAMES: tuple[str] = (
        "FASM_INVALID_DEFINITION", "FASM_WRITE_FAILED", "FASM_FORMAT_LIMITATIONS_EXCEDDED",
        "FASM_CANNOT_GENERATE_CODE", "FASM_UNEXPECTED_END_OF_SOURCE", "FASM_SOURCE_NOT_FOUND",
        "FASM_STACK_OVERFLOW", "FASM_OUT_OF_MEMORY", "FASM_INVALID_PARAMETER",
        "FASM_OK", "FASM_WORKING", "FASM_ERROR"
    )

    def __init__(self, fasm_buffer: int = None, source_code: str = None):
        """
        Initializes a FasmError with the provided output buffer and source code.

        Args:
            fasm_buffer (Array, optional): The raw ctypes buffer from FASM.dll.
            source_code (str, optional): The original assembly source code.

        Populates:
            self._error_code: The raw error code.
            self._error_name: Human-readable error name.
            self._error_msg: Detailed error message if available.
        """

        self._fasm_buffer: int = fasm_buffer
        self._source_code: str = source_code
        self._error_code: int = INT.from_address(fasm_buffer).value

        if -9 <= self._error_code <= 2:
            self._error_name: str = "%s(%d)" % (FasmError.CODE_NAMES[self._error_code + 9], self._error_code)
            self._error_msg: str = self.get_message()
        else:
            self._error_name: str = "UNKNOWN ERROR(%d)" % self._error_code
            self._error_msg: str = ""

        super().__init__(self._error_name, self._error_msg)

    def __str__(self):
        """Returns the formatted error name and detailed message."""
        return "%s -> %s" % (self._error_name, self._error_msg)

    def __repr__(self) -> str:
        """Returns the string representation of the error."""
        return str(self)

    def get_message(self) -> str:
        """
        Retrieves a detailed, human-readable error message, including
        the failing assembly line (if available).

        Returns:
            str: Detailed error description, or empty string if not available.
        """
        if self._error_code != 2:
            return ""

        condition: int = INT.from_address(self._fasm_buffer + 0x0000).value
        error: int = INT.from_address(self._fasm_buffer + 0x0004).value
        info_ptr: int = DWORD.from_address(self._fasm_buffer + 0x0008).value

        error_buffer: Array = (INT * 4).from_address(info_ptr)  # type: ignore
        print("condition:", condition)
        print("error:", error)
        print("info_ptr:", info_ptr)

        path = error_buffer[0]
        line = error_buffer[1]
        offset = error_buffer[2]
        macro_line = error_buffer[3]
        print()
        print(f"path: 0x{path:X}")
        print("line:", line)
        print("offset:", offset)
        print("macro_line:", macro_line)

        # input("")

        if -141 <= error <= -101:
            error_info: tuple[Any, ...] = unpack_from('iiii', error_buffer)
            errr: ErrorState = ErrorState(error)
            out_string: str = f"{errr.name}({errr.value})"
            line: int = error_info[1] - 1
            lines: list[str] = self._source_code.splitlines()
            print(line)

            if 0 < line <= len(lines):
                out_string += f"\n    -> Line: {line}"
                out_string += "\n    -> ASM:"

                for i in range(line - 10, line + 11):
                    if i < 0 or i >= len(lines):
                        continue

                    if i == line:
                        out_string += f"\nERROR -> [{i}] " + lines[i]
                    else:
                        out_string += f"\n         [{i}] " + lines[i]

            return out_string

        return ""
