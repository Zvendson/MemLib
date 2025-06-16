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

from ctypes import Array, WinDLL, memmove
from ctypes.wintypes import CHAR, DWORD, INT
from enum import IntEnum
from os import path
from typing import Any

from MemLib.Constants import MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE
from MemLib.windows import VirtualAlloc, VirtualFree, is_32bit


__FASM_DIRECTORY: str = path.dirname(__file__)
if is_32bit():
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
    """
    Allocates memory in the lower 4GB address range of a process.

    Args:
        size (int): Number of bytes to allocate.
        alloc_type (int): Allocation type flags (default is MEM_COMMIT | MEM_RESERVE).
        prot (int): Memory protection (default is PAGE_EXECUTE_READWRITE).
        min_addr (int): Minimum base address for the allocation.
        max_addr (int): Maximum base address limit (must be ≤ 0x100000000).

    Returns:
        int: Base address of the allocated memory.

    Raises:
        ValueError: If max_addr exceeds 4GB.
        MemoryError: If no suitable region is found.
    """
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


def get_version() -> tuple[int, int]:
    """
    Returns the version string of the linked FASM library.

    Returns:
        str: The version in the format 'FASM vMAJOR.MINOR'.
    """
    fasm_version: int = _FASM.fasm_GetVersion()
    major: int = fasm_version & 0xFFFF
    minor: int = fasm_version >> 16

    return major, minor

def get_version_string() -> str:
    """
    Returns the version string of the linked FASM library.

    Returns:
        str: The version in the format 'Flat Assembler vMAJOR.MINOR'.
    """
    major, minor = get_version()
    return f'Flat Assembler v{major}.{minor}'


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

    src_bytes = source_code.encode('ascii') + b"\x00"
    src = allocate_in_32bit_space(len(src_bytes) + max_memory_size)

    dst = src + len(src_bytes)
    memmove(src, src_bytes, len(src_bytes))

    error_code: int = _FASM.fasm_Assemble(src, dst, max_memory_size, max_iterations, 0)
    print(error_code)
    if error_code:
        error = FASMError(dst, source_code)
        VirtualFree(src, 0, MEM_RELEASE)
        raise error

    size: int = DWORD.from_address(dst + 0x0004).value
    address: int = DWORD.from_address(dst + 0x0008).value
    offset: int =  address - dst

    buffer: bytes = bytes((CHAR * max_memory_size).from_address(dst))  # type: ignore
    VirtualFree(src, 0, MEM_RELEASE)
    return buffer[offset:offset + size]


class FASMNState(IntEnum):
    OK 			                = 0	# FASM_STATE points to output
    WORKING			            = 1
    ERROR			            = 2	# FASM_STATE contains error code
    INVALID_PARAMETER		    = -1
    OUT_OF_MEMORY		        = -2
    STACK_OVERFLOW		        = -3
    SOURCE_NOT_FOUND		    = -4
    UNEXPECTED_END_OF_SOURCE	= -5
    CANNOT_GENERATE_CODE	    = -6
    FORMAT_LIMITATIONS_EXCEEDED = -7
    WRITE_FAILED		        = -8
    INVALID_DEFINITION 	        = -9

    @classmethod
    def _missing_(cls, value: Any):
        obj = int.__new__(cls, value)
        obj._name_ = "UNKNOWN"
        obj._value_ = value
        return obj

class FASMERR(IntEnum):
    FILE_NOT_FOUND = -101
    ERROR_READING_FILE = -102
    INVALID_FILE_FORMAT = -103
    INVALID_MACRO_ARGUMENTS = -104
    INCOMPLETE_MACRO = -105
    UNEXPECTED_CHARACTERS = -106
    INVALID_ARGUMENT = -107
    ILLEGAL_INSTRUCTION = -108
    INVALID_OPERAND = -109
    INVALID_OPERAND_SIZE = -110
    OPERAND_SIZE_NOT_SPECIFIED = -111
    OPERAND_SIZES_DO_NOT_MATCH = -112
    INVALID_ADDRESS_SIZE = -113
    ADDRESS_SIZES_DO_NOT_AGREE = -114
    DISALLOWED_COMBINATION_OF_REGISTERS = -115
    LONG_IMMEDIATE_NOT_ENCODABLE = -116
    RELATIVE_JUMP_OUT_OF_RANGE = -117
    INVALID_EXPRESSION = -118
    INVALID_ADDRESS = -119
    INVALID_VALUE = -120
    VALUE_OUT_OF_RANGE = -121
    UNDEFINED_SYMBOL = -122
    INVALID_USE_OF_SYMBOL = -123
    NAME_TOO_LONG = -124
    INVALID_NAME = -125
    RESERVED_WORD_USED_AS_SYMBOL = -126
    SYMBOL_ALREADY_DEFINED = -127
    MISSING_END_QUOTE = -128
    MISSING_END_DIRECTIVE = -129
    UNEXPECTED_INSTRUCTION = -130
    EXTRA_CHARACTERS_ON_LINE = -131
    SECTION_NOT_ALIGNED_ENOUGH = -132
    SETTING_ALREADY_SPECIFIED = -133
    DATA_ALREADY_DEFINED = -134
    TOO_MANY_REPEATS = -135
    SYMBOL_OUT_OF_SCOPE = -136
    USER_ERROR = -140
    ASSERTION_FAILED = -141

    @classmethod
    def _missing_(cls, value: Any):
        obj = int.__new__(cls, value)
        obj._name_ = "UNKNOWN"
        obj._value_ = value
        return obj

class FASMError(Exception):
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
        self._error_code: FASMNState = FASMNState(INT.from_address(fasm_buffer).value)
        self._error_name: str = f"{self._error_code.name}({self._error_code.value})"
        self._error_msg: str = self._get_message()

        super().__init__(self._error_name, self._error_msg)

    def __str__(self):
        """Returns the formatted error name and detailed message."""
        return f"{self._error_name}:\n{self._error_msg}"

    def __repr__(self) -> str:
        """Returns the string representation of the error."""
        return str(self)

    def _get_message(self) -> str:
        """
        Retrieves a detailed, human-readable error message, including
        the failing assembly line (if available).

        Returns:
            str: Detailed error description, or empty string if not available.
        """

        error: FASMERR = FASMERR(INT.from_address(self._fasm_buffer + 0x0004).value)
        if self._error_code.value != 2:
            return ""

        info_ptr: int = DWORD.from_address(self._fasm_buffer + 0x0008).value

        error_buffer: Array = (INT * 4).from_address(info_ptr)  # type: ignore

        # path = error_buffer[0]
        line = error_buffer[1] - 1
        # offset = error_buffer[2]
        # macro_line = error_buffer[3]

        lines: list[str] = self._source_code.splitlines()
        start: int = max(0, line - 5)
        end: int = min(len(lines), line + 6)
        longest_length: int = max(len(l) for l in lines[start:end])

        out_error: str  = f" <<< {error.name} (Code: {error.value})"
        out_string: str = f"Line | {"Assembly":{longest_length}} | {"Error":{len(out_error)}}"
        out_string   += f"\n-----|-{"-" * longest_length}-|-{"-"*len(out_error)}"

        for i in range(start, end):
            if i == line:
                out_string += f"\n{i:4} | {lines[i]:{longest_length}} | {out_error}"
            else:
                out_string += f"\n{i:4} | {lines[i]:{longest_length}} |"

        return out_string
