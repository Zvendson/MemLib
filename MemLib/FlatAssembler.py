"""
:platform: Windows
"""
from ctypes import Array, CDLL, WinDLL, addressof, create_string_buffer
from ctypes.wintypes import INT, LPSTR
from os import path
from struct import unpack_from
from typing import Any


_FASM_DIRECTORY: str  = path.dirname(__file__)
_FASM_PATH:      str  = path.join(_FASM_DIRECTORY, 'FASM.dll')
_FASM:           CDLL = WinDLL(_FASM_PATH)


def get_version() -> str:
    """
    Returns the version of FASM.
    """

    fasm_version: int = _FASM.fasm_GetVersion()
    major:        str = str(fasm_version & 0xFFFF)
    minor:        str = str(fasm_version >> 16)

    return f'FASM v{major}.{minor}'


def compile_asm(source_code: str, max_memory_size: int = 0x5E8000, max_iterations: int = 100) -> bytes:
    """
    Takes a string of assembly code and compiles it during runtime.

    :param source_code: The assembly code to compile.
    :param max_memory_size: The maximum size of the memory buffer that the FASM.dll can use.
    :param max_iterations: The maximum number of recursions that the FASM.dll can make.

    :return: The machine code as a bytes object.
    """

    assembly_source: LPSTR = LPSTR(source_code.encode('ascii'))
    output_buffer:   Array = create_string_buffer(max_memory_size)
    error_code:      int   = _FASM.fasm_Assemble(assembly_source, output_buffer, max_memory_size, max_iterations, 0)

    if error_code:
        raise FasmError(output_buffer, source_code)

    unpack:  tuple[Any, ...] = unpack_from('II', output_buffer, 4)
    size:    int             = unpack[0]
    address: int             = unpack[1]
    offset:  int             = address - addressof(output_buffer)

    return bytes(output_buffer)[offset:offset + size]


class FasmError(Exception):
    """
    Exception raised when FASM returns an error code.
    """

    CODE_NAMES: tuple[str] = (
        "FASM_INVALID_DEFINITION", "FASM_WRITE_FAILED", "FASM_FORMAT_LIMITATIONS_EXCEDDED",
        "FASM_CANNOT_GENERATE_CODE", "FASM_UNEXPECTED_END_OF_SOURCE", "FASM_SOURCE_NOT_FOUND",
        "FASM_STACK_OVERFLOW", "FASM_OUT_OF_MEMORY", "FASM_INVALID_PARAMETER",
        "FASM_OK", "FASM_WORKING", "FASM_ERROR"
    )

    ERROR_NAMES: tuple[str] = (
        "ASSERTION_FAILED", "USER_ERROR", None, None, None, "SYMBOL_OUT_OF_SCOPE",
        "TOO_MANY_REPEATS", "DATA_ALREADY_DEFINED", "SETTING_ALREADY_SPECIFIED",
        "SECTION_NOT_ALIGNED_ENOUGH", "EXTRA_CHARACTERS_ON_LINE", "UNEXPECTED_INSTRUCTION",
        "MISSING_END_DIRECTIVE", "MISSING_END_QUOTE", "SYMBOL_ALREADY_DEFINED",
        "RESERVED_WORD_USED_AS_SYMBOL", "INVALID_NAME", "NAME_TOO_LONG",
        "INVALID_USE_OF_SYMBOL", "UNDEFINED_SYMBOL", "VALUE_OUT_OF_RANGE",
        "INVALID_VALUE", "INVALID_ADDRESS", "INVALID_EXPRESSION",
        "RELATIVE_JUMP_OUT_OF_RANGE", "LONG_IMMEDIATE_NOT_ENCODABLE", "DISALLOWED_COMBINATION_OF_REGISTERS",
        "ADDRESS_SIZES_DO_NOT_AGREE", "INVALID_ADDRESS_SIZE", "OPERAND_SIZES_DO_NOT_MATCH",
        "OPERAND_SIZE_NOT_SPECIFIED", "INVALID_OPERAND_SIZE", "INVALID_OPERAND",
        "ILLEGAL_INSTRUCTION", "INVALID_ARGUMENT", "UNEXPECTED_CHARACTERS",
        "INCOMPLETE_MACRO",  "INVALID_MACRO_ARGUMENTS", "INVALID_FILE_FORMAT",
        "ERROR_READING_FILE", "FILE_NOT_FOUND"
    )

    def __init__(self, fasm_buffer: Array = None, source_code: str = None):
        """
        An exception with detailed info about the FASM error.

        :param fasm_buffer: The ctypes fasm buffer.
        :param source_code: The source code containing assembly instruction.
        """

        self._fasm_buffer: Array = fasm_buffer
        self._source_code: str   = source_code
        self._error_code:  int   = unpack_from('I', fasm_buffer)[0]

        if -9 <= self._error_code <= 2:
            self._error_name: str = "%s(%d)" % (FasmError.CODE_NAMES[self._error_code + 9], self._error_code)
            self._error_msg: str  = self.get_message()
        else:
            self._error_name: str = "UNKNOWN ERROR(%d)" % self._error_code
            self._error_msg: str  = ""

    def __str__(self):
        return "%s -> %s" % (self._error_name, self._error_msg)

    def __repr__(self) -> str:
        return str(self)

    def get_message(self) -> str:
        if self._error_code != 2:
            return ""

        buffer_info:  tuple[Any, ...] = unpack_from('iI', self._fasm_buffer, 4)
        error:       int             = buffer_info[0]
        info_ptr:     int             = buffer_info[1]
        error_buffer: Array           = (INT * 4).from_address(info_ptr)

        if -141 <= error <= -101:
            error_info: tuple[Any, ...] = unpack_from('iiii', error_buffer)
            out_string: str             = FasmError.ERROR_NAMES[error + 141]
            line:      int              = error_info[1] - 1
            lines:     list[str]        = self._source_code.splitlines()

            if 0 < line <= len(lines):
                out_string += f"\n    -> Line: {line}"
                out_string +=  "\n    -> ASM:"

                for i in range(line - 10, line + 11):
                    if i < 0 or i >= len(lines):
                        continue

                    if i == line:
                        out_string += f"\nERROR -> [{i}] " + lines[i]
                    else:
                        out_string += f"\n         [{i}] " + lines[i]

            return out_string

        return ""



