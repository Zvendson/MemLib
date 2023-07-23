"""
:platform: Windows
"""
from ctypes import WinDLL, addressof
from ctypes.wintypes import CHAR, INT, LPSTR
from os import path
from struct import unpack_from


_fasm_directory = path.dirname(__file__)
_fasm_path = path.join(_fasm_directory, 'fasm.dll')

_FASM = WinDLL(_fasm_path)


def GetVersion() -> str:
    """
    Returns the version of FASM.
    """

    ver = _FASM.fasm_GetVersion()
    ver = str(ver & 0xFFFF), str(ver >> 16)
    return 'FASM v' + '.'.join(ver)


def Compile(src: str, mem_size: int = 0x5E8000, max_passes: int = 100) -> bytes:
    """
    Takes a string of assembly code and compiles it during runtime.

    :param sourceCode: The assembly code to compile.
    :param maxMemorySize: The maximum size of the memory buffer that the fasm.dll can use.
    :param maxIterations: The maximum number of recursions that the fasm.dll can make.

    :return: The machine code as a bytes object.
    """

    asm_src = LPSTR(src.encode('ascii'))
    buf = (CHAR * mem_size)()

    err = _FASM.fasm_Assemble(asm_src, buf, mem_size, max_passes, 0)

    if err:
        raise FasmError(buf, src)

    size, addr = unpack_from('II', buf, 4)


    offset = addr - addressof(buf)
    return bytes(buf)[offset:offset + size]


class FasmError(Exception):
    """
    Exception raised when FASM returns an error code.
    """

    CODE_NAMES = ["FASM_INVALID_DEFINITION", "FASM_WRITE_FAILED", "FASM_FORMAT_LIMITATIONS_EXCEDDED",
                  "FASM_CANNOT_GENERATE_CODE", "FASM_UNEXPECTED_END_OF_SOURCE", "FASM_SOURCE_NOT_FOUND",
                  "FASM_STACK_OVERFLOW", "FASM_OUT_OF_MEMORY", "FASM_INVALID_PARAMETER", "FASM_OK", "FASM_WORKING",
                  "FASM_ERROR"]
    ERROR_NAMES = ["ASSERTION_FAILED", "USER_ERROR", None, None, None, "SYMBOL_OUT_OF_SCOPE",
                   "TOO_MANY_REPEATS", "DATA_ALREADY_DEFINED", "SETTING_ALREADY_SPECIFIED",
                   "SECTION_NOT_ALIGNED_ENOUGH", "EXTRA_CHARACTERS_ON_LINE", "UNEXPECTED_INSTRUCTION",
                   "MISSING_END_DIRECTIVE", "MISSING_END_QUOTE", "SYMBOL_ALREADY_DEFINED",
                   "RESERVED_WORD_USED_AS_SYMBOL", "INVALID_NAME", "NAME_TOO_LONG", "INVALID_USE_OF_SYMBOL",
                   "UNDEFINED_SYMBOL", "VALUE_OUT_OF_RANGE", "INVALID_VALUE", "INVALID_ADDRESS", "INVALID_EXPRESSION",
                   "RELATIVE_JUMP_OUT_OF_RANGE", "LONG_IMMEDIATE_NOT_ENCODABLE", "DISALLOWED_COMBINATION_OF_REGISTERS",
                   "ADDRESS_SIZES_DO_NOT_AGREE", "INVALID_ADDRESS_SIZE", "OPERAND_SIZES_DO_NOT_MATCH",
                   "OPERAND_SIZE_NOT_SPECIFIED", "INVALID_OPERAND_SIZE", "INVALID_OPERAND", "ILLEGAL_INSTRUCTION",
                   "INVALID_ARGUMENT", "UNEXPECTED_CHARACTERS", "INCOMPLETE_MACRO", "INVALID_MACRO_ARGUMENTS",
                   "INVALID_FILE_FORMAT", "ERROR_READING_FILE", "FILE_NOT_FOUND"]

    def __init__(self, fasmBuffer: object = None, sourceCode: str = None):
        """
        An exception with detailed info about the FASM error.

        :param fasmBuffer: The ctypes fasm buffer.
        :param sourceCode: The source code containing assembly instruction.
        """

        if -9 <= err_code <= 2:
            self._buffer = fasm_buffer
            self._asm_code = asm_code
            self._name = "%s(%d)" % (FasmError.CODE_NAMES[err_code + 9], err_code)
            self._msg = self._format_error(err_code)
        else:
            self._name = "UNKNOWN ERROR(%d)" % err_code
            self._msg = ""
            return

    def __str__(self):
        return repr(self)

    def __repr__(self) -> str:
        return "%s -> %s" % (self._name, self._msg)

    def _format_error(self, code: int) -> str:
        if code != 2:
            return ""

        error, error_info_ptr = unpack_from('iI', self._buffer, 4)
        error_buffer = (INT * 4).from_address(error_info_ptr)

        if -141 <= error <= -101:
            error_info = unpack_from('iiii', error_buffer)

            out = FasmError.ERROR_NAMES[error + 141]

            line = error_info[1] - 1
            lines = self._asm_code.splitlines()

            if 0 < line <= len(lines):
                out += f"\n    -> Line: {line}"
                out += "\n    -> ASM:"
                for i in range(line - 5, line + 6):
                    if i < 0 or i >= len(lines):
                        continue
                    if i == line:
                        out += f"\nERROR -> [{i}] " + lines[i]
                    else:
                        out += f"\n         [{i}] " + lines[i]

            return out

        return ""
