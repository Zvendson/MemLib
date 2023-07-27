"""
:platform: Windows
"""

from ctypes import Array, CDLL, WinDLL, addressof
from ctypes.wintypes import CHAR, INT, LPSTR
from os import path
from struct import unpack_from
from typing import Any, List, Tuple


_FASM_DIRECTORY: str = path.dirname(__file__)
_FASM_PATH: str      = path.join(_FASM_DIRECTORY, 'fasm.dll')
_FASM: CDLL          = WinDLL(_FASM_PATH)


def GetVersion() -> str:
    """
    Returns the version of FASM.
    """

    fasmVersion = _FASM.fasm_GetVersion()
    fasmVersion = str(fasmVersion & 0xFFFF), str(fasmVersion >> 16)
    return 'FASM v' + '.'.join(fasmVersion)


def Compile(sourceCode: str, maxMemorySize: int = 0x5E8000, maxIterations: int = 100) -> bytes:
    """
    Takes a string of assembly code and compiles it during runtime.

    :param sourceCode: The assembly code to compile.
    :param maxMemorySize: The maximum size of the memory buffer that the fasm.dll can use.
    :param maxIterations: The maximum number of recursions that the fasm.dll can make.

    :return: The machine code as a bytes object.
    """

    assemblySource = LPSTR(sourceCode.encode('ascii'))
    outputBuffer = (CHAR * maxMemorySize)()

    errorCode = _FASM.fasm_Assemble(assemblySource, outputBuffer, maxMemorySize, maxIterations, 0)

    if errorCode:
        raise FasmError(outputBuffer, sourceCode)

    size, address = unpack_from('II', outputBuffer, 4)
    offset = address - addressof(outputBuffer)

    return bytes(outputBuffer)[offset:offset + size]


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

        errorCode, = unpack_from('I', fasmBuffer)

        if -9 <= errorCode <= 2:
            self._fasmBuffer = fasmBuffer
            self._sourceCode = sourceCode
            self._errorName = "%s(%d)" % (FasmError.CODE_NAMES[errorCode + 9], errorCode)
            self._errorMessage = self._format_error(errorCode)
        else:
            self._errorName = "UNKNOWN ERROR(%d)" % errorCode
            self._errorMessage = ""
            return

    def __str__(self):
        return repr(self)

    def __repr__(self) -> str:
        return "%s -> %s" % (self._errorName, self._errorMessage)

    def _format_error(self, errorCode: int) -> str:
        if errorCode != 2:
            return ""

        bufferInfo: Tuple[Any, ...] = unpack_from('iI', self._fasmBuffer, 4)
        error: int         = bufferInfo[0]
        infoPtr: int       = bufferInfo[1]
        errorBuffer: Array = (INT * 4).from_address(infoPtr)

        if -141 <= error <= -101:
            errorInfo: Tuple[Any, ...] = unpack_from('iiii', errorBuffer)
            outString: str             = FasmError.ERROR_NAMES[error + 141]

            line: int        = errorInfo[1] - 1
            lines: List[str] = self._sourceCode.splitlines()

            if 0 < line <= len(lines):
                outString += f"\n    -> Line: {line}"
                outString += "\n    -> ASM:"

                for i in range(line - 5, line + 6):
                    if i < 0 or i >= len(lines):
                        continue

                    if i == line:
                        outString += f"\nERROR -> [{i}] " + lines[i]
                    else:
                        outString += f"\n         [{i}] " + lines[i]

            return outString

        return ""
