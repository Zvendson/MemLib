"""
:platform: Windows
"""

from ctypes import CFUNCTYPE, POINTER, byref
from ctypes.wintypes import BYTE, CHAR, DWORD, LPVOID
from os import PathLike
from typing import Callable, Type

from _ctypes import Array

from MemLib.Constants import MEM_COMMIT, MEM_RELEASE, PAGE_EXECUTE_READWRITE
from MemLib.FlatAssembler import Compile
from MemLib.Kernel32 import VirtualAlloc, VirtualFree, Win32Exception
from MemLib.Structs import Struct


def generateAssemblyPayload(file: int | str | bytes | PathLike[str] | PathLike[bytes]) -> str:
    """
    Generates a prettified string of opcode from a file using FASM. String is optimized to fit into 120 char line
    length including indentations for "readability".

    :param file: The path to the file including the name of the file.
    :returns: The pretiffied opcode in python like bytes assignments.
    """

    with open(file) as asm:
        opcode: bytes = Compile(asm.read())
        opcode: str = opcode.hex().upper()
        out:    str = ""

        while len(opcode):
            temp: str = opcode[:74]
            temp = ' '.join(a + b for a, b in zip(temp[::2], temp[1::2]))
            out += f"'{temp}'\n"
            opcode = opcode[74::]

        return out


class Pattern(Struct):

    _fields_ = [
        ('Length', DWORD),
        ('Binary', BYTE * 256),
        ('Mask', BYTE * 256),
        ("Offset", DWORD),
    ]

    def __init__(self, comboPattern: str, offset: int = 0):
        """
        Container for pattern, utilizes auto breakdown of combo pattern.
        Combo patterns can contain wildcards and spaces.
        Currently supported wildcards: '*', '.', '_' and '?'

        Example: Pattern("55 8B EC ?? 33 C0")

        Note: Single wildcards do not work.
              Pattern("55 8B EC ? 33 C0") will raise a ValueError.
              Pattern("55 8B EC 5? 33 C0") result to the same Pattern as in the Example.

        :raises ValueError: If the pattern has an invalid length (length is not even).
        :param comboPattern: The pattern.
        :param offset: The offset.
        """

        combo: str = comboPattern.replace(' ', '')
        combo      = combo.replace('*', '?')
        combo      = combo.replace('.', '?')
        combo      = combo.replace('_', '?')

        if len(combo) % 2 != 0:
            raise ValueError("Pattern has an invalid length!")

        binary: str = ''
        mask:   str = ''

        for a, b in zip(combo[::2], combo[1::2]):
            if '?' in (a + b):
                binary += '00'
                mask += '?'
            else:
                binary += a + b
                mask += 'x'

        super().__init__(
            len(mask),
            (BYTE * 256)(*bytes.fromhex(binary)),
            (BYTE * 256)(*mask.encode()),
            offset
        )

    def IsValid(self):
        """
        :returns: True if the pattern is valid, False otherwise.
        """

        return self.Length > 0


class BinaryScanner:
    __PAYLOAD = bytes.fromhex(
        '55 89 E5 83 EC 08 53 51 52 56 57 8B 55 08 8B 02 85 C0 74 51 48 8B 9A 04 02 00 00 89 5D FC 8D 72 04 8D BA 04 01'
        '00 00 8B 55 0C 8B 1A 8B 4A 04 89 5D F8 29 C1 8A 14 06 39 CB 73 28 38 14 03 75 20 50 48 80 3C 07 78 75 08 8A 34'
        '06 38 34 03 75 04 85 C0 75 ED 58 75 09 89 D8 8B 5D F8 29 D8 EB 05 43 EB D4 31 C0 85 C0 74 03 03 45 FC 5F 5E 5A'
        '59 5B 83 C4 08 C9 C2 08 00'
    )

    class _Buffer(Struct):
        _fields_ = [
            ('Base', LPVOID),
            ('End', LPVOID),
        ]

    def __init__(self, buffer: bytes | None = None):
        """
        A 32 bit scanner written in assembly that works with a mask. It utilizes a Pattern object to make it more
        user friendly. You can create multiple Binary Scanner for different byte buffers.
        Make sure to call 'Close' when you dont need it anymore to free the memory.

        :raises Win32Exception: If it could not allocate memory for the payload or the buffer.
        :param buffer: The bytes where the scanner will run the pattern on.
        """

        self._buffer: BinaryScanner._Buffer = BinaryScanner._Buffer(0, 0)

        # Writing payload to py memory
        payload: bytes = BinaryScanner.__PAYLOAD

        self._handlerAddress: int = VirtualAlloc(0, len(payload), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        if not self._handlerAddress:
            raise Win32Exception()

        binary: Array = (CHAR * len(payload)).from_address(self._handlerAddress)
        binary.value  = payload

        # Transform py written payload to a callable function
        functype:      CFUNCTYPE          = CFUNCTYPE(DWORD, POINTER(Pattern), POINTER(BinaryScanner._Buffer))

        self._handler: Callable[[str, str], int] = functype(self._handlerAddress)

        # Writing buffer to py memory
        if buffer is not None:
            self.SetBuffer(buffer)

    def Close(self) -> None:
        """
        Closes the BinaryScanner and frees the allocated memory.
        """

        if not VirtualFree(self._handlerAddress, 0, MEM_RELEASE):
            raise Win32Exception()

        self._handlerAddress = 0

    def SetBuffer(self, newBuffer: bytes) -> None:
        """
        Change the buffer where the BinaryScanner will run the pattern on.

        :raises Win32Exception: If it could not allocate memory for the buffer.
        :param newBuffer: The new buffer.
        """

        size: int = len(newBuffer)

        if self._buffer.Base:
            print("freed old buffer")
            VirtualFree(self._buffer.Base, 0, MEM_RELEASE)

        self._buffer.Base = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        if not self._buffer.Base:
            raise Win32Exception()

        buffer: Array = (CHAR * size).from_address(self._buffer.Base)
        buffer.value  = newBuffer

        self._buffer.End = self._buffer.Base + size

    def Find(self, pattern: str | Pattern) -> int:
        """
        Finds the pattern in the buffer and returns the RVA (Relative Virtual Address).
        A RVA is the offset to the base address of a module.
        In the BinaryScanner the RVA is the offset from the beginning of the buffer.

        :param pattern: A string of a ComboPattern or the Pattern object itself.
        :returns: The RVA where the pattern was found. If not found it returns 0.
        """

        if not self._handlerAddress:
            raise RuntimeError("Scanner is not initialized!")

        if isinstance(pattern, str):
            pattern = Pattern(pattern)

        if not isinstance(pattern, Pattern) or not pattern.IsValid():
            raise ValueError("Invalid Pattern: " + str(pattern))

        return self._handler(byref(pattern), byref(self._buffer))


if __name__ == '__main__':
    scanner: str = generateAssemblyPayload("Scanner.asm")
    print(scanner)



