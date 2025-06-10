"""
:platform: Windows
"""

from ctypes import CFUNCTYPE, POINTER, byref
from ctypes.wintypes import BYTE, CHAR, DWORD, LPVOID
from typing import Callable

from _ctypes import Array

from MemLib.Constants import MEM_COMMIT, MEM_RELEASE, PAGE_EXECUTE_READWRITE
from MemLib.FlatAssembler import compile_asm
from MemLib.Kernel32 import VirtualAlloc, VirtualFree, Win32Exception
from MemLib.Structs import Struct


def generate_assembly_payload(file_path: str) -> str:
    """
    Generates a prettified string of opcode from a file using FASM. String is optimized to fit into 120 char line
    length including indentations for "readability".

    :param file_path: The path to the file including the name of the file.
    :returns: The pretiffied opcode in python like bytes assignments.
    """

    with open(file_path) as asm:
        binary: bytes = compile_asm(asm.read())
        opcode: str = binary.hex().upper()
        out: str = ""

        while len(opcode):
            temp: str = opcode[:74]
            temp = ' '.join(a + b for a, b in zip(temp[::2], temp[1::2]))
            out += f"'{temp}'\n"
            opcode = opcode[74::]

        return out


class Pattern(Struct):

    _fields_ = [
        ('length', DWORD),
        ('binary', BYTE * 256),
        ('mask', BYTE * 256),
        ("offset", DWORD),
    ]

    def __init__(self, combo_pattern: str, offset: int = 0):
        """
        Container for pattern, utilizes auto breakdown of combo pattern.
        Combo patterns can contain wildcards and spaces.
        Currently supported wildcards: '*', '.', '_' and '?'

        Example: Pattern("55 8B EC ?? 33 C0")

        Note: Single wildcards do not work.
              Pattern("55 8B EC ? 33 C0") will raise a ValueError.
              Pattern("55 8B EC 5? 33 C0") result to the same Pattern as in the Example.

        :raises ValueError: If the pattern has an invalid length (length is not even).
        :param combo_pattern: The pattern.
        :param offset: The offset.
        """

        if len(combo_pattern) % 2 != 0:
            raise ValueError("Pattern has an invalid length!")

        binary: str = ""
        mask: str   = ""

        for a, b in zip(combo_pattern[::2], combo_pattern[1::2]):
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

    def is_valid(self):
        """
        :returns: True if the pattern is valid, False otherwise.
        """

        return self.length > 0


class BinaryScanner:
    __PAYLOAD = bytes.fromhex(
        '55 89 E5 83 EC 08 53 51 52 56 57 8B 55 08 8B 02 85 C0 74 51 48 8B 9A 04 02 00 00 89 5D FC 8D 72 04 8D BA 04 01'
        '00 00 8B 55 0C 8B 1A 8B 4A 04 89 5D F8 29 C1 8A 14 06 39 CB 73 28 38 14 03 75 20 50 48 80 3C 07 78 75 08 8A 34'
        '06 38 34 03 75 04 85 C0 75 ED 58 75 09 89 D8 8B 5D F8 29 D8 EB 05 43 EB D4 31 C0 85 C0 74 03 03 45 FC 5F 5E 5A'
        '59 5B 83 C4 08 C9 C2 08 00'
    )

    class _Buffer(Struct):
        _fields_ = [
            ('base', LPVOID),
            ('end', LPVOID),
        ]

    def __init__(self, buffer: bytes | None = None, base: int = 0):
        """
        A 32 bit scanner written in assembly that works with a mask. It utilizes a Pattern object to make it more
        user-friendly. You can create multiple Binary Scanner for different byte buffers.
        Make sure to call 'Close' when you don't need it anymore to free the memory.

        :raises Win32Exception: If it could not allocate memory for the payload or the buffer.
        :param buffer: The bytes where the scanner will run the pattern on.
        """

        self._buffer: BinaryScanner._Buffer = BinaryScanner._Buffer(0, 0)
        self._base:   int                   = base

        # Writing payload to py memory
        payload: bytes = BinaryScanner.__PAYLOAD

        self._handler_address: int = VirtualAlloc(0, len(payload), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        if not self._handler_address:
            raise Win32Exception()

        binary: Array = (CHAR * len(payload)).from_address(self._handler_address)
        binary.value  = payload

        # Transform py written payload to a callable function
        functype: CFUNCTYPE = CFUNCTYPE(DWORD, POINTER(Pattern), POINTER(BinaryScanner._Buffer))

        self._handler: Callable[[str, str], int] = functype(self._handler_address)

        # Writing buffer to py memory
        if buffer is not None:
            self.set_buffer(buffer, base)

    def get_base(self) -> int:
        return self._base

    def close(self) -> None:
        """
        Closes the BinaryScanner and frees the allocated memory.
        """

        if not VirtualFree(self._handler_address, 0, MEM_RELEASE):
            raise Win32Exception()

        self._handler_address = 0

    def set_buffer(self, new_buffer: bytes, base: int = 0) -> None:
        """
        Change the buffer where the BinaryScanner will run the pattern on.

        :raises Win32Exception: If it could not allocate memory for the buffer.
        :param new_buffer: The new buffer.
        """

        size: int = len(new_buffer)

        if self._buffer.base:
            print("freed old buffer")
            VirtualFree(self._buffer.base, 0, MEM_RELEASE)

        self._base        = base
        self._buffer.base = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        if not self._buffer.base:
            raise Win32Exception()

        buffer: Array = (CHAR * size).from_address(self._buffer.base)
        buffer.value  = new_buffer

        self._buffer.end = self._buffer.base + size

    def find_rva(self, pattern: str | Pattern) -> int:
        """
        Finds the pattern in the buffer and returns the RVA (Relative Virtual Address).
        A RVA is the offset to the base address of a module.
        In the BinaryScanner the RVA is the offset from the beginning of the buffer.

        :param pattern: A string of a ComboPattern or the Pattern object itself.
        :returns: The RVA where the pattern was found. If not found it returns 0.
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
        Finds the pattern in the buffer and returns the virtual Address.

        :param pattern: A string of a ComboPattern or the Pattern object itself.
        :returns: The virtual Address where the pattern was found. If not found it returns 0.
        """

        rva = self.find_rva(pattern)
        return self._base + rva


if __name__ == '__main__':
    scanner_opcode: str = generate_assembly_payload("Scanner.asm")
    print(scanner_opcode)
