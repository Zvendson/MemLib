"""
:platform: Windows
"""

from __future__ import annotations

import struct
from ctypes.wintypes import BYTE, DWORD

from MemLib.Process import Process
from MemLib.Structs import Struct


class HookBuffer(Struct):
    """
    A buffer structure containing necessary infos about a hook. It can be stored in a process to guarantee that it
    can be restored when python crashes.
    """

    _pack_ = 1
    _fields_ = [
        ("original_opcode", BYTE * 5),
        ("source_address", DWORD),
        ("target_address", DWORD),
    ]

    def has_contents(self) -> bool:
        values = list(self.original_opcode)

        for val in values:
            if val != 0:
                break
        else:
            return False

        if self.source_address != 0 and self.target_address != 0:
            return True

        return False


class Hook:
    """
    Prepares a Jump-Call in target process and make it toggleable. It also detects if it was already enabled and sets
    the state accordingly. If storeBufferAddress is 0, there will be no way to get the original opcodes back when the
    hook was already written. If storeBufferAddress is nonzero it will check if its already written and adapt to the
    buffer and will store a struct of 14 Bytes at the address in every case.

    :param name: The name of the Hook.
    :param process: Target Process.
    :param source: The address in the Process to write the jump at.
    :param destination: The address in the Process where the jump should target to.
    :param enable_hook: If True it writes the jump immediately into targets process memory.
    :param buffer: The address in the Process to store the buffer.
    """

    def __init__(self, *, name: str, process: Process, source: int, destination: int, enable_hook: bool = False,
                 buffer: int = 0) -> None:

        self._name: str                 = name
        self._process: Process          = process
        self._src_address: int          = source
        self._dst_address: int          = destination
        self._opcode: bytes             = struct.pack('=Bi', 0xE9, destination - source - 0x0005)
        self._enabled: bool             = enable_hook
        self._buffer_address: int       = buffer
        self._buffer: HookBuffer | None = None

        original_opcode: bytes = self._process.read(source, 5)
        buffer_content:  bytes = struct.pack('=5BII', *original_opcode, source, destination)

        if buffer:
            self._buffer = self._process.read_struct(buffer, HookBuffer)

        if self._buffer is None or self._buffer.source_address == 0:
            self._buffer            = HookBuffer.from_buffer_copy(buffer_content)
            self._buffer.ADDRESS_EX = buffer

        if original_opcode == self._opcode:
            self._enabled = True

        self.store(buffer)
        self.enable(enable_hook)

    @classmethod
    def from_stored_buffer(cls, name: str, process: Process, buffer_address: int = 0) -> Hook:
        """
        Creates a hook instance from target address.

        :param name: the name of the hook.
        :param process: the process.
        :param buffer_address: the address in the Process to store the original opcodes.
        :returns: the hook instance.
        """

        buffer: HookBuffer = process.read_struct(buffer_address, HookBuffer)

        return cls(
            name=name,
            process=process,
            source=buffer.source_address,
            destination=buffer.target_address,
            buffer=buffer_address,
        )

    def __str__(self):
        return f"{self._name}-Hook(Source=0x{self._src_address:08X}, Target=0x{self._dst_address:08X}, Storage=" \
               f"0x{self._buffer.get_address():08X}, Hook='{self._opcode.hex(' ').upper()}', OriginalOpcode" \
               f"='{bytes(self._buffer.original_opcode).hex(' ').upper()}', Process={self._process.get_process_id()})"

    def __repr__(self):
        return str(self)

    def get_name(self) -> str:
        return self._name

    def get_source_address(self) -> int:
        """
        :returns: The address where the hook is or will be written.
        """

        return self._src_address

    def get_destination_address(self) -> int:
        """
        :returns: The target address of the jump-call.
        """

        return self._dst_address

    def get_process(self) -> Process:
        """
        :returns: the process the hook is written in.
        """

        return self._process

    def get_buffer(self) -> HookBuffer:
        """
        :returns: the buffer containing the hook details. (original opcode, source addr, target addr)
        """

        return self._buffer

    def is_enabled(self) -> bool:
        """        
        :returns: True if enabled, False otherwise.
        """

        return self._enabled

    def enable(self, enable_hook: bool) -> None:
        """
        Enables or disables the hook.

        :param enable_hook: If True the hook will write a jump at the source address to targets address. If False it will
                           restore the jump to the original opcode.
        """

        if self._enabled == enable_hook:
            return

        self._enabled = enable_hook

        if enable_hook:
            self._process.write(self._src_address, self._opcode)
        else:
            self._process.write(self._src_address, bytes(self._buffer.original_opcode))

    def toggle(self) -> bool:
        """
        Toggles the Hook between enabled and disabled.

        :returns: The new state.
        """

        self.enable(not self._enabled)
        return self._enabled

    def store(self, buffer_address: int) -> bool:
        """
        Stores the buffer at the specific address

        :param buffer_address: the address in the Process to store the buffer.
        :returns: True if it could store it successfully, False otherwise.
        """

        if buffer_address:
            self._buffer_address = buffer_address
            return self._process.write_struct(self._buffer_address, self._buffer)

        return False



