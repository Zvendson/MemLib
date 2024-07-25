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
        ("OriginalOpcode", BYTE * 5),
        ("SourceAddress", DWORD),
        ("TargetAddress", DWORD),
    ]

    def HasContents(self) -> bool:
        values = list(self.OriginalOpcode)

        for val in values:
            if val != 0:
                break
        else:
            return False

        if self.SourceAddress != 0 and self.TargetAddress != 0:
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
    :param enableHook: If True it writes the jump immediately into targets process memory.
    :param buffer: The address in the Process to store the buffer.
    """

    def __init__(self, *,
                 name:        str,
                 process:     Process,
                 source:      int,
                 destination: int,
                 enableHook:  bool = False,
                 buffer:      int = 0) -> None:

        self._name:          str               = name
        self._process:       Process           = process
        self._srcAddress:    int               = source
        self._dstAddress:    int               = destination
        self._opcode:        bytes             = struct.pack('=Bi', 0xE9, destination - source - 0x0005)
        self._enabled:       bool              = enableHook
        self._bufferAddress: int               = buffer
        self._buffer:        HookBuffer | None = None

        originalOpcode: bytes = self._process.Read(source, 5)
        bufferContent:  bytes = struct.pack('=5BII', *originalOpcode, source, destination)

        if buffer:
            self._buffer = self._process.ReadStruct(buffer, HookBuffer)

        if self._buffer is None or self._buffer.SourceAddress == 0:
            self._buffer = HookBuffer.from_buffer_copy(bufferContent)
            self._buffer.ADRESS_EX = buffer

        if originalOpcode == self._opcode:
            self._enabled = True

        self.Store(buffer)
        self.Enable(enableHook)

    @classmethod
    def FromStoredBuffer(cls, name: str, process: Process, bufferAddress: int = 0) -> Hook:
        """
        Creates a hook instance from target address.

        :param name: the name of the hook.
        :param process: the process.
        :param bufferAddress: the address in the Process to store the original opcodes.
        :returns: the hook instance.
        """

        buffer: HookBuffer = process.ReadStruct(bufferAddress, HookBuffer)

        return cls(
            name=name,
            process=process,
            source=buffer.SourceAddress,
            destination=buffer.TargetAddress,
            buffer=bufferAddress,
        )

    def __str__(self):
        return f"{self._name}-Hook(Source=0x{self._srcAddress:08X}, Target=0x{self._dstAddress:08X}, Storage=" \
               f"0x{self._buffer.GetAddress():08X}, Hook='{self._opcode.hex(' ').upper()}', OriginalOpcode" \
               f"='{bytes(self._buffer.OriginalOpcode).hex(' ').upper()}', Process={self._process.GetProcessId()})"

    def __repr__(self):
        return str(self)

    def GetName(self) -> str:
        return self._name

    def GetSourceAddress(self) -> int:
        """
        :returns: The address where the hook is or will be written.
        """

        return self._srcAddress

    def GetDestinationAddress(self) -> int:
        """
        :returns: The target address of the jump-call.
        """

        return self._dstAddress

    def GetProcess(self) -> Process:
        """
        :returns: the process the hook is written in.
        """

        return self._process

    def GetBuffer(self) -> HookBuffer:
        """
        :returns: the buffer containing the hook details. (original opcode, source addr, target addr)
        """

        return self._buffer

    def IsEnabled(self) -> bool:
        """        
        :returns: True if enabled, False otherwise.
        """

        return self._enabled

    def Enable(self, enableHook: bool) -> None:
        """
        Enables or disables the hook.

        :param enableHook: If True the hook will write a jump at the source address to targets address. If False it will
                           restore the jump to the original opcode.
        """

        if self._enabled == enableHook:
            return

        self._enabled = enableHook

        if enableHook:
            self._process.Write(self._srcAddress, self._opcode)
        else:
            self._process.Write(self._srcAddress, bytes(self._buffer.OriginalOpcode))

    def Toggle(self) -> bool:
        """
        Toggles the Hook between enabled and disabled.

        :returns: The new state.
        """

        self.Enable(not self._enabled)
        return self._enabled

    def Store(self, bufferAddress: int) -> bool:
        """
        Stores the buffer at the specific address

        :param bufferAddress: the address in the Process to store the buffer.
        :returns: True if it could store it successfully, False otherwise.
        """

        if bufferAddress:
            self._bufferAddress = bufferAddress
            return self._process.WriteStruct(self._bufferAddress, self._buffer)

        return False



