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
    hook was already written. If storeBufferAddress is non zero it will check if its already written and adapt to the
    buffer and will store a struct of 14 Bytes at the address in every case.

    :param name: the name of the Hook.
    :param process: target Process.
    :param sourceAddress: the address in the Process to write the jump at.
    :param destinationAddress: the address in the Process where the jump should target to.
    :param enableHook: If True it will write the jump immediately into targets process memory.
    :param bufferAddress: the address in the Process to store the buffer.
    """

    def __init__(self, *,
                 name: str,
                 process: Process,
                 sourceAddress: int,
                 destinationAddress: int,
                 enableHook: bool = False,
                 bufferAddress: int = 0):
        self._name: str                 = name
        self._process: Process          = process
        self._srcAddress: int           = sourceAddress
        self._dstAddress: int           = destinationAddress
        self._opcode: bytes             = struct.pack('=Bi', 0xE9, destinationAddress - sourceAddress - 0x0005)
        self._enabled: bool             = enableHook
        self._bufferAddress: int        = bufferAddress
        self._buffer: HookBuffer | None = None

        originalOpcode: bytes = self._process.Read(sourceAddress, 5)
        buffer: bytes         = struct.pack('=5BII', *originalOpcode, sourceAddress, destinationAddress)

        if bufferAddress:
            self._buffer = self._process.ReadStruct(bufferAddress, HookBuffer)

        if self._buffer is None or self._buffer.SourceAddress == 0:
            self._buffer = HookBuffer.from_buffer_copy(buffer)
            self._buffer.AddressEx = bufferAddress

        if originalOpcode == self._opcode:
            self._enabled = True

        self.Store(bufferAddress)
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
            sourceAddress=buffer.SourceAddress,
            destinationAddress=buffer.TargetAddress,
            bufferAddress=bufferAddress,
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

    def Toggle(self) -> None:
        """
        Toggles the Hook between enabled and disabled.
        """

        self.Enable(not self._enabled)

    def Store(self, bufferAddress: int) -> bool:
        """
        Stores the buffer at the specific address

        :param bufferAddress: the address in the Process to store the buffer.
        :return: True if it could store it successfully, False otherwise.
        """

        if bufferAddress:
            self._bufferAddr = bufferAddress
            return self._process.WriteStruct(self._bufferAddr, self._buffer)

        return False
