"""
:platform: Windows
"""

from __future__ import annotations

import struct
from ctypes.wintypes import BYTE, DWORD

import memlib.process
import memlib.structs


class HookBuffer(memlib.structs.Struct):
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


class Hook:
    """
    Prepares a Jump-Call in target process and make it toggleable. It also detects if it was already enabled and sets
    the state accordingly. If storeBufferAddress is 0, there will be no way to get the original opcodes back when the
    hook was already written. If storeBufferAddress is non zero it will check if its already written and adapt to the
    buffer and will store a struct of 14 Bytes at the address in every case.

    :param process: target Process.
    :param sourceAddress: the address in the Process to write the jump at.
    :param destinationAddress: the address in the Process where the jump should target to.
    :param enableHook: If True it will write the jump immediately into targets process memory.
    :param bufferAddress: the address in the Process to store the buffer.
    """

    def __init__(self, *,
                 process: memlib.process.Process,
                 srcAddr: int,
                 dstAddr: int,
                 enable: bool = False,
                 bufferAddr: int = 0):
        self._proc    = process
        self._srcAddr = srcAddr
        self._dstAddr = dstAddr
        self._opcode  = struct.pack('=Bi', 0xE9, dstAddr - srcAddr - 0x0005)
        self._enabled = enable
        self._bufferAddr = bufferAddr
        self._buffer  = None

        originalOpcode = process.Read(srcAddr, 5)
        buffer         = struct.pack('=5BII', *originalOpcode, srcAddr, dstAddr)

        if bufferAddr:
            self._buffer = process.ReadStruct(bufferAddr, HookBuffer)

        if self._buffer is None or self._buffer.SourceAddress == 0:
            self._buffer = HookBuffer.from_buffer_copy(buffer)
            self._buffer.AddressEx = bufferAddr

        if originalOpcode == self._opcode:
            self._enabled = True

        self.Store(bufferAddr)
        self.Enable(enable)

    @classmethod
    def FromStoredBuffer(cls, process: memlib.process.Process, storeBufferAddress: int = 0) -> Hook:
        """
        Creates a hook instance from target address.

        :param process: the process.
        :param bufferAddress: the address in the Process to store the original opcodes.
        :returns: the hook instance.
        """

        buffer: HookBuffer = process.ReadStruct(storeBufferAddress, HookBuffer)

        print(buffer.ToPrettyString(True))

        hook = cls(
            process=process,
            srcAddr=buffer.SourceAddress,
            dstAddr=buffer.TargetAddress,
            bufferAddr=storeBufferAddress,
        )

        return hook

    def __str__(self):
        return f"Jump(Source=0x{self._srcAddr:08X}, Target=0x{self._dstAddr:08X}, Storage=" \
               f"0x{self._buffer.GetAddress():08X}, Jump='{self._opcode.hex(' ').upper()}', OriginalOpcode" \
               f"='{bytes(self._buffer.OriginalOpcode).hex(' ').upper()}', Process={self._proc.GetProcessId()})"

    def __repr__(self):
        return str(self)

    def GetSourceAddress(self) -> int:
        """
        :returns: The address where the hook is or will be written.
        """

        return self._srcAddr

    def GetDestinationAddress(self) -> int:
        """
        :returns: The target address of the jump-call.
        """

        return self._dstAddr

    def GetProcess(self) -> memlib.process.Process:
        """
        :returns: the process the hook is written in.
        """

        return self._proc

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

    def Enable(self, enable: bool) -> None:
        """
        Enables or disables the hook.

        :param enableHook: If True the hook will write a jump at the source address to targets address. If False it will
                           restore the jump to the original opcode.
        """

        if self._enabled == enable:
            return

        self._enabled = enable

        if enable:
            self._proc.Write(self._srcAddr, self._opcode)
        else:
            self._proc.Write(self._srcAddr, bytes(self._buffer.OriginalOpcode))

    def Toggle(self) -> None:
        """
        Toggles the Hook between enabled and disabled.
        """

        self.Enable(not self._enabled)

    def Store(self, address: int) -> bool:
        """
        Stores the buffer at the specific address

        :param bufferAddress: the address in the Process to store the buffer.
        :return: True if it could store it successfully, False otherwise.
        """

        if address:
            self._bufferAddr = address
            return self._proc.WriteStruct(self._bufferAddr, self._buffer)

        return False
