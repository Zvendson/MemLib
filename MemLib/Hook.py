"""
:platform: Windows

Contains structures and classes to manage runtime code hooks in external processes.

- HookBuffer: Structure for storing hook information in remote memory.
- Hook:      Manages jump/call hooks, their state, and their persistence.
"""

import struct
from ctypes.wintypes import BYTE, DWORD

from MemLib.Process import Process
from MemLib.Structs import Struct


class HookBuffer(Struct):
    """
    Structure to store information about an installed hook.

    Used to persist the original bytes and metadata at a specified location in the target process,
    so the hook can be restored even after a crash or restart.

    Fields:
        original_opcode (BYTE * 5):   Original bytes at the hook address.
        source_address  (DWORD):      Address where the hook was installed.
        target_address  (DWORD):      Address where the jump/call redirects to.
    """

    _pack_ = 1
    original_opcode: BYTE * 5
    source_address:  DWORD
    target_address:  DWORD

    def has_contents(self) -> bool:
        """
        Checks if the buffer contains valid hook information.

        Returns:
            bool: True if both original_opcode and addresses are set, False otherwise.
        """
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
    Manages an inline code hook (e.g., a JMP) in a remote process.

    On construction, can immediately enable the hook and optionally store the original
    bytes and hook information in remote process memory for recovery.

    Parameters:
        name (str):        Identifier for the hook.
        process (Process): The target process object.
        source (int):      Address in the target process to patch (hook entry point).
        destination (int): Address in the target process to jump/call to.
        enable_hook (bool):If True, immediately installs the hook.
        buffer (int):      Address in the target process for storing HookBuffer. If zero, persistence is skipped.

    Usage:
        hook = Hook(name="MyHook", process=proc, source=0x401000, destination=0x402000, enable_hook=True, buffer=0x500000)
    """

    def __init__(self, *, name: str, process: Process, source: int, destination: int, enable_hook: bool = False,
                 buffer: int = 0) -> None:
        """
        Initializes a new Hook instance.

        Parameters:
            name (str):        Name of the hook.
            process (Process): Target process.
            source (int):      Hook address in the process.
            destination (int): Jump/call target address.
            enable_hook (bool):Enable the hook immediately.
            buffer (int):      Remote address to store buffer struct (for crash recovery).
        """
        self._name: str                 = name
        self._process: Process          = process
        self._src_address: int          = source
        self._dst_address: int          = destination
        self._opcode: bytes             = struct.pack('=Bi', 0xE9, destination - source - 0x0005)
        self._enabled: bool             = False
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
        if enable_hook:
            self.enable()

    @classmethod
    def from_stored_buffer(cls, name: str, process: Process, buffer_address: int = 0) -> 'Hook':
        """
        Creates a Hook instance using a stored HookBuffer in process memory.

        Parameters:
            name (str):         Name for the hook.
            process (Process):  Target process.
            buffer_address (int):Remote address containing the HookBuffer.

        Returns:
            Hook: New Hook instance restored from buffer.
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
        """
        Returns a human-readable string representation of the hook.

        Returns:
            str: Human-readable summary.
        """
        return f"{self._name}-Hook(Source=0x{self._src_address:08X}, Target=0x{self._dst_address:08X}, Storage=" \
               f"0x{self._buffer.get_address():08X}, Hook='{self._opcode.hex(' ').upper()}', OriginalOpcode" \
               f"='{bytes(self._buffer.original_opcode).hex(' ').upper()}', Process={self._process.get_process_id()})"

    def __repr__(self):
        """
        Returns the canonical string representation of the hook.

        Returns:
            str: Canonical string representation.
        """
        return str(self)

    @property
    def name(self) -> str:
        """
        Returns the name of the hook.

        Returns:
            str: The hook name.
        """
        return self._name

    @property
    def src_address(self) -> int:
        """
        Returns the address where the hook is or will be written.

        Returns:
            int: The source address for the hook.
        """
        return self._src_address

    @property
    def dest_address(self) -> int:
        """
        Returns the jump/call target address of the hook.

        Returns:
            int: The destination address.
        """
        return self._dst_address

    @property
    def process(self) -> Process:
        """
        Returns the process object where the hook is managed.

        Returns:
            Process: The target process.
        """
        return self._process

    @property
    def buffer(self) -> HookBuffer:
        """
        Returns the buffer structure with the original opcode and addresses.

        Returns:
            HookBuffer: The buffer instance.
        """
        return self._buffer

    def is_enabled(self) -> bool:
        """
        Checks if the hook is currently enabled.

        Returns:
            bool: True if enabled, False otherwise.
        """
        return self._enabled

    def enable(self) -> None:
        """
        Installs (enables) the hook in the target process.

        If the hook is already enabled, this method does nothing.
        Otherwise, it writes the JMP instruction at the source address
        and updates the enabled state.
        """
        if self._enabled:
            return

        self._process.write(self._src_address, self._opcode)
        self._enabled = True

    def disable(self) -> None:
        """
        Restores (disables) the original bytes at the hook location.

        If the hook is not enabled, this method does nothing.
        Otherwise, it writes back the saved original opcode at the source
        address and updates the enabled state.
        """
        if not self._enabled:
            return

        self._process.write(self._src_address, bytes(self._buffer.original_opcode))
        self._enabled = False

    def toggle(self) -> bool:
        """
        Toggles the enabled state of the hook (on/off).

        Returns:
            bool: The new enabled state (True if enabled, False if disabled).
        """
        if self._enabled:
            self.disable()
        else:
            self.enable()

        return self._enabled

    def store(self, buffer_address: int) -> bool:
        """
        Stores the buffer information at a specified address in the target process.

        Parameters:
            buffer_address (int): Address to store the HookBuffer.

        Returns:
            bool: True if buffer is stored successfully, False otherwise.
        """
        if buffer_address:
            self._buffer_address = buffer_address
            return self._process.write_struct(self._buffer_address, self._buffer)

        return False
