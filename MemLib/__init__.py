"""
Public package interface for MemLib.

MemLib is a Windows-only toolkit for process inspection, memory access,
binary scanning, runtime assembly generation, and related ctypes helpers.
"""

from MemLib import Constants, windows
from MemLib.Decorators import deprecated, func_timer, require_32bit, require_64bit, require_admin
from MemLib.Exceptions import NoAdminPrivileges, Not32BitException, Not64BitException
from MemLib.FlatAssembler import (
    FASMERR,
    FASMNState,
    FASMError,
    allocate_in_32bit_space,
    compile_asm,
    get_version,
    get_version_string,
)
from MemLib.FasmWrapper import FASM
from MemLib.Hook import Hook, HookBuffer
from MemLib.Module import Module
from MemLib.Process import Process
from MemLib.Registry import get_registry_value, set_registry_value
from MemLib.Scanner import BinaryScanner, Pattern, generate_assembly_payload
from MemLib.SharedMemory import (
    SharedMemory,
    SharedMemoryBuffer,
    SharedMemoryCleanupError,
    close_shared_memory_connection,
)
from MemLib.Stopwatch import Stopwatch
from MemLib.Struct import Struct
from MemLib.Thread import Priority, Thread
from MemLib.windows import Win32Exception

try:
    from MemLib.CredentialManager import CredentialManager, Credentials
except ModuleNotFoundError:
    CredentialManager = None
    Credentials = None

__version__ = "1.7.6"

__all__ = [
    "BinaryScanner",
    "Constants",
    "CredentialManager",
    "Credentials",
    "FASM",
    "FASMERR",
    "FASMNState",
    "FASMError",
    "Hook",
    "HookBuffer",
    "Module",
    "NoAdminPrivileges",
    "Not32BitException",
    "Not64BitException",
    "Pattern",
    "Priority",
    "Process",
    "SharedMemory",
    "SharedMemoryBuffer",
    "SharedMemoryCleanupError",
    "Stopwatch",
    "Struct",
    "Thread",
    "Win32Exception",
    "__version__",
    "allocate_in_32bit_space",
    "close_shared_memory_connection",
    "compile_asm",
    "deprecated",
    "func_timer",
    "generate_assembly_payload",
    "get_registry_value",
    "get_version",
    "get_version_string",
    "require_32bit",
    "require_64bit",
    "require_admin",
    "set_registry_value",
    "windows",
]
