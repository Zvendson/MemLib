# MemLib

`MemLib` is a Windows-only Python package for working with Win32 APIs through `ctypes`, with higher-level helpers for process inspection, remote memory access, binary scanning, runtime assembly generation, hooks, and shared memory.

## What It Covers

- Process, module, and thread wrappers over common Win32 APIs
- Remote memory read/write helpers for raw bytes, strings, and structs
- Binary pattern scanning with 32-bit and 64-bit FASM-backed payloads
- Runtime assembly generation and compilation
- Simple inline JMP hooks for local or remote processes
- Shared memory helpers for cross-process communication
- Utility decorators, registry helpers, and structure formatting tools

## Installation

Base package:

```powershell
pip install MemLib
```

With KeePass support:

```powershell
pip install "MemLib[keepass]"
```

For local testing:

```powershell
pip install "MemLib[test]"
```

## Requirements

- Windows
- Python 3.10+

## Quick Start

Top-level imports are available for the main public API:

```python
from MemLib import Process, SharedMemory, FASM, Hook, Struct
```

Open a process and inspect it:

```python
from MemLib import Process

process = Process.get_first_process("notepad.exe")
if process is None:
    raise RuntimeError("notepad.exe is not running")

print(process)
print(process.get_main_module())
print(process.get_threads())
```

Compile a small FASM snippet:

```python
from MemLib import FASM

fasm = FASM()
fasm.use64()
fasm.write("entry:\n  nop\n  ret")
fasm.export("entry")

binary = fasm.compile()
entry_address = fasm.get_export("entry")
print(binary.hex())
print(entry_address)
```

Work with a custom struct:

```python
from ctypes.wintypes import DWORD

from MemLib import Struct


class ExampleStruct(Struct):
    value: DWORD


example = ExampleStruct()
example.value = 123
print(example)
print(example.prettify())
```

## Public API

Main exports from `MemLib`:

- `Process`, `Module`, `Thread`, `Priority`
- `SharedMemory`, `SharedMemoryBuffer`, `close_shared_memory_connection`
- `Pattern`, `BinaryScanner`
- `FASM`, `compile_asm`, `get_version`, `get_version_string`
- `Hook`, `HookBuffer`
- `Struct`, `Stopwatch`
- `func_timer`, `require_admin`, `require_32bit`, `require_64bit`, `deprecated`
- `Win32Exception`
- `windows`, `Constants`

KeePass helpers live behind the optional `keepass` extra:

```python
from MemLib.CredentialManager import CredentialManager, Credentials
```

## Hook Notes

- `Hook` is a simple inline jump hook helper, not a full detour engine.
- On x86 and on nearby x64 targets, it uses a 5-byte `jmp rel32`.
- On x64, when the destination is out of `rel32` range, it falls back to an absolute jump sequence via `RAX`.
- `HookBuffer` stores the original bytes and hook metadata so a hook can be disabled or reconstructed from stored state.

## Notes

- This package is Windows-only and depends heavily on native Win32 behavior.
- Some features require elevated privileges, depending on the target process.
- The project ships native DLL and assembly assets used by the scanner and assembler helpers.
- Package metadata currently marks the project as `Beta`.

## License

MIT. See [LICENSE](LICENSE).
