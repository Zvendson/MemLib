# MemLib

**MemLib** is a Windows-only Python library for low-level memory manipulation, remote process introspection, and binary pattern scanning with native FASM-powered assembly code.

> ⚠️ Requires a 32-bit or 64-bit Windows OS with permissions to interact with other processes.

## Features

* 🧠 **Process Manipulation**

  * Open, suspend, resume, terminate processes
  * Read/write remote memory (raw, strings, structures)
  * Enumerate modules and threads
  * Remote thread injection

* 🔍 **Pattern Scanning**

  * Written in assembly
  * High-speed binary scan using native x86/x64 routines
  * Wildcard mask support (`55 EC ?? ?? 90 90`)
  * Architecture-aware payload selection

* 🪝 **Inline Hooking**

  * JMP/CALL code hook installation
  * Buffer-persisted recovery support
  * Toggle, enable, disable hooks at runtime

* 🧩 **Flat Assembler Integration**

  * Compile raw x86/x64 assembly from Python at runtime
  * Structured FASM error reporting with source context

* 📦 **Struct Utilities**

  * Colorized, pretty-printing `ctypes.Structure` base class wrapper
  * Automatic identifier detection and layout display

---

## Installation

WIP

---

## Requirements

* Windows (32-bit or 64-bit)
* Python 3.10+

---

## License

MIT License. See [LICENSE](LICENSE) for details.
