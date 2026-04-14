from ctypes import addressof, c_char, c_int32, create_string_buffer

import pytest

import MemLib.FlatAssembler as flat
from MemLib.FasmWrapper import FASM


class _FakeDll:
    def __init__(self, version=0):
        self._version = version
        self.fasm_Assemble = lambda *_args: 0

    def fasm_GetVersion(self):
        return self._version


def test_allocate_in_32bit_space_rejects_high_max_addr():
    with pytest.raises(ValueError):
        flat.allocate_in_32bit_space(0x1000, max_addr=0x100000001)


def test_allocate_in_32bit_space_returns_first_valid_low_address(monkeypatch):
    calls = []

    def fake_alloc(base, size, alloc_type, prot):
        calls.append((base, size, alloc_type, prot))
        if len(calls) == 1:
            return 0
        return 0x20000

    monkeypatch.setattr(flat, "VirtualAlloc", fake_alloc)
    monkeypatch.setattr(flat, "VirtualFree", lambda *_args: False)

    address = flat.allocate_in_32bit_space(0x1000, min_addr=0x10000, max_addr=0x30000)

    assert address == 0x20000
    assert calls[0][0] == 0x10000
    assert calls[1][0] == 0x20000


def test_allocate_in_32bit_space_frees_addresses_above_limit(monkeypatch):
    freed = []

    monkeypatch.setattr(flat, "VirtualAlloc", lambda *_args: 0x100000000)
    monkeypatch.setattr(flat, "VirtualFree", lambda addr, size, flag: freed.append((addr, size, flag)) or True)

    with pytest.raises(MemoryError):
        flat.allocate_in_32bit_space(0x1000, min_addr=0x10000, max_addr=0x20000)

    assert freed == [(0x100000000, 0, flat.MEM_RELEASE)]


def test_get_version_and_string(monkeypatch):
    monkeypatch.setattr(flat, "_FASM", _FakeDll(version=(25 << 16) | 1))

    assert flat.get_version() == (1, 25)
    assert flat.get_version_string() == "Flat Assembler v1.25"


def test_compile_asm_returns_binary_slice(monkeypatch):
    source_code = "nop"
    max_memory_size = 16
    src_addr = 0x1000
    dst_addr = src_addr
    expected = b"\x90\xC3"
    payload = b"\x00" * 12 + expected + b"\x00" * (max_memory_size - 12 - len(expected))
    dword_values = {
        dst_addr + 0x0004: len(expected),
        dst_addr + 0x0008: dst_addr + 12,
    }

    class _Cell:
        def __init__(self, value):
            self.value = value

    class _FakeDword:
        @staticmethod
        def from_address(address):
            return _Cell(dword_values[address])

    class _FakeCharFactory:
        @staticmethod
        def from_address(address):
            assert address == dst_addr
            return payload

    class _FakeCharMeta(type):
        def __mul__(cls, other):
            assert other == max_memory_size
            return _FakeCharFactory

    class _FakeChar(metaclass=_FakeCharMeta):
        pass

    freed = []

    monkeypatch.setattr(flat, "allocate_in_32bit_space", lambda size: src_addr - (len(source_code.encode("ascii")) + 1))
    monkeypatch.setattr(flat, "memmove", lambda *_args: None)
    monkeypatch.setattr(flat, "_FASM", type("FakeAsm", (), {"fasm_Assemble": staticmethod(lambda *_args: 0)})())
    monkeypatch.setattr(flat, "VirtualFree", lambda addr, size, flag: freed.append((addr, size, flag)) or True)
    monkeypatch.setattr(flat, "DWORD", _FakeDword)
    monkeypatch.setattr(flat, "CHAR", _FakeChar)

    binary = flat.compile_asm(source_code, max_memory_size=max_memory_size)

    assert binary == expected
    assert freed == [(src_addr - (len(source_code.encode("ascii")) + 1), 0, flat.MEM_RELEASE)]


def test_compile_asm_raises_fasm_error_and_frees_memory(monkeypatch):
    src_addr = 0x3000
    captured = []
    freed = []

    monkeypatch.setattr(flat, "allocate_in_32bit_space", lambda size: src_addr)
    monkeypatch.setattr(flat, "memmove", lambda *_args: None)
    monkeypatch.setattr(flat, "_FASM", type("FakeAsm", (), {"fasm_Assemble": staticmethod(lambda *_args: 1)})())
    monkeypatch.setattr(flat, "VirtualFree", lambda addr, size, flag: freed.append((addr, size, flag)) or True)
    monkeypatch.setattr(
        flat,
        "FASMError",
        lambda dst, source: captured.append((dst, source)) or RuntimeError(f"fasm error at {dst}"),
    )

    with pytest.raises(RuntimeError) as exc_info:
        flat.compile_asm("nop", max_memory_size=32)

    assert "fasm error at 12292" in str(exc_info.value)
    assert captured == [(12292, "nop")]
    assert freed == [(src_addr, 0, flat.MEM_RELEASE)]


def test_fasm_error_formats_error_context():
    source = "line0\nline1\nline2\nline3\nline4\nline5\nline6"
    base = 0x1000
    info_ptr = 0x2000
    memory = {
        base: flat.FASMNState.ERROR.value,
        base + 4: flat.FASMERR.INVALID_OPERAND.value,
        base + 8: info_ptr,
    }
    info = [0, 4, 0, 0]

    class _Cell:
        def __init__(self, value):
            self.value = value

    class _FakeArrayFactory:
        @staticmethod
        def from_address(address):
            assert address == info_ptr
            return info

    class _FakeIntMeta(type):
        def __mul__(cls, other):
            assert other == 4
            return _FakeArrayFactory

    class _FakeInt(metaclass=_FakeIntMeta):
        @staticmethod
        def from_address(address):
            return _Cell(memory[address])

    class _FakeDword:
        @staticmethod
        def from_address(address):
            return _Cell(memory[address])

    original_int = flat.INT
    original_dword = flat.DWORD
    try:
        flat.INT = _FakeInt
        flat.DWORD = _FakeDword
        error = flat.FASMError(base, source)
    finally:
        flat.INT = original_int
        flat.DWORD = original_dword

    message = str(error)

    assert "ERROR(2)" in message
    assert "INVALID_OPERAND (Code: -109)" in message
    assert "line3" in message


def test_enum_missing_values_are_preserved():
    assert flat.FASMNState(12345).name == "UNKNOWN"
    assert flat.FASMERR(-999).name == "UNKNOWN"


def test_fasm_wrapper_switches_architecture_and_builds_assembly(monkeypatch):
    monkeypatch.setattr("MemLib.FasmWrapper.windows.is_32bit", lambda: True)
    fasm = FASM()

    fasm.use64().format("pe").org(0x401000)
    fasm.define("CONST", 7)
    fasm.write("start:\n  nop")
    fasm.add_byte("byte_var", 1)
    fasm.add_word("word_var", 2)
    fasm.add_dword("dword_var", 3)
    fasm.add_qword("qword_var", 4)
    fasm.add_byte_array("byte_arr", 5)
    fasm.add_word_array("word_arr", 6)
    fasm.add_dword_array("dword_arr", 7)
    fasm.add_qword_array("qword_arr", 8)
    fasm.add_buffer("buf", b"\xAA\xBB")
    fasm.add_string("txt", "abc")
    fasm.add_wstring("wtxt", "xyz")
    fasm.export("target")
    fasm.write("target:\n  ret")

    assembly = fasm.generate_assembly()

    assert "format pe" in assembly
    assert "use64" in assembly
    assert "org 4198400" in assembly
    assert "CONST = 7" in assembly
    assert "byte_var db 1" in assembly
    assert "word_var dw 2" in assembly
    assert "dword_var dd 3" in assembly
    assert "qword_var dq 4" in assembly
    assert "byte_arr rb 5" in assembly
    assert "word_arr rw 6" in assembly
    assert "dword_arr rd 7" in assembly
    assert "qword_arr rq 8" in assembly
    assert "buf db 0xAA, 0xBB" in assembly
    assert "txt db 'abc', 0" in assembly
    assert "wtxt du 'xyz', 0" in assembly
    assert "dq target" in assembly
    assert fasm._export_map["target"] == 8


def test_fasm_wrapper_rejects_duplicate_symbols():
    fasm = FASM()
    fasm.add_byte("dup", 1)

    with pytest.raises(KeyError):
        fasm.add_word("dup", 2)

    fasm.export("label")
    with pytest.raises(KeyError):
        fasm.export("label")


def test_fasm_wrapper_compile_and_get_export(monkeypatch):
    fasm = FASM()
    fasm.use32()
    fasm.write("entry:\n  ret")
    fasm.export("entry")

    def fake_compile(source, max_memory_size, max_iterations):
        assert "entry:" in source
        return b"\xC3" + (0x12345678).to_bytes(4, "little")

    monkeypatch.setattr("MemLib.FasmWrapper.compile_asm", fake_compile)

    binary = fasm.compile()

    assert binary == b"\xC3" + (0x12345678).to_bytes(4, "little")
    assert fasm.get_export("entry") == 0x12345678


def test_fasm_wrapper_get_export_requires_compile():
    fasm = FASM()

    with pytest.raises(RuntimeError):
        fasm.get_export("missing")
