from MemLib.Constants import MEM_RELEASE
from MemLib.FasmWrapper import FASM
import MemLib.FlatAssembler as flat

import pytest


def test_allocate_in_32bit_space_rejects_high_max_addr():
    with pytest.raises(ValueError):
        flat.allocate_in_32bit_space(0x1000, max_addr=0x100000001)


def test_allocate_in_32bit_space_returns_low_address():
    address = flat.allocate_in_32bit_space(0x1000)
    try:
        assert 0x10000 <= address < 0x100000000
    finally:
        assert flat.VirtualFree(address, 0, MEM_RELEASE)


def test_get_version_and_string():
    major, minor = flat.get_version()

    assert isinstance(major, int)
    assert isinstance(minor, int)
    assert major > 0
    assert minor >= 0
    assert flat.get_version_string() == f"Flat Assembler v{major}.{minor}"


def test_compile_asm_returns_machine_code():
    binary = flat.compile_asm("use32\nnop\nret")

    assert binary == b"\x90\xC3"


def test_compile_asm_raises_fasm_error_for_invalid_source():
    with pytest.raises(flat.FASMError) as exc_info:
        flat.compile_asm("use32\nthis_is_invalid")

    message = str(exc_info.value)
    assert "ERROR(2)" in message
    assert "line1" not in message
    assert "this_is_invalid" in message


def test_fasm_error_formats_error_context():
    with pytest.raises(flat.FASMError) as exc_info:
        flat.compile_asm("use32\nmov eax,")

    message = str(exc_info.value)

    assert "ERROR(2)" in message
    assert "INVALID_OPERAND" in message or "UNEXPECTED_CHARACTERS" in message
    assert "mov eax," in message


def test_enum_missing_values_are_preserved():
    assert flat.FASMNState(12345).name == "UNKNOWN"
    assert flat.FASMERR(-999).name == "UNKNOWN"


def test_fasm_wrapper_switches_architecture_and_builds_assembly():
    fasm = FASM()

    fasm.use64().format("pe").org(0x401000)
    fasm.define("CONST", 7)
    fasm.write("start_label:\n  nop")
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
    fasm.export("target_label")
    fasm.write("target_label:\n  ret")

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
    assert "dq target_label" in assembly
    assert fasm._export_map["target_label"] == 8


def test_fasm_wrapper_rejects_duplicate_symbols():
    fasm = FASM()
    fasm.add_byte("dup", 1)

    with pytest.raises(KeyError):
        fasm.add_word("dup", 2)

    fasm.export("label")
    with pytest.raises(KeyError):
        fasm.export("label")


def test_fasm_wrapper_compile_and_get_export():
    fasm = FASM()
    fasm.use32()
    fasm.write("start_label:\n  ret")
    fasm.export("start_label")

    binary = fasm.compile(max_memory_size=0x1000)

    assert binary[-4:] == (8).to_bytes(4, "little")
    assert fasm.get_export("start_label") == 8


def test_fasm_wrapper_compile_and_get_export_64bit():
    fasm = FASM()
    fasm.use64()
    fasm.write("start_label:\n  ret")
    fasm.export("start_label")

    binary = fasm.compile(max_memory_size=0x1000)

    assert binary[-8:] == (8).to_bytes(8, "little")
    assert fasm.get_export("start_label") == 8


def test_fasm_wrapper_compile_tracks_multiple_exports():
    fasm = FASM()
    fasm.use32()
    fasm.write("first_label:\n  nop\nsecond_label:\n  ret")
    fasm.export("first_label")
    fasm.export("second_label")

    binary = fasm.compile(max_memory_size=0x1000)
    export_values = {
        int.from_bytes(binary[-8:-4], "little"),
        int.from_bytes(binary[-4:], "little"),
    }

    assert export_values == {8, 9}
    assert {fasm.get_export("first_label"), fasm.get_export("second_label")} == {8, 9}


def test_fasm_wrapper_compile_emits_wrapper_scaffolding_for_empty_source():
    fasm = FASM()

    assert fasm.compile(max_memory_size=0x1000) == (b"\x90" * 16) + b"\x00"


def test_fasm_wrapper_compile_raises_fasm_error_for_invalid_source():
    fasm = FASM()
    fasm.use32()
    fasm.write("mov eax,")

    with pytest.raises(flat.FASMError) as exc_info:
        fasm.compile(max_memory_size=0x1000)

    message = str(exc_info.value)
    assert "INVALID_OPERAND" in message
    assert "mov eax," in message


def test_fasm_wrapper_exported_definitions_are_not_resolved():
    fasm = FASM()
    fasm.use32()
    fasm.define("CONST_LABEL", 0x11223344)
    fasm.export("CONST_LABEL")
    fasm.write("start_label:\n  ret")

    fasm.compile(max_memory_size=0x1000)

    with pytest.raises(KeyError):
        fasm.get_export("CONST_LABEL")


def test_fasm_wrapper_get_export_requires_compile():
    fasm = FASM()

    with pytest.raises(RuntimeError):
        fasm.get_export("missing")
