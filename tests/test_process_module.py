from types import SimpleNamespace
from unittest.mock import patch

import pytest

from MemLib.Hook import Hook
from MemLib.Module import Module
from MemLib.Process import Process
from MemLib.Structs import MODULEENTRY32, PROCESSENTRY32
from MemLib.Thread import Thread
from MemLib.windows import Win32Exception


def _make_process_entry(pid: int, name: bytes) -> PROCESSENTRY32:
    entry = PROCESSENTRY32()
    entry.th32ProcessID = pid
    entry.szExeFile = name
    return entry


def _copy_process_entry(target_ptr, source: PROCESSENTRY32) -> bool:
    target = target_ptr._obj
    target.dwSize = source.dwSize
    target.th32ProcessID = source.th32ProcessID
    target.szExeFile = source.szExeFile
    return True


def test_get_process_list_skips_inaccessible_processes():
    entries = iter(
        [
            _make_process_entry(11, b"blocked.exe"),
            _make_process_entry(22, b"open.exe"),
        ]
    )

    def first(_snapshot, buffer):
        return _copy_process_entry(buffer, next(entries))

    def next_fn(_snapshot, buffer):
        try:
            return _copy_process_entry(buffer, next(entries))
        except StopIteration:
            return False

    accessible = SimpleNamespace(is_64bit=True, _name=None)

    with patch("MemLib.Process.windows.CreateToolhelp32Snapshot", return_value=1), patch(
        "MemLib.Process.windows.CloseHandle", return_value=True
    ), patch("MemLib.Process.windows.Process32First", side_effect=first), patch(
        "MemLib.Process.windows.Process32Next", side_effect=next_fn
    ), patch(
        "MemLib.Process.Process._open_discovered_process", side_effect=[None, accessible]
    ):
        result = Process.get_process_list()

    assert result == [accessible]
    assert accessible._name == "open.exe"


def test_get_first_process_continues_after_inaccessible_process():
    entries = iter(
        [
            _make_process_entry(11, b"blocked.exe"),
            _make_process_entry(22, b"open.exe"),
        ]
    )

    def first(_snapshot, buffer):
        return _copy_process_entry(buffer, next(entries))

    def next_fn(_snapshot, buffer):
        try:
            return _copy_process_entry(buffer, next(entries))
        except StopIteration:
            return False

    accessible = SimpleNamespace(_name=None)

    with patch("MemLib.Process.windows.CreateToolhelp32Snapshot", return_value=1), patch(
        "MemLib.Process.windows.CloseHandle", return_value=True
    ), patch("MemLib.Process.windows.Process32First", side_effect=first), patch(
        "MemLib.Process.windows.Process32Next", side_effect=next_fn
    ), patch(
        "MemLib.Process.Process._open_discovered_process", side_effect=[None, accessible]
    ):
        result = Process.get_first_process()

    assert result is accessible
    assert accessible._name == "open.exe"


def test_open_discovered_process_returns_none_when_process_stays_inaccessible():
    with patch("MemLib.Process.Process", side_effect=[Win32Exception(), Win32Exception()]):
        assert Process._open_discovered_process(1234) is None


def test_module_decodes_snapshot_text_with_active_codepage():
    module_entry = MODULEENTRY32()
    module_entry.szModule = b"mod\x80.dll"
    module_entry.szExePath = b"C:\\tmp\\caf\x82.dll"

    module = Module(module_entry, SimpleNamespace())

    assert module.name == b"mod\x80.dll".decode("mbcs", errors="replace")
    assert str(module.path) == b"C:\\tmp\\caf\x82.dll".decode("mbcs", errors="replace")


def test_get_exports_tolerates_sparse_export_tables():
    module = Module.__new__(Module)
    module._base = 0x1000
    module._exports = {}
    module._expo_dir = SimpleNamespace(
        NumberOfFunctions=3,
        NumberOfNames=2,
        AddressOfNames=0x200,
        AddressOfNameOrdinals=0x300,
        AddressOfFunctions=0x400,
        Base=1,
    )

    name_rvas = {
        0x1000 + 0x200: 0x500,
        0x1000 + 0x204: 0x510,
    }
    ordinals = {
        0x1000 + 0x300: 0,
        0x1000 + 0x302: 2,
    }
    functions = {
        0x1000 + 0x400: 0x900,
        0x1000 + 0x404: 0,
        0x1000 + 0x408: 0xA00,
    }
    names = {
        0x1000 + 0x500: b"NamedOne",
        0x1000 + 0x510: b"NamedThree",
    }

    module._process = SimpleNamespace(
        read_dword=lambda address: name_rvas.get(address, functions.get(address, 0)),
        read_word=lambda address: ordinals[address],
        read_string=lambda address, _length: names[address],
    )

    exports = module.get_exports()

    assert exports == {
        "NamedOne": 0x1900,
        "NamedThree": 0x1A00,
    }


def test_get_export_by_ordinal_raises_value_error_for_missing_slot():
    module = Module.__new__(Module)
    module._base = 0x1000
    module._expo_dir = SimpleNamespace(NumberOfFunctions=1, AddressOfFunctions=0x200, Base=1)
    module._process = SimpleNamespace(read_dword=lambda _address: 0)
    module._name = "demo.dll"

    with pytest.raises(ValueError, match="does not map"):
        module.get_export_by_ordinal(1)


def test_export_directory_raises_when_module_has_no_exports():
    module = Module.__new__(Module)
    module._expo_dir = None
    module._base = 0x1000
    module._name = "demo.dll"
    module.data_directory = lambda _index: SimpleNamespace(VirtualAddress=0)
    module._process = SimpleNamespace(read_struct=lambda *_args: None)

    with pytest.raises(ValueError, match="has no export directory"):
        _ = module.export_directory


def test_nt_headers_raise_value_error_for_invalid_signature():
    module = Module.__new__(Module)
    module._base = 0x1000
    module._name = "demo.dll"
    module._nt_headers = None
    module._dos = SimpleNamespace(e_lfanew=0x80)
    module._process = SimpleNamespace(
        is_64bit=False,
        read_struct=lambda *_args: SimpleNamespace(Signature=0x1234, OptionalHeader=SimpleNamespace(Magic=0x10B)),
    )

    with pytest.raises(ValueError, match="Invalid NT header signature"):
        _ = module.nt_headers


def test_process_destructor_swallows_cleanup_failures():
    process = Process.__new__(Process)
    process._callbacks = []
    process._handle = 1
    process._unregister_wait = lambda: True
    process.close = lambda: (_ for _ in ()).throw(RuntimeError("boom"))

    process.__del__()


def test_thread_destructor_swallows_cleanup_failures():
    thread = Thread.__new__(Thread)
    thread.close = lambda: (_ for _ in ()).throw(RuntimeError("boom"))

    thread.__del__()


def test_hook_rejects_relative_jump_out_of_range():
    with pytest.raises(ValueError, match="out of rel32 range"):
        Hook._build_jump_opcode(0x1000, 0x1_0000_0000)
