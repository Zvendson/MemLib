import ctypes
import os

import pytest

from MemLib.Constants import (
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE,
)
from MemLib.Process import Process
from MemLib.windows import VirtualAlloc, Win32Exception


class _MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]


def _protection_of(address: int) -> int:
    info = _MEMORY_BASIC_INFORMATION()
    queried = ctypes.windll.kernel32.VirtualQuery(
        ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info)
    )
    assert queried, "VirtualQuery failed"
    return info.Protect


@pytest.fixture
def process() -> Process:
    target = Process(os.getpid())
    try:
        yield target
    finally:
        target.close()


@pytest.fixture
def readwrite_page() -> int:
    address = VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    assert address
    return address


def test_write_restores_readwrite_protection(process, readwrite_page):
    assert _protection_of(readwrite_page) == PAGE_READWRITE

    assert process.write(readwrite_page, b"\xAA\xBB\xCC\xDD")

    assert process.read(readwrite_page, 4) == b"\xAA\xBB\xCC\xDD"
    # Must not be left executable.
    assert _protection_of(readwrite_page) == PAGE_READWRITE


def test_write_restores_readonly_protection(process):
    address = VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY)
    assert address
    assert _protection_of(address) == PAGE_READONLY

    assert process.write(address, b"\x01\x02")

    assert process.read(address, 2) == b"\x01\x02"
    assert _protection_of(address) == PAGE_READONLY


def test_write_does_not_leave_pages_executable_when_restore_value_is_missing(
    process, readwrite_page, monkeypatch
):
    """A failed `protect` must not cause the region to be left RWX.

    `protect` returns 0 on failure. Feeding that 0 back to VirtualProtectEx fails,
    which previously left the page PAGE_EXECUTE_READWRITE with the error discarded.
    """
    calls: list[int] = []
    real_protect = process.protect

    def fake_protect(address, size, new_protection):
        calls.append(new_protection)
        if new_protection == PAGE_EXECUTE_READWRITE:
            return 0  # simulate VirtualProtectEx failure
        return real_protect(address, size, new_protection)

    monkeypatch.setattr(process, "protect", fake_protect)
    process.write(readwrite_page, b"\x05")

    # Only the widening attempt happened; no bogus restore to protection value 0.
    assert calls == [PAGE_EXECUTE_READWRITE]
    assert _protection_of(readwrite_page) == PAGE_READWRITE


def test_write_struct_restores_protection(process, readwrite_page):
    from MemLib.Structs import PROCESSENTRY32

    entry = PROCESSENTRY32()
    entry.th32ProcessID = 4321

    assert process.write_struct(readwrite_page, entry)

    assert _protection_of(readwrite_page) == PAGE_READWRITE
    restored = process.read_struct(readwrite_page, PROCESSENTRY32)
    assert restored is not None
    assert restored.th32ProcessID == 4321


def test_zero_memory_restores_protection_and_zeroes(process, readwrite_page):
    assert process.write(readwrite_page, b"\xFF" * 16)

    assert process.zero_memory(readwrite_page, 16)

    assert process.read(readwrite_page, 16) == b"\x00" * 16
    assert _protection_of(readwrite_page) == PAGE_READWRITE


def test_zero_memory_uses_a_single_protection_window(process, readwrite_page, monkeypatch):
    calls: list[int] = []
    real_protect = process.protect

    def counting_protect(address, size, new_protection):
        calls.append(new_protection)
        return real_protect(address, size, new_protection)

    monkeypatch.setattr(process, "protect", counting_protect)
    assert process.zero_memory(readwrite_page, 16)

    # Previously 4 calls (zero_memory + the nested write); now one widen + one restore.
    assert calls == [PAGE_EXECUTE_READWRITE, PAGE_READWRITE]


def test_write_raw_does_not_touch_protection(process, readwrite_page, monkeypatch):
    calls: list[int] = []
    monkeypatch.setattr(process, "protect", lambda a, s, p: calls.append(p) or 0)

    assert process.write_raw(readwrite_page, b"\x77\x88")

    assert calls == []
    assert process.read(readwrite_page, 2) == b"\x77\x88"
    assert _protection_of(readwrite_page) == PAGE_READWRITE


def test_write_of_empty_payload_skips_protection_changes(process, readwrite_page, monkeypatch):
    calls: list[int] = []
    monkeypatch.setattr(process, "protect", lambda a, s, p: calls.append(p) or 0)

    process.write(readwrite_page, b"")

    assert calls == []


def test_restore_failure_does_not_swallow_the_original_error(process, readwrite_page, monkeypatch):
    """A failing restore must not hide why the wrapped operation blew up."""

    def protect(address, size, protection):
        # Succeed when widening, fail when restoring.
        return PAGE_READWRITE if protection == PAGE_EXECUTE_READWRITE else 0

    monkeypatch.setattr(process, "protect", protect)

    with pytest.raises(Win32Exception) as caught:
        with process._writable(readwrite_page, 16):
            raise RuntimeError("the actual write failure")

    assert "Failed to restore page protection" in str(caught.value)
    assert isinstance(caught.value.__cause__, RuntimeError)
    assert "the actual write failure" in str(caught.value.__cause__)

