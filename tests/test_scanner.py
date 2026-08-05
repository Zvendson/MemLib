import ctypes

from MemLib.Constants import PAGE_READWRITE
from MemLib.Scanner import BinaryScanner


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


def _query_protection(address: int) -> int:
    info = _MEMORY_BASIC_INFORMATION()
    queried = ctypes.windll.kernel32.VirtualQuery(
        ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info)
    )
    assert queried, "VirtualQuery failed"
    return info.Protect


def test_find_returns_zero_when_pattern_is_missing():
    scanner = BinaryScanner(b"\x11\x22\x33\x44", base=0x400000)
    try:
        assert scanner.find_rva("DE AD BE EF") == 0
        # Must not report the module base as a hit: callers test `if address:`.
        assert scanner.find("DE AD BE EF") == 0
    finally:
        scanner.close()


def test_find_still_returns_absolute_address_on_hit():
    scanner = BinaryScanner(b"\x11\x22\x33\x44", base=0x400000)
    try:
        assert scanner.find_rva("33 44") == 2
        assert scanner.find("33 44") == 0x400002
    finally:
        scanner.close()


def test_find_matching_at_offset_zero_is_not_confused_with_a_miss():
    scanner = BinaryScanner(b"\x11\x22\x33\x44", base=0x400000)
    try:
        # A hit at RVA 0 legitimately resolves to the base address.
        assert scanner.find_rva("11 22") == 0
        assert scanner.find("11 22") == 0x400000
        # ...whereas a miss also yields RVA 0 but must resolve to 0.
        assert scanner.find_rva("DE AD") == 0
        assert scanner.find("DE AD") == 0
    finally:
        scanner.close()


def test_matches_at_disambiguates_and_respects_wildcards():
    scanner = BinaryScanner(b"\x11\x22\x33\x44", base=0x400000)
    try:
        assert scanner.matches_at("11 22", 0) is True
        assert scanner.matches_at("11 ?? 33", 0) is True
        assert scanner.matches_at("DE AD", 0) is False
        assert scanner.matches_at("33 44", 2) is True
        # Out of bounds must not read past the buffer.
        assert scanner.matches_at("44 55", 3) is False
        assert scanner.matches_at("11 22", -1) is False
    finally:
        scanner.close()


def test_close_releases_the_scan_buffer():
    scanner = BinaryScanner(b"\x90" * 128, base=0)
    buffer_base = scanner._buffer.base
    assert buffer_base

    scanner.close()

    assert scanner._handler_address == 0
    assert not scanner._buffer.base
    assert not scanner._buffer.end


def test_set_buffer_clears_previous_pointer_before_reallocating():
    scanner = BinaryScanner(b"\x90" * 128, base=0)
    try:
        first_base = scanner._buffer.base
        scanner.set_buffer(b"\x91" * 256, base=0x1000)

        assert scanner._buffer.base
        assert scanner._buffer.end == scanner._buffer.base + 256
        assert scanner._base == 0x1000
        assert first_base != 0
    finally:
        scanner.close()


def test_scan_buffer_is_not_executable():
    scanner = BinaryScanner(b"\x90" * 4096, base=0)
    try:
        assert _query_protection(scanner._buffer.base) == PAGE_READWRITE
    finally:
        scanner.close()
