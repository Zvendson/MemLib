import ctypes
import os

import pytest

from MemLib.Process import MemoryWindow, Process
from MemLib.Structs import PROCESSENTRY32


UNMAPPED = 0x00010000


@pytest.fixture
def process() -> Process:
    return Process(os.getpid())


@pytest.fixture
def payload():
    raw = bytes(range(0x40)) + b"name\x00pad"
    buffer = ctypes.create_string_buffer(raw, len(raw))
    return buffer, ctypes.addressof(buffer), raw


def test_read_into_fills_a_caller_buffer(process, payload):
    _source, address, raw = payload
    destination = ctypes.create_string_buffer(0x10)

    read = process.read_into(address, destination, 0x10)

    assert read == 0x10
    assert destination.raw == raw[:0x10]


def test_read_into_defaults_to_the_full_buffer(process, payload):
    _source, address, raw = payload
    destination = ctypes.create_string_buffer(8)

    assert process.read_into(address, destination) == 8
    assert destination.raw == raw[:8]


def test_read_into_returns_zero_on_failure(process):
    destination = ctypes.create_string_buffer(8)
    assert process.read_into(UNMAPPED, destination) == 0


def test_read_into_rejects_oversized_and_negative_sizes(process, payload):
    _source, address, _raw = payload
    destination = ctypes.create_string_buffer(8)

    with pytest.raises(ValueError):
        process.read_into(address, destination, 16)

    with pytest.raises(ValueError):
        process.read_into(address, destination, -1)


def test_read_into_can_fill_a_struct(process):
    source = PROCESSENTRY32()
    source.th32ProcessID = 9876
    destination = PROCESSENTRY32()

    assert process.read_into(ctypes.addressof(source), destination)
    assert destination.th32ProcessID == 9876


def test_read_struct_into_reuses_the_instance(process):
    source = PROCESSENTRY32()
    source.th32ProcessID = 4242
    address = ctypes.addressof(source)
    destination = PROCESSENTRY32()

    result = process.read_struct_into(address, destination)

    assert result is destination
    assert result.th32ProcessID == 4242
    assert result.ADDRESS_EX == address


def test_read_struct_into_returns_none_on_failure(process):
    destination = PROCESSENTRY32()
    assert process.read_struct_into(UNMAPPED, destination) is None


def test_read_window_snapshots_once_and_serves_fields(process, payload):
    _source, address, raw = payload

    window = process.read_window(address, 0x40)

    assert window is not None
    assert len(window) == 0x40
    assert window.address == address
    assert window.byte(0x00) == raw[0]
    assert window.word(0x00) == int.from_bytes(raw[0:2], "little")
    assert window.dword(0x00) == int.from_bytes(raw[0:4], "little")
    assert window.qword(0x00) == int.from_bytes(raw[0:8], "little")
    assert window.dword(0x0C) == int.from_bytes(raw[0x0C:0x10], "little")
    assert window.bytes(0x10, 4) == raw[0x10:0x14]


def test_read_window_returns_none_on_failure(process):
    assert process.read_window(UNMAPPED, 0x40) is None


def test_window_respects_endianness_and_sign():
    window = MemoryWindow(0x1000, b"\xFF\xFF\xFF\xFF\x12\x34")

    assert window.dword(0) == 0xFFFFFFFF
    assert window.integer(0, 4, signed=True) == -1
    assert window.word(4, "big") == 0x1234
    assert window.word(4, "little") == 0x3412


def test_window_rejects_out_of_range_access():
    window = MemoryWindow(0x1000, b"\x01\x02\x03\x04")

    assert window.dword(0) == 0x04030201

    with pytest.raises(IndexError):
        window.dword(2)

    with pytest.raises(IndexError):
        window.byte(4)

    with pytest.raises(ValueError):
        window.bytes(-1, 2)


def test_window_reads_strings(process, payload):
    _source, address, _raw = payload

    window = process.read_window(address, 0x48)
    assert window is not None
    assert window.string(0x40, 8) == b"name"
    assert window.string(0x40, 8, strip=False) == b"name\x00pad"


def test_window_reads_wide_strings():
    text = "MemLib"
    window = MemoryWindow(0x2000, text.encode("utf-16-le") + b"\x00\x00")

    assert window.wide_string(0, 6) == "MemLib"
    assert window.wide_string(0, 7) == "MemLib"


def test_window_materialises_a_struct(process):
    source = PROCESSENTRY32()
    source.th32ProcessID = 555
    address = ctypes.addressof(source)

    window = process.read_window(address, ctypes.sizeof(PROCESSENTRY32))

    assert window is not None
    entry = window.struct(0, PROCESSENTRY32)
    assert entry.th32ProcessID == 555
    assert entry.ADDRESS_EX == address


def test_window_membership_and_repr():
    window = MemoryWindow(0x1000, b"\x00" * 16)

    assert 0 in window
    assert 15 in window
    assert 16 not in window
    assert "0x1000" in repr(window)


def test_window_matches_field_by_field_reads(process, payload):
    """The whole point: the batched path must agree with the per-field path."""
    _source, address, _raw = payload

    window = process.read_window(address, 0x40)
    assert window is not None

    for offset in range(0, 0x40, 4):
        assert window.dword(offset) == process.read_dword(address + offset)
