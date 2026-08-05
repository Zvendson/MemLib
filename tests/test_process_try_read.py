import ctypes
import os

import pytest

from MemLib.Process import Process
from MemLib.Structs import PROCESSENTRY32


UNMAPPED = 0x00010000
"""An address that is reliably not committed in this process."""


@pytest.fixture
def process() -> Process:
    return Process(os.getpid())


@pytest.fixture
def zero_dword():
    """A real, readable DWORD whose value is 0."""
    value = ctypes.c_ulong(0)
    return value, ctypes.addressof(value)


def test_try_read_returns_none_on_failure(process):
    assert process.try_read(UNMAPPED, 4) is None


def test_try_read_returns_data_on_success(process):
    buffer = ctypes.create_string_buffer(b"\x01\x02\x03\x04")
    assert process.try_read(ctypes.addressof(buffer), 4) == b"\x01\x02\x03\x04"


def test_try_read_dword_distinguishes_zero_from_failure(process, zero_dword):
    _value, address = zero_dword

    # This is the whole point: a real zero and a failed read are different results.
    assert process.try_read_dword(address) == 0
    assert process.try_read_dword(UNMAPPED) is None

    # The lossy API cannot tell them apart, and still does not.
    assert process.read_dword(address) == 0
    assert process.read_dword(UNMAPPED) == 0


def test_try_read_word_and_byte_distinguish_zero_from_failure(process, zero_dword):
    _value, address = zero_dword

    assert process.try_read_word(address) == 0
    assert process.try_read_byte(address) == 0
    assert process.try_read_word(UNMAPPED) is None
    assert process.try_read_byte(UNMAPPED) is None


def test_try_read_integer_supports_width_endianness_and_sign(process):
    buffer = ctypes.create_string_buffer(b"\xFF\xFF\xFF\xFF")
    address = ctypes.addressof(buffer)

    assert process.try_read_integer(address, 4) == 0xFFFFFFFF
    assert process.try_read_integer(address, 4, signed=True) == -1
    assert process.try_read_integer(address, 2) == 0xFFFF

    packed = ctypes.create_string_buffer(b"\x12\x34")
    assert process.try_read_integer(ctypes.addressof(packed), 2, "big") == 0x1234
    assert process.try_read_integer(ctypes.addressof(packed), 2, "little") == 0x3412


def test_try_read_integer_returns_none_on_failure(process):
    assert process.try_read_integer(UNMAPPED, 8) is None


def test_try_read_string_distinguishes_empty_from_failure(process):
    empty = ctypes.create_string_buffer(b"\x00hello")
    address = ctypes.addressof(empty)

    # A legitimately empty (immediately null-terminated) string.
    assert process.try_read_string(address, 8) == b""
    # A failed read.
    assert process.try_read_string(UNMAPPED, 8) is None

    assert process.read_string(address, 8) == b""
    assert process.read_string(UNMAPPED, 8) == b""


def test_try_read_wide_string_distinguishes_empty_from_failure(process):
    empty = ctypes.create_unicode_buffer("")
    address = ctypes.addressof(empty)

    assert process.try_read_wide_string(address, 4) == ""
    assert process.try_read_wide_string(UNMAPPED, 4) is None


def test_try_read_string_still_strips_and_honours_strip_false(process):
    buffer = ctypes.create_string_buffer(b"abc\x00def")
    address = ctypes.addressof(buffer)

    assert process.try_read_string(address, 7) == b"abc"
    assert process.try_read_string(address, 7, strip=False) == b"abc\x00def"


def test_try_read_rejects_negative_length(process):
    buffer = ctypes.create_string_buffer(8)

    with pytest.raises(ValueError):
        process.try_read(ctypes.addressof(buffer), -1)


def test_try_read_of_zero_length_is_an_empty_success(process):
    buffer = ctypes.create_string_buffer(8)

    # Distinct from None: nothing was requested, nothing failed.
    assert process.try_read(ctypes.addressof(buffer), 0) == b""


def test_lossy_string_reads_stay_tolerant_of_non_positive_lengths(process):
    """The try_* variants raise on these; the legacy read* APIs must not start to.

    read() has always returned b'' for length <= 0, and read_string/read_wide_string
    inherited that. Delegating to try_read* without a guard turned it into ValueError.
    """
    buffer = ctypes.create_string_buffer(b"abc\x00", 8)
    address = ctypes.addressof(buffer)

    assert process.read_string(address, 0) == b""
    assert process.read_string(address, -1) == b""
    assert process.read_wide_string(address, 0) == ""
    assert process.read_wide_string(address, -1) == ""


def test_is_readable_probes_without_ambiguity(process, zero_dword):
    _value, address = zero_dword

    assert process.is_readable(address, 4) is True
    assert process.is_readable(UNMAPPED, 4) is False
    assert process.is_readable(0) is False
    assert process.is_readable(address, 0) is False


def test_lossy_read_api_is_unchanged(process):
    """The documented fallbacks must stay put: existing callers depend on them."""
    assert process.read(UNMAPPED, 4) == b""
    assert process.read_dword(UNMAPPED) == 0
    assert process.read_word(UNMAPPED) == 0
    assert process.read_byte(UNMAPPED) == 0
    assert process.read_string(UNMAPPED, 4) == b""
    assert process.read_wide_string(UNMAPPED, 4) == ""
    assert process.read_struct(UNMAPPED, PROCESSENTRY32) is None

    # read() stays tolerant of non-positive lengths rather than raising.
    buffer = ctypes.create_string_buffer(8)
    assert process.read(ctypes.addressof(buffer), 0) == b""
    assert process.read(ctypes.addressof(buffer), -5) == b""


def test_pointer_chain_walk_can_tell_null_from_unreadable(process):
    """The motivating case: NULL is meaningful data, not an error."""
    null_pointer = ctypes.c_ulong(0)
    address = ctypes.addressof(null_pointer)

    target = process.try_read_dword(address)
    assert target == 0, "a readable NULL pointer must read as 0, not None"

    missing = process.try_read_dword(UNMAPPED)
    assert missing is None, "an unreadable pointer must be None, not 0"
