import ctypes
import os
import subprocess
import sys
import time

import pytest

from MemLib.Process import Process


@pytest.fixture
def process() -> Process:
    return Process(os.getpid())


@pytest.fixture
def scratch_buffer():
    buffer = ctypes.create_string_buffer(512)
    return buffer, ctypes.addressof(buffer)


def test_memlib_does_not_import_psutil():
    """psutil was the only non-stdlib runtime dependency, used for one PID check.

    Runs in a subprocess: reloading MemLib in-process would swap out the module
    objects other tests have already patched.
    """
    probe = (
        "import sys; import MemLib, MemLib.Process; "
        "sys.exit(1 if 'psutil' in sys.modules else 0)"
    )
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True)

    assert result.returncode == 0, "MemLib still imports psutil"


def test_exists_is_true_for_a_live_process(process):
    assert process.exists is True


def test_exists_is_false_without_a_handle(process):
    process._handle = 0
    assert process.exists is False


def test_exists_flips_to_false_when_the_target_exits():
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        time.sleep(0.4)
        target = Process(child.pid)
        assert target.exists is True
    finally:
        child.kill()
        child.wait()

    # Give Windows a moment to signal the process object.
    for _ in range(20):
        if not target.exists:
            break
        time.sleep(0.05)

    assert target.exists is False


def test_reads_still_work_and_round_trip(process, scratch_buffer):
    buffer, address = scratch_buffer
    ctypes.memmove(address, b"\x78\x56\x34\x12hello\x00", 10)

    assert process.read(address, 4) == b"\x78\x56\x34\x12"
    assert process.read_dword(address) == 0x12345678
    assert process.read_word(address) == 0x5678
    assert process.read_byte(address) == 0x78
    assert process.read_string(address + 4, 16) == b"hello"


def test_read_dword_respects_endianness(process, scratch_buffer):
    buffer, address = scratch_buffer
    ctypes.memmove(address, b"\x12\x34\x56\x78", 4)

    assert process.read_dword(address, "little") == 0x78563412
    assert process.read_dword(address, "big") == 0x12345678


def test_reads_of_unmapped_memory_still_return_the_documented_fallbacks(process):
    unmapped = 0x00010000

    assert process.read(unmapped, 4) == b""
    assert process.read_dword(unmapped) == 0
    assert process.read_word(unmapped) == 0
    assert process.read_byte(unmapped) == 0
    assert process.read_string(unmapped, 8) == b""
    assert process.read_wide_string(unmapped, 8) == ""


def test_zero_and_negative_lengths_do_not_call_into_windows(process, scratch_buffer):
    _buffer, address = scratch_buffer

    assert process.read(address, 0) == b""
    assert process.read(address, -1) == b""


def test_read_struct_still_returns_none_on_failure(process):
    from MemLib.Structs import PROCESSENTRY32

    assert process.read_struct(0x00010000, PROCESSENTRY32) is None


def test_read_struct_reads_a_real_structure(process, scratch_buffer):
    from MemLib.Structs import PROCESSENTRY32

    source = PROCESSENTRY32()
    source.th32ProcessID = 1234
    address = ctypes.addressof(source)

    result = process.read_struct(address, PROCESSENTRY32)

    assert result is not None
    assert result.th32ProcessID == 1234
    assert result.ADDRESS_EX == address


def test_read_wide_string_decodes_and_strips(process):
    text = ctypes.create_unicode_buffer("MemLib")
    address = ctypes.addressof(text)

    assert process.read_wide_string(address, 6) == "MemLib"
    assert process.read_wide_string(address, 32) == "MemLib"
    assert process.read_wide_string(address, 32, strip=False).startswith("MemLib")
