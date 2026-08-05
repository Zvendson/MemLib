"""NTSTATUS routines report failure in their return value, not via SetLastError.

Without translation, a `Win32Exception()` raised after one of them reads whatever the
previous call left behind: 0 on a fresh thread ("The operation completed successfully"),
or a stale unrelated code otherwise. These tests pin the translated behaviour.
"""

import ctypes

from MemLib.Constants import STATUS_SUCCESS
from MemLib.Process import Process
from MemLib.windows import (
    GetLastError, NtUnmapViewOfSection, RtlNtStatusToDosError, SetLastError, Win32Exception, _nt_ok,
)

# What NtUnmapViewOfSection returns for an address that is not the base of a mapped
# view. Translates to ERROR_INVALID_ADDRESS (487).
STATUS_NOT_MAPPED_VIEW: int = 0xC0000019
ERROR_INVALID_ADDRESS: int = 487
UNMAPPED_ADDRESS: int = 0xDEAD0000


def test_status_translates_to_the_matching_win32_code():
    assert RtlNtStatusToDosError(STATUS_NOT_MAPPED_VIEW) == ERROR_INVALID_ADDRESS
    assert RtlNtStatusToDosError(0xC0000008) == 6  # STATUS_INVALID_HANDLE -> ERROR_INVALID_HANDLE
    assert RtlNtStatusToDosError(0xC000000D) == 87  # STATUS_INVALID_PARAMETER -> ERROR_INVALID_PARAMETER


def test_nt_ok_leaves_last_error_alone_on_success():
    SetLastError(1234)

    assert _nt_ok(STATUS_SUCCESS) is True
    # A successful Win32 call does not clear the last error either, so neither does this.
    assert GetLastError() == 1234


def test_nt_ok_publishes_the_translated_failure():
    SetLastError(0)

    assert _nt_ok(STATUS_NOT_MAPPED_VIEW) is False
    assert GetLastError() == ERROR_INVALID_ADDRESS


def test_failure_is_reported_even_from_a_clean_last_error():
    """Regression: GetLastError() == 0 here made Win32Exception() say
    'The operation completed successfully.' inside a raised exception."""
    process = Process(ctypes.windll.kernel32.GetCurrentProcessId())
    SetLastError(0)

    assert NtUnmapViewOfSection(process.handle, UNMAPPED_ADDRESS) is False

    error = Win32Exception()
    assert error.code == ERROR_INVALID_ADDRESS
    assert "completed successfully" not in error.message


def test_failure_is_not_masked_by_a_stale_last_error():
    """Regression: the stale code from an earlier call was reported instead, which is
    wrong but plausible -- harder to spot than the 'success' message."""
    process = Process(ctypes.windll.kernel32.GetCurrentProcessId())
    SetLastError(1234)

    assert NtUnmapViewOfSection(process.handle, UNMAPPED_ADDRESS) is False
    assert GetLastError() == ERROR_INVALID_ADDRESS
