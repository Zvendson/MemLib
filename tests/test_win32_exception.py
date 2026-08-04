import ctypes
import pickle

import pytest

from MemLib.SharedMemory import SharedMemoryCleanupError, close_shared_memory_connection
from MemLib.windows import Win32Exception


def _set_last_error(code: int) -> None:
    ctypes.windll.kernel32.SetLastError(code)


def test_zero_error_code_does_not_claim_success():
    error = Win32Exception(0)

    assert error.code == 0
    # FormatMessageW(0) would yield "The operation completed successfully."
    assert "completed successfully" not in error.message
    assert "completed successfully" not in str(error)
    assert "GetLastError() == 0" in error.message


def test_implicit_zero_last_error_does_not_claim_success():
    _set_last_error(0)
    error = Win32Exception()

    assert error.code == 0
    assert "completed successfully" not in str(error)


def test_real_error_code_still_formats_the_windows_message():
    error = Win32Exception(5)  # ERROR_ACCESS_DENIED

    assert error.code == 5
    # FormatMessageW is localized, so compare against what this system reports for 5
    # rather than the English string.
    assert ctypes.FormatError(5).strip() in error.message


def test_custom_message_is_preserved():
    error = Win32Exception(5, "custom text")

    assert error.code == 5
    assert error.message == "custom text"
    assert "custom text" in str(error)


def test_args_are_populated_for_logging_and_reraise():
    error = Win32Exception(5)

    # Previously empty, which made the exception opaque to code inspecting `args`.
    assert error.args == (error.message, 5)


def test_exception_survives_pickling_without_rereading_last_error():
    _set_last_error(5)
    error = Win32Exception()
    assert error.code == 5

    # A different last-error value must not leak into the unpickled copy.
    _set_last_error(2)
    restored = pickle.loads(pickle.dumps(error))

    assert restored.code == 5
    assert restored.message == error.message


def test_is_still_a_runtime_error():
    assert isinstance(Win32Exception(5), RuntimeError)


def test_cleanup_error_keeps_individual_failures_inspectable():
    errors = [Win32Exception(5), Win32Exception(2)]
    aggregate = SharedMemoryCleanupError(errors)

    assert aggregate.codes == [5, 2]
    assert [error.code for error in aggregate.errors] == [5, 2]
    # Callers can now branch on a code instead of grepping the message.
    assert 5 in aggregate.codes
    assert "Caught 2 Win32Exception" in str(aggregate)


def test_cleanup_error_is_catchable_as_exception():
    # Existing `except Exception` handlers must keep working.
    assert issubclass(SharedMemoryCleanupError, Exception)

    with pytest.raises(Exception) as caught:
        raise SharedMemoryCleanupError([Win32Exception(5)])

    assert isinstance(caught.value, SharedMemoryCleanupError)


def test_close_connection_raises_cleanup_error_with_codes():
    # 0x1 fails both cleanup steps: CloseHandle sets ERROR_INVALID_HANDLE and
    # UnmapViewOfFile sets ERROR_INVALID_ADDRESS. Not the pseudo-handle -1, which means
    # "current process" and makes CloseHandle *succeed*.
    with pytest.raises(SharedMemoryCleanupError) as caught:
        close_shared_memory_connection(handle=0x1, base_addr=0x1)

    assert caught.value.errors
    assert all(isinstance(error, Win32Exception) for error in caught.value.errors)
    assert all("completed successfully" not in str(error) for error in caught.value.errors)


def test_close_connection_is_a_noop_for_empty_arguments():
    close_shared_memory_connection(handle=0, base_addr=0)
