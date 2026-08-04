import gc
import os
import subprocess
import sys

import pytest

from MemLib.Process import Process
from MemLib.Thread import Thread


def test_process_close_still_raises_by_default(monkeypatch):
    process = Process(os.getpid())

    from MemLib import windows

    monkeypatch.setattr(windows, "CloseHandle", lambda _handle: False)

    with pytest.raises(windows.Win32Exception):
        process.close()


def test_process_close_can_suppress_errors(monkeypatch):
    process = Process(os.getpid())

    from MemLib import windows

    monkeypatch.setattr(windows, "CloseHandle", lambda _handle: False)

    assert process.close(raise_on_error=False) is False
    # The handle reference is dropped either way, so __del__ will not retry it.
    assert process.handle == 0


def test_thread_close_still_raises_by_default(monkeypatch):
    process = Process(os.getpid())
    thread = process.get_threads()[0]
    thread._handle = 0x1

    thread_module = sys.modules["MemLib.Thread"]

    monkeypatch.setattr(thread_module, "CloseHandle", lambda _handle: False)

    with pytest.raises(thread_module.Win32Exception):
        thread.close()


def test_thread_close_can_suppress_errors(monkeypatch):
    process = Process(os.getpid())
    thread = process.get_threads()[0]
    thread._handle = 0x1

    thread_module = sys.modules["MemLib.Thread"]

    monkeypatch.setattr(thread_module, "CloseHandle", lambda _handle: False)

    assert thread.close(raise_on_error=False) is False
    assert thread._handle == 0


def test_destructor_does_not_raise_when_close_fails(monkeypatch):
    """__del__ must stay silent: exceptions there are unraisable and confusing."""
    process = Process(os.getpid())

    from MemLib import windows

    monkeypatch.setattr(windows, "CloseHandle", lambda _handle: False)

    unraisable: list = []
    original_hook = sys.unraisablehook
    sys.unraisablehook = lambda args: unraisable.append(args)
    try:
        del process
        gc.collect()
    finally:
        sys.unraisablehook = original_hook

    assert not unraisable, f"destructor raised: {unraisable}"


def test_interpreter_shutdown_is_clean():
    """Regression: raising from close() during teardown produced a bogus
    'TypeError: exceptions must derive from BaseException', because module globals
    are already torn down by the time __del__ runs."""
    probe = (
        "import os\n"
        "from MemLib.Process import Process\n"
        "from MemLib.Thread import Thread\n"
        "p = Process(os.getpid())\n"
        "t = p.get_threads()[0]\n"
        "t.open()\n"
        "# leave both alive so they are collected during interpreter shutdown\n"
    )
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True)

    stderr = result.stderr.decode()
    assert result.returncode == 0, stderr
    assert "must derive from BaseException" not in stderr
    assert "Exception ignored" not in stderr, stderr


def test_close_is_idempotent_and_safe_on_zero_handle():
    process = Process(os.getpid())

    assert process.close() is True
    assert process.close() is True
    assert process.close(raise_on_error=False) is True
