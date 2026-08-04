import os

import pytest

from MemLib.Constants import PROCESS_ALL_ACCESS
from MemLib.Process import Process
from MemLib.windows import CloseHandle, OpenProcess


@pytest.fixture
def process() -> Process:
    return Process(os.getpid())


def test_process_is_hashable_and_usable_in_containers(process):
    assert Process.__hash__ is not None

    same = Process(os.getpid())
    assert {process, same} == {process}
    assert {process: "value"}[same] == "value"


def test_process_hash_is_consistent_with_equality(process):
    same = Process(os.getpid())

    assert process == same
    assert hash(process) == hash(same)


def test_pid_equality_stays_container_consistent(process):
    """Process == int is deliberate; __hash__ keeps it from splitting set membership."""
    pid = os.getpid()

    assert process == pid
    assert pid == process  # reflected, via int.__eq__ returning NotImplemented
    assert hash(process) == hash(pid)

    # The failure mode this guards: a set holding both the PID and the Process.
    assert len({pid, process}) == 1


def test_process_equality_rejects_foreign_types(process):
    assert process.__eq__("not a process") is NotImplemented
    assert process != "not a process"


def test_module_is_hashable_and_deduplicates(process):
    from MemLib.Module import Module

    assert Module.__hash__ is not None

    first = process.get_main_module()
    second = process.get_module(first.name)

    assert first == second
    assert hash(first) == hash(second)
    assert len({first, second}) == 1


def test_thread_is_hashable_and_deduplicates(process):
    from MemLib.Thread import Thread

    assert Thread.__hash__ is not None

    threads = process.get_threads()
    assert threads

    first = threads[0]
    same = Thread(first.id, process)

    assert first == same
    assert hash(first) == hash(same)
    assert len({first, same}) == 1


def test_module_and_thread_equality_reject_foreign_types(process):
    module = process.get_main_module()
    thread = process.get_threads()[0]

    assert module.__eq__("not a module") is NotImplemented
    assert thread.__eq__("not a thread") is NotImplemented
    assert module != "not a module"
    assert thread != "not a thread"


def test_process_context_manager_closes_the_handle():
    with Process(os.getpid()) as target:
        assert target.handle
        # The PE header starts with "MZ", so a usable handle reads a non-zero DWORD.
        assert target.read_dword(target.base) != 0

    assert target.handle == 0


def test_process_context_manager_reopens_a_closed_handle(process):
    process.close()
    assert process.handle == 0

    with process as reopened:
        assert reopened.handle

    assert process.handle == 0


def test_owned_handle_is_closed(process):
    assert process.owns_handle is True

    handle = process.handle
    assert process.close()
    assert process.handle == 0

    # The handle really is gone: closing it again fails.
    assert not CloseHandle(handle)


def test_borrowed_handle_is_not_closed():
    handle = OpenProcess(PROCESS_ALL_ACCESS, False, os.getpid())
    assert handle

    borrower = Process(os.getpid(), handle, owns_handle=False)
    assert borrower.owns_handle is False

    assert borrower.close()
    assert borrower.handle == 0

    # Still valid for the real owner, who can now close it exactly once.
    assert CloseHandle(handle)


def test_handle_passed_in_defaults_to_borrowed():
    handle = OpenProcess(PROCESS_ALL_ACCESS, False, os.getpid())
    assert handle

    try:
        borrower = Process(os.getpid(), handle)
        # Not opened by this instance, so not owned by it.
        assert borrower.owns_handle is False
        del borrower

        # __del__ must not have invalidated the caller's handle.
        assert Process(os.getpid(), handle, owns_handle=False).exists
    finally:
        CloseHandle(handle)


def test_explicitly_claimed_handle_is_owned():
    handle = OpenProcess(PROCESS_ALL_ACCESS, False, os.getpid())
    assert handle

    owner = Process(os.getpid(), handle, owns_handle=True)
    assert owner.owns_handle is True
    assert owner.close()
    assert not CloseHandle(handle)


def test_open_takes_ownership_of_the_new_handle():
    handle = OpenProcess(PROCESS_ALL_ACCESS, False, os.getpid())
    assert handle

    try:
        target = Process(os.getpid(), handle, owns_handle=False)
        assert target.owns_handle is False

        # Opening allocates a fresh handle, which this instance does own.
        target.open()
        assert target.owns_handle is True
        assert target.handle != handle
        assert target.close()
    finally:
        CloseHandle(handle)


def test_close_is_idempotent(process):
    assert process.close()
    assert process.close()
    assert process.handle == 0


def test_name_is_always_a_string_and_is_not_cached_on_failure(process, monkeypatch):
    from MemLib import windows

    def fail(*_args, **_kwargs):
        raise windows.Win32Exception(5)

    monkeypatch.setattr(process, "get_main_module", fail)
    assert process.name == ""
    assert isinstance(process.name, str)

    # A later successful lookup must still populate the name.
    monkeypatch.undo()
    process._name = None
    assert process.name
