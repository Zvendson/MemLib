from ctypes.wintypes import HANDLE, LPVOID
from unittest.mock import Mock, patch

import pytest

from MemLib.SharedMemory import SharedMemory, SharedMemoryBuffer, close_shared_memory_connection


class FakeProcess:
    def __init__(self):
        self.handle = 0xBEEF
        self.process_id = 1337
        self.read_struct = Mock()
        self.write_struct = Mock(return_value=True)
        self.zero_memory = Mock(return_value=True)


def _duplicate_handle_success(source_process_handle, source_handle, target_process_handle, target_handle, *_args):
    if target_handle is not None:
        target_handle.value = 0xCAFE
    return True


def _nt_map_success(_section_handle, _process_handle, base_address, *_args):
    base_address._obj.value = 0x5000
    return True


def _make_live_buffer() -> SharedMemoryBuffer:
    mapping = SharedMemoryBuffer()
    mapping.handle = HANDLE(0x1001)
    mapping.handle_ex = HANDLE(0x1002)
    mapping.base_address = LPVOID(0x2001)
    mapping.base_address_ex = LPVOID(0x2002)
    mapping.size_high = 0
    mapping.size_low = 0x1000
    return mapping


def test_shared_memory_buffer_validity():
    mapping = SharedMemoryBuffer()
    assert mapping.is_valid() is False

    mapping.handle_ex = HANDLE(1)
    assert mapping.is_valid() is False

    mapping.base_address_ex = LPVOID(2)
    assert mapping.is_valid() is True


def test_close_shared_memory_connection_closes_both_resources():
    with patch("MemLib.SharedMemory.UnmapViewOfFile", return_value=True) as unmap, patch(
        "MemLib.SharedMemory.CloseHandle", return_value=True
    ) as close:
        close_shared_memory_connection(0x11, 0x22)

    unmap.assert_called_once_with(0x22)
    close.assert_called_once_with(0x11)


def test_close_shared_memory_connection_aggregates_errors():
    with patch("MemLib.SharedMemory.UnmapViewOfFile", return_value=False), patch(
        "MemLib.SharedMemory.CloseHandle", return_value=False
    ):
        with pytest.raises(Exception) as exc_info:
            close_shared_memory_connection(0x11, 0x22)

    assert "Caught 2 Win32Exception" in str(exc_info.value)


def test_accessors_require_initialized_buffer():
    shared = SharedMemory(FakeProcess())

    with pytest.raises(RuntimeError):
        _ = shared.handle

    with pytest.raises(RuntimeError):
        shared.disconnect()


def test_can_reconnect_reflects_read_struct_result():
    process = FakeProcess()
    shared = SharedMemory(process)

    process.read_struct.return_value = None
    assert shared.can_reconnect(0x5000) is False

    mapping = SharedMemoryBuffer()
    mapping.handle_ex = HANDLE(1)
    mapping.base_address_ex = LPVOID(2)
    process.read_struct.return_value = mapping
    assert shared.can_reconnect(0x5000) is True


@patch("MemLib.SharedMemory.DuplicateHandle", side_effect=_duplicate_handle_success)
@patch("MemLib.SharedMemory.NtMapViewOfSection", side_effect=_nt_map_success)
@patch("MemLib.SharedMemory.MapViewOfFile", return_value=0x4000)
@patch("MemLib.SharedMemory.CreateFileMappingW", return_value=0x3000)
def test_create_initializes_mapping(_create, _map, _nt_map, _dup):
    shared = SharedMemory(FakeProcess())
    shared.create(0x1234)

    assert shared.handle == 0x3000
    assert shared.handle_ex == 0xCAFE
    assert shared.base_address == 0x4000
    assert shared.base_address_ex == 0x5000
    assert shared.size_low == 0x1234


def test_create_rejects_non_positive_sizes():
    shared = SharedMemory(FakeProcess())

    with pytest.raises(ValueError):
        shared.create(0)

    with pytest.raises(ValueError):
        shared.create(-1)


@patch("MemLib.SharedMemory.CloseHandle", return_value=True)
@patch("MemLib.SharedMemory.CreateFileMappingW", return_value=0x3000)
@patch("MemLib.SharedMemory.MapViewOfFile", return_value=0)
def test_create_closes_mapping_handle_when_local_map_fails(_map, _create, close):
    shared = SharedMemory(FakeProcess())

    with pytest.raises(Exception):
        shared.create(0x1000)

    close.assert_called_once_with(0x3000)


@patch("MemLib.SharedMemory.CloseHandle", return_value=True)
@patch("MemLib.SharedMemory.UnmapViewOfFile", return_value=True)
@patch("MemLib.SharedMemory.NtMapViewOfSection", return_value=False)
@patch("MemLib.SharedMemory.MapViewOfFile", return_value=0x4000)
@patch("MemLib.SharedMemory.CreateFileMappingW", return_value=0x3000)
def test_create_cleans_up_when_remote_map_fails(_create, _map, _nt_map, unmap, close):
    shared = SharedMemory(FakeProcess())

    with pytest.raises(Exception):
        shared.create(0x1000)

    unmap.assert_called_once()
    close.assert_called_once()


@patch("MemLib.SharedMemory.CloseHandle", return_value=True)
@patch("MemLib.SharedMemory.UnmapViewOfFile", return_value=True)
@patch("MemLib.SharedMemory.NtUnmapViewOfSection", return_value=True)
@patch("MemLib.SharedMemory.DuplicateHandle", return_value=False)
@patch("MemLib.SharedMemory.NtMapViewOfSection", side_effect=_nt_map_success)
@patch("MemLib.SharedMemory.MapViewOfFile", return_value=0x4000)
@patch("MemLib.SharedMemory.CreateFileMappingW", return_value=0x3000)
def test_create_cleans_up_when_handle_duplication_fails(_create, _map, _nt_map, _dup, nt_unmap, unmap, close):
    shared = SharedMemory(FakeProcess())

    with pytest.raises(Exception):
        shared.create(0x1000)

    nt_unmap.assert_called_once()
    unmap.assert_called_once()
    close.assert_called_once()


def test_destroy_requires_owned_resources():
    shared = SharedMemory(FakeProcess())

    with pytest.raises(RuntimeError):
        shared.destroy()


@patch("MemLib.SharedMemory.DuplicateHandle", side_effect=_duplicate_handle_success)
@patch("MemLib.SharedMemory.NtUnmapViewOfSection", return_value=True)
@patch("MemLib.SharedMemory.UnmapViewOfFile", return_value=True)
@patch("MemLib.SharedMemory.CloseHandle", return_value=True)
def test_destroy_releases_local_and_remote_resources(close, unmap, nt_unmap, duplicate):
    shared = SharedMemory(FakeProcess())
    shared._memory_buffer = _make_live_buffer()
    shared._owns_remote_resources = True
    original_handle = shared._memory_buffer.handle
    original_base = shared._memory_buffer.base_address

    shared.destroy()

    unmap.assert_called_once_with(original_base)
    close.assert_called_once_with(original_handle)
    nt_unmap.assert_called_once_with(shared.process.handle, 0x2002)
    duplicate.assert_called_once()
    assert shared.handle is None
    assert shared.handle_ex is None


@patch("MemLib.SharedMemory.CloseHandle", return_value=True)
@patch("MemLib.SharedMemory.UnmapViewOfFile", return_value=True)
def test_disconnect_closes_only_local_resources(unmap, close):
    shared = SharedMemory(FakeProcess())
    shared._memory_buffer = _make_live_buffer()

    shared.disconnect()

    unmap.assert_called_once_with(0x2001)
    close.assert_called_once_with(0x1001)
    assert shared.handle is None
    assert shared.base_address is None


def test_store_and_free_delegate_to_process():
    process = FakeProcess()
    shared = SharedMemory(process)
    shared._memory_buffer = _make_live_buffer()

    assert shared.store(0x9000) is True
    process.write_struct.assert_called_once_with(0x9000, shared.buffer)

    assert shared.free() is True
    process.zero_memory.assert_called_once_with(0x9000, shared.buffer.get_size())


def test_store_requires_non_zero_address():
    shared = SharedMemory(FakeProcess())
    shared._memory_buffer = _make_live_buffer()

    with pytest.raises(ValueError):
        shared.store(0)


def test_free_returns_false_when_no_buffer_address_is_known():
    shared = SharedMemory(FakeProcess())
    shared._memory_buffer = _make_live_buffer()

    assert shared.free() is False


@patch("MemLib.SharedMemory.DuplicateHandle", side_effect=_duplicate_handle_success)
@patch("MemLib.SharedMemory.MapViewOfFile", return_value=0x7000)
def test_connect_initializes_local_view(_map, _dup):
    shared = SharedMemory(FakeProcess())
    shared.connect(0x1234, 0x5678)

    assert shared.handle == 0xCAFE
    assert shared.handle_ex == 0x1234
    assert shared.base_address == 0x7000
    assert shared.base_address_ex == 0x5678


def test_connect_rejects_invalid_inputs():
    shared = SharedMemory(FakeProcess())

    with pytest.raises(ValueError):
        shared.connect(0, 1)

    with pytest.raises(ValueError):
        shared.connect(1, 0)


@patch("MemLib.SharedMemory.DuplicateHandle", side_effect=_duplicate_handle_success)
@patch("MemLib.SharedMemory.MapViewOfFile", return_value=0x7000)
def test_connect_from_buffer_reads_remote_struct(_map, _dup):
    process = FakeProcess()
    process.read_struct.return_value = _make_live_buffer()
    shared = SharedMemory(process)

    shared.connect_from_buffer(0xDEAD)

    process.read_struct.assert_called_once()
    assert shared.base_address == 0x7000
    assert shared.base_address_ex == 0x2002


def test_connect_from_buffer_rejects_invalid_remote_buffer():
    process = FakeProcess()
    process.read_struct.return_value = None
    shared = SharedMemory(process)

    with pytest.raises(ValueError):
        shared.connect_from_buffer(0xDEAD)


def test_string_representations_handle_disconnected_state():
    shared = SharedMemory(FakeProcess())

    assert "disconnected" in str(shared)
    assert "disconnected" in repr(shared)
