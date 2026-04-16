import os
import struct

import pytest

from MemLib import FASM, FASMError
from MemLib.Hook import Hook, HookBuffer
from MemLib.Process import Process


@pytest.fixture
def current_process():
    process = Process(os.getpid())
    allocations: list[int] = []

    def allocate(size: int, initial_data: bytes = b"") -> int:
        address = process.allocate(size)
        assert address != 0
        allocations.append(address)

        if initial_data:
            assert process.write(address, initial_data)

        return address

    try:
        yield process, allocate
    finally:
        for address in reversed(allocations):
            process.free(address)
        process.close()


def _make_buffer(original_opcode: bytes, source: int, destination: int, *, address: int = 0) -> HookBuffer:
    padded_opcode = original_opcode.ljust(16, b"\x00")
    buffer = HookBuffer.from_buffer_copy(struct.pack("=16sQQB", padded_opcode, source, destination, len(original_opcode)))
    buffer.ADDRESS_EX = address
    return buffer


def _get_kernel32_export(process: Process, name: str) -> int:
    kernel32 = process.get_module("kernel32.dll")
    assert kernel32 is not None

    export = kernel32.get_export_by_name(name)
    proc_address = kernel32.get_proc_address(name)

    assert export == proc_address
    return export


def test_hook_buffer_has_contents_requires_opcode_and_addresses():
    empty = HookBuffer()
    assert empty.has_contents() is False

    opcode_only = _make_buffer(b"\x90\x90\x90\x90\x90", 0, 0)
    assert opcode_only.has_contents() is False

    complete = _make_buffer(b"\x90\x90\x90\x90\x90", 0x401000, 0x402000)
    assert complete.has_contents() is True


def test_hook_initializes_from_current_process_memory_and_stores_buffer(current_process):
    process, allocate = current_process
    source = allocate(0x1000, b"\x55\x8B\xEC\x83\xEC")
    buffer_address = allocate(HookBuffer().get_size())
    destination = source + 0x100

    hook = Hook(
        name="entry",
        process=process,
        source=source,
        destination=destination,
        buffer=buffer_address,
    )

    expected_opcode = struct.pack("=Bi", 0xE9, destination - source - 0x5)
    stored = process.read_struct(buffer_address, HookBuffer)

    assert hook.name == "entry"
    assert hook.process == process
    assert hook.src_address == source
    assert hook.dest_address == destination
    assert hook.is_enabled() is False
    assert hook.buffer.ADDRESS_EX == buffer_address
    assert bytes(hook.buffer.original_opcode)[:hook.buffer.opcode_size] == b"\x55\x8B\xEC\x83\xEC"
    assert hook.buffer.opcode_size == len(expected_opcode)
    assert stored is not None
    assert bytes(stored.original_opcode)[:stored.opcode_size] == b"\x55\x8B\xEC\x83\xEC"
    assert stored.source_address == source
    assert stored.target_address == destination
    assert "entry-Hook" in str(hook)
    assert expected_opcode.hex(" ").upper() in str(hook)


def test_hook_reuses_stored_buffer_from_current_process(current_process):
    process, allocate = current_process
    source = allocate(0x1000, b"\xCC\xCC\xCC\xCC\xCC")
    buffer_address = allocate(HookBuffer().get_size())
    destination = source + 0x100
    stored_buffer = _make_buffer(b"\x90\x90\x90\x90\x90", source, destination, address=buffer_address)

    assert process.write_struct(buffer_address, stored_buffer)

    hook = Hook(
        name="entry",
        process=process,
        source=source,
        destination=destination,
        buffer=buffer_address,
    )

    assert bytes(hook.buffer.original_opcode)[:hook.buffer.opcode_size] == b"\x90\x90\x90\x90\x90"
    assert hook.buffer.source_address == source
    assert hook.buffer.target_address == destination


def test_hook_detects_preexisting_enabled_state_and_toggle_restores_original_bytes(current_process):
    process, allocate = current_process
    source = allocate(0x1000)
    buffer_address = allocate(HookBuffer().get_size())
    destination = source + 0x100
    original_opcode = b"\x01\x02\x03\x04\x05"
    jump_opcode = Hook._build_jump_opcode(source, destination)
    stored_buffer = _make_buffer(original_opcode, source, destination, address=buffer_address)

    assert process.write(source, jump_opcode)
    assert process.write_struct(buffer_address, stored_buffer)

    hook = Hook(
        name="entry",
        process=process,
        source=source,
        destination=destination,
        buffer=buffer_address,
    )

    assert hook.is_enabled() is True

    assert hook.toggle() is False
    assert process.read(source, len(original_opcode)) == original_opcode

    assert hook.toggle() is True
    assert process.read(source, len(jump_opcode)) == jump_opcode


def test_enable_and_disable_are_idempotent_on_current_process(current_process):
    process, allocate = current_process
    source = allocate(0x1000, b"\x01\x02\x03\x04\x05")
    destination = source + 0x100
    hook = Hook(name="entry", process=process, source=source, destination=destination)
    jump_opcode = Hook._build_jump_opcode(source, destination)

    hook.enable()
    hook.enable()
    assert process.read(source, 5) == jump_opcode

    hook.disable()
    hook.disable()
    assert process.read(source, 5) == b"\x01\x02\x03\x04\x05"


def test_store_returns_false_without_buffer_address(current_process):
    process, allocate = current_process
    source = allocate(0x1000, b"\x01\x02\x03\x04\x05")
    destination = source + 0x100
    hook = Hook(name="entry", process=process, source=source, destination=destination)

    assert hook.store(0) is False


def test_hook_rejects_short_read_from_source():
    process = Process.__new__(Process)
    process.read = lambda _address, _size: b"\x90\x90"

    with pytest.raises(ValueError, match="Could not read 5 bytes"):
        Hook(name="entry", process=process, source=0x401000, destination=0x401100)


def test_hook_rejects_stored_buffer_with_mismatched_opcode_size(current_process):
    process, allocate = current_process
    if not process.is_64bit:
        pytest.skip("mismatched opcode-size regression is x64-specific")

    source = _get_kernel32_export(process, "GetCurrentProcessId")
    destination = allocate(0x1000, b"\xC3")
    buffer_address = allocate(HookBuffer().get_size())
    stored_buffer = _make_buffer(b"\x90" * 5, source, destination, address=buffer_address)

    assert process.write_struct(buffer_address, stored_buffer)

    with pytest.raises(ValueError, match="opcode size 5, expected 12"):
        Hook(name="entry", process=process, source=source, destination=destination, buffer=buffer_address)


def test_from_stored_buffer_reconstructs_hook_from_current_process(current_process):
    process, allocate = current_process
    source = allocate(0x1000, b"\x90\x90\x90\x90\x90")
    buffer_address = allocate(HookBuffer().get_size())
    destination = source + 0x100
    stored_buffer = _make_buffer(b"\x90\x90\x90\x90\x90", source, destination, address=buffer_address)

    assert process.write_struct(buffer_address, stored_buffer)

    hook = Hook.from_stored_buffer("restored", process, buffer_address)

    assert hook.name == "restored"
    assert hook.src_address == source
    assert hook.dest_address == destination
    assert bytes(hook.buffer.original_opcode)[:hook.buffer.opcode_size] == b"\x90\x90\x90\x90\x90"
    assert hook.buffer.source_address == source
    assert hook.buffer.target_address == destination


def test_hook_accepts_kernel32_export_only_when_within_rel32_range(current_process):
    process, allocate = current_process

    fasm = FASM()
    old_pid = os.getpid()

    if process.is_64bit:
        fasm.write(f"mov rax, {old_pid + 1}")
    else:
        fasm.write(f"mov eax, {old_pid + 1}")

    fasm.write("ret")
    hook_bytes = fasm.compile(max_memory_size=0x1000)

    source = allocate(len(hook_bytes), hook_bytes)
    destination = _get_kernel32_export(process, "GetCurrentProcessId")

    hook = Hook(name="entry", process=process, source=destination, destination=source)
    hook.enable()

    new_pid = os.getpid()

    hook.disable()

    assert new_pid == old_pid + 1
    assert new_pid != old_pid
    assert len(hook._opcode) in (5, 12)


def test_hook_uses_long_jump_for_out_of_range_x64_targets(current_process):
    process, allocate = current_process

    if not process.is_64bit:
        pytest.skip("long jump path is x64-specific")

    source = _get_kernel32_export(process, "GetCurrentProcessId")
    destination = allocate(0x1000, b"\xC3")
    buffer_address = allocate(HookBuffer().get_size())

    hook = Hook(name="entry", process=process, source=source, destination=destination, buffer=buffer_address)

    assert hook._opcode == Hook._build_long_jump_opcode(destination)
    assert hook.buffer.opcode_size == 12
