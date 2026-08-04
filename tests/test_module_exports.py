import os

import pytest

from MemLib.Process import Process


@pytest.fixture
def process() -> Process:
    return Process(os.getpid())


@pytest.fixture
def kernel32(process):
    module = process.get_module("kernel32.dll")
    assert module is not None
    return module


def _split_exports(process, module):
    """Returns (forwarded, real) export names straight from the PE tables."""
    export_dir = module.export_directory
    forwarded, real = [], []

    for index in range(export_dir.NumberOfNames):
        name_rva = process.read_dword(module.base + export_dir.AddressOfNames + index * 4)
        name = process.read_string(module.base + name_rva, 256).decode("ascii", errors="replace")

        ordinal_index = process.read_word(module.base + export_dir.AddressOfNameOrdinals + index * 2)
        function_rva = process.read_dword(module.base + export_dir.AddressOfFunctions + ordinal_index * 4)

        target = forwarded if module._is_forwarder(function_rva) else real
        target.append(name)

    return forwarded, real


def test_kernel32_actually_has_forwarded_exports(process, kernel32):
    forwarded, real = _split_exports(process, kernel32)

    # Not a synthetic edge case: a large share of kernel32 is forwarded to ntdll.
    assert forwarded, "expected kernel32 to contain forwarded exports"
    assert real


def test_forwarded_export_raises_instead_of_returning_a_string_pointer(process, kernel32):
    forwarded, _real = _split_exports(process, kernel32)
    name = forwarded[0]

    with pytest.raises(ValueError) as caught:
        kernel32.get_export_by_name(name)

    assert "forwarded" in str(caught.value)


def test_get_forwarder_resolves_the_target(process, kernel32):
    forwarded, _real = _split_exports(process, kernel32)
    target = kernel32.get_forwarder(forwarded[0])

    assert target
    assert "." in target, "a forwarder target looks like 'MODULE.Function'"


def test_get_forwarder_returns_none_for_a_real_export(kernel32):
    assert kernel32.get_forwarder("CreateFileW") is None


def test_get_forwarder_raises_for_a_missing_export(kernel32):
    with pytest.raises(ValueError):
        kernel32.get_forwarder("ThisExportDoesNotExist")


def test_real_exports_still_resolve(kernel32):
    address = kernel32.get_export_by_name("CreateFileW")

    assert address
    assert kernel32.base <= address < kernel32.base + kernel32.size


def test_get_exports_skips_forwarders_by_default(process, kernel32):
    forwarded, _real = _split_exports(process, kernel32)
    exports = kernel32.get_exports()

    directory_rva, directory_size = kernel32._export_directory_range()
    low = kernel32.base + directory_rva
    high = low + directory_size

    # No returned address may point inside the export directory.
    assert not [address for address in exports.values() if low <= address < high]
    assert forwarded[0] not in exports


def test_get_exports_can_include_forwarders_on_request(kernel32):
    default = kernel32.get_exports()
    assert "CreateFileW" in default

    fresh = process_module(kernel32)
    included = fresh.get_exports(include_forwarders=True)
    assert len(included) >= len(default)


def process_module(module):
    """Returns a fresh Module for the same DLL, with an empty export cache."""
    return module.process.get_module(module.name)


def test_missing_export_raises(kernel32):
    with pytest.raises(ValueError):
        kernel32.get_export_by_name("ThisExportDoesNotExist")


def test_export_lookup_is_cached(kernel32):
    first = kernel32.get_export_by_name("CreateFileW")
    second = kernel32.get_export_by_name("CreateFileW")

    assert first == second
    assert kernel32._exports["CreateFileW"] == first


def test_get_export_by_ordinal_rejects_forwarders(process, kernel32):
    export_dir = kernel32.export_directory
    forwarded_ordinal = None

    for index in range(export_dir.NumberOfFunctions):
        function_rva = process.read_dword(kernel32.base + export_dir.AddressOfFunctions + index * 4)
        if function_rva and kernel32._is_forwarder(function_rva):
            forwarded_ordinal = export_dir.Base + index
            break

    if forwarded_ordinal is None:
        pytest.skip("no forwarded ordinal available in kernel32")

    with pytest.raises(ValueError) as caught:
        kernel32.get_export_by_ordinal(forwarded_ordinal)

    assert "forwarded" in str(caught.value)


def test_cached_forwarder_is_still_rejected(process, kernel32):
    """get_exports(include_forwarders=True) poisons the cache with forwarder entries.

    The cache-hit path returned those verbatim, handing back a pointer into the export
    directory and bypassing the rejection this PR added.
    """
    forwarded, _real = _split_exports(process, kernel32)
    fresh = process_module(kernel32)

    fresh.get_exports(include_forwarders=True)
    assert forwarded[0] in fresh._exports, "expected the forwarder to be cached"

    with pytest.raises(ValueError) as caught:
        fresh.get_export_by_name(forwarded[0])

    assert "forwarded" in str(caught.value)


def test_get_forwarder_reports_a_zero_rva_instead_of_calling_it_real_code(kernel32, monkeypatch):
    """RVA 0 is neither a forwarder nor an address; None would mean "not forwarded"."""
    monkeypatch.setattr(kernel32, "_function_rva_by_name", lambda name: 0)

    with pytest.raises(ValueError) as caught:
        kernel32.get_forwarder("CreateFileW")

    assert "RVA is 0" in str(caught.value)
