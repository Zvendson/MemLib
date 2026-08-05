from ctypes import c_ubyte, c_uint16, c_uint32, sizeof

from MemLib.Struct import Struct


# c_uint32 rather than c_ulong: c_ulong is 8 bytes on LP64 platforms, which changes the
# padding and makes the expected offsets below platform-dependent.
class UnpackedStruct(Struct):
    """ctypes inserts padding here: a=0, b=4, c=8 (sizeof 12)."""

    _fields_ = [("a", c_ubyte), ("b", c_uint32), ("c", c_uint16)]


class PackedStruct(Struct):
    """No padding: a=0, b=1, c=5 (sizeof 7)."""

    _pack_ = 1
    _fields_ = [("a", c_ubyte), ("b", c_uint32), ("c", c_uint16)]


class UnpackedChild(Struct):
    _fields_ = [("x", c_ubyte), ("y", c_uint32)]


class UnpackedParent(Struct):
    _fields_ = [("lead", c_ubyte), ("child", UnpackedChild), ("tail", c_uint32)]


class BitfieldStruct(Struct):
    """A `_fields_` entry with a bit width is a 3-tuple, not a 2-tuple."""

    _fields_ = [("low", c_uint32, 3), ("high", c_uint32, 5)]


def _offsets_from_ctypes(struct_type) -> dict[str, int]:
    return {name: getattr(struct_type, name).offset for name, *_ in struct_type._fields_}


def test_field_offsets_match_ctypes_for_unpacked_struct():
    instance = UnpackedStruct(1, 2, 3)
    assert instance.get_field_offsets() == _offsets_from_ctypes(UnpackedStruct)
    assert instance.get_field_offsets() == {"a": 0, "b": 4, "c": 8}


def test_field_offsets_match_ctypes_for_packed_struct():
    instance = PackedStruct(1, 2, 3)
    assert instance.get_field_offsets() == _offsets_from_ctypes(PackedStruct)
    assert instance.get_field_offsets() == {"a": 0, "b": 1, "c": 5}


def test_prettify_reports_padded_offsets_not_accumulated_sizes():
    instance = UnpackedStruct(1, 2, 3)
    lines = instance.prettify().splitlines()[1:]

    printed = [line.split("|")[1] for line in lines]
    assert printed == ["0000", "0004", "0008"]


def test_prettify_still_correct_for_packed_struct():
    instance = PackedStruct(1, 2, 3)
    lines = instance.prettify().splitlines()[1:]

    printed = [line.split("|")[1] for line in lines]
    assert printed == ["0000", "0001", "0005"]


def test_prettify_addresses_track_real_field_offsets():
    instance = UnpackedStruct(1, 2, 3)
    base = instance.get_address()
    lines = instance.prettify().splitlines()[1:]

    printed = [int(line.split(":")[0], 16) for line in lines]
    assert printed == [base + 0, base + 4, base + 8]


def test_prettify_nested_struct_uses_real_offsets():
    instance = UnpackedParent()
    assert instance.get_field_offsets() == _offsets_from_ctypes(UnpackedParent)

    # The nested child starts after padding, not immediately after `lead`.
    assert instance.get_field_offsets()["child"] == getattr(UnpackedParent, "child").offset
    assert instance.get_field_offsets()["child"] != sizeof(c_ubyte)

    rendered = instance.prettify()
    child_offset = instance.get_field_offsets()["child"]
    assert f"|{child_offset:04X}|" in rendered


def test_prettify_does_not_crash_on_bitfields():
    """A 3-tuple `_fields_` entry used to raise ValueError from `zip(*fields)`."""
    instance = BitfieldStruct()

    rendered = instance.prettify()
    assert "low" in rendered
    assert "high" in rendered
    assert instance.get_field_offsets() == {"low": 0, "high": 0}


def test_identifier_lookup_does_not_crash_on_bitfields():
    """The IDENTIFIER path unpacked 2-tuples too, so bitfields broke to_string()."""

    class BitfieldWithIdentifier(BitfieldStruct):
        IDENTIFIER = "low"

    instance = BitfieldWithIdentifier()
    instance.low = 5

    assert "low" in instance.to_string()
