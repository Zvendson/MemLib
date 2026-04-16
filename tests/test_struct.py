from ctypes import c_uint, c_void_p

from MemLib.Struct import Struct


class StructWithSingleIdentifier(Struct):
    IDENTIFIER = "foo"
    _fields_ = [("foo", c_uint), ("bar", c_uint)]


class StructWithIdentifierList(Struct):
    IDENTIFIER = ("first", "missing", "first", 123, "second")
    _fields_ = [("first", c_uint), ("second", c_uint)]


class StructWithInvalidIdentifier(Struct):
    IDENTIFIER = 123
    _fields_ = [("value", c_uint)]


class NestedChild(Struct):
    _fields_ = [("value", c_uint)]


class NestedParent(Struct):
    _fields_ = [("child", NestedChild), ("ptr", c_void_p)]


def test_to_string_formats_hex_size_correctly():
    value = StructWithSingleIdentifier()
    value.foo = 42

    result = value.to_string()

    assert "foo=42" in result or "foo=0x2A" in result
    assert "Size=0x8/8" in result


def test_to_string_uses_address_ex_when_available():
    value = StructWithSingleIdentifier()
    value.ADDRESS_EX = 0x1234

    result = value.to_string()

    assert result.startswith("StructWithSingleIdentifier(AddressEx=0x1234")


def test_to_string_deduplicates_and_filters_identifier_list():
    value = StructWithIdentifierList()
    value.first = 1
    value.second = 2

    result = value.to_string()

    assert result.count("first=") == 1
    assert result.count("second=") == 1
    assert "missing=" not in result


def test_to_string_ignores_invalid_identifier_configuration():
    value = StructWithInvalidIdentifier()
    value.value = 7

    result = value.to_string()

    assert result.startswith("StructWithInvalidIdentifier(Address=")
    assert ", value=" not in result


def test_prettify_uses_external_address_for_nested_summary():
    value = NestedParent()
    value.ADDRESS_EX = 0x4000

    output = value.prettify()

    assert "NestedChild" in output
    assert "// Start: NestedChild(AddressEx=0x4000, Size=0x4/4)" in output


def test_repr_is_single_line_summary():
    value = StructWithSingleIdentifier()
    value.foo = 99

    result = repr(value)

    assert "\n" not in result
    assert result == value.to_string()


def test_pointer_type_names_and_values_render_consistently():
    value = NestedParent()
    value.ptr = 0x1234

    output = value.prettify()

    assert "VOID*" in output
    assert "0x1234" in output
