"""
Enhanced ctypes.Structure base class with colorized debug output.

This module provides a custom `Struct` class that enables human-friendly and colorized string representations for
debugging, and supplies some helpers.

Features:
    * Single-line and multiline colorized summaries
    * Utility methods
    * Visual Debugging

Example:
    class MyStruct(Struct):
        _fields_ = [
            ("foo", INT),
            ("bar", LPWSTR)
        ]

    s = MyStruct(42, "1337")
    print(s.prettify())
    print(s.prettify(colorized=True))

Prettify output:
MyStruct(Address=0x35C51C0, Size=0x8/8):
35C51C0:    |0000|  DWORD    foo = 42
35C51C4:    |0004|  WCHAR*   bar = 1337

References:
    https://docs.python.org/3/library/ctypes.html
    https://docs.python.org/3/reference/datamodel.html#class.__annotations__
"""

from ctypes import (
    Array, Structure, addressof, c_byte, c_char, c_char_p, c_double, c_float, c_int, c_long, c_longlong,
    c_size_t, c_ubyte, c_uint, c_ulong, c_ulonglong, c_ushort, c_void_p, c_wchar, c_wchar_p, sizeof,
)
from typing import Any

# noinspection PyProtectedMember
from _ctypes import _Pointer

from MemLib.ANSI import (
    BRINK_PINK, ELECTRIC_BLUE, END, FLAMENCO,
    GRANNY_SMITH_APPLE, GREY, HELIOTROPE, JADE,
    LIGHT_GREEN, STRAW, WHITE,
)


_TYPE_NAME_MAP: tuple[tuple[tuple[type[Any], ...], str], ...] = (
    ((c_byte,), "BYTE"),
    ((c_ubyte,), "BYTE"),
    ((c_ushort,), "WORD"),
    ((c_ulong,), "DWORD"),
    ((c_uint,), "UINT"),
    ((c_longlong,), "LONGLONG"),
    ((c_ulonglong,), "ULONGLONG"),
    ((c_float,), "FLOAT"),
    ((c_double,), "DOUBLE"),
    ((c_long,), "BOOL"),
    ((c_int,), "INT"),
    ((c_char,), "CHAR"),
    ((c_wchar,), "WCHAR"),
    ((c_char_p,), "CHAR"),
    ((c_wchar_p,), "WCHAR"),
    ((c_void_p,), "VOID"),
    ((c_size_t,), "SIZE_T"),
)

_HEX_FORMAT_TYPES: tuple[type[Any], ...] = (
    c_ubyte,
    c_ushort,
    c_ulong,
    c_void_p,
    c_size_t,
    c_ulonglong,
)

_DECIMAL_FORMAT_TYPES: tuple[type[Any], ...] = (
    c_byte,
    c_uint,
    c_longlong,
    c_long,
    c_int,
)

_FLOAT_FORMAT_TYPES: tuple[type[Any], ...] = (
    c_float,
    c_double,
)


def _safe_issubclass(candidate: Any, parents: type[Any] | tuple[type[Any], ...]) -> bool:
    """Returns False instead of raising when issubclass receives a non-type."""
    try:
        return issubclass(candidate, parents)
    except TypeError:
        return False


class Struct(Structure):
    """
    ctypes.Structure with improved debug formatting helpers.

    Supports pretty-printing, byte conversion, and colorized debugging output.

    Attributes:
        IDENTIFIER (str | list[str] | tuple[str]): Optional field(s) used as identifiers for summaries.
        ADDRESS_EX (int): Optional address override for display/debugging structs read from another process.

    Example:
        class MyStruct(Struct):
            field1: ctypes.c_uint
            field2: ctypes.c_float

        s = MyStruct(42, 3.14)
        print(s)          # Human-readable summary
        print(s.prettify(colorized=True))  # Multiline, colored

    """

    IDENTIFIER: str | list[str] | tuple[str] = None
    ADDRESS_EX: int = 0x0

    def __init__(self, *args: Any, **kw: Any) -> None:
        """Initializes the structure with given positional and keyword arguments.

        Args:
            *args: Positional arguments for the base Structure.
            **kw: Keyword arguments for the base Structure.
        """
        super(Struct, self).__init__(*args, **kw)

    def _get_display_address(self, address_override: int | None = None) -> tuple[str, int]:
        """Returns the label and address used for string output."""
        if address_override is not None:
            return "AddressEx", address_override

        if self.ADDRESS_EX:
            return "AddressEx", self.ADDRESS_EX

        return "Address", addressof(self)

    def _iter_identifier_fields(self) -> list[tuple[str, Any]]:
        """Returns identifier fields that exist on the structure in display order."""
        identifier = self.IDENTIFIER
        if identifier is None:
            return []

        if isinstance(identifier, str):
            names = [identifier]
        elif isinstance(identifier, (list, tuple)):
            names = list(identifier)
        else:
            return []

        fields_by_name = {field[0]: field[1] for field in self.get_fields()}
        seen: set[str] = set()
        resolved: list[tuple[str, Any]] = []

        for name in names:
            if not isinstance(name, str) or name in seen:
                continue

            field_type = fields_by_name.get(name)
            if field_type is None:
                continue

            seen.add(name)
            resolved.append((name, field_type))

        return resolved

    def to_string(self, colorized: bool = False) -> str:
        """Returns a single-line string summary of the structure."""
        return self._to_string(colorized)

    def _to_string(self, colorized: bool = False, address_override: int | None = None) -> str:
        """Returns a single-line string summary of the structure.

        Args:
            colorized (bool, optional): If True, output includes ANSI colors. Defaults to False.

        Returns:
            str: One-line string representation of the structure.
        """
        addr_name, address = self._get_display_address(address_override)

        if colorized:
            out = (
                f"{JADE}{self.__class__.__name__}{END}"
                f"({FLAMENCO}{addr_name}{END}={BRINK_PINK}0x{address:X}{END}"
            )
        else:
            out = f"{self.__class__.__name__}({addr_name}=0x{address:X}"

        for field_name, field_type in self._iter_identifier_fields():
            value = _ctype_format_value(getattr(self, field_name, 0), field_type, colorized)
            if colorized:
                out += f", {FLAMENCO}{field_name}{END}={value}"
            else:
                out += f", {field_name}={value}"

        size = sizeof(self)
        if colorized:
            out += (
                f", {FLAMENCO}Size{END}={ELECTRIC_BLUE}0x{size:X}{END}/"
                f"{ELECTRIC_BLUE}{size}{END})"
            )
        else:
            out += f", Size=0x{size:X}/{size})"

        return out

    def prettify(self, colorized: bool = False, indention: int = 0, start_offset: int = 0) -> str:
        """Returns a pretty, multiline string of the structure and its fields."""
        return self._prettify(colorized, indention, start_offset, self.ADDRESS_EX or None)

    def _prettify(
        self,
        colorized: bool = False,
        indention: int = 0,
        start_offset: int = 0,
        address_ex: int | None = None,
    ) -> str:
        """Returns a pretty, multiline string of the structure and its fields.

        Args:
            colorized (bool, optional): If True, output includes ANSI colors. Defaults to False.
            indention (int, optional): Number of spaces to indent (for nested structs). Defaults to 0.
            start_offset (int, optional): Offset for nested struct display. Defaults to 0.

        Returns:
            str: Multi-line string representation of the structure.
        """
        if address_ex is not None:
            address: int = address_ex + start_offset
        else:
            address: int = addressof(self)

        fields = self.get_fields()
        if not fields:
            if indention:
                return f"// Empty: {self.to_string(colorized)}"

            return self.to_string(colorized)

        # calc lengths. A _fields_ entry is (name, ctype) or (name, ctype, bit_width) for
        # bitfields, so unpack positionally rather than assuming a 2-tuple.
        var_names = [field[0] for field in fields]
        var_types = [_ctype_get_name(field[1]) for field in fields]

        var_type_len: int = len(max(var_types, key=len))
        var_name_len: int = len(max(var_names, key=len))

        if indention:
            out: str = ""
        else:
            out: str = self.to_string(colorized) + ':\n'

        offset: int = start_offset
        local_offset: int = 0
        is_first: bool = True

        for field in fields:
            var_name, var_type = field[0], field[1]
            value: Any = getattr(self, var_name, 0)

            # Real ctypes offset, so alignment padding is reported correctly.
            local_offset = self._field_offset(var_name)
            offset = start_offset + local_offset

            if issubclass(var_type, Struct):
                var_type_name: str = _ctype_get_name(var_type, colorized)

                if colorized:
                    spaces: int = var_type_len - len(_ctype_get_name(var_type)) + 2

                    out += f"{address + local_offset:X}:{' ' * indention}    {GREY}|{offset:04X}|{END}  " \
                           f"{var_type_name} " + " " * spaces + f"{WHITE}" \
                                                                f"{var_name}{END}\n"

                else:
                    out += f"{address + local_offset:X}:{' ' * indention}    |{offset:04X}|  " \
                           f"{var_type_name:{var_type_len}s}   {var_name}\n"

                out += value._prettify(colorized, indention + 5, offset, address_ex) + "\n"

            else:
                var_type_name: str = _ctype_get_name(var_type, colorized)
                value: str = _ctype_format_value(value, var_type, colorized)

                if colorized:
                    spaces: int = var_type_len - len(_ctype_get_name(var_type)) + 2

                    out += f"{address + local_offset:X}:{' ' * indention}    {GREY}|{offset:04X}|{END}  " \
                           f"{var_type_name} " + " " * spaces + f"{WHITE}" \
                                                                f"{var_name:{var_name_len}}{END} = {value}\n"

                else:
                    out += f"{address + local_offset:X}:{' ' * indention}    |{offset:04X}|  " \
                           f"{var_type_name:{var_type_len}s}   {var_name:{var_name_len}} = {value}\n"

                if is_first and indention:
                    is_first = False
                    start_summary = self._to_string(
                        colorized=colorized,
                        address_override=(address_ex + start_offset) if address_ex is not None else None,
                    )
                    if colorized:
                        out = out.rstrip('\n') + f" {GREY}// Start: {start_summary}{END}\n"
                    else:
                        out = out.rstrip('\n') + f" // Start: {start_summary}\n"

        if indention:
            if colorized:
                return out.rstrip('\n') + f" {GREY}// End: {self.__class__.__name__ + END}"
            else:
                return out.rstrip('\n') + f" // End: {self.__class__.__name__}"

        else:
            return out.rstrip('\n')

    def get_fields(self) -> list[tuple[str, Any]]:
        """Returns the fields of the structure.

        Returns:
            list[tuple[str, Any]]: List of (field_name, ctype) pairs for the structure.
        """
        return self._fields_

    def _field_offset(self, field_name: str) -> int:
        """Returns the real byte offset of a field, including alignment padding.

        ctypes inserts padding between fields unless ``_pack_ = 1`` is set, so an offset
        derived by accumulating ``sizeof()`` is wrong for any unpacked structure. The
        descriptor on the class carries the authoritative offset.

        Args:
            field_name (str): Name of the field.

        Returns:
            int: Byte offset of the field from the start of the structure.
        """
        descriptor = getattr(type(self), field_name, None)
        offset = getattr(descriptor, "offset", None)
        if offset is None:
            # Bitfields and exotic descriptors expose no offset; fall back to 0 rather
            # than reporting a fabricated one.
            return 0

        return int(offset)

    def get_field_offsets(self) -> dict[str, int]:
        """Returns the real byte offset of every field, including alignment padding.

        Returns:
            dict[str, int]: Mapping of field name to its byte offset.
        """
        return {name: self._field_offset(name) for name, *_ in self.get_fields()}

    def get_size(self) -> int:
        """Returns the size of the structure in bytes.

        Returns:
            int: Size of the structure.
        """
        return sizeof(self)

    def get_address(self) -> int:
        """Returns the address of the structure in Python memory.

        Returns:
            int: Memory address of this structure.
        """
        return addressof(self)

    def get_address_ex(self) -> int:
        """Returns the external address of the structure if set.

        Returns:
            int: Custom (external) address or 0 if not set.
        """
        return self.ADDRESS_EX

    def __repr__(self) -> str:
        """Returns a human-readable full summary string for the structure.

        Returns:
            str: The string representation of the structure.
        """
        return self.to_string()

    def __str__(self) -> str:
        """Returns a human-readable summary string for the structure.

        Returns:
            str: Human-readable summary.
        """
        return self.to_string()

def _ctype_get_array_type(ctype: Any) -> Any:
    """Returns the underlying type of a ctypes array.

    Args:
        ctype (Any): The ctypes array type.

    Returns:
        Any: The element type of the array.
    """
    # noinspection PyProtectedMember
    return ctype._type_

def _ctype_get_is_array(ctype) -> bool:
    """Returns the base type of a ctypes array.

    Args:
        ctype (Any): The ctypes array type.

    Returns:
        Any: The element type of the array.
    """
    return _safe_issubclass(ctype, Array)

def _ctype_get_is_pointer(ctype) -> bool:
    """Checks if the given ctypes type is a pointer.

    Args:
        ctype (Any): The ctypes type to check.

    Returns:
        bool: True if the type is a pointer, False otherwise.
    """
    return _safe_issubclass(ctype, _Pointer) or getattr(ctype, "__name__", "").startswith("LP")

def _ctype_get_name(ctype, colorized: bool = False) -> str:
    """Gets the display name for a ctypes type, optionally colorized.

    Args:
        ctype (Any): The ctypes type.
        colorized (bool, optional): If True, include ANSI colors in output. Defaults to False.

    Returns:
        str: Readable (and optionally colorized) type name.
    """
    if _safe_issubclass(ctype, Struct):
        if colorized:
            return LIGHT_GREEN + ctype.__name__ + END
        else:
            return ctype.__name__

    extra: str = ''
    is_array: bool = _ctype_get_is_array(ctype)

    if is_array:
        count = getattr(ctype, "_length_", 0)
        ctype = _ctype_get_array_type(ctype)

        if colorized:
            extra = f'[{ELECTRIC_BLUE}{count}{END}]'
        else:
            extra = f'[{count}]'

    is_pointer: bool = _ctype_get_is_pointer(ctype)
    color: str = ""
    endcolor: str = ""
    base_type = ctype

    if colorized:
        color = STRAW
        endcolor = END

    if is_pointer and hasattr(ctype, "_type_") and isinstance(ctype._type_, type):
        base_type = ctype._type_

    name = None
    for type_group, display_name in _TYPE_NAME_MAP:
        if _safe_issubclass(base_type, type_group):
            name = display_name
            if base_type in (c_char_p, c_wchar_p, c_void_p):
                is_pointer = True
            break

    if name is None:
        if is_pointer and getattr(ctype, "__name__", "").startswith("LP") and len(ctype.__name__) > 2:
            name = ctype.__name__[2:]
        else:
            name = getattr(base_type, "__name__", str(base_type))

    if colorized:
        name = color + name + endcolor
    else:
        name = str(name)

    if is_pointer and colorized:
        name += BRINK_PINK + '*' + END
    elif is_pointer:
        name += '*'

    return name + extra

def _ctype_get_format(ctype, color: str = "") -> str:
    """Returns the format string used to display a value of the given ctypes type.

    Args:
        ctype (Any): The ctypes type.
        color (str, optional): ANSI color string prefix for formatting. Defaults to "".

    Returns:
        str: Format string for the type, e.g. '%d', '%X', '%f'.
    """
    endcolor: str = ""
    cname: str = ctype.__name__

    if color != "":
        endcolor = END

    if _ctype_get_is_pointer(ctype):
        return color + '0x%X' + endcolor

    if _safe_issubclass(ctype, _HEX_FORMAT_TYPES):
        return color + '0x%X' + endcolor
    if _safe_issubclass(ctype, _DECIMAL_FORMAT_TYPES):
        return color + '%d' + endcolor
    if _safe_issubclass(ctype, _FLOAT_FORMAT_TYPES):
        return color + '%f' + endcolor

    return color + f'%s' + endcolor

def _ctype_get_color(ctype) -> str:
    """Returns an ANSI color code for the given ctypes type.

    Args:
        ctype (Any): The ctypes type.

    Returns:
        str: ANSI color code as a string for pretty-printing.
    """
    cname: str = ctype.__name__

    if _ctype_get_is_pointer(ctype):
        return BRINK_PINK

    if _safe_issubclass(ctype, _HEX_FORMAT_TYPES + _DECIMAL_FORMAT_TYPES):
        return ELECTRIC_BLUE
    if _safe_issubclass(ctype, _FLOAT_FORMAT_TYPES):
        return HELIOTROPE

    return GRANNY_SMITH_APPLE

def _ctype_format_value(cvalue: Any, ctype, colorized: bool = False) -> str:
    """Formats a ctypes value as a string, handling arrays, pointers, and scalar values.

    Args:
        cvalue (Any): The value to format.
        ctype (Any): The ctypes type of the value.
        colorized (bool, optional): If True, output will include ANSI color codes. Defaults to False.

    Returns:
        str: The formatted string for the value.
    """

    if colorized:
        color: str = _ctype_get_color(ctype)
    else:
        color: str = ""

    if _ctype_get_is_array(ctype):
        _type: Any = _ctype_get_array_type(ctype)
        fmt: str = _ctype_get_format(_type, color)
        arr_type: Any = _ctype_get_array_type(ctype)

        if issubclass(arr_type, c_char) or issubclass(arr_type, c_wchar):
            return fmt % cvalue

        else:
            values: list[int] = list(cvalue)

        for i, value in enumerate(values):
            if _ctype_get_is_pointer(value.__class__):
                values[i] = addressof(value)
            if value is None and ('%X' in fmt or '%f' in fmt):
                values[i] = 0

        return f"[{', '.join([(fmt % val) for val in values])}]"

    fmt: str = _ctype_get_format(ctype, color)

    if ctype == c_char_p:
        if cvalue is None:
            cvalue = b''
        return fmt % cvalue

    if ctype == c_wchar_p:
        if cvalue is None:
            cvalue = ""
        return fmt % cvalue

    if _ctype_get_is_pointer(cvalue.__class__):
        cvalue = addressof(cvalue) if cvalue else 0

    if cvalue is None and ('%X' in fmt or '%f' in fmt):
        cvalue = 0

    return fmt % cvalue
