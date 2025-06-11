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



class Struct(Structure):
    """
    ctypes.Structure with automatic _fields_ population from type annotations.

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

    Raises:
        TypeError: If non-ctypes annotation is used.
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

    def to_string(self, colorized: bool = False) -> str:
        """Returns a single-line string summary of the structure.

        Args:
            colorized (bool, optional): If True, output includes ANSI colors. Defaults to False.

        Returns:
            str: One-line string representation of the structure.
        """
        out: str = self.__class__.__name__
        addr_name: str = "Address"
        address: int = self.ADDRESS_EX

        if self.ADDRESS_EX:
            addr_name += "Ex"
        else:
            address = addressof(self)

        if colorized:
            out = JADE + out + END + f"({FLAMENCO}{addr_name}{END}={BRINK_PINK}0" \
                                     f"x{address:X}{END}"
        else:
            out += f'({addr_name}=0x{address:X}'

        if self.IDENTIFIER is not None:

            if isinstance(self.IDENTIFIER, list) or isinstance(self.IDENTIFIER, tuple):
                for key in self.IDENTIFIER:
                    for var_name, var_type in self.get_fields():
                        if key != var_name:
                            continue

                        value: Any = getattr(self, key, 0)
                        value_str: str = _ctype_format_value(value, var_type, colorized)

                        if colorized:
                            out += f', {FLAMENCO}{key}{END}={value_str}'
                        else:
                            out += f', {key}={value_str}'

            elif isinstance(self.IDENTIFIER, str):
                for var_name, var_type in self.get_fields():
                    if self.IDENTIFIER != var_name:
                        continue

                    value: Any = getattr(self, self.IDENTIFIER, 0)
                    value = _ctype_format_value(value, var_type, colorized)

                    if colorized:
                        out += f', {FLAMENCO}{self.IDENTIFIER}{END}={value}'
                    else:
                        out += f', {self.IDENTIFIER}={value}'

        size: int = sizeof(self)

        if colorized:
            out += f', {FLAMENCO}Size{END}={ELECTRIC_BLUE}0x{size:X}{END}/' \
                   f'{ELECTRIC_BLUE}{size}{END})'
        else:
            out += f', Size=0x{size}/{size})'

        return out

    def prettify(self, colorized: bool = False, indention: int = 0, start_offset: int = 0) -> str:
        """Returns a pretty, multiline string of the structure and its fields.

        Args:
            colorized (bool, optional): If True, output includes ANSI colors. Defaults to False.
            indention (int, optional): Number of spaces to indent (for nested structs). Defaults to 0.
            start_offset (int, optional): Offset for nested struct display. Defaults to 0.

        Returns:
            str: Multi-line string representation of the structure.
        """
        if self.ADDRESS_EX:
            address: int = self.ADDRESS_EX + start_offset
        else:
            address: int = addressof(self)

        fields = self.get_fields()

        # calc lengths
        var_names, var_types = zip(*fields)
        var_types = [_ctype_get_name(t) for t in var_types]

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
            var_name, var_type = field
            value: Any = getattr(self, var_name, 0)

            if issubclass(var_type, Struct):
                value.ADDRESS_EX = self.ADDRESS_EX + offset
                var_type_name: str = _ctype_get_name(var_type, colorized)

                if colorized:
                    spaces: int = var_type_len - len(_ctype_get_name(var_type)) + 2

                    out += f"{address + local_offset:X}:{' ' * indention}    {GREY}|{offset:04X}|{END}  " \
                           f"{var_type_name} " + " " * spaces + f"{WHITE}" \
                                                                f"{var_name}{END}\n"

                else:
                    out += f"{address + local_offset:X}:{' ' * indention}    |{offset:04X}|  " \
                           f"{var_type_name:{var_type_len}s}   {var_name}\n"

                out += value.prettify(colorized, indention + 5, offset) + "\n"
                offset += sizeof(var_type)
                local_offset += sizeof(var_type)

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
                    if colorized:
                        out = out.rstrip('\n') + f" {GREY}// Start: {self.to_string()}{END}\n"
                    else:
                        out = out.rstrip('\n') + f" // Start: {self.to_string()}\n"

                offset += sizeof(var_type)
                local_offset += sizeof(var_type)

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
        return self.prettify()

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
    return issubclass(ctype, Array)

def _ctype_get_is_pointer(ctype) -> bool:
    """Checks if the given ctypes type is a pointer.

    Args:
        ctype (Any): The ctypes type to check.

    Returns:
        bool: True if the type is a pointer, False otherwise.
    """
    return issubclass(ctype, _Pointer) or ctype.__name__[0:2] == "LP"

def _ctype_get_name(ctype, colorized: bool = False) -> str:
    """Gets the display name for a ctypes type, optionally colorized.

    Args:
        ctype (Any): The ctypes type.
        colorized (bool, optional): If True, include ANSI colors in output. Defaults to False.

    Returns:
        str: Readable (and optionally colorized) type name.
    """
    if issubclass(ctype, Struct):
        if colorized:
            return LIGHT_GREEN + ctype.__name__ + END
        else:
            return ctype.__name__

    extra: str = ''
    is_array: bool = _ctype_get_is_array(ctype)

    if is_array:
        arr_size: int = sizeof(ctype)
        ctype: Any = _ctype_get_array_type(ctype)

        if colorized:
            extra = f'[{ELECTRIC_BLUE}{int(arr_size / sizeof(ctype))}{END}]'
        else:
            extra = f'[{int(arr_size / sizeof(ctype))}]'

    # isinstance or issubclass doesnt work well
    is_pointer: bool = _ctype_get_is_pointer(ctype)
    cname: str = ctype.__name__
    color: str = ""
    endcolor: str = ""

    if colorized:
        color = STRAW
        endcolor = END

    if is_pointer:
        cname = cname[3:]

    if cname in c_byte.__name__:
        name: str = color + 'BYTE' + endcolor
    elif cname in c_ubyte.__name__:
        name: str = color + 'BYTE' + endcolor
    elif cname in c_ushort.__name__:
        name: str = 'WORD'
    elif cname in c_ulong.__name__:
        name: str = 'DWORD'
    elif cname in c_float.__name__:
        name: str = 'FLOAT'
    elif cname in c_long.__name__:
        name: str = 'BOOL'
    elif cname in c_void_p.__name__:
        is_pointer = True
        name: str = 'VOID'
    elif cname in c_size_t.__name__:
        name: str = 'SIZE_T'
    elif cname in c_uint.__name__:
        name: str = 'UINT'
    elif cname in c_longlong.__name__:
        name: str = 'LONGLONG'
    elif cname in c_ulonglong.__name__:
        name: str = 'ULONGLONG'
    elif cname in c_char.__name__:
        name: str = 'CHAR'
    elif cname in c_wchar.__name__:
        name: str = 'WCHAR'
    elif cname in c_char_p.__name__:
        is_pointer = True
        name: str = 'CHAR'
    elif cname in c_wchar_p.__name__:
        is_pointer = True
        name: str = 'WCHAR'
    else:
        name: str = ctype.__name__

    name = color + name + endcolor

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

    if cname in c_byte.__name__:
        return color + '%d' + endcolor
    if cname in c_ubyte.__name__:
        return color + '0x%X' + endcolor
    if cname in c_ushort.__name__:
        return color + '0x%X' + endcolor
    if cname in c_ulong.__name__:
        return color + '0x%X' + endcolor
    if cname in c_void_p.__name__:
        return color + '0x%X' + endcolor
    if cname in c_size_t.__name__:
        return color + '0x%X' + endcolor
    if cname in c_uint.__name__:
        return color + '%d' + endcolor
    if cname in c_longlong.__name__:
        return color + '%d' + endcolor
    if cname in c_ulonglong.__name__:
        return color + '0x%X' + endcolor
    if cname in c_long.__name__:
        return color + '%d' + endcolor
    if cname in c_int.__name__:
        return color + '%d' + endcolor
    if cname in c_float.__name__:
        return color + '%f' + endcolor
    if cname in c_double.__name__:
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

    if c_byte.__name__ in cname:
        return ELECTRIC_BLUE
    if c_ubyte.__name__ in cname:
        return ELECTRIC_BLUE
    if c_ushort.__name__ in cname:
        return ELECTRIC_BLUE
    if c_ulong.__name__ in cname:
        return ELECTRIC_BLUE
    if c_void_p.__name__ in cname:
        return BRINK_PINK
    if c_size_t.__name__ in cname:
        return ELECTRIC_BLUE
    if c_uint.__name__ in cname:
        return ELECTRIC_BLUE
    if c_longlong.__name__ in cname:
        return ELECTRIC_BLUE
    if c_ulonglong.__name__ in cname:
        return ELECTRIC_BLUE
    if c_long.__name__ in cname:
        return ELECTRIC_BLUE
    if c_int.__name__ in cname:
        return ELECTRIC_BLUE
    if c_float.__name__ in cname:
        return HELIOTROPE
    if c_double.__name__ in cname:
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
