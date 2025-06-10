"""
:platform: Windows
"""

from __future__ import annotations

from ctypes import (
    Array, Structure, addressof, c_byte,
    c_char, c_char_p, c_double, c_float,
    c_int, c_long, c_longlong, c_size_t, c_ubyte,
    c_uint, c_ulong, c_ulonglong, c_ushort,
    c_void_p, c_wchar, c_wchar_p, create_string_buffer, memmove,
    sizeof,
)
from typing import Any

# noinspection PyProtectedMember
from _ctypes import _Pointer

from MemLib.ANSI import (
    BRINK_PINK, ELECTRIC_BLUE, END, FLAMENCO,
    GRANNY_SMITH_APPLE, GREY, HELIOTROPE, JADE,
    LIGHT_GREEN, STRAW, WHITE,
)
from MemLib.Decorators import deprecated


class Struct(Structure):
    """
    A structure wrapper for the ctype library to allow for pretty debug printing and some utils.
    """

    IDENTIFIER: str | list[str] | tuple[str] = None
    ADDRESS_EX: int = 0x0

    _fields_ = []

    def __init__(self, *args: Any, **kw: Any):
        super(Struct, self).__init__(*args, **kw)

    def __repr__(self):
        return str(self)

    def __str__(self):
        return self.to_string()

    @deprecated("Use ToBytes() instead.")
    def __bytes__(self):
        return self.to_bytes()

    @classmethod
    def from_bytes(cls, buffer: bytes) -> Struct:
        struct: Struct = cls()
        size:   int    = len(buffer)

        if size > struct.get_size():
            size = struct.get_size()

        memmove(struct.get_address(), buffer, size)

        return struct

    @classmethod
    def from_addr(cls, address: int) -> Struct | None:
        return cls.from_address(address)

    def to_bytes(self):
        buffer: Array = create_string_buffer(self.get_size())

        memmove(buffer, self.get_address(), self.get_size())

        return buffer.raw

    def to_string(self, colorized: bool = False) -> str:
        """
        :param colorized: Determines if the output should be ANSI colored or not.
        :returns: A single line string representation of the structure.
        """

        out: str       = self.__class__.__name__
        addr_name: str = "Address"
        address: int   = self.ADDRESS_EX

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

                        value: Any     = getattr(self, key, 0)
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
                    value      = _ctype_format_value(value, var_type, colorized)

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
        """
        :param colorized: Determines if the output should be ANSI colored or not.
        :param indention: The number of spaces to indent the output. *For Struct inside struct representation.*
        :param start_offset: The offset to start the output at. *For Struct inside struct representation.*
        :returns: A multi line string representation of the structure.
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

        offset: int       = start_offset
        local_offset: int = 0
        is_first: bool    = True

        for field in fields:
            var_name, var_type = field
            value: Any = getattr(self, var_name, 0)

            if issubclass(var_type, Struct):
                value.ADDRESS_EX   = self.ADDRESS_EX + offset
                var_type_name: str = _ctype_get_name(var_type, colorized)

                if colorized:
                    spaces: int = var_type_len - len(_ctype_get_name(var_type)) + 2

                    out += f"{address + local_offset:X}:{' ' * indention}    {GREY}|{offset:04X}|{END}  " \
                           f"{var_type_name} " + " " * spaces + f"{WHITE}" \
                           f"{var_name}{END}\n"

                else:
                    out += f"{address + local_offset:X}:{' ' * indention}    |{offset:04X}|  " \
                           f"{var_type_name:{var_type_len}s}   {var_name}\n"

                out          += value.prettify(colorized, indention + 5, offset) + "\n"
                offset       += sizeof(var_type)
                local_offset += sizeof(var_type)

            else:
                var_type_name: str = _ctype_get_name(var_type, colorized)
                value: str         = _ctype_format_value(value, var_type, colorized)

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

                offset       += sizeof(var_type)
                local_offset += sizeof(var_type)

        if indention:
            if colorized:
                return out.rstrip('\n') + f" {GREY}// End: {self.__class__.__name__ + END}"
            else:
                return out.rstrip('\n') + f" // End: {self.__class__.__name__}"

        else:
            return out.rstrip('\n')

    def get_fields(self) -> list:
        """
        :returns: The fields of the structure.
        """

        return self._fields_

    def get_size(self) -> int:
        """
        :returns: The size of the structure.
        """

        return sizeof(self)

    def get_address(self) -> int:
        """
        :returns: the address in Python's memory area..
        """

        return addressof(self)

    def get_address_ex(self) -> int:
        """
        :returns: the address in Python's memory area..
        """

        return self.ADDRESS_EX


def _ctype_get_array_type(ctype: Any):
    # noinspection PyProtectedMember
    return ctype._type_


def _ctype_get_is_array(ctype) -> bool:
    return issubclass(ctype, Array)


def _ctype_get_is_pointer(ctype) -> bool:
    return issubclass(ctype, _Pointer) or ctype.__name__[0:2] == "LP"


def _ctype_get_name(ctype, colorized: bool = False) -> str:
    if issubclass(ctype, Struct):
        if colorized:
            return LIGHT_GREEN + ctype.__name__ + END
        else:
            return ctype.__name__

    extra: str     = ''
    is_array: bool = _ctype_get_is_array(ctype)

    if is_array:
        arr_size: int = sizeof(ctype)
        ctype: Any    = _ctype_get_array_type(ctype)

        if colorized:
            extra = f'[{ELECTRIC_BLUE}{int(arr_size / sizeof(ctype))}{END}]'
        else:
            extra = f'[{int(arr_size / sizeof(ctype))}]'

    # isinstance or issubclass doesnt work well
    is_pointer: bool = _ctype_get_is_pointer(ctype)
    cname: str       = ctype.__name__
    color: str       = ""
    endcolor: str    = ""

    if colorized:
        color    = STRAW
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
    endcolor: str = ""
    cname:    str = ctype.__name__

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
    if colorized:
        color: str = _ctype_get_color(ctype)
    else:
        color: str = ""

    if _ctype_get_is_array(ctype):
        _type:    Any = _ctype_get_array_type(ctype)
        fmt:      str = _ctype_get_format(_type, color)
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

    if _ctype_get_is_pointer(cvalue.__class__):
        cvalue = addressof(cvalue)

    if cvalue is None and ('%X' in fmt or '%f' in fmt):
        cvalue = 0

    return fmt % cvalue
