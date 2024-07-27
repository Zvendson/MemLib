"""
:platform: Windows
"""

from __future__ import annotations

from ctypes import (
    Array, Structure, addressof, c_byte,
    c_char, c_char_p, c_double, c_float,
    c_int, c_long, c_longlong, c_size_t, c_ubyte,
    c_uint, c_ulong, c_ulonglong, c_ushort,
    c_void_p, c_wchar, c_wchar_p, memmove,
    sizeof, wintypes,
)
from ctypes.wintypes import CHAR
from typing import Any

# noinspection PyProtectedMember
from _ctypes import _Pointer

from MemLib.ANSI import (
    BRINK_PINK, ELECTRIC_BLUE, END, FLAMENCO,
    GRANNY_SMITH_APPLE, GREY, HELIOTROPE, JADE,
    LIGHT_GREEN, STRAW, WHITE,
)
from MemLib.Decorators import Deprecated


# redeclaring, because ctypes made BYTE a signed value, which is incorrect.
wintypes.BYTE = c_ubyte


class Struct(Structure):
    """
    A structure wrapper for the ctype library to allow for pretty debug printing and some utils.
    """

    IDENTIFIER = None
    ADRESS_EX  = 0x0

    _fields_ = []

    def __init__(self, *args: Any, **kw: Any):
        super(Struct, self).__init__(*args, **kw)

    def __repr__(self):
        return str(self)

    def __str__(self):
        return self.ToString()

    @Deprecated("Use ToBytes() instead.")
    def __bytes__(self):
        return self.ToBytes()

    @classmethod
    def FromBytes(cls, buffer: bytes) -> Struct:
        struct: Struct = cls()
        size:   int    = len(buffer)

        if size > struct.GetSize():
            size = struct.GetSize()

        memmove(struct.GetAddress(), buffer, size)

        return struct

    @classmethod
    def FromAddress(cls, address: int) -> Struct | None:
        return cls.from_address(address)

    def ToBytes(self):
        buffer: Array = (CHAR * self.GetSize())()

        memmove(buffer, self.GetAddress(), self.GetSize())

        return buffer.raw

    def ToString(self, colorized: bool = False) -> str:
        """
        :param colorized: Determines if the output should be ANSI colored or not.
        :returns: A single line string representation of the structure.
        """

        out:      str = self.__class__.__name__
        addrName: str = "Adress"
        address:  int = self.ADRESS_EX

        if self.ADRESS_EX:
            addrName += "Ex"
        else:
            address = addressof(self)

        if colorized:
            out = JADE + out + END + f"({FLAMENCO}{addrName}{END}={BRINK_PINK}0" \
                                                 f"x{address:X}{END}"
        else:
            out += f'({addrName}=0x{address:X}'

        if self.IDENTIFIER is not None:

            if isinstance(self.IDENTIFIER, list) or isinstance(self.IDENTIFIER, tuple):
                for key in self.IDENTIFIER:
                    for varname, vartype in self.GetFields():
                        if key != varname:
                            continue

                        value: Any = getattr(self, key, 0)
                        value      = _ctype_format_value(value, vartype, colorized)

                        if colorized:
                            out += f', {FLAMENCO}{key}{END}={value}'
                        else:
                            out += f', {key}={value}'

            elif isinstance(self.IDENTIFIER, str):
                for varname, vartype in self.GetFields():
                    if self.IDENTIFIER != varname:
                        continue

                    value: Any = getattr(self, self.IDENTIFIER, 0)
                    value      = _ctype_format_value(value, vartype, colorized)

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

    def Prettify(self, colorized: bool = False, Indention: int = 0, StartOffset: int = 0) -> str:
        """
        :param colorized: Determines if the output should be ANSI colored or not.
        :param Indention: The number of spaces to indent the output. *For Struct inside struct representation.*
        :param StartOffset: The offset to start the output at. *For Struct inside struct representation.*
        :returns: A multi line string representation of the structure.
        """

        if self.ADRESS_EX:
            address: int = self.ADRESS_EX + StartOffset
        else:
            address: int = addressof(self)

        fields = self.GetFields()

        # calc lengths
        varNames, varTypes = zip(*fields)
        varTypes = [_ctype_get_name(t) for t in varTypes]

        vartype_len: int = len(max(varTypes, key=len))
        varname_len: int = len(max(varNames, key=len))

        if Indention:
            out: str = ""
        else:
            out: str = self.ToString(colorized) + ':\n'

        offset:      int  = StartOffset
        localoffset: int  = 0
        isFirst:     bool = True

        for field in fields:
            varname, vartype = field
            value: Any = getattr(self, varname, 0)

            if issubclass(vartype, Struct):
                value.ADRESS_EX  = self.ADRESS_EX + offset
                vartype_name: str = _ctype_get_name(vartype, colorized)

                if colorized:
                    spaces: int = vartype_len - len(_ctype_get_name(vartype)) + 2

                    out += f"{address + localoffset:X}:{' ' * Indention}    {GREY}|{offset:04X}|{END}  " \
                           f"{vartype_name} " + " " * spaces + f"{WHITE}" \
                           f"{varname}{END}\n"

                else:
                    out += f"{address + localoffset:X}:{' ' * Indention}    |{offset:04X}|  " \
                           f"{vartype_name:{vartype_len}s}   {varname}\n"

                out             += value.Prettify(colorized, Indention + 5, offset) + "\n"
                offset          += sizeof(vartype)
                localoffset     += sizeof(vartype)

            else:
                vartype_name: str = _ctype_get_name(vartype, colorized)
                value:        str = _ctype_format_value(value, vartype, colorized)

                if colorized:
                    spaces: int = vartype_len - len(_ctype_get_name(vartype)) + 2

                    out += f"{address + localoffset:X}:{' ' * Indention}    {GREY}|{offset:04X}|{END}  " \
                           f"{vartype_name} " + " " * spaces + f"{WHITE}" \
                           f"{varname:{varname_len}}{END} = {value}\n"

                else:
                    out += f"{address + localoffset:X}:{' ' * Indention}    |{offset:04X}|  " \
                           f"{vartype_name:{vartype_len}s}   {varname:{varname_len}} = {value}\n"

                if isFirst and Indention:
                    isFirst = False
                    if colorized:
                        out = out.rstrip('\n') + f" {GREY}// Start: {self.ToString()}{END}\n"
                    else:
                        out = out.rstrip('\n') + f" // Start: {self.ToString()}\n"

                offset      += sizeof(vartype)
                localoffset += sizeof(vartype)

        if Indention:
            if colorized:
                return out.rstrip('\n') + f" {GREY}// End: {self.__class__.__name__ + END}"
            else:
                return out.rstrip('\n') + f" // End: {self.__class__.__name__}"

        else:
            return out.rstrip('\n')

    def GetFields(self) -> list:
        """
        :returns: The fields of the structure.
        """

        return self._fields_

    def GetSize(self) -> int:
        """
        :returns: The size of the structure.
        """

        return sizeof(self)

    def GetAddress(self) -> int:
        """
        :returns: the address in Python's memory area..
        """

        return addressof(self)

    def GetAddressEx(self) -> int:
        """
        :returns: the address in Python's memory area..
        """

        return self.ADRESS_EX


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

    extra:   str  = ''
    isArray: bool = _ctype_get_is_array(ctype)

    if isArray:
        arr_size: int = sizeof(ctype)
        ctype:    Any = _ctype_get_array_type(ctype)

        if colorized:
            extra = f'[{ELECTRIC_BLUE}{int(arr_size / sizeof(ctype))}{END}]'
        else:
            extra = f'[{int(arr_size / sizeof(ctype))}]'

    # isinstance or issubclass doesnt work well
    isPointer: bool = _ctype_get_is_pointer(ctype)
    cname:     str  = ctype.__name__
    color:     str  = ""
    endcolor:  str  = ""

    if colorized:
        color    = STRAW
        endcolor = END

    if isPointer:
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
        isPointer = True
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
        isPointer = True
        name: str = 'CHAR'
    elif cname in c_wchar_p.__name__:
        isPointer = True
        name: str = 'WCHAR'
    else:
        name: str = ctype.__name__

    name = color + name + endcolor

    if isPointer and colorized:
        name += BRINK_PINK + '*' + END
    elif isPointer:
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



