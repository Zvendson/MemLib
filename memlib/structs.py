"""
:platform: Windows
"""

from __future__ import annotations

from ctypes import wintypes
from ctypes import (
    Structure, WINFUNCTYPE, addressof, c_byte, c_char, c_char_p, c_double, c_float, c_int, c_long, c_size_t, c_uint,
    c_ulong,
    c_ulonglong,
    c_ushort,
    c_void_p, c_wchar, c_wchar_p, c_ubyte,
)
from ctypes.wintypes import (
    BYTE, CHAR, DWORD, HANDLE, HMODULE, HWND, INT, LONG, LPARAM, LPCSTR, LPSTR, LPVOID, MAX_PATH, PBYTE, UINT, ULONG,
    WORD, WPARAM,
)
from typing import Any

# noinspection PyProtectedMember
from _ctypes import Array, _Pointer, sizeof, _SimpleCData

# redeclaring, because ctypes made BYTE a signed value, which is incorrect.
wintypes.BYTE = c_ubyte


def __RGB2AnsiCodeFG(red: int, green: int, blue: int) -> str:
    return f"\033[38;2;{red};{green};{blue}m"

# https://www.color-blindness.com/color-name-hue/
ANSIFG_SAFETY_ORANGE = __RGB2AnsiCodeFG(255, 111, 0)
ANSIFG_ELECTRIC_BLUE = __RGB2AnsiCodeFG(135, 239, 255)
ANSIFG_HELIOTROPE = __RGB2AnsiCodeFG(230, 130, 255)
ANSIFG_GRANNY_SMITH_APPLE = __RGB2AnsiCodeFG(155, 230, 142)
ANSIFG_FLAMENCO = __RGB2AnsiCodeFG(232, 152, 77)
ANSIFG_BRINK_PINK = __RGB2AnsiCodeFG(250, 102, 129)
ANSIFG_GREY = __RGB2AnsiCodeFG(120, 120, 120)
ANSIFG_STRAW = __RGB2AnsiCodeFG(217, 187, 134)
ANSIFG_WHITE = __RGB2AnsiCodeFG(255, 255, 255)
ANSIFG_JADE = __RGB2AnsiCodeFG(0, 199, 103)

ANSI_END = "\033[0m"


def _ctype_get_array_type(ctype: Any):
    # noinspection PyProtectedMember
    return ctype._type_


def _ctype_get_is_array(ctype) -> bool:
    return issubclass(ctype, Array)


def _ctype_get_is_pointer(ctype) -> bool:
    return issubclass(ctype, _Pointer) or ctype.__name__[0:2] == "LP"


def _ctype_get_name(ctype, colorized: bool = False) -> str:
    if issubclass(ctype, Struct):
        return ""

    extra = ''
    if _ctype_get_is_array(ctype):
        arr_size = sizeof(ctype)
        ctype = _ctype_get_array_type(ctype)

        if colorized:
            extra = f'[{ANSIFG_ELECTRIC_BLUE}{int(arr_size / sizeof(ctype))}{ANSI_END}]'
        else:
            extra = f'[{int(arr_size / sizeof(ctype))}]'

    # isinstance or issubclass doesnt work well
    cname = ctype.__name__
    color = ""
    endcolor = ""
    if colorized:
        color = ANSIFG_STRAW
        endcolor = ANSI_END

    isPointer = _ctype_get_is_pointer(ctype)

    if isPointer:
        cname = cname[3:]

    if cname in c_byte.__name__:
        name = color + 'BYTE' + endcolor
    elif cname in c_ubyte.__name__:
        name = color + 'BYTE' + endcolor
    elif cname in c_ushort.__name__:
        name = 'WORD'
    elif cname in c_ulong.__name__:
        name = 'DWORD'
    elif cname in c_float.__name__:
        name = 'FLOAT'
    elif cname in c_long.__name__:
        name = 'BOOL'
    elif cname in c_void_p.__name__:
        isPointer = True
        name = 'VOID'
    elif cname in c_size_t.__name__:
        name = 'SIZE_T'
    elif cname in c_uint.__name__:
        name = 'UINT'
    elif cname in c_ulonglong.__name__:
        name = 'ULONGLONG'
    elif cname in c_char.__name__:
        isPointer = True
        name = 'CHAR'
    elif cname in c_wchar.__name__:
        isPointer = True
        name = 'WCHAR'
    elif cname in c_char_p.__name__:
        isPointer = True
        name = 'CHAR'
    elif cname in c_wchar_p.__name__:
        isPointer = True
        name = 'WCHAR'
    else:
        name = ctype.__name__

    name = color + name + endcolor
    if isPointer and colorized:
        name += ANSIFG_BRINK_PINK + '*' + ANSI_END
    elif isPointer:
        name += '*'

    return name + extra


def _ctype_get_format(ctype, color: str = "") -> str:
    endcolor = ""
    if color != "":
        endcolor = ANSI_END

    cname = ctype.__name__
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
    cname = ctype.__name__

    if _ctype_get_is_pointer(ctype):
        return ANSIFG_BRINK_PINK

    if c_byte.__name__ in cname:
        return ANSIFG_ELECTRIC_BLUE
    if c_ubyte.__name__ in cname:
        return ANSIFG_ELECTRIC_BLUE
    if c_ushort.__name__ in cname:
        return ANSIFG_ELECTRIC_BLUE
    if c_ulong.__name__ in cname:
        return ANSIFG_ELECTRIC_BLUE
    if c_void_p.__name__ in cname:
        return ANSIFG_BRINK_PINK
    if c_size_t.__name__ in cname:
        return ANSIFG_ELECTRIC_BLUE
    if c_uint.__name__ in cname:
        return ANSIFG_ELECTRIC_BLUE
    if c_ulonglong.__name__ in cname:
        return ANSIFG_ELECTRIC_BLUE
    if c_long.__name__ in cname:
        return ANSIFG_ELECTRIC_BLUE
    if c_int.__name__ in cname:
        return ANSIFG_ELECTRIC_BLUE
    if c_float.__name__ in cname:
        return ANSIFG_HELIOTROPE
    if c_double.__name__ in cname:
        return ANSIFG_HELIOTROPE

    return ANSIFG_GRANNY_SMITH_APPLE


def _ctype_format_value(cvalue, ctype, colorized: bool = False) -> str:
    if colorized:
        color = _ctype_get_color(ctype)
    else:
        color = ""

    if _ctype_get_is_array(ctype):
        fmt = _ctype_get_array_type(ctype)
        fmt = _ctype_get_format(fmt, color)
        arr_type = _ctype_get_array_type(ctype)

        if issubclass(arr_type, c_char) or issubclass(arr_type, c_wchar):
            return fmt % cvalue

        values = list(cvalue)

        for i, value in enumerate(values):
            if _ctype_get_is_pointer(value.__class__):
                values[i] = addressof(value)
            if value is None and ('%X' in fmt or '%f' in fmt):
                values[i] = 0

        return f"[{', '.join([(fmt % val) for val in values])}]"

    fmt = _ctype_get_format(ctype, color)
    if _ctype_get_is_pointer(cvalue.__class__):
        cvalue = addressof(cvalue)

    if cvalue is None and ('%X' in fmt or '%f' in fmt):
        cvalue = 0

    return fmt % cvalue


class Struct(Structure):
    """
    A structure wrapper for the ctype library to allow for pretty debug printing and some utils.
    """

    IDENTIFIER = None
    ADRESS_EX = 0x0
    dwSize = 0x0

    def __init__(self, *args: Any, **kw: Any):
        if not hasattr(self, 'fields'):
            self.fields = []
        self.dwSize = sizeof(self)

        for field in self._fields_:
            if field not in self.fields:
                self.fields.append(field)

        super(Struct, self).__init__(*args, **kw)

    def __repr__(self):
        return str(self)

    def __str__(self):
        return self.ToString()

    def ToString(self, colorized: bool = False) -> str:
        """
        :param colorized: Determines if the output should be ANSI colored or not.
        :returns: A single line string representation of the structure.
        """

        out = self.__class__.__name__
        addrName = "Adress"
        address = self.ADRESS_EX
        if self.ADRESS_EX:
            addrName += "Ex"
        else:
            address = addressof(self)

        if colorized:
            out = ANSIFG_JADE + out + ANSI_END + f"({ANSIFG_FLAMENCO}{addrName}{ANSI_END}={ANSIFG_BRINK_PINK}0" \
                                                 f"x{address:X}{ANSI_END}"
        else:
            out += f'({addrName}=0x{address:X}'

        if self.IDENTIFIER is not None:
            if isinstance(self.IDENTIFIER, list) or isinstance(self.IDENTIFIER, tuple):
                for key, fmt in self.IDENTIFIER:
                    if colorized:
                        out += f", {ANSIFG_FLAMENCO}{key}{ANSI_END}={ANSIFG_WHITE}{fmt % getattr(self, key)}{ANSI_END}"
                    else:
                        out += f', {key}={fmt % getattr(self, key)}'

        size = sizeof(self)
        if colorized:
            out += f', {ANSIFG_FLAMENCO}Size{ANSI_END}={ANSIFG_ELECTRIC_BLUE}0x{size:X}{ANSI_END}/' \
                   f'{ANSIFG_ELECTRIC_BLUE}{size}{ANSI_END})'
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
            address = self.ADRESS_EX + StartOffset
        else:
            address = addressof(self)

        fields = self.GetFields()

        # calc lengths
        varNames, varTypes = zip(*fields)
        varTypes = [_ctype_get_name(t) for t in varTypes]

        vartype_len = len(max(varTypes, key=len))
        varname_len = len(max(varNames, key=len))

        if Indention:
            out = ""
        else:
            out = self.ToString(colorized) + ':\n'

        offset = StartOffset
        localoffset = 0

        isFirst = True

        for field in fields:
            varname, vartype = field
            value = getattr(self, varname, 0)

            if issubclass(vartype, Struct):
                value.ADRESS_EX = self.ADRESS_EX

                out += value.Prettify(colorized, Indention + 5, offset) + "\n"
                offset += sizeof(vartype)
                localoffset += sizeof(vartype)
            else:
                vartype_name = _ctype_get_name(vartype, colorized)
                value = _ctype_format_value(value, vartype, colorized)

                if colorized:
                    spaces = vartype_len - len(_ctype_get_name(vartype)) + 2
                    out += f"{address + localoffset:X}:{' ' * Indention}    {ANSIFG_GREY}|{offset:04X}|{ANSI_END}  " \
                           f"{vartype_name} " + " " * spaces + f"{ANSIFG_WHITE}" \
                           f"{varname:{varname_len}}{ANSI_END} = {value}\n"

                else:
                    out += f"{address + localoffset:X}:{' ' * Indention}    |{offset:04X}|  " \
                           f"{vartype_name:{vartype_len}s}   {varname:{varname_len}} = {value}\n"

                if isFirst and Indention:
                    isFirst = False
                    out = out.rstrip('\n') + f" {ANSIFG_GREY}// Start: {self.ToString()}{ANSI_END}\n"

                offset += sizeof(vartype)
                localoffset += sizeof(vartype)

        if Indention:
            return out.rstrip('\n') + f" {ANSIFG_GREY}// End: {self.__class__.__name__ + ANSI_END}"
        else:
            return out.rstrip('\n')

    def GetFields(self):
        """
        :returns: The fields of the structure.
        """
        if not hasattr(self, 'fields'):
            if hasattr(self, '_fields_'):
                self.fields = self._fields_
            else:
                self.fields = list()
        return self.fields

    def GetSize(self) -> int:
        """
        :returns: The size of the structure.
        """

        return sizeof(self)

    def GetAddress(self):
        """
        :returns: the address in Python's memory area..
        """

        return addressof(self)

    def GetAddressEx(self):
        """
        :returns: the address in Python's memory area..
        """

        return self.ADRESS_EX


class StartupInfoW(Struct):
    """
    Specifies the window station, desktop, standard handles, and appearance of the main window for a process at creation
    time.

    **See also:** `STARTUPINFOW <https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns
    -processthreadsapi-startupinfow>`_
    """

    _fields_ = [
        ('cb', DWORD),
        ('lpReserved', LPSTR),
        ('lpDesktop', LPSTR),
        ('lpTitle', LPSTR),
        ('dwX', DWORD),
        ('dwY', DWORD),
        ('dwXSize', DWORD),
        ('dwYSize', DWORD),
        ('dwXCountChars', DWORD),
        ('dwYCountChars', DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags', DWORD),
        ('wShowWindow', WORD),
        ('cbReserved2', WORD),
        ('lpReserved2', PBYTE),
        ('hStdInput', HANDLE),
        ('hStdOutput', HANDLE),
        ('hStdError', HANDLE)
    ]


class ProcessInfo(Struct):
    """
    Contains information about a newly created process and its primary thread. It is used with the CreateProcess.

    **See also:** `PROCESS_INFORMATION <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/
    ns-processthreadsapi-process_information>`_
    """

    _fields_ = [
        ('hProcess', HANDLE),
        ('hThread', HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId', DWORD)
    ]


class ProcessBasicInformation(Struct):
    """
    Contains basic information about a process.

    **See also:** `PROCESS_BASIC_INFORMATION
    <https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
    #process_basic_information>`_
    """

    _fields_ = [
        ('ExitStatus', DWORD),
        ('PebBaseAddress', LPVOID),
        ('AffinityMask', ULONG),
        ('BasePriority', DWORD),
        ('UniqueProcessId', ULONG),
        ('InheritedFromUniqueProcessId', ULONG)
    ]


class PEB(Struct):
    """
    Contains process information.

    **See also:** `PEB <https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb>`_
    """

    _fields_ = [
        ('InheritedAddressSpace', BYTE),
        ('ReadImageFileExecOptions', BYTE),
        ('BeingDebugged', BYTE),
        ('BitField', BYTE),
        ('Mutant', LPVOID),
        ('ImageBaseAddress', LPVOID)
        # And more but not interested in them
    ]


class PROCESSENTRY32(Struct):
    """
    Contains information about a process encountered by an application that traverses processes throughout the system.

    **See also:** `PROCESSENTRY32 <https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32
    -processentry32>`_
    """

    _fields_ = [
        ('dwSize', DWORD),
        ('cntUsage', DWORD),
        ('th32ProcessID', DWORD),
        ('th32DefaultHeapID', ULONG),
        ('th32ModuleID', DWORD),
        ('cntThreads', DWORD),
        ('th32ParentProcessID', DWORD),
        ('pcPriClassBase', LONG),
        ('dwFlags', DWORD),
        ('szExeFile', CHAR * MAX_PATH)
    ]


class MODULEENTRY32(Struct):
    """
    Contains information about a module in a process's address space.

    **See also:** `MODULEENTRY32 <https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32
    -moduleentry32>`_
    """

    _fields_ = [
        ('dwSize', DWORD),
        ('th32ModuleID', DWORD),
        ('th32ProcessID', DWORD),
        ('GlblcntUsage', DWORD),
        ('ProccntUsage', DWORD),
        ('modBaseAddr', ULONG),
        ('modBaseSize', DWORD),
        ('hModule', HMODULE),
        ('szModule', CHAR * 256),
        ('szExePath', CHAR * MAX_PATH)
    ]


WNDPROC = WINFUNCTYPE(LONG, HWND, UINT, LONG, DWORD)

class WNDCLASS(Struct):
    """
    Contains the window class attributes that are registered by the RegisterClass function.

    This structure has been superseded by the WNDCLASSEX structure used with the RegisterClassEx function. You can
    still use WNDCLASS and RegisterClass if you do not need to set the small icon associated with the window class.

    **See also:** `WNDCLASS <https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-wndclassa>`_
    """

    _fields_ = [
        ('style', DWORD),
        ('lpfnWndProc', WNDPROC),
        ('cbClsExtra', INT),
        ('cbWndExtra', INT),
        ('hInstance', HANDLE),
        ('hIcon', HANDLE),
        ('hCursor', HANDLE),
        ('hbrBackground', HANDLE),
        ('lpszMenuName', LPCSTR),
        ('lpszClassName', LPCSTR)
    ]


class MSG(Struct):
    """
    Contains message information from a thread's message queue.

    **See also:** `MSG <https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-msg>`_
    """

    _fields_ = [
        ('hWnd', HWND),
        ('message', UINT),
        ('wParam', WPARAM),
        ('lParam', LPARAM),
        ('time', DWORD),
        ('pt', HANDLE),
        ('lprivate', DWORD),
    ]
