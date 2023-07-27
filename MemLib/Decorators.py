"""
:platform: Windows
"""

from ctypes import windll
from struct import calcsize
from typing import Any, Callable

from MemLib.Exceptions import NoAdminPrivileges, Not32BitException, Not64BitException
def Require32Bit(f: Callable) -> Callable:
    def wrapper(*args, **kwargs):
        if calcsize("P") * 8 != 32:
            raise Not32BitException()
        return f(*args, **kwargs)

    return wrapper


def Require64Bit(f: Callable) -> Callable:
    def wrapper(*args, **kwargs):
        if calcsize("P") * 8 != 64:
            raise Not64BitException()
        return f(*args, **kwargs)

    return wrapper


def RequireAdmin(f: Callable) -> Callable:
    def wrapper(*args, **kwargs):
        if windll.shell32.IsUserAnAdmin() == 0:
            raise NoAdminPrivileges()
        return f(*args, **kwargs)

    return wrapper


