"""
:platform: Windows
"""

import inspect
import sys
from ctypes import windll
from struct import calcsize
from typing import Any, Callable

from MemLib.Exceptions import NoAdminPrivileges, Not32BitException, Not64BitException


_STRING_TYPES = (type(b''), type(u''))


def Export(*, module: str = None) -> Any:
    """
    Simple decorator to add a function to the __all__ list.

    :param module: The module it should get exported to.
    :returns: The wrapped object.
    """

    def ReturnFunction(function: Any) -> Any:
        nonlocal module

        if module is None or module not in sys.modules:
            print('\n-> '.join(sys.modules))
            module = function.__module__

        mod = sys.modules[module]

        if hasattr(mod, '__all__'):
            mod.__all__.append(function.__name__)
        else:
            mod.__all__ = [function.__name__]

        print(f"Added '{function.__name__}' to module: '{mod}'")

        return function

    return ReturnFunction


@Export(module="MemLib")
def Require32Bit(f: Callable) -> Callable:
    def wrapper(*args, **kwargs):
        if calcsize("P") * 8 != 32:
            raise Not32BitException()
        return f(*args, **kwargs)

    return wrapper


@Export(module="MemLib")
def Require64Bit(f: Callable) -> Callable:
    def wrapper(*args, **kwargs):
        if calcsize("P") * 8 != 64:
            raise Not64BitException()
        return f(*args, **kwargs)

    return wrapper


@Export(module="MemLib")
def RequireAdmin(f: Callable) -> Callable:
    def wrapper(*args, **kwargs):
        if windll.shell32.IsUserAnAdmin() == 0:
            raise NoAdminPrivileges()
        return f(*args, **kwargs)

    return wrapper


