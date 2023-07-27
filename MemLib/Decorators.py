"""
:platform: Windows
"""

import functools
import inspect
import sys
import warnings
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


@Export(module="MemLib")
def Deprecated(reason: Callable | str) -> Callable:
    """
    This is a decorator which can be used to mark functions
    as deprecated. It will result in a warning being emitted
    when the function is used.

    Credits to: https://stackoverflow.com/a/40301488
    """

    if isinstance(reason, _STRING_TYPES):

        # The @deprecated is used with a 'reason'.
        #
        # .. code-block:: python
        #
        #    @deprecated("please, use another function")
        #    def old_function(x, y):
        #      pass

        def decorator(func1):

            if inspect.isclass(func1):
                fmt1 = "Call to deprecated class {name} ({reason})."
            else:
                fmt1 = "Call to deprecated function {name} ({reason})."

            @functools.wraps(func1)
            def new_func1(*args, **kwargs):
                warnings.simplefilter('always', DeprecationWarning)
                warnings.warn(
                    fmt1.format(name=func1.__name__, reason=reason),
                    category=DeprecationWarning,
                    stacklevel=2
                )
                warnings.simplefilter('default', DeprecationWarning)
                return func1(*args, **kwargs)

            return new_func1

        return decorator

    elif inspect.isclass(reason) or inspect.isfunction(reason):

        # The @deprecated is used without any 'reason'.
        #
        # .. code-block:: python
        #
        #    @deprecated
        #    def old_function(x, y):
        #      pass

        func2 = reason

        if inspect.isclass(func2):
            fmt2 = "Call to deprecated class {name}."
        else:
            fmt2 = "Call to deprecated function {name}."

        @functools.wraps(func2)
        def new_func2(*args, **kwargs):
            warnings.simplefilter('always', DeprecationWarning)
            warnings.warn(
                fmt2.format(name=func2.__name__),
                category=DeprecationWarning,
                stacklevel=2
            )
            warnings.simplefilter('default', DeprecationWarning)
            return func2(*args, **kwargs)

        return new_func2

    else:
        raise TypeError(repr(type(reason)))


print(__name__)
