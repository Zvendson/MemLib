"""
:platform: Windows
"""

import inspect
import warnings
from ctypes import windll
from functools import wraps
from struct import calcsize
from time import time
from typing import Any, Callable

from MemLib.Exceptions import NoAdminPrivileges, Not32BitException, Not64BitException


_STRING_TYPES = (type(b''), type(u''))


def FuncTimer(function: Callable[[str], Any]) -> Callable:
    @wraps(function)
    def wrap(*args, **kwargs):
        argstr = ", ".join(["%r" % a for a in args]) if args else ""
        kwargstr = ", ".join(["%s=%r" % (k, v) for k, v in kwargs.items()]) \
            if kwargs else ""
        comma = ", " if (argstr and kwargstr) else ""
        fargs = "%s(%s%s%s)" % (function.__name__, argstr, comma, kwargstr)

        ts = time()
        result = function(*args, **kwargs)
        te = time()
        print('%s took: %2.4f sec' % (fargs, te-ts))

        return result

    return wrap


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

            @wraps(func1)
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

        @wraps(func2)
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
