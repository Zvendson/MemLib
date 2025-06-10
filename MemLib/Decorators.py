"""
:platform: Windows

Decorator utilities and platform enforcement helpers.

This module provides decorators for timing, privilege checking, bitness checks,
and function deprecation with warnings, tailored for Windows Python projects.
"""

import inspect
import warnings

from ctypes import windll
from struct import calcsize
from functools import wraps
from time import time
from typing import Any, Callable

from MemLib.Exceptions import NoAdminPrivileges, Not32BitException, Not64BitException


_STRING_TYPES: tuple[type, type] = (str, bytes)
"""Tuple of recognized string types for decorator argument detection."""


def func_timer(out: Callable[[str], Any]) -> Callable:
    """
    Decorator to measure the execution time of the wrapped function.

    Args:
        out (Callable[[str], Any]): Callback function that will receive the timing output string.

    Returns:
        Callable: The wrapped function with timing instrumentation.

    Example:
        @func_timer(print)
        def my_function():
            ...
    """

    def decorator(function: Callable[[str], Any]) -> Callable:
        @wraps(function)
        def wrap(*args, **kwargs):
            arg_str: str   = ", ".join(["%r" % a for a in args]) if args else ""
            kwarg_str: str = ", ".join(["%s=%r" % (k, v) for k, v in kwargs.items()]) if kwargs else ""
            comma: str     = ", " if (arg_str and kwarg_str) else ""
            fn_args: str   = "%s(%s%s%s)" % (function.__name__, arg_str, comma, kwarg_str)

            ts: float = time()
            result: Any = function(*args, **kwargs)
            te = time()
            out(f"{fn_args} took: {te - ts:2.4f} sec")

            return result

        return wrap

    return decorator


def require_32bit(function: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator to restrict execution to 32-bit Python interpreters.

    Raises:
        Not32BitException: If not running in a 32-bit Python process.

    Returns:
        Callable: The wrapped function.

    Example:
        @require_32bit
        def some_func():
            ...
    """
    """
    Decorator: Raises Not32BitException if running in anything other than a 32-bit python process.
    """
    @wraps(function)
    def wrapper(*args, **kwargs):
        if calcsize("P") * 8 != 32:
            raise Not32BitException()
        return function(*args, **kwargs)

    return wrapper


def require_64bit(function: Callable) -> Callable:
    """
    Decorator to restrict execution to 64-bit Python interpreters.

    Raises:
        Not64BitException: If not running in a 64-bit Python process.

    Returns:
        Callable: The wrapped function.
    """
    @wraps(function)
    def wrapper(*args, **kwargs):
        if calcsize("P") * 8 != 64:
            raise Not64BitException()
        return function(*args, **kwargs)

    return wrapper


def require_admin(function: Callable) -> Callable:
    """
    Decorator to require the process to be running with administrative privileges.

    Raises:
        NoAdminPrivileges: If the current user is not an administrator.

    Returns:
        Callable: The wrapped function.
    """
    @wraps(function)
    def wrapper(*args, **kwargs):
        if windll.shell32.IsUserAnAdmin() == 0:
            raise NoAdminPrivileges()
        return function(*args, **kwargs)

    return wrapper


def deprecated(reason: Callable | str) -> Callable:
    """
    Decorator to mark functions or classes as deprecated.

    Emits a DeprecationWarning when the decorated function or class is called.
    Can be used both with and without a reason string.

    Credits to: https://stackoverflow.com/a/40301488

    Usage:
        @deprecated("Use another function instead")
        def old_func(): ...

        @deprecated
        def really_old_func(): ...

    Args:
        reason (str | Callable): Reason for deprecation, or the function/class itself.

    Returns:
        Callable: The decorated function/class with deprecation warning.

    Raises:
        TypeError: If used with an unsupported argument type.
    """

    if isinstance(reason, _STRING_TYPES):
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
