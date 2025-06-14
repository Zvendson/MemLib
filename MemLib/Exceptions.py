"""
Custom exceptions for platform bitness and privilege enforcement.

Defines exceptions to indicate missing requirements for Windows Python projects:
    * Not32BitException: Raised when 32-bit Python is required but not present.
    * Not64BitException: Raised when 64-bit Python is required but not present.
    * NoAdminPrivileges: Raised when administrator privileges are required but not present.

Intended for use with decorators or API calls that depend on interpreter bitness or administrative rights.
"""


class Not32BitException(Exception):
    """
    Exception raised when a function requires 32-bit Python,
    but the current interpreter is not 32-bit.

    Example:
        if calcsize("P") * 8 != 32:
            raise Not32BitException()
    """
    def __init__(self):
        super().__init__("Python is required to run in 32 bit mode!")


class Not64BitException(Exception):
    """
    Exception raised when a function requires 64-bit Python,
    but the current interpreter is not 64-bit.

    Example:
        if calcsize("P") * 8 != 64:
            raise Not64BitException()
    """
    def __init__(self):
        super().__init__("Python is required to run in 64 bit mode!")


class NoAdminPrivileges(Exception):
    """
    Exception raised when a function requires administrator privileges,
    but the current process does not have them.

    Example:
        if windll.shell32.IsUserAnAdmin() == 0:
            raise NoAdminPrivileges()
    """
    def __init__(self):
        super().__init__("Python has no admin privileges!")
