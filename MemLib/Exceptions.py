"""
:platform: Windows
"""

from ctypes.wintypes import WCHAR
from MemLib.Kernel32 import FormatMessageW, GetLastError


class Not32BitException(Exception):
    def __init__(self):
        Exception.__init__(self, "Python is required to run in 32 bit mode!")


class Not64BitException(Exception):
    def __init__(self):
        Exception.__init__(self, "Python is required to run in 64 bit mode!")


class NoAdminPrivileges(Exception):
    def __init__(self):
        Exception.__init__(self, "Python has no admin privileges!")


class Win32Exception(RuntimeError):
    """
    Simple Exception-class to represent Windows Errors in python.

    :param errorCode:     Windows error code. if not provided, the windows last error will be used.
    :param customMessage: A customized message to show when raised. if not provided, the windows message
                          will be used.

    .. note:: **See also:** `GetLastError
          <https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror>`_ and
          `FormatMessageW <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-formatmessagew>`_
    """

    def __init__(self, errorCode: int = None, customMessage: str = None):
        self._errorCode: int = GetLastError() if (errorCode is None) else errorCode
        self._message: str = customMessage

        if customMessage is None:
            self.__FormatMessage()

    def GetErrorCode(self) -> int:
        """
        :returns: The error code.
        """

        return self._errorCode

    def GetErrorMessage(self) -> str:
        """
        :returns: The error message of the error code.
        """

        return self._message

    def __str__(self) -> str:
        return '%s (0x%08x)' % (self._message, self._errorCode)

    def __repr__(self) -> str:
        return 'Win32Exception(%s)' % str(self)

    def __FormatMessage(self) -> None:
        size = 256

        while size < 0x10000:  # Found 0x10000 in C# std lib
            msgBuffer = (WCHAR * size)()

            result = FormatMessageW(0x200 | 0x1000 | 0x2000, None, self._errorCode, 0, msgBuffer, size, None)

            if result > 0:
                self._message = msgBuffer[:result - 2]
                return

            if GetLastError() != 0x7A:  # ERROR_INSUFFICIENT_BUFFER
                break

        self._message = 'Unknown Error'
