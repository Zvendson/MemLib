"""
:platform: Windows

Describes an entry from a list of the modules belonging to the specified process.

.. warning::
  Don't instantiate this class.\n
  Use the methods inside :py:class:`~eve.MemLib.process.Process` to retrieve a Module object instead:\n
  - :py:meth:`~eve.MemLib.process.Process.GetModules`
  - :py:meth:`~eve.MemLib.process.Process.GetMainModule`
  - :py:meth:`~eve.MemLib.process.Process.GetModule`
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from MemLib.Kernel32 import GetProcAddress, Win32Exception
from MemLib.Structs import MODULEENTRY32



if TYPE_CHECKING:
    from MemLib.Process import Process


class Module:
    """
    :param module: The module buffer struct
    :param process: The module's parent process

    .. note:: **See also:**
        `MODULEENTRY32 <https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-moduleentry32>`_
    """

    def __init__(self, module: MODULEENTRY32, process: Process):
        self._handle: int      = module.hModule
        self._process: Process = process
        self._name: str        = module.szModule.decode('ascii')
        self._path: str        = module.szExePath.decode('ascii')
        self._base: int        = module.modBaseAddr
        self._size: int        = module.modBaseSize

    def GetBase(self) -> int:
        """
        :returns: The base address of the module.
        """

        return self._base

    def GetHandle(self) -> int:
        """
        :returns: The handle of the module.
        """

        return self._handle

    def GetName(self) -> str:
        """
        :returns: The Module name and its extension. *Example:* :olive:`"kernel32.dll"`
        """

        return self._name

    def GetPath(self) -> str:
        """
        :returns: The local path of the module.
        """

        return self._path

    def GetProcAddress(self, name: str) -> int:
        """
        Retrieves the address of an exported function (also known as a procedure) or variable from the module.

        See also `GetProcAddress
        <https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress>`_

        :param name: The name of the procedure
        :raises Win32Exception: if the procedure could not be exported
        :returns: The address of the procedure
        """

        handle: int = GetProcAddress(self._handle, name)
        if not handle:
            raise Win32Exception()
        return handle

    def GetProcess(self) -> Process:
        """
        :returns: a reference to its :py:class:`~process.Process`.
        """

        return self._process

    def GetSize(self) -> int:
        """
        :returns: the size of Bytes of the module.

        .. note:: :py:meth:`~eve.MemLib.module.Module.GetBase` + :py:meth:`~eve.MemLib.module.Module.GetSize` = end of
                  module's memory.
        """

        return self._size

    def __eq__(self, other: Module) -> bool:
        sameHandle: bool    = (self._handle == other.GetHandle())
        sameProcessId: bool = (self._process.GetProcessId() == other._process.GetProcessId())

        return sameHandle and sameProcessId

    def __repr__(self) -> str:
        return f"Module('{self.GetName()}' in Process '{self._process.GetProcessId()}')"
