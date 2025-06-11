"""
Utility functions for reading and writing Windows Registry values.

This module provides simple wrappers around the `winreg` module for safely querying and setting
Windows Registry keys and values, with type annotations and admin privilege enforcement.

Functions:
    - get_registry_value: Read a value from the Windows Registry.
    - set_registry_value: Write a value to the Windows Registry (requires admin).

Example:
    val = get_registry_value(HKEY_LOCAL_MACHINE, r"SOFTWARE\\MyApp", "Version")

References:
    https://docs.python.org/3/library/winreg.html
    https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry
"""

import winreg
from typing import Any, TYPE_CHECKING, Tuple

from MemLib.Decorators import require_admin



if TYPE_CHECKING:
    from winreg import HKEYType

def get_registry_value(key: int, key_path: str, key_name: str) -> Any:
    """
    Retrieves a value from the Windows Registry.

    Args:
        key (int): The registry hive/root (e.g. winreg.HKEY_LOCAL_MACHINE).
        key_path (str): Path to the registry key.
        key_name (str): Name of the value to retrieve.

    Returns:
        Any: The value if found, or None if the key or value does not exist.
    """
    try:
        key_handle: HKEYType = winreg.OpenKeyEx(key, key_path)
    except FileNotFoundError:
        return None

    try:
        value: Tuple[Any, int] = winreg.QueryValueEx(key_handle, key_name)
    except FileNotFoundError:
        winreg.CloseKey(key_handle)
        return None

    winreg.CloseKey(key_handle)
    return value[0]

@require_admin
def set_registry_value(key: int, key_path: str, key_name: str, key_type: int, value: str) -> None:
    """
    Sets a value in the Windows Registry.

    Args:
        key (int): The registry hive/root (e.g. winreg.HKEY_LOCAL_MACHINE).
        key_path (str): Path to the registry key.
        key_name (str): Name of the value to set.
        key_type (int): Type of the value (e.g. winreg.REG_SZ, winreg.REG_DWORD).
        value (str): The value to write.

    Raises:
        PermissionError: If the current process lacks administrator privileges.
        FileNotFoundError: If the specified key path does not exist.

    Returns:
        None
    """
    key_handle: HKEYType = winreg.OpenKeyEx(key, key_path, 0, winreg.KEY_ALL_ACCESS)

    winreg.SetValueEx(key_handle, key_name, 0, key_type, value)

    if key_handle:
        winreg.CloseKey(key_handle)
