"""
:platform: Windows
"""

from typing import Any, TYPE_CHECKING, Tuple

import winreg

from MemLib.Decorators import require_admin


if TYPE_CHECKING:
    from winreg import HKEYType


def get_registry_value(key: int, key_path: str, key_name: str) -> Any:
    """
    Get a value from the registry.

    :param key: The HKEY type
    :param key_path: The path to the key
    :param key_name: The name of the key
    :returns: The value of the key
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
    Set a value in the registry.

    :param key: The HKEY type
    :param key_path: The path to the key
    :param key_name: The name of the key
    :param key_type: The type of the key
    :param value: The value of the key
    :returns: None
    """

    key_handle: HKEYType = winreg.OpenKeyEx(key, key_path, 0, winreg.KEY_ALL_ACCESS)

    winreg.SetValueEx(key_handle, key_name, 0, key_type, value)

    if key_handle:
        winreg.CloseKey(key_handle)
