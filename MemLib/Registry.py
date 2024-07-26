"""
:platform: Windows
"""

from typing import Any, TYPE_CHECKING, Tuple
from winreg import CloseKey, OpenKeyEx, QueryValueEx, SetValueEx

from MemLib.Decorators import RequireAdmin



if TYPE_CHECKING:
    # noinspection PyCompatibility
    from winreg import HKEYType


def GetRegistryValue(key: int, key_path: str, key_name: str) -> Any:
    """
    Get a value from the registry.

    :param key: The HKEY type
    :param key_path: The path to the key
    :param key_name: The name of the key
    :returns: The value of the key
    """

    try:
        keyHandle: HKEYType = OpenKeyEx(key, key_path)
    except FileNotFoundError:
        return None

    try:
        value: Tuple[Any, int] = QueryValueEx(keyHandle, key_name)
    except FileNotFoundError:
        CloseKey(keyHandle)
        return None

    CloseKey(keyHandle)
    return value[0]


@RequireAdmin
def SetRegistryValue(key: int, key_path: str, key_name: str, key_type: int, value: str) -> None:
    """
    Set a value in the registry.

    :param key: The HKEY type
    :param key_path: The path to the key
    :param key_name: The name of the key
    :param key_type: The type of the key
    :param value: The value of the key
    :returns: None
    """

    keyHandle: HKEYType = OpenKeyEx(key, key_path, 0, KEY_ALL_ACCESS)

    SetValueEx(keyHandle, key_name, 0, key_type, value)

    if keyHandle:
        CloseKey(keyHandle)


# copied the constants from winreg, cause importing winreg causes a compatibility error.
HKEY_CLASSES_ROOT = 2147483648

HKEY_CURRENT_CONFIG = 2147483653
HKEY_CURRENT_USER = 2147483649

HKEY_DYN_DATA = 2147483654

HKEY_LOCAL_MACHINE = 2147483650

HKEY_PERFORMANCE_DATA = 2147483652

HKEY_USERS = 2147483651

KEY_ALL_ACCESS = 983103

KEY_CREATE_LINK = 32

KEY_CREATE_SUB_KEY = 4

KEY_ENUMERATE_SUB_KEYS = 8

KEY_EXECUTE = 131097
KEY_NOTIFY = 16

KEY_QUERY_VALUE = 1

KEY_READ = 131097

KEY_SET_VALUE = 2

KEY_WOW64_32KEY = 512
KEY_WOW64_64KEY = 256

KEY_WRITE = 131078

REG_BINARY = 3

REG_CREATED_NEW_KEY = 1

REG_DWORD = 4

REG_DWORD_BIG_ENDIAN = 5

REG_DWORD_LITTLE_ENDIAN = 4

REG_EXPAND_SZ = 2

REG_FULL_RESOURCE_DESCRIPTOR = 9

REG_LEGAL_CHANGE_FILTER = 268435471

REG_LEGAL_OPTION = 31

REG_LINK = 6

REG_MULTI_SZ = 7

REG_NONE = 0

REG_NOTIFY_CHANGE_ATTRIBUTES = 2

REG_NOTIFY_CHANGE_LAST_SET = 4

REG_NOTIFY_CHANGE_NAME = 1
REG_NOTIFY_CHANGE_SECURITY = 8

REG_NO_LAZY_FLUSH = 4

REG_OPENED_EXISTING_KEY = 2

REG_OPTION_BACKUP_RESTORE = 4

REG_OPTION_CREATE_LINK = 2

REG_OPTION_NON_VOLATILE = 0

REG_OPTION_OPEN_LINK = 8

REG_OPTION_RESERVED = 0
REG_OPTION_VOLATILE = 1

REG_QWORD = 11

REG_QWORD_LITTLE_ENDIAN = 11

REG_REFRESH_HIVE = 2

REG_RESOURCE_LIST = 8

REG_RESOURCE_REQUIREMENTS_LIST = 10

REG_SZ = 1

REG_WHOLE_HIVE_VOLATILE = 1



