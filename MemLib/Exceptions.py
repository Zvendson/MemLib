"""
:platform: Windows
"""


class Not32BitException(Exception):
    def __init__(self):
        Exception.__init__(self, "Python is required to run in 32 bit mode!")


class Not64BitException(Exception):
    def __init__(self):
        Exception.__init__(self, "Python is required to run in 64 bit mode!")


class NoAdminPrivileges(Exception):
    def __init__(self):
        Exception.__init__(self, "Python has no admin privileges!")



