import importlib


def test_package_exports_main_public_api():
    memlib = importlib.import_module("MemLib")

    assert memlib.__version__ == "1.7.6"
    assert memlib.Process.__name__ == "Process"
    assert memlib.SharedMemory.__name__ == "SharedMemory"
    assert memlib.FASM.__name__ == "FASM"
    assert memlib.Struct.__name__ == "Struct"
    assert memlib.Win32Exception.__name__ == "Win32Exception"
    assert memlib.windows is not None
    assert memlib.Constants is not None


def test_package_exports_are_listed_in_all():
    memlib = importlib.import_module("MemLib")

    for name in ("Process", "SharedMemory", "FASM", "Struct", "windows", "Constants"):
        assert name in memlib.__all__


def test_keepass_exports_do_not_break_top_level_import():
    memlib = importlib.import_module("MemLib")

    assert hasattr(memlib, "CredentialManager")
    assert hasattr(memlib, "Credentials")
