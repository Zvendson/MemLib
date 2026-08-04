import subprocess
import sys
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent.parent / "MemLib"


def test_py_typed_marker_exists():
    """PEP 561: without this file, every annotation in the package is invisible."""
    assert (PACKAGE_ROOT / "py.typed").is_file()


def test_py_typed_is_listed_in_manifest():
    manifest = (PACKAGE_ROOT.parent / "MANIFEST.in").read_text(encoding="utf-8")
    assert "MemLib/py.typed" in manifest


def test_py_typed_is_declared_as_package_data():
    pyproject = (PACKAGE_ROOT.parent / "pyproject.toml").read_text(encoding="utf-8")
    assert "py.typed" in pyproject


def test_package_is_importable_and_exports_its_public_names():
    probe = (
        "import MemLib; "
        "names = ['Process', 'Module', 'Thread', 'Struct', 'BinaryScanner', 'SharedMemory']; "
        "missing = [n for n in names if not hasattr(MemLib, n)]; "
        "raise SystemExit(1 if missing else 0)"
    )
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True)

    assert result.returncode == 0, result.stderr.decode()
