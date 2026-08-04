import subprocess
import sys
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent.parent / "MemLib"


def test_py_typed_marker_exists():
    """PEP 561: without this file, every annotation in the package is invisible."""
    assert (PACKAGE_ROOT / "py.typed").is_file()


def test_py_typed_is_listed_in_manifest():
    """A substring match would also accept a commented-out or unrelated mention."""
    manifest = (PACKAGE_ROOT.parent / "MANIFEST.in").read_text(encoding="utf-8")
    directives = [line.strip() for line in manifest.splitlines()]

    assert "include MemLib/py.typed" in directives


def test_py_typed_is_declared_as_package_data():
    """Checks the MemLib package-data entry, not just any mention of the filename."""
    pyproject = (PACKAGE_ROOT.parent / "pyproject.toml").read_text(encoding="utf-8")
    entries = [
        line.strip() for line in pyproject.splitlines()
        if line.strip().startswith("MemLib = [")
    ]

    assert entries, "no MemLib package-data entry found"
    assert any('"py.typed"' in entry for entry in entries)


def test_package_is_importable_and_exports_its_public_names():
    probe = (
        "import MemLib; "
        "names = ['Process', 'Module', 'Thread', 'Struct', 'BinaryScanner', 'SharedMemory']; "
        "missing = [n for n in names if not hasattr(MemLib, n)]; "
        "raise SystemExit(1 if missing else 0)"
    )
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True)

    assert result.returncode == 0, result.stderr.decode(errors="replace")
