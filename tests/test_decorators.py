import warnings
from unittest.mock import patch

import pytest

from MemLib.Decorators import deprecated, func_timer, require_32bit, require_64bit, require_admin
from MemLib.Exceptions import NoAdminPrivileges, Not32BitException, Not64BitException


def test_func_timer_reports_function_call_and_result():
    output = []

    @func_timer(output.append)
    def add(a, b, *, scale=1):
        return (a + b) * scale

    with patch("MemLib.Decorators.time", side_effect=[10.0, 10.25]):
        result = add(2, 3, scale=4)

    assert result == 20
    assert output == ["add(2, 3, scale=4) took: 0.2500 sec"]


def test_require_32bit_allows_32bit_and_rejects_otherwise():
    @require_32bit
    def fn():
        return "ok"

    with patch("MemLib.Decorators.calcsize", return_value=4):
        assert fn() == "ok"

    with patch("MemLib.Decorators.calcsize", return_value=8):
        with pytest.raises(Not32BitException):
            fn()


def test_require_64bit_allows_64bit_and_rejects_otherwise():
    @require_64bit
    def fn():
        return "ok"

    with patch("MemLib.Decorators.calcsize", return_value=8):
        assert fn() == "ok"

    with patch("MemLib.Decorators.calcsize", return_value=4):
        with pytest.raises(Not64BitException):
            fn()


def test_require_admin_rejects_non_admin():
    @require_admin
    def fn():
        return "ok"

    with patch("MemLib.Decorators.windll.shell32.IsUserAnAdmin", return_value=1):
        assert fn() == "ok"

    with patch("MemLib.Decorators.windll.shell32.IsUserAnAdmin", return_value=0):
        with pytest.raises(NoAdminPrivileges):
            fn()


def test_deprecated_with_reason_warns_and_returns_value():
    @deprecated("use replacement")
    def fn():
        return 7

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert fn() == 7

    assert len(caught) == 1
    assert "deprecated function fn (use replacement)" in str(caught[0].message)


def test_deprecated_without_reason_warns_for_class():
    @deprecated
    class OldType:
        def __init__(self):
            self.value = 9

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        instance = OldType()

    assert instance.value == 9
    assert len(caught) == 1
    assert "deprecated class OldType." in str(caught[0].message)


def test_deprecated_rejects_invalid_argument_type():
    with pytest.raises(TypeError):
        deprecated(123)
