"""
:platform: Windows

Simple RGB to ANSI converter.
"""


class ForeColor:

    def __init__(self, red: int, green: int, blue: int):
        self._red:   int = red
        self._green: int = green
        self._blue:  int = blue

    def __str__(self) -> str:
        return ForeRGB(self._red, self._green, self._blue)

    def __repr__(self) -> str:
        return str(self)


def ForeRGB(red: int, green: int, blue: int) -> str:
    return f"\033[38;2;{red};{green};{blue}m"


def BackRGB(red: int, green: int, blue: int) -> str:
    return f"\033[48;2;{red};{green};{blue}m"


def CursorPos(line: int, column: int) -> str:
    if not line and not column:
        return f"{ESC}[H"

    return f"{ESC}[{line};{column}H"


def CursorCol(column: int) -> str:
    if not column:
        return ""
    return f"{ESC}[{column}G"


def CursorUp(lines: int) -> str:
    if not lines:
        return ""

    return f"{ESC}[{lines}A"


def CursorDown(lines: int) -> str:
    if not lines:
        return ""

    return f"{ESC}[{lines}B"


def CursorRight(columns: int) -> str:
    if not columns:
        return ""

    return f"{ESC}[{columns}C"


def CursorLeft(columns: int) -> str:
    if not columns:
        return ""

    return f"{ESC}[{columns}D"


def CursorNextLine(lines: int) -> str:
    if not lines:
        return ""

    return f"{ESC}[{lines}E"


def CursorPrevLine(lines: int) -> str:
    if not lines:
        return ""

    return f"{ESC}[{lines}F"


def CursorSaveDEC() -> str:
    return f"{ESC} 7"


def CursorSaveSEC() -> str:
    return f"{ESC}[s"


def CursorRestoreDEC() -> str:
    return f"{ESC} 8"


def CursorRestoreSEC() -> str:
    return f"{ESC}[u"


BEL: str = "\x07"
BS:  str = "\x08"
HT:  str = "\x09"
LF:  str = "\x0A"
VT:  str = "\x0B"
FF:  str = "\x0C"
CR:  str = "\x0D"
ESC: str = "\x1B"
DEL: str = "\x7F"


BLACK:        str = f"{ESC}[0;30m"
RED:          str = f"{ESC}[0;31m"
GREEN:        str = f"{ESC}[0;32m"
BROWN:        str = f"{ESC}[0;33m"
BLUE:         str = f"{ESC}[0;34m"
PURPLE:       str = f"{ESC}[0;35m"
CYAN:         str = f"{ESC}[0;36m"
LIGHT_GRAY:   str = f"{ESC}[0;37m"
DARK_GRAY:    str = f"{ESC}[1;30m"
LIGHT_RED:    str = f"{ESC}[1;31m"
LIGHT_GREEN:  str = f"{ESC}[1;32m"
YELLOW:       str = f"{ESC}[1;33m"
LIGHT_BLUE:   str = f"{ESC}[1;34m"
LIGHT_PURPLE: str = f"{ESC}[1;35m"
LIGHT_CYAN:   str = f"{ESC}[1;36m"
LIGHT_WHITE:  str = f"{ESC}[1;37m"
BOLD:         str = f"{ESC}[1m"
FAINT:        str = f"{ESC}[2m"
ITALIC:       str = f"{ESC}[3m"
UNDERLINE:    str = f"{ESC}[4m"
BLINK:        str = f"{ESC}[5m"
NEGATIVE:     str = f"{ESC}[7m"
CROSSED:      str = f"{ESC}[9m"
END:          str = f"{ESC}[0m"


# Identifying the color name: https://www.color-blindness.com/color-name-hue/
SAFETY_ORANGE:      str = ForeRGB(255, 111, 0)
ELECTRIC_BLUE:      str = ForeRGB(135, 239, 255)
HELIOTROPE:         str = ForeRGB(230, 130, 255)
GRANNY_SMITH_APPLE: str = ForeRGB(155, 230, 142)
FLAMENCO:           str = ForeRGB(232, 152, 77)
BRINK_PINK:         str = ForeRGB(250, 102, 129)
GREY:               str = ForeRGB(120, 120, 120)
STRAW:              str = ForeRGB(217, 187, 134)
WHITE:              str = ForeRGB(255, 255, 255)
JADE:               str = ForeRGB(0, 199, 103)



