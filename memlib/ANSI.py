
BEL = "\x07"
BS  = "\x08"
HT  = "\x09"
LF  = "\x0A"
VT  = "\x0B"
FF  = "\x0C"
CR  = "\x0D"
ESC = "\x1B"
DEL = "\x7F"


def ForeRGB(red: int, green: int, blue: int) -> str:
    return f"\033[38;2;{red};{green};{blue}m"


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


BLACK        = f"{ESC}[0;30m"
RED          = f"{ESC}[0;31m"
GREEN        = f"{ESC}[0;32m"
BROWN        = f"{ESC}[0;33m"
BLUE         = f"{ESC}[0;34m"
PURPLE       = f"{ESC}[0;35m"
CYAN         = f"{ESC}[0;36m"
LIGHT_GRAY   = f"{ESC}[0;37m"
DARK_GRAY    = f"{ESC}[1;30m"
LIGHT_RED    = f"{ESC}[1;31m"
LIGHT_GREEN  = f"{ESC}[1;32m"
YELLOW       = f"{ESC}[1;33m"
LIGHT_BLUE   = f"{ESC}[1;34m"
LIGHT_PURPLE = f"{ESC}[1;35m"
LIGHT_CYAN   = f"{ESC}[1;36m"
LIGHT_WHITE  = f"{ESC}[1;37m"
BOLD         = f"{ESC}[1m"
FAINT        = f"{ESC}[2m"
ITALIC       = f"{ESC}[3m"
UNDERLINE    = f"{ESC}[4m"
BLINK        = f"{ESC}[5m"
NEGATIVE     = f"{ESC}[7m"
CROSSED      = f"{ESC}[9m"
END          = f"{ESC}[0m"


# Identifying the color name: https://www.color-blindness.com/color-name-hue/
SAFETY_ORANGE      = ForeRGB(255, 111, 0)
ELECTRIC_BLUE      = ForeRGB(135, 239, 255)
HELIOTROPE         = ForeRGB(230, 130, 255)
GRANNY_SMITH_APPLE = ForeRGB(155, 230, 142)
FLAMENCO           = ForeRGB(232, 152, 77)
BRINK_PINK         = ForeRGB(250, 102, 129)
GREY               = ForeRGB(120, 120, 120)
STRAW              = ForeRGB(217, 187, 134)
WHITE              = ForeRGB(255, 255, 255)
JADE               = ForeRGB(0, 199, 103)
