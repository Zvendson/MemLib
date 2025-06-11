"""
Simple RGB to ANSI converter and ANSI terminal utility.

Provides helpers to generate ANSI escape codes for colors, cursor control, and common formatting.
"""

#######################
# core ANSI constants #
#######################

BEL: str = "\x07"
"""ASCII Bell (BEL), triggers a beep in the terminal."""

BS:  str = "\x08"
"""ASCII Backspace (BS), moves the cursor one position left."""

HT:  str = "\x09"
"""ASCII Horizontal Tab (HT), moves the cursor to the next tab stop."""

LF:  str = "\x0A"
"""ASCII Line Feed (LF), moves the cursor to the next line."""

VT:  str = "\x0B"
"""ASCII Vertical Tab (VT), moves the cursor down a line (rarely used)."""

FF:  str = "\x0C"
"""ASCII Form Feed (FF), advances to the next page (rarely used)."""

CR:  str = "\x0D"
"""ASCII Carriage Return (CR), moves the cursor to the beginning of the line."""

ESC: str = "\x1B"
"""Escape character (ASCII 27, '\\x1B') used to begin all ANSI sequences."""

DEL: str = "\x7F"
"""ASCII Delete (DEL), deletes the character at the cursor position."""


####################
# helper functions #
####################

def fore_rgb(red: int, green: int, blue: int) -> str:
    """
    Return ANSI escape sequence for setting the foreground (text) color via RGB.

    Args:
        red (int): Red component (0-255)
        green (int): Green component (0-255)
        blue (int): Blue component (0-255)

    Returns:
        str: ANSI escape code for the specified RGB color.
    """
    return f"\033[38;2;{red};{green};{blue}m"


def back_rgb(red: int, green: int, blue: int) -> str:
    """
    Return ANSI escape sequence for setting the background color via RGB.

    Args:
        red (int): Red component (0-255)
        green (int): Green component (0-255)
        blue (int): Blue component (0-255)

    Returns:
        str: ANSI escape code for the specified RGB background color.
    """
    return f"\033[48;2;{red};{green};{blue}m"


def cursor_pos(line: int, column: int) -> str:
    """
    Return ANSI escape sequence to move the cursor to a specific position (1-based).

    Args:
        line (int): Line number (1-based)
        column (int): Column number (1-based)

    Returns:
        str: ANSI escape code for the cursor position.
    """
    if not line and not column:
        return f"{ESC}[H"

    return f"{ESC}[{line};{column}H"


def cursor_col(column: int) -> str:
    """
    Return ANSI escape sequence to move the cursor to a specific column in the current line.

    Args:
        column (int): Column number (1-based)

    Returns:
        str: ANSI escape code for setting the cursor column.
    """
    if not column:
        return ""
    return f"{ESC}[{column}G"


def cursor_up(lines: int) -> str:
    """
    Return ANSI escape sequence to move the cursor up by a given number of lines.

    Args:
        lines (int): Number of lines to move up

    Returns:
        str: ANSI escape code to move cursor up.
    """
    if not lines:
        return ""

    return f"{ESC}[{lines}A"


def cursor_down(lines: int) -> str:
    """
    Return ANSI escape sequence to move the cursor down by a given number of lines.

    Args:
        lines (int): Number of lines to move down

    Returns:
        str: ANSI escape code to move cursor down.
    """
    if not lines:
        return ""

    return f"{ESC}[{lines}B"


def cursor_right(columns: int) -> str:
    """
    Return ANSI escape sequence to move the cursor right by a given number of columns.

    Args:
        columns (int): Number of columns to move right

    Returns:
        str: ANSI escape code to move cursor right.
    """
    if not columns:
        return ""

    return f"{ESC}[{columns}C"


def cursor_left(columns: int) -> str:
    """
    Return ANSI escape sequence to move the cursor left by a given number of columns.

    Args:
        columns (int): Number of columns to move left

    Returns:
        str: ANSI escape code to move cursor left.
    """
    if not columns:
        return ""

    return f"{ESC}[{columns}D"


def cursor_next_line(lines: int) -> str:
    """
    Return ANSI escape sequence to move the cursor down by a number of lines and to the first column.

    Args:
        lines (int): Number of lines to move down

    Returns:
        str: ANSI escape code to move cursor to next line(s).
    """
    if not lines:
        return ""

    return f"{ESC}[{lines}E"


def cursor_prev_line(lines: int) -> str:
    """
    Return ANSI escape sequence to move the cursor up by a number of lines and to the first column.

    Args:
        lines (int): Number of lines to move up

    Returns:
        str: ANSI escape code to move cursor to previous line(s).
    """
    if not lines:
        return ""

    return f"{ESC}[{lines}F"


def cursor_save_dec() -> str:
    """
    Return ANSI escape sequence to save the current cursor position (DEC private mode, deprecated).

    Returns:
        str: ANSI escape code to save cursor position.
    """
    return f"{ESC} 7"


def cursor_save_sec() -> str:
    """
    Return ANSI escape sequence to save the current cursor position (CSI standard, modern).

    Returns:
        str: ANSI escape code to save cursor position.
    """
    return f"{ESC}[s"


def cursor_restore_dec() -> str:
    """
    Return ANSI escape sequence to restore the cursor position (CSI standard, modern).

    Returns:
        str: ANSI escape code to restore cursor position.
    """
    return f"{ESC} 8"


def cursor_restore_sec() -> str:
    return f"{ESC}[u"

########################
# ANSI color constants #
########################

BLACK: str = f"{ESC}[0;30m"
"""ANSI escape code for black text."""

RED: str = f"{ESC}[0;31m"
"""ANSI escape code for red text."""

GREEN: str = f"{ESC}[0;32m"
"""ANSI escape code for green text."""

BROWN: str = f"{ESC}[0;33m"
"""ANSI escape code for brown/yellow text."""

BLUE: str = f"{ESC}[0;34m"
"""ANSI escape code for blue text."""

PURPLE: str = f"{ESC}[0;35m"
"""ANSI escape code for purple/magenta text."""

CYAN: str = f"{ESC}[0;36m"
"""ANSI escape code for cyan text."""

LIGHT_GRAY: str = f"{ESC}[0;37m"
"""ANSI escape code for light gray text."""

DARK_GRAY: str = f"{ESC}[1;30m"
"""ANSI escape code for dark gray text."""

LIGHT_RED: str = f"{ESC}[1;31m"
"""ANSI escape code for light red text."""

LIGHT_GREEN: str = f"{ESC}[1;32m"
"""ANSI escape code for light green text."""

YELLOW: str = f"{ESC}[1;33m"
"""ANSI escape code for yellow text."""

LIGHT_BLUE: str = f"{ESC}[1;34m"
"""ANSI escape code for light blue text."""

LIGHT_PURPLE: str = f"{ESC}[1;35m"
"""ANSI escape code for light purple/magenta text."""

LIGHT_CYAN: str = f"{ESC}[1;36m"
"""ANSI escape code for light cyan text."""

LIGHT_WHITE: str = f"{ESC}[1;37m"
"""ANSI escape code for bright white text."""

BOLD: str = f"{ESC}[1m"
"""ANSI escape code for bold text."""

FAINT: str = f"{ESC}[2m"
"""ANSI escape code for faint/dim text."""

ITALIC: str = f"{ESC}[3m"
"""ANSI escape code for italic text."""

UNDERLINE: str = f"{ESC}[4m"
"""ANSI escape code for underlined text."""

BLINK: str = f"{ESC}[5m"
"""ANSI escape code for blinking text."""

NEGATIVE: str = f"{ESC}[7m"
"""ANSI escape code for reverse video (swap foreground and background)."""

CROSSED: str = f"{ESC}[9m"
"""ANSI escape code for crossed-out text."""

END: str = f"{ESC}[0m"
"""ANSI escape code to reset all styles and colors."""

#############################
# Extended named RGB colors #
#############################
# RGB to Name converter: https://www.color-blindness.com/color-name-hue/
SAFETY_ORANGE: str = fore_rgb(255, 111, 0)
"""ANSI escape code for 'Safety Orange' (RGB: 255, 111, 0)."""

ELECTRIC_BLUE: str = fore_rgb(135, 239, 255)
"""ANSI escape code for 'Electric Blue' (RGB: 135, 239, 255)."""

HELIOTROPE: str = fore_rgb(230, 130, 255)
"""ANSI escape code for 'Heliotrope' (RGB: 230, 130, 255)."""

GRANNY_SMITH_APPLE: str = fore_rgb(155, 230, 142)
"""ANSI escape code for 'Granny Smith Apple' (RGB: 155, 230, 142)."""

FLAMENCO: str = fore_rgb(232, 152, 77)
"""ANSI escape code for 'Flamenco' (RGB: 232, 152, 77)."""

BRINK_PINK: str = fore_rgb(250, 102, 129)
"""ANSI escape code for 'Brink Pink' (RGB: 250, 102, 129)."""

GREY: str = fore_rgb(120, 120, 120)
"""ANSI escape code for grey text (RGB: 120, 120, 120)."""

STRAW: str = fore_rgb(217, 187, 134)
"""ANSI escape code for 'Straw' (RGB: 217, 187, 134)."""

WHITE: str = fore_rgb(255, 255, 255)
"""ANSI escape code for pure white text (RGB: 255, 255, 255)."""

JADE: str = fore_rgb(0, 199, 103)
"""ANSI escape code for 'Jade' (RGB: 0, 199, 103)."""

ALICE_BLUE: str = fore_rgb(240, 248, 255)
"""ANSI escape code for Alice Blue (RGB: 240, 248, 255)."""

ANTIQUE_WHITE: str = fore_rgb(250, 235, 215)
"""ANSI escape code for Antique White (RGB: 250, 235, 215)."""

AQUA: str = fore_rgb(0, 255, 255)
"""ANSI escape code for Aqua (RGB: 0, 255, 255)."""

AQUAMARINE: str = fore_rgb(127, 255, 212)
"""ANSI escape code for Aquamarine (RGB: 127, 255, 212)."""

AZURE: str = fore_rgb(240, 255, 255)
"""ANSI escape code for Azure (RGB: 240, 255, 255)."""

BEIGE: str = fore_rgb(245, 245, 220)
"""ANSI escape code for Beige (RGB: 245, 245, 220)."""

BISQUE: str = fore_rgb(255, 228, 196)
"""ANSI escape code for Bisque (RGB: 255, 228, 196)."""

BLUE_VIOLET: str = fore_rgb(138, 43, 226)
"""ANSI escape code for Blue Violet (RGB: 138, 43, 226)."""

CADET_BLUE: str = fore_rgb(95, 158, 160)
"""ANSI escape code for Cadet Blue (RGB: 95, 158, 160)."""

CHARTREUSE: str = fore_rgb(127, 255, 0)
"""ANSI escape code for Chartreuse (RGB: 127, 255, 0)."""

CHOCOLATE: str = fore_rgb(210, 105, 30)
"""ANSI escape code for Chocolate (RGB: 210, 105, 30)."""

CORAL: str = fore_rgb(255, 127, 80)
"""ANSI escape code for Coral (RGB: 255, 127, 80)."""

CORNFLOWER_BLUE: str = fore_rgb(100, 149, 237)
"""ANSI escape code for Cornflower Blue (RGB: 100, 149, 237)."""

CORNSILK: str = fore_rgb(255, 248, 220)
"""ANSI escape code for Cornsilk (RGB: 255, 248, 220)."""

CRIMSON: str = fore_rgb(220, 20, 60)
"""ANSI escape code for Crimson (RGB: 220, 20, 60)."""

DARK_BLUE: str = fore_rgb(0, 0, 139)
"""ANSI escape code for Dark Blue (RGB: 0, 0, 139)."""

DARK_CYAN: str = fore_rgb(0, 139, 139)
"""ANSI escape code for Dark Cyan (RGB: 0, 139, 139)."""

DARK_GOLDENROD: str = fore_rgb(184, 134, 11)
"""ANSI escape code for Dark Goldenrod (RGB: 184, 134, 11)."""

DARK_GREEN: str = fore_rgb(0, 100, 0)
"""ANSI escape code for Dark Green (RGB: 0, 100, 0)."""

DARK_KHAKI: str = fore_rgb(189, 183, 107)
"""ANSI escape code for Dark Khaki (RGB: 189, 183, 107)."""

DARK_MAGENTA: str = fore_rgb(139, 0, 139)
"""ANSI escape code for Dark Magenta (RGB: 139, 0, 139)."""

DARK_OLIVE_GREEN: str = fore_rgb(85, 107, 47)
"""ANSI escape code for Dark Olive Green (RGB: 85, 107, 47)."""

DARK_ORANGE: str = fore_rgb(255, 140, 0)
"""ANSI escape code for Dark Orange (RGB: 255, 140, 0)."""

DARK_ORCHID: str = fore_rgb(153, 50, 204)
"""ANSI escape code for Dark Orchid (RGB: 153, 50, 204)."""

DARK_RED: str = fore_rgb(139, 0, 0)
"""ANSI escape code for Dark Red (RGB: 139, 0, 0)."""

DARK_SALMON: str = fore_rgb(233, 150, 122)
"""ANSI escape code for Dark Salmon (RGB: 233, 150, 122)."""

DARK_SEA_GREEN: str = fore_rgb(143, 188, 143)
"""ANSI escape code for Dark Sea Green (RGB: 143, 188, 143)."""

DARK_SLATE_BLUE: str = fore_rgb(72, 61, 139)
"""ANSI escape code for Dark Slate Blue (RGB: 72, 61, 139)."""

DARK_SLATE_GRAY: str = fore_rgb(47, 79, 79)
"""ANSI escape code for Dark Slate Gray (RGB: 47, 79, 79)."""

DARK_TURQUOISE: str = fore_rgb(0, 206, 209)
"""ANSI escape code for Dark Turquoise (RGB: 0, 206, 209)."""

DARK_VIOLET: str = fore_rgb(148, 0, 211)
"""ANSI escape code for Dark Violet (RGB: 148, 0, 211)."""

DEEP_PINK: str = fore_rgb(255, 20, 147)
"""ANSI escape code for Deep Pink (RGB: 255, 20, 147)."""

DEEP_SKY_BLUE: str = fore_rgb(0, 191, 255)
"""ANSI escape code for Deep Sky Blue (RGB: 0, 191, 255)."""

DIM_GRAY: str = fore_rgb(105, 105, 105)
"""ANSI escape code for Dim Gray (RGB: 105, 105, 105)."""

DODGER_BLUE: str = fore_rgb(30, 144, 255)
"""ANSI escape code for Dodger Blue (RGB: 30, 144, 255)."""

FIREBRICK: str = fore_rgb(178, 34, 34)
"""ANSI escape code for Firebrick (RGB: 178, 34, 34)."""

FLORAL_WHITE: str = fore_rgb(255, 250, 240)
"""ANSI escape code for Floral White (RGB: 255, 250, 240)."""

FOREST_GREEN: str = fore_rgb(34, 139, 34)
"""ANSI escape code for Forest Green (RGB: 34, 139, 34)."""

FUCHSIA: str = fore_rgb(255, 0, 255)
"""ANSI escape code for Fuchsia (RGB: 255, 0, 255)."""

GAINSBORO: str = fore_rgb(220, 220, 220)
"""ANSI escape code for Gainsboro (RGB: 220, 220, 220)."""

GHOST_WHITE: str = fore_rgb(248, 248, 255)
"""ANSI escape code for Ghost White (RGB: 248, 248, 255)."""

GOLD: str = fore_rgb(255, 215, 0)
"""ANSI escape code for Gold (RGB: 255, 215, 0)."""

GOLDENROD: str = fore_rgb(218, 165, 32)
"""ANSI escape code for Goldenrod (RGB: 218, 165, 32)."""

GRAY: str = fore_rgb(128, 128, 128)
"""ANSI escape code for Gray (RGB: 128, 128, 128)."""

GREEN_YELLOW: str = fore_rgb(173, 255, 47)
"""ANSI escape code for Green Yellow (RGB: 173, 255, 47)."""

HONEYDEW: str = fore_rgb(240, 255, 240)
"""ANSI escape code for Honeydew (RGB: 240, 255, 240)."""

HOT_PINK: str = fore_rgb(255, 105, 180)
"""ANSI escape code for Hot Pink (RGB: 255, 105, 180)."""

INDIAN_RED: str = fore_rgb(205, 92, 92)
"""ANSI escape code for Indian Red (RGB: 205, 92, 92)."""

INDIGO: str = fore_rgb(75, 0, 130)
"""ANSI escape code for Indigo (RGB: 75, 0, 130)."""

IVORY: str = fore_rgb(255, 255, 240)
"""ANSI escape code for Ivory (RGB: 255, 255, 240)."""

KHAKI: str = fore_rgb(240, 230, 140)
"""ANSI escape code for Khaki (RGB: 240, 230, 140)."""

LAVENDER: str = fore_rgb(230, 230, 250)
"""ANSI escape code for Lavender (RGB: 230, 230, 250)."""

LAVENDER_BLUSH: str = fore_rgb(255, 240, 245)
"""ANSI escape code for Lavender Blush (RGB: 255, 240, 245)."""

LAWN_GREEN: str = fore_rgb(124, 252, 0)
"""ANSI escape code for Lawn Green (RGB: 124, 252, 0)."""

LEMON_CHIFFON: str = fore_rgb(255, 250, 205)
"""ANSI escape code for Lemon Chiffon (RGB: 255, 250, 205)."""

LIGHT_CORAL: str = fore_rgb(240, 128, 128)
"""ANSI escape code for Light Coral (RGB: 240, 128, 128)."""

LIGHT_GOLDENROD: str = fore_rgb(250, 250, 210)
"""ANSI escape code for Light Goldenrod (RGB: 250, 250, 210)."""

LIGHT_PINK: str = fore_rgb(255, 182, 193)
"""ANSI escape code for Light Pink (RGB: 255, 182, 193)."""

LIGHT_SALMON: str = fore_rgb(255, 160, 122)
"""ANSI escape code for Light Salmon (RGB: 255, 160, 122)."""

LIGHT_SEA_GREEN: str = fore_rgb(32, 178, 170)
"""ANSI escape code for Light Sea Green (RGB: 32, 178, 170)."""

LIGHT_SKY_BLUE: str = fore_rgb(135, 206, 250)
"""ANSI escape code for Light Sky Blue (RGB: 135, 206, 250)."""

LIGHT_SLATE_GRAY: str = fore_rgb(119, 136, 153)
"""ANSI escape code for Light Slate Gray (RGB: 119, 136, 153)."""

LIGHT_STEEL_BLUE: str = fore_rgb(176, 196, 222)
"""ANSI escape code for Light Steel Blue (RGB: 176, 196, 222)."""

LIGHT_YELLOW: str = fore_rgb(255, 255, 224)
"""ANSI escape code for Light Yellow (RGB: 255, 255, 224)."""

LIME: str = fore_rgb(0, 255, 0)
"""ANSI escape code for Lime (RGB: 0, 255, 0)."""

LIME_GREEN: str = fore_rgb(50, 205, 50)
"""ANSI escape code for Lime Green (RGB: 50, 205, 50)."""

LINEN: str = fore_rgb(250, 240, 230)
"""ANSI escape code for Linen (RGB: 250, 240, 230)."""

MAGENTA: str = fore_rgb(255, 0, 255)
"""ANSI escape code for Magenta (RGB: 255, 0, 255)."""

MAROON: str = fore_rgb(128, 0, 0)
"""ANSI escape code for Maroon (RGB: 128, 0, 0)."""

MEDIUM_AQUAMARINE: str = fore_rgb(102, 205, 170)
"""ANSI escape code for Medium Aquamarine (RGB: 102, 205, 170)."""

MEDIUM_BLUE: str = fore_rgb(0, 0, 205)
"""ANSI escape code for Medium Blue (RGB: 0, 0, 205)."""

MEDIUM_ORCHID: str = fore_rgb(186, 85, 211)
"""ANSI escape code for Medium Orchid (RGB: 186, 85, 211)."""

MEDIUM_PURPLE: str = fore_rgb(147, 112, 219)
"""ANSI escape code for Medium Purple (RGB: 147, 112, 219)."""

MEDIUM_SEA_GREEN: str = fore_rgb(60, 179, 113)
"""ANSI escape code for Medium Sea Green (RGB: 60, 179, 113)."""

MEDIUM_SLATE_BLUE: str = fore_rgb(123, 104, 238)
"""ANSI escape code for Medium Slate Blue (RGB: 123, 104, 238)."""

MEDIUM_SPRING_GREEN= fore_rgb(0, 250, 154)
"""ANSI escape code for Medium Spring Green (RGB: 0, 250, 154)."""

MEDIUM_TURQUOISE: str = fore_rgb(72, 209, 204)
"""ANSI escape code for Medium Turquoise (RGB: 72, 209, 204)."""

MEDIUM_VIOLET_RED: str = fore_rgb(199, 21, 133)
"""ANSI escape code for Medium Violet Red (RGB: 199, 21, 133)."""

MIDNIGHT_BLUE: str = fore_rgb(25, 25, 112)
"""ANSI escape code for Midnight Blue (RGB: 25, 25, 112)."""

MINT_CREAM: str = fore_rgb(245, 255, 250)
"""ANSI escape code for Mint Cream (RGB: 245, 255, 250)."""

MISTY_ROSE: str = fore_rgb(255, 228, 225)
"""ANSI escape code for Misty Rose (RGB: 255, 228, 225)."""

MOCCASIN: str = fore_rgb(255, 228, 181)
"""ANSI escape code for Moccasin (RGB: 255, 228, 181)."""

NAVAJO_WHITE: str = fore_rgb(255, 222, 173)
"""ANSI escape code for Navajo White (RGB: 255, 222, 173)."""

NAVY: str = fore_rgb(0, 0, 128)
"""ANSI escape code for Navy (RGB: 0, 0, 128)."""

OLD_LACE: str = fore_rgb(253, 245, 230)
"""ANSI escape code for Old Lace (RGB: 253, 245, 230)."""

OLIVE: str = fore_rgb(128, 128, 0)
"""ANSI escape code for Olive (RGB: 128, 128, 0)."""

OLIVE_DRAB: str = fore_rgb(107, 142, 35)
"""ANSI escape code for Olive Drab (RGB: 107, 142, 35)."""

ORANGE: str = fore_rgb(255, 165, 0)
"""ANSI escape code for Orange (RGB: 255, 165, 0)."""

ORANGE_RED: str = fore_rgb(255, 69, 0)
"""ANSI escape code for Orange Red (RGB: 255, 69, 0)."""

ORCHID: str = fore_rgb(218, 112, 214)
"""ANSI escape code for Orchid (RGB: 218, 112, 214)."""

PALE_GOLDENROD: str = fore_rgb(238, 232, 170)
"""ANSI escape code for Pale Goldenrod (RGB: 238, 232, 170)."""

PALE_GREEN: str = fore_rgb(152, 251, 152)
"""ANSI escape code for Pale Green (RGB: 152, 251, 152)."""

PALE_TURQUOISE: str = fore_rgb(175, 238, 238)
"""ANSI escape code for Pale Turquoise (RGB: 175, 238, 238)."""

PALE_VIOLET_RED: str = fore_rgb(219, 112, 147)
"""ANSI escape code for Pale Violet Red (RGB: 219, 112, 147)."""

PAPAYA_WHIP: str = fore_rgb(255, 239, 213)
"""ANSI escape code for Papaya Whip (RGB: 255, 239, 213)."""

PEACH_PUFF: str = fore_rgb(255, 218, 185)
"""ANSI escape code for Peach Puff (RGB: 255, 218, 185)."""

PERU: str = fore_rgb(205, 133, 63)
"""ANSI escape code for Peru (RGB: 205, 133, 63)."""

PINK: str = fore_rgb(255, 192, 203)
"""ANSI escape code for Pink (RGB: 255, 192, 203)."""

PLUM: str = fore_rgb(221, 160, 221)
"""ANSI escape code for Plum (RGB: 221, 160, 221)."""

POWDER_BLUE: str = fore_rgb(176, 224, 230)
"""ANSI escape code for Powder Blue (RGB: 176, 224, 230)."""

REBECCA_PURPLE: str = fore_rgb(102, 51, 153)
"""ANSI escape code for Rebecca Purple (RGB: 102, 51, 153)."""

ROSY_BROWN: str = fore_rgb(188, 143, 143)
"""ANSI escape code for Rosy Brown (RGB: 188, 143, 143)."""

ROYAL_BLUE: str = fore_rgb(65, 105, 225)
"""ANSI escape code for Royal Blue (RGB: 65, 105, 225)."""

SADDLE_BROWN: str = fore_rgb(139, 69, 19)
"""ANSI escape code for Saddle Brown (RGB: 139, 69, 19)."""

SALMON: str = fore_rgb(250, 128, 114)
"""ANSI escape code for Salmon (RGB: 250, 128, 114)."""

SANDY_BROWN: str = fore_rgb(244, 164, 96)
"""ANSI escape code for Sandy Brown (RGB: 244, 164, 96)."""

SEA_GREEN: str = fore_rgb(46, 139, 87)
"""ANSI escape code for Sea Green (RGB: 46, 139, 87)."""

SEASHELL: str = fore_rgb(255, 245, 238)
"""ANSI escape code for Seashell (RGB: 255, 245, 238)."""

SIENNA: str = fore_rgb(160, 82, 45)
"""ANSI escape code for Sienna (RGB: 160, 82, 45)."""

SILVER: str = fore_rgb(192, 192, 192)
"""ANSI escape code for Silver (RGB: 192, 192, 192)."""

SKY_BLUE: str = fore_rgb(135, 206, 235)
"""ANSI escape code for Sky Blue (RGB: 135, 206, 235)."""

SLATE_BLUE: str = fore_rgb(106, 90, 205)
"""ANSI escape code for Slate Blue (RGB: 106, 90, 205)."""

SLATE_GRAY: str = fore_rgb(112, 128, 144)
"""ANSI escape code for Slate Gray (RGB: 112, 128, 144)."""

SNOW: str = fore_rgb(255, 250, 250)
"""ANSI escape code for Snow (RGB: 255, 250, 250)."""

SPRING_GREEN: str = fore_rgb(0, 255, 127)
"""ANSI escape code for Spring Green (RGB: 0, 255, 127)."""

STEEL_BLUE: str = fore_rgb(70, 130, 180)
"""ANSI escape code for Steel Blue (RGB: 70, 130, 180)."""

TAN: str = fore_rgb(210, 180, 140)
"""ANSI escape code for Tan (RGB: 210, 180, 140)."""

TEAL: str = fore_rgb(0, 128, 128)
"""ANSI escape code for Teal (RGB: 0, 128, 128)."""

THISTLE: str = fore_rgb(216, 191, 216)
"""ANSI escape code for Thistle (RGB: 216, 191, 216)."""

TOMATO: str = fore_rgb(255, 99, 71)
"""ANSI escape code for Tomato (RGB: 255, 99, 71)."""

TURQUOISE: str = fore_rgb(64, 224, 208)
"""ANSI escape code for Turquoise (RGB: 64, 224, 208)."""

VIOLET: str = fore_rgb(238, 130, 238)
"""ANSI escape code for Violet (RGB: 238, 130, 238)."""

WHEAT: str = fore_rgb(245, 222, 179)
"""ANSI escape code for Wheat (RGB: 245, 222, 179)."""

WHITE_SMOKE: str = fore_rgb(245, 245, 245)
"""ANSI escape code for White Smoke (RGB: 245, 245, 245)."""

YELLOW_GREEN: str = fore_rgb(154, 205, 50)
"""ANSI escape code for Yellow Green (RGB: 154, 205, 50)."""

BLACK_BG: str = f"{ESC}[40m"
"""ANSI escape code for black background."""

RED_BG: str = f"{ESC}[41m"
"""ANSI escape code for red background."""

GREEN_BG: str = f"{ESC}[42m"
"""ANSI escape code for green background."""

BROWN_BG: str = f"{ESC}[43m"
"""ANSI escape code for brown/yellow background."""

BLUE_BG: str = f"{ESC}[44m"
"""ANSI escape code for blue background."""

PURPLE_BG: str = f"{ESC}[45m"
"""ANSI escape code for purple/magenta background."""

CYAN_BG: str = f"{ESC}[46m"
"""ANSI escape code for cyan background."""

LIGHT_GRAY_BG: str = f"{ESC}[47m"
"""ANSI escape code for light gray background."""

DARK_GRAY_BG: str = f"{ESC}[100m"
"""ANSI escape code for dark gray background."""

LIGHT_RED_BG: str = f"{ESC}[101m"
"""ANSI escape code for light red background."""

LIGHT_GREEN_BG: str = f"{ESC}[102m"
"""ANSI escape code for light green background."""

YELLOW_BG: str = f"{ESC}[103m"
"""ANSI escape code for yellow background."""

LIGHT_BLUE_BG: str = f"{ESC}[104m"
"""ANSI escape code for light blue background."""

LIGHT_PURPLE_BG: str = f"{ESC}[105m"
"""ANSI escape code for light purple/magenta background."""

LIGHT_CYAN_BG: str = f"{ESC}[106m"
"""ANSI escape code for light cyan background."""

LIGHT_WHITE_BG: str = f"{ESC}[107m"
"""ANSI escape code for bright white background."""

SAFETY_ORANGE_BG: str = back_rgb(255, 111, 0)
"""ANSI escape code for 'Safety Orange' background (RGB: 255, 111, 0)."""

ELECTRIC_BLUE_BG: str = back_rgb(135, 239, 255)
"""ANSI escape code for 'Electric Blue' background (RGB: 135, 239, 255)."""

HELIOTROPE_BG: str = back_rgb(230, 130, 255)
"""ANSI escape code for 'Heliotrope' background (RGB: 230, 130, 255)."""

GRANNY_SMITH_APPLE_BG: str = back_rgb(155, 230, 142)
"""ANSI escape code for 'Granny Smith Apple' background (RGB: 155, 230, 142)."""

FLAMENCO_BG: str = back_rgb(232, 152, 77)
"""ANSI escape code for 'Flamenco' background (RGB: 232, 152, 77)."""

BRINK_PINK_BG: str = back_rgb(250, 102, 129)
"""ANSI escape code for 'Brink Pink' background (RGB: 250, 102, 129)."""

GREY_BG: str = back_rgb(120, 120, 120)
"""ANSI escape code for grey background (RGB: 120, 120, 120)."""

STRAW_BG: str = back_rgb(217, 187, 134)
"""ANSI escape code for 'Straw' background (RGB: 217, 187, 134)."""

WHITE_BG: str = back_rgb(255, 255, 255)
"""ANSI escape code for pure white background (RGB: 255, 255, 255)."""

JADE_BG: str = back_rgb(0, 199, 103)
"""ANSI escape code for 'Jade' background (RGB: 0, 199, 103)."""

ALICE_BLUE_BG: str = back_rgb(240, 248, 255)
"""ANSI escape code for Alice Blue background (RGB: 240, 248, 255)."""

ANTIQUE_WHITE_BG: str = back_rgb(250, 235, 215)
"""ANSI escape code for Antique White background (RGB: 250, 235, 215)."""

AQUA_BG: str = back_rgb(0, 255, 255)
"""ANSI escape code for Aqua background (RGB: 0, 255, 255)."""

AQUAMARINE_BG: str = back_rgb(127, 255, 212)
"""ANSI escape code for Aquamarine background (RGB: 127, 255, 212)."""

AZURE_BG: str = back_rgb(240, 255, 255)
"""ANSI escape code for Azure background (RGB: 240, 255, 255)."""

BEIGE_BG: str = back_rgb(245, 245, 220)
"""ANSI escape code for Beige background (RGB: 245, 245, 220)."""

BISQUE_BG: str = back_rgb(255, 228, 196)
"""ANSI escape code for Bisque background (RGB: 255, 228, 196)."""

BLUE_VIOLET_BG: str = back_rgb(138, 43, 226)
"""ANSI escape code for Blue Violet background (RGB: 138, 43, 226)."""

CADET_BLUE_BG: str = back_rgb(95, 158, 160)
"""ANSI escape code for Cadet Blue background (RGB: 95, 158, 160)."""

CHARTREUSE_BG: str = back_rgb(127, 255, 0)
"""ANSI escape code for Chartreuse background (RGB: 127, 255, 0)."""

CHOCOLATE_BG: str = back_rgb(210, 105, 30)
"""ANSI escape code for Chocolate background (RGB: 210, 105, 30)."""

CORAL_BG: str = back_rgb(255, 127, 80)
"""ANSI escape code for Coral background (RGB: 255, 127, 80)."""

CORNFLOWER_BLUE_BG: str = back_rgb(100, 149, 237)
"""ANSI escape code for Cornflower Blue background (RGB: 100, 149, 237)."""

CORNSILK_BG: str = back_rgb(255, 248, 220)
"""ANSI escape code for Cornsilk background (RGB: 255, 248, 220)."""

CRIMSON_BG: str = back_rgb(220, 20, 60)
"""ANSI escape code for Crimson background (RGB: 220, 20, 60)."""

DARK_BLUE_BG: str = back_rgb(0, 0, 139)
"""ANSI escape code for Dark Blue background (RGB: 0, 0, 139)."""

DARK_CYAN_BG: str = back_rgb(0, 139, 139)
"""ANSI escape code for Dark Cyan background (RGB: 0, 139, 139)."""

DARK_GOLDENROD_BG: str = back_rgb(184, 134, 11)
"""ANSI escape code for Dark Goldenrod background (RGB: 184, 134, 11)."""

DARK_GREEN_BG: str = back_rgb(0, 100, 0)
"""ANSI escape code for Dark Green background (RGB: 0, 100, 0)."""

DARK_KHAKI_BG: str = back_rgb(189, 183, 107)
"""ANSI escape code for Dark Khaki background (RGB: 189, 183, 107)."""

DARK_MAGENTA_BG: str = back_rgb(139, 0, 139)
"""ANSI escape code for Dark Magenta background (RGB: 139, 0, 139)."""

DARK_OLIVE_GREEN_BG: str = back_rgb(85, 107, 47)
"""ANSI escape code for Dark Olive Green background (RGB: 85, 107, 47)."""

DARK_ORANGE_BG: str = back_rgb(255, 140, 0)
"""ANSI escape code for Dark Orange background (RGB: 255, 140, 0)."""

DARK_ORCHID_BG: str = back_rgb(153, 50, 204)
"""ANSI escape code for Dark Orchid background (RGB: 153, 50, 204)."""

DARK_RED_BG: str = back_rgb(139, 0, 0)
"""ANSI escape code for Dark Red background (RGB: 139, 0, 0)."""

DARK_SALMON_BG: str = back_rgb(233, 150, 122)
"""ANSI escape code for Dark Salmon background (RGB: 233, 150, 122)."""

DARK_SEA_GREEN_BG: str = back_rgb(143, 188, 143)
"""ANSI escape code for Dark Sea Green background (RGB: 143, 188, 143)."""

DARK_SLATE_BLUE_BG: str = back_rgb(72, 61, 139)
"""ANSI escape code for Dark Slate Blue background (RGB: 72, 61, 139)."""

DARK_SLATE_GRAY_BG: str = back_rgb(47, 79, 79)
"""ANSI escape code for Dark Slate Gray background (RGB: 47, 79, 79)."""

DARK_TURQUOISE_BG: str = back_rgb(0, 206, 209)
"""ANSI escape code for Dark Turquoise background (RGB: 0, 206, 209)."""

DARK_VIOLET_BG: str = back_rgb(148, 0, 211)
"""ANSI escape code for Dark Violet background (RGB: 148, 0, 211)."""

DEEP_PINK_BG: str = back_rgb(255, 20, 147)
"""ANSI escape code for Deep Pink background (RGB: 255, 20, 147)."""

DEEP_SKY_BLUE_BG: str = back_rgb(0, 191, 255)
"""ANSI escape code for Deep Sky Blue background (RGB: 0, 191, 255)."""

DIM_GRAY_BG: str = back_rgb(105, 105, 105)
"""ANSI escape code for Dim Gray background (RGB: 105, 105, 105)."""

DODGER_BLUE_BG: str = back_rgb(30, 144, 255)
"""ANSI escape code for Dodger Blue background (RGB: 30, 144, 255)."""

FIREBRICK_BG: str = back_rgb(178, 34, 34)
"""ANSI escape code for Firebrick background (RGB: 178, 34, 34)."""

FLORAL_WHITE_BG: str = back_rgb(255, 250, 240)
"""ANSI escape code for Floral White background (RGB: 255, 250, 240)."""

FOREST_GREEN_BG: str = back_rgb(34, 139, 34)
"""ANSI escape code for Forest Green background (RGB: 34, 139, 34)."""

FUCHSIA_BG: str = back_rgb(255, 0, 255)
"""ANSI escape code for Fuchsia background (RGB: 255, 0, 255)."""

GAINSBORO_BG: str = back_rgb(220, 220, 220)
"""ANSI escape code for Gainsboro background (RGB: 220, 220, 220)."""

GHOST_WHITE_BG: str = back_rgb(248, 248, 255)
"""ANSI escape code for Ghost White background (RGB: 248, 248, 255)."""

GOLD_BG: str = back_rgb(255, 215, 0)
"""ANSI escape code for Gold background (RGB: 255, 215, 0)."""

GOLDENROD_BG: str = back_rgb(218, 165, 32)
"""ANSI escape code for Goldenrod background (RGB: 218, 165, 32)."""

GRAY_BG: str = back_rgb(128, 128, 128)
"""ANSI escape code for Gray background (RGB: 128, 128, 128)."""

GREEN_YELLOW_BG: str = back_rgb(173, 255, 47)
"""ANSI escape code for Green Yellow background (RGB: 173, 255, 47)."""

HONEYDEW_BG: str = back_rgb(240, 255, 240)
"""ANSI escape code for Honeydew background (RGB: 240, 255, 240)."""

HOT_PINK_BG: str = back_rgb(255, 105, 180)
"""ANSI escape code for Hot Pink background (RGB: 255, 105, 180)."""

INDIAN_RED_BG: str = back_rgb(205, 92, 92)
"""ANSI escape code for Indian Red background (RGB: 205, 92, 92)."""

INDIGO_BG: str = back_rgb(75, 0, 130)
"""ANSI escape code for Indigo background (RGB: 75, 0, 130)."""

IVORY_BG: str = back_rgb(255, 255, 240)
"""ANSI escape code for Ivory background (RGB: 255, 255, 240)."""

KHAKI_BG: str = back_rgb(240, 230, 140)
"""ANSI escape code for Khaki background (RGB: 240, 230, 140)."""

LAVENDER_BG: str = back_rgb(230, 230, 250)
"""ANSI escape code for Lavender background (RGB: 230, 230, 250)."""

LAVENDER_BLUSH_BG: str = back_rgb(255, 240, 245)
"""ANSI escape code for Lavender Blush background (RGB: 255, 240, 245)."""

LAWN_GREEN_BG: str = back_rgb(124, 252, 0)
"""ANSI escape code for Lawn Green background (RGB: 124, 252, 0)."""

LEMON_CHIFFON_BG: str = back_rgb(255, 250, 205)
"""ANSI escape code for Lemon Chiffon background (RGB: 255, 250, 205)."""

LIGHT_CORAL_BG: str = back_rgb(240, 128, 128)
"""ANSI escape code for Light Coral background (RGB: 240, 128, 128)."""

LIGHT_GOLDENROD_BG: str = back_rgb(250, 250, 210)
"""ANSI escape code for Light Goldenrod background (RGB: 250, 250, 210)."""

LIGHT_PINK_BG: str = back_rgb(255, 182, 193)
"""ANSI escape code for Light Pink background (RGB: 255, 182, 193)."""

LIGHT_SALMON_BG: str = back_rgb(255, 160, 122)
"""ANSI escape code for Light Salmon background (RGB: 255, 160, 122)."""

LIGHT_SEA_GREEN_BG: str = back_rgb(32, 178, 170)
"""ANSI escape code for Light Sea Green background (RGB: 32, 178, 170)."""

LIGHT_SKY_BLUE_BG: str = back_rgb(135, 206, 250)
"""ANSI escape code for Light Sky Blue background (RGB: 135, 206, 250)."""

LIGHT_SLATE_GRAY_BG: str = back_rgb(119, 136, 153)
"""ANSI escape code for Light Slate Gray background (RGB: 119, 136, 153)."""

LIGHT_STEEL_BLUE_BG: str = back_rgb(176, 196, 222)
"""ANSI escape code for Light Steel Blue background (RGB: 176, 196, 222)."""

LIGHT_YELLOW_BG: str = back_rgb(255, 255, 224)
"""ANSI escape code for Light Yellow background (RGB: 255, 255, 224)."""

LIME_BG: str = back_rgb(0, 255, 0)
"""ANSI escape code for Lime background (RGB: 0, 255, 0)."""

LIME_GREEN_BG: str = back_rgb(50, 205, 50)
"""ANSI escape code for Lime Green background (RGB: 50, 205, 50)."""

LINEN_BG: str = back_rgb(250, 240, 230)
"""ANSI escape code for Linen background (RGB: 250, 240, 230)."""

MAGENTA_BG: str = back_rgb(255, 0, 255)
"""ANSI escape code for Magenta background (RGB: 255, 0, 255)."""

MAROON_BG: str = back_rgb(128, 0, 0)
"""ANSI escape code for Maroon background (RGB: 128, 0, 0)."""

MEDIUM_AQUAMARINE_BG: str = back_rgb(102, 205, 170)
"""ANSI escape code for Medium Aquamarine background (RGB: 102, 205, 170)."""

MEDIUM_BLUE_BG: str = back_rgb(0, 0, 205)
"""ANSI escape code for Medium Blue background (RGB: 0, 0, 205)."""

MEDIUM_ORCHID_BG: str = back_rgb(186, 85, 211)
"""ANSI escape code for Medium Orchid background (RGB: 186, 85, 211)."""

MEDIUM_PURPLE_BG: str = back_rgb(147, 112, 219)
"""ANSI escape code for Medium Purple background (RGB: 147, 112, 219)."""

MEDIUM_SEA_GREEN_BG: str = back_rgb(60, 179, 113)
"""ANSI escape code for Medium Sea Green background (RGB: 60, 179, 113)."""

MEDIUM_SLATE_BLUE_BG: str = back_rgb(123, 104, 238)
"""ANSI escape code for Medium Slate Blue background (RGB: 123, 104, 238)."""

MEDIUM_SPRING_GREEN_BG: str = back_rgb(0, 250, 154)
"""ANSI escape code for Medium Spring Green background (RGB: 0, 250, 154)."""

MEDIUM_TURQUOISE_BG: str = back_rgb(72, 209, 204)
"""ANSI escape code for Medium Turquoise background (RGB: 72, 209, 204)."""

MEDIUM_VIOLET_RED_BG: str = back_rgb(199, 21, 133)
"""ANSI escape code for Medium Violet Red background (RGB: 199, 21, 133)."""

MIDNIGHT_BLUE_BG: str = back_rgb(25, 25, 112)
"""ANSI escape code for Midnight Blue background (RGB: 25, 25, 112)."""

MINT_CREAM_BG: str = back_rgb(245, 255, 250)
"""ANSI escape code for Mint Cream background (RGB: 245, 255, 250)."""

MISTY_ROSE_BG: str = back_rgb(255, 228, 225)
"""ANSI escape code for Misty Rose background (RGB: 255, 228, 225)."""

MOCCASIN_BG: str = back_rgb(255, 228, 181)
"""ANSI escape code for Moccasin background (RGB: 255, 228, 181)."""

NAVAJO_WHITE_BG: str = back_rgb(255, 222, 173)
"""ANSI escape code for Navajo White background (RGB: 255, 222, 173)."""

NAVY_BG: str = back_rgb(0, 0, 128)
"""ANSI escape code for Navy background (RGB: 0, 0, 128)."""

OLD_LACE_BG: str = back_rgb(253, 245, 230)
"""ANSI escape code for Old Lace background (RGB: 253, 245, 230)."""

OLIVE_BG: str = back_rgb(128, 128, 0)
"""ANSI escape code for Olive background (RGB: 128, 128, 0)."""

OLIVE_DRAB_BG: str = back_rgb(107, 142, 35)
"""ANSI escape code for Olive Drab background (RGB: 107, 142, 35)."""

ORANGE_BG: str = back_rgb(255, 165, 0)
"""ANSI escape code for Orange background (RGB: 255, 165, 0)."""

ORANGE_RED_BG: str = back_rgb(255, 69, 0)
"""ANSI escape code for Orange Red background (RGB: 255, 69, 0)."""

ORCHID_BG: str = back_rgb(218, 112, 214)
"""ANSI escape code for Orchid background (RGB: 218, 112, 214)."""

PALE_GOLDENROD_BG: str = back_rgb(238, 232, 170)
"""ANSI escape code for Pale Goldenrod background (RGB: 238, 232, 170)."""

PALE_GREEN_BG: str = back_rgb(152, 251, 152)
"""ANSI escape code for Pale Green background (RGB: 152, 251, 152)."""

PALE_TURQUOISE_BG: str = back_rgb(175, 238, 238)
"""ANSI escape code for Pale Turquoise background (RGB: 175, 238, 238)."""

PALE_VIOLET_RED_BG: str = back_rgb(219, 112, 147)
"""ANSI escape code for Pale Violet Red background (RGB: 219, 112, 147)."""

PAPAYA_WHIP_BG: str = back_rgb(255, 239, 213)
"""ANSI escape code for Papaya Whip background (RGB: 255, 239, 213)."""

PEACH_PUFF_BG: str = back_rgb(255, 218, 185)
"""ANSI escape code for Peach Puff background (RGB: 255, 218, 185)."""

PERU_BG: str = back_rgb(205, 133, 63)
"""ANSI escape code for Peru background (RGB: 205, 133, 63)."""

PINK_BG: str = back_rgb(255, 192, 203)
"""ANSI escape code for Pink background (RGB: 255, 192, 203)."""

PLUM_BG: str = back_rgb(221, 160, 221)
"""ANSI escape code for Plum background (RGB: 221, 160, 221)."""

POWDER_BLUE_BG: str = back_rgb(176, 224, 230)
"""ANSI escape code for Powder Blue background (RGB: 176, 224, 230)."""

REBECCA_PURPLE_BG: str = back_rgb(102, 51, 153)
"""ANSI escape code for Rebecca Purple background (RGB: 102, 51, 153)."""

ROSY_BROWN_BG: str = back_rgb(188, 143, 143)
"""ANSI escape code for Rosy Brown background (RGB: 188, 143, 143)."""

ROYAL_BLUE_BG: str = back_rgb(65, 105, 225)
"""ANSI escape code for Royal Blue background (RGB: 65, 105, 225)."""

SADDLE_BROWN_BG: str = back_rgb(139, 69, 19)
"""ANSI escape code for Saddle Brown background (RGB: 139, 69, 19)."""

SALMON_BG: str = back_rgb(250, 128, 114)
"""ANSI escape code for Salmon background (RGB: 250, 128, 114)."""

SANDY_BROWN_BG: str = back_rgb(244, 164, 96)
"""ANSI escape code for Sandy Brown background (RGB: 244, 164, 96)."""

SEA_GREEN_BG: str = back_rgb(46, 139, 87)
"""ANSI escape code for Sea Green background (RGB: 46, 139, 87)."""

SEASHELL_BG: str = back_rgb(255, 245, 238)
"""ANSI escape code for Seashell background (RGB: 255, 245, 238)."""

SIENNA_BG: str = back_rgb(160, 82, 45)
"""ANSI escape code for Sienna background (RGB: 160, 82, 45)."""

SILVER_BG: str = back_rgb(192, 192, 192)
"""ANSI escape code for Silver background (RGB: 192, 192, 192)."""

SKY_BLUE_BG: str = back_rgb(135, 206, 235)
"""ANSI escape code for Sky Blue background (RGB: 135, 206, 235)."""

SLATE_BLUE_BG: str = back_rgb(106, 90, 205)
"""ANSI escape code for Slate Blue background (RGB: 106, 90, 205)."""

SLATE_GRAY_BG: str = back_rgb(112, 128, 144)
"""ANSI escape code for Slate Gray background (RGB: 112, 128, 144)."""

SNOW_BG: str = back_rgb(255, 250, 250)
"""ANSI escape code for Snow background (RGB: 255, 250, 250)."""

SPRING_GREEN_BG: str = back_rgb(0, 255, 127)
"""ANSI escape code for Spring Green background (RGB: 0, 255, 127)."""

STEEL_BLUE_BG: str = back_rgb(70, 130, 180)
"""ANSI escape code for Steel Blue background (RGB: 70, 130, 180)."""

TAN_BG: str = back_rgb(210, 180, 140)
"""ANSI escape code for Tan background (RGB: 210, 180, 140)."""

TEAL_BG: str = back_rgb(0, 128, 128)
"""ANSI escape code for Teal background (RGB: 0, 128, 128)."""

THISTLE_BG: str = back_rgb(216, 191, 216)
"""ANSI escape code for Thistle background (RGB: 216, 191, 216)."""

TOMATO_BG: str = back_rgb(255, 99, 71)
"""ANSI escape code for Tomato background (RGB: 255, 99, 71)."""

TURQUOISE_BG: str = back_rgb(64, 224, 208)
"""ANSI escape code for Turquoise background (RGB: 64, 224, 208)."""

VIOLET_BG: str = back_rgb(238, 130, 238)
"""ANSI escape code for Violet background (RGB: 238, 130, 238)."""

WHEAT_BG: str = back_rgb(245, 222, 179)
"""ANSI escape code for Wheat background (RGB: 245, 222, 179)."""

WHITE_SMOKE_BG: str = back_rgb(245, 245, 245)
"""ANSI escape code for White Smoke background (RGB: 245, 245, 245)."""

YELLOW_GREEN_BG: str = back_rgb(154, 205, 50)
"""ANSI escape code for Yellow Green background (RGB: 154, 205, 50)."""
