"""
:platform: Windows
"""

from __future__ import annotations

import logging
import sys

from enum import IntEnum
from pathlib import Path

import MemLib.ANSI as ANSI


class Level(IntEnum):
    """
    Simple enum level representation of the logging module.
    """

    NOTSET = 0
    Debug = 10
    Info = 20
    Warning = 30
    Error = 40
    Critical = 50


class Text:
    """
    Simple Text class that supports coloring and lets you grab both the ANSI colored text or the raw text.
    """

    def __init__(self, text: str, color: str = None):
        if color is None:
            color = ""

        self._text = text
        self._color = color

    def __str__(self) -> str:
        return self._text

    def Get(self, colored: bool = False) -> str:
        if colored and self._color != "":
            return self._color + self._text + ANSI.END
        return self._text


_Formatter = logging.Formatter()

_COLORMAP = {
    Level.Debug: ANSI.ForeRGB(58, 150, 221),
    logging.INFO: ANSI.ForeRGB(249, 241, 165),
    logging.WARNING: ANSI.ForeRGB(255, 199, 6),
    logging.ERROR: ANSI.RED,
    logging.CRITICAL: ANSI.BOLD + ANSI.ForeRGB(255, 50, 50)
}
_MSGMAP = {
    Level.Debug: ANSI.WHITE,
    logging.INFO: "",
    logging.WARNING: ANSI.ForeRGB(255, 199, 6),
    logging.ERROR: ANSI.RED,
    logging.CRITICAL: ANSI.BOLD + ANSI.BackRGB(255, 50, 50) + ANSI.ForeRGB(255, 255, 255),
}

_FORMAT = "[{time:s}][{name:s}][{level:s}] "


def GetLevelColor(level: Level | int):
    return _COLORMAP.get(level, ANSI.WHITE)


def GetMessageColor(level: Level | int):
    return _MSGMAP.get(level, ANSI.WHITE)


class ColorHandler(logging.StreamHandler):
    """
    A StreamHandler wrapper to allow custom color tags for different level styles.
    """

    def __init__(self, *, stream = None, color: ANSI.ForeColor = None, useColors: bool = True):
        super().__init__(stream)

        if color is None:
            color = ""

        self._color = str(color)
        self._useColors = useColors

    def SetColor(self, color: ANSI.ForeColor) -> None:
        self._color = color

    def SetUseColor(self, state: bool) -> None:
        self._useColors = state

    def emit(self, record):
        """
        Emit a record.

        If a formatter is specified, it is used to format the record.
        The record is then written to the stream with a trailing newline.  If
        exception information is present, it is formatted using
        traceback.print_exception and appended to the stream.  If the stream
        has an 'encoding' attribute, it is used to determine how to do the
        output to the stream.
        """

        time  = Text(_Formatter.formatTime(record, "%H:%M:%S"), ANSI.LIGHT_GRAY)
        name  = Text(record.name, self._color)
        level = Text(record.levelname, GetLevelColor(record.levelno))
        msg   = Text(self.format(record), GetMessageColor(record.levelno))

        # noinspection PyBroadException
        try:
            # cutting of last space to allow prefixed messages
            template = _FORMAT
            if msg.Get()[0] == '[' or msg.Get()[:5] == (ANSI.END + "["):
                template = template[:-1]

            text = template.format(
                time=time.Get(self._useColors),
                name=name.Get(self._useColors),
                level=level.Get(self._useColors),
            )
            stream = self.stream
            stream.write(f"{text}{msg.Get(self._useColors)}{self.terminator}")
            self.flush()
        except RecursionError:
            raise
        except Exception:
            self.handleError(record)


class FileHandler(logging.FileHandler):
    """
    A FileHandler wrapper to avoid custom color to be written into files.
    """

    def emit(self, record):
        """
        Emit a record.

        If a formatter is specified, it is used to format the record.
        The record is then written to the stream with a trailing newline.  If
        exception information is present, it is formatted using
        traceback.print_exception and appended to the stream.  If the stream
        has an 'encoding' attribute, it is used to determine how to do the
        output to the stream.
        """

        time = _Formatter.formatTime(record, "%H:%M:%S")
        name = record.name
        level = record.levelname
        msg = self.format(record)

        # noinspection PyBroadException
        try:
            template = _FORMAT
            if len(msg) and msg[0] == '[':
                template = template[:-1]

            text = template.format(
                time=time,
                name=name,
                level=level,
            )
            stream = self.stream
            stream.write(f"{text}{msg}{self.terminator}")
            self.flush()
        except RecursionError:
            raise
        except Exception:
            self.handleError(record)


class ANSILogger:
    """
    Simple logging wrapper that supports ANSI coloring.
    """

    def __init__(self, *,
                 name: str = None,
                 path: Path = None,
                 color: ANSI.ForeColor = None,
                 useColors: bool = True,
                 level: Level = Level.Info):
        self._filepath = path

        if name is None:
            name = f"Global"
        if color is None:
            color = ANSI.ForeRGB(153, 89, 227)

        self._useColors = useColors

        self._logger = logging.getLogger(name)
        self._logger.propagate = False
        self._logger.setLevel(Level.Debug)

        self._ch = ColorHandler(
            stream=sys.stdout,
            color=color,
            useColors=self._useColors,
        )
        self._logger.addHandler(self._ch)

        if isinstance(path, str):
            self._logger.addHandler(FileHandler(self._filepath))

        self._logger.setLevel(level)

    def SetName(self, newName: str) -> None:
        self._logger.name = newName

    def GetName(self) -> str:
        return self._logger.name

    def GetPath(self) -> Path:
        return self._filepath

    def IsColorized(self) -> bool:
        return self._useColors

    def CanLog(self, level: Level) -> bool:
        """
        Checks if a message could be logged.

        .. note:: Computing the arguments passed to the logging method can also be expensive, and you may want to avoid
                  doing it if the logger will just throw away your event. In some cases, CanLog() can itself be
                  more expensive than you’d like (e.g. for deeply nested loggers where an explicit level is only set
                  high up in the logger hierarchy). In such cases (or if you want to avoid calling a method in tight
                  loops), you can cache the result of a call to CanLog() in a local or instance variable, and use that
                  instead of calling the method each time. Such a cached value would only need to be recomputed when the
                  logging configuration changes dynamically while the application is running (which is not all that
                  common).

        :param level: the level to check for
        :returns: True, if message can be logged, False otherwise.
        """

        return self._logger.isEnabledFor(level)

    def SetLevel(self, level: Level) -> None:
        """
        Set the logging level of this logger.

        :param level: the level
        """

        self._logger.setLevel(level)

    def Debug(self, message: str, *args, **kwargs) -> None:
        """
        Log 'msg % args' with severity 'DEBUG'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.debug("Houston, we have a %s", "thorny problem", exc_info=1)

        :param message: the message to log.
        """

        self._logger.debug(message, *args, **kwargs)

    def Info(self, message: str, *args, **kwargs) -> None:
        """
        Log 'msg % args' with severity 'INFO'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.info("Houston, we have a %s", "interesting problem", exc_info=1)

        :param message: the message to log.
        """

        self._logger.info(message, *args, **kwargs)

    def Warning(self, message: str, *args, **kwargs) -> None:
        """
        Log 'msg % args' with severity 'WARNING'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.warning("Houston, we have a %s", "bit of a problem", exc_info=1)

        :param message: the message to log.
        """

        self._logger.warning(message, *args, **kwargs)

    def Error(self, message: str, *args, **kwargs) -> None:
        """
        Log 'msg % args' with severity 'ERROR'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.error("Houston, we have a %s", "major problem", exc_info=1)

        :param message: the message to log.
        """

        self._logger.error(message, *args, **kwargs)

    def Critical(self, message: str, *args, **kwargs) -> None:
        """
        Log 'msg % args' with severity 'ERROR'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.error("Houston, we have a %s", "major problem", exc_info=1)

        :param message: the message to log.
        """

        self._logger.critical(message, *args, **kwargs)

    def Log(self, level: Level, message: str, *args, **kwargs):
        """
        Log 'msg % args' with the integer severity 'level'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.log(level, "We have a %s", "mysterious problem", exc_info=1)
        """

        self._logger.log(level, message, *args, **kwargs)

    def LogWithPrefix(self, level: Level, prefix, message: str, *args, **kwargs) -> None:
        """
        Same like Log() but it allows you to add another [<>] right after name and level tags.
        """

        if not self.CanLog(level):
            return

        if self._useColors:
            prefix = f"{ANSI.END}[{ANSI.ForeRGB(153, 204, 255) + prefix + ANSI.END}] "
            message = prefix + GetMessageColor(level) + message + ANSI.END
        else:
            message = f"[{prefix}] " + message

        self._logger.log(level, message, *args, **kwargs)



