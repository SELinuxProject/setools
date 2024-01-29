# SPDX-License-Identifier: LGPL-2.1-only

import logging
import traceback
import types
import typing

from PyQt6 import QtWidgets

__all__: typing.Final[tuple[str, ...]] = ("QMessageOnException",)


class QMessageOnException:

    """Context manager to display a message box on exception."""

    def __init__(self, title: str, message: str, /, *,
                 suppress: bool = True,
                 log: logging.Logger | None = None,
                 icon: QtWidgets.QMessageBox.Icon = QtWidgets.QMessageBox.Icon.Critical,
                 parent: QtWidgets.QWidget | None = None) -> None:

        self.title: typing.Final[str] = title
        self.message: typing.Final[str] = message
        self.suppress: typing.Final[bool] = suppress
        self.parent: typing.Final[QtWidgets.QWidget | None] = parent
        self.log: typing.Final[logging.Logger] = log if log else logging.getLogger(__name__)
        self.icon: typing.Final[QtWidgets.QMessageBox.Icon] = icon

    def __enter__(self) -> None:
        pass

    def __exit__(self,
                 exc_type: type[BaseException] | None,
                 exc_value: BaseException | None,
                 tb: types.TracebackType | None) -> bool:

        if exc_type:
            self.log.critical(self.message)
            self.log.debug("Backtrace", exc_info=True)

            msg = QtWidgets.QMessageBox(self.icon,
                                        self.title,
                                        self.message,
                                        parent=self.parent)

            msg.setInformativeText(str(exc_value))
            msg.setDetailedText("\n".join(traceback.format_tb(tb)))
            msg.exec()

            return self.suppress

        return False
