# SPDX-License-Identifier: LGPL-2.1-only

import enum
import logging
import typing

from PyQt6 import QtWidgets

__all__ = ('CriteriaWidget', 'OptionsPlacement')


class OptionsPlacement(enum.Enum):

    """Enumeration of options placement relative to the primary criteria widget (eg line edit)."""

    RIGHT = enum.auto()
    BELOW = enum.auto()


class CriteriaWidget(QtWidgets.QGroupBox):

    """Base class for criteria widgets."""

    def __init__(self, title: str, query, attrname: str,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(parent=parent)
        self.log: typing.Final = logging.getLogger(self.__module__)
        self.query: typing.Final = query
        self.attrname: typing.Final[str] = attrname

        self.setTitle(title)

    @property
    def has_errors(self) -> bool:
        """
        Get error state of this widget.

        If the error text is set, there is an error.
        """
        raise NotImplementedError

    #
    # Overridden methods for typing purposes
    #
    # @typing.override
    def style(self) -> QtWidgets.QStyle:
        """Type-narrowed style() method.  Always returns a QStyle."""
        style = super().style()
        assert style, "No style set, this is an SETools bug"  # type narrowing
        return style

    #
    # Save/Load field
    #

    def save(self, settings: dict) -> None:
        """Save the widget settings to the settings dictionary."""
        raise NotImplementedError

    def load(self, settings: dict) -> None:
        """Load the widget settings from the settings dictionary."""
        raise NotImplementedError
