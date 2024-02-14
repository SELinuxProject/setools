# SPDX-License-Identifier: LGPL-2.1-only

import collections
from contextlib import suppress
import enum
import setools
import typing

from PyQt6 import QtCore, QtWidgets

from .criteria import CriteriaWidget

E = typing.TypeVar("E", bound=enum.Enum)

__all__ = ('RadioEnumWidget',)


class RadioEnumWidget(CriteriaWidget, typing.Generic[E]):

    """
    Criteria selection widget presenting possible options as vertical list of
    radio buttons.
    """

    selectionChanged = QtCore.pyqtSignal(enum.Enum)

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, enum_class: type[E],
                 colspan: int = 1, parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(title, query, attrname, parent=parent)

        self.enum_class: typing.Final[type[E]] = enum_class
        self.top_layout = QtWidgets.QGridLayout(self)

        count: int
        enu: E
        self.criteria = collections.OrderedDict[E, QtWidgets.QRadioButton]()
        for count, enu in enumerate(enum_class):
            w = QtWidgets.QRadioButton(enu.value, parent=self)
            w.toggled.connect(self._update_query)
            w.setChecked(False if count else True)  # set first option checked.
            self.top_layout.addWidget(w, count, 0, 1, colspan)
            self.criteria[enu] = w

        self._update_query()

    @property
    def has_errors(self) -> bool:
        """Get error state of this widget."""
        # Radio buttons are exclusive, so this should always be false
        # if the widget is configured correctly.
        checks: int = sum(1 for w in self.criteria.values() if w.isChecked())
        return (checks != 1)

    def selection(self) -> E:
        """Return the current selection."""
        for enu, w in self.criteria.items():
            if w.isChecked():
                return enu

        raise RuntimeError(f"No options selected in {self.attrname}. This is an SETools bug.")

    def set_selection(self, val: E) -> None:
        """Set the selection of the enum."""
        for enu, w in self.criteria.items():
            w.setChecked(enu == val)

    def _update_query(self, val: bool = True) -> None:
        """Update the query based on the radio button state."""
        if not val:
            return  # only apply updates once per radio button switch

        for enu, w in self.criteria.items():
            if w.isChecked():
                setattr(self.query, self.attrname, enu)
                self.selectionChanged.emit(enu)
                self.log.debug(f"Selection changed to {enu}")
                break

    #
    # Workspace methods
    #

    def save(self, settings: dict) -> None:
        settings[self.attrname] = self.selection().name

    def load(self, settings: dict) -> None:
        with suppress(AttributeError, KeyError):
            self.set_selection(self.enum_class[settings[self.attrname]])


if __name__ == '__main__':
    import sys
    import logging
    import pprint
    import warnings

    class local_enum_class(enum.Enum):
        """Enum for local testing"""
        Val1 = "Value 1"
        Val2 = "Value 2"
        Val3 = "Value 3"
        Val4 = "Value 4"

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.TERuleQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    widget = RadioEnumWidget("Test radio enum", q, "radioattrname", local_enum_class, parent=mw)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.show()
    rc = app.exec()
    local_settings: typing.Dict[str, str] = {}
    widget.save(local_settings)
    pprint.pprint(local_settings)
    sys.exit(rc)
