# SPDX-License-Identifier: LGPL-2.1-only

from collections import OrderedDict
from contextlib import suppress
import logging
from typing import TYPE_CHECKING

from PyQt5 import QtCore, QtGui, QtWidgets

from .criteria import CriteriaWidget

if TYPE_CHECKING:
    from typing import Dict, Final, Iterable, List, Optional, OrderedDict
    import logging


class CheckboxSetCriteriaWidget(CriteriaWidget):

    """
    Criteria selection widget presenting possible options as a series of checkboxes.
    The selected checkboxes are then merged into a single Python list and stored
    in the query's specified attribute.

    If a checkbox is set to disabled in a subclass, the clear and invert
    buttons will not change the state of the checkbox.
    """

    selectionChanged = QtCore.pyqtSignal(list)

    @property
    def has_errors(self) -> bool:
        """
        Get error state of this widget.

        Cannot be in an error state(?)
        """
        return False

    def __init__(self, title: str, query, attrname: str, items: "Iterable[str]",
                 num_cols: int = 4, parent: "Optional[QtWidgets.QWidget]" = None) -> None:

        super().__init__(title, query, attrname, parent=parent)

        assert items, "Checkbox criteria items are empty, this is an SETools bug."
        self.top_layout = QtWidgets.QGridLayout(self)

        self.criteria: "OrderedDict[str, QtWidgets.QCheckBox]" = OrderedDict()
        for count, name in enumerate(items):
            w = QtWidgets.QCheckBox(self)
            w.setObjectName(name)
            w.setText(name)
            w.stateChanged.connect(self._sync_selection)
            self.top_layout.addWidget(w, int(count / num_cols), count % num_cols)
            self.criteria[name] = w

        self.top_layout.addItem(
            QtWidgets.QSpacerItem(20, 20,
                                  QtWidgets.QSizePolicy.Policy.MinimumExpanding,
                                  QtWidgets.QSizePolicy.Policy.Minimum),
            0, num_cols + 1)

        # Clear button
        self.clear_criteria = QtWidgets.QPushButton(self)
        self.clear_criteria.setText("Clear")
        self.clear_criteria.clicked.connect(self.clear_selection)
        self.top_layout.addWidget(self.clear_criteria, 0, num_cols)

        # Invert button
        self.invert_criteria = QtWidgets.QPushButton(self)
        self.invert_criteria.setText("Invert")
        self.invert_criteria.clicked.connect(self.invert_selection)
        self.top_layout.addWidget(self.invert_criteria, 1, num_cols)

        if len(self.criteria) == 1:
            # Disable the widget if there is only one checkbox.
            self.setDisabled(True)

        QtCore.QMetaObject.connectSlotsByName(self)

    def _sync_selection(self) -> None:
        """Store checkbox state into the query's specified attribute."""
        items = self.selection()
        self.log.debug(f"Setting {self.attrname} to {items!r}")
        setattr(self.query, self.attrname, items)
        self.selectionChanged.emit(items)

    def selection(self) -> "List[str]":
        """Return a list with the names of the checked boxes."""
        return [n for n, w in self.criteria.items() if w.isChecked()]

    def set_selection(self, items: "List[str]") -> None:
        """Set selected checkboxes."""
        self.clear_selection()
        for name, widget in self.criteria.items():
            if widget.isEnabled():
                widget.setChecked(name in items)

    def clear_selection(self) -> None:
        """Uncheck all enabled checkboxes."""
        self.log.debug(f"Clearing {self.attrname} selection.")
        for w in self.criteria.values():
            if w.isEnabled():
                w.setChecked(False)

    def invert_selection(self) -> None:
        """Invert the state of all checkboxes."""
        self.log.debug(f"Inverting {self.attrname} selection.")
        for w in self.criteria.values():
            if w.isEnabled():
                w.toggle()

    #
    # Workspace methods
    #

    def save(self, settings: "Dict") -> None:
        settings[self.attrname] = self.selection()

    def load(self, settings: "Dict") -> None:
        try:
            # for compat for pre 4.5 configs
            for name, widget in self.criteria.items():
                if widget.isEnabled():
                    widget.setChecked(settings[name])

            QtWidgets.QMessageBox.warning(self, "Warning", "The loaded configuration is using the "
                                          f"old format for {self.title()}.  Please re-save the "
                                          "settings to save the configuration in the new format. "
                                          "Support for the old format will be removed in SETools "
                                          "4.6.")

        except KeyError:
            with suppress(KeyError):
                self.set_selection(settings[self.attrname])
