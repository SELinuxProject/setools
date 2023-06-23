# SPDX-License-Identifier: LGPL-2.1-only

from contextlib import suppress
import logging
from typing import TYPE_CHECKING

from PyQt5 import QtCore, QtGui, QtWidgets

from .criteria import CriteriaWidget

if TYPE_CHECKING:
    from ..models.list import SEToolsListModel
    from typing import Dict, Iterable, List, Optional

# equal/subset default setting.  At most one can be True
# as these are radio buttons.
EQUAL_DEFAULT_CHECKED = False
SUBSET_DEFAULT_CHECKED = False

INVERT_SELECTION_FLAGS = QtCore.QItemSelectionModel.SelectionFlags(
        QtCore.QItemSelectionModel.SelectionFlag.Toggle) | \
        QtCore.QItemSelectionModel.SelectionFlag.Columns


class ListCriteriaWidget(CriteriaWidget):

    equal_toggled = QtCore.pyqtSignal(bool)
    selectionChanged = QtCore.pyqtSignal(list)
    subset_toggled = QtCore.pyqtSignal(bool)

    def __init__(self, title: str, query, attrname: str, model: "SEToolsListModel",
                 enable_equal: bool = False, enable_subset: bool = False,
                 parent: "Optional[QtWidgets.QWidget]" = None) -> None:

        super().__init__(title, query, attrname, parent=parent)

        self.top_layout = QtWidgets.QGridLayout(self)
        self.criteria = QtWidgets.QListView(self)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding,
                                           QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.criteria.sizePolicy().hasHeightForWidth())
        self.criteria.setSizePolicy(sizePolicy)
        self.criteria.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.criteria.setObjectName(self.attrname)
        self.criteria.setModel(model)
        self.criteria.selectionModel().selectionChanged.connect(self._selection_changed)
        self.top_layout.addWidget(self.criteria, 0, 0, 3, 1)

        # Clear button
        self.clear_criteria = QtWidgets.QPushButton(self)
        self.clear_criteria.setText("Clear")
        self.clear_criteria.setToolTip("Clear selection.")
        self.clear_criteria.setWhatsThis("<b>Clear the list selection.</b>")
        self.top_layout.addWidget(self.clear_criteria, 0, 1, 1, 1)
        self.clear_criteria.clicked.connect(self.criteria.clearSelection)

        spacerItem = QtWidgets.QSpacerItem(4, 20, QtWidgets.QSizePolicy.Expanding,
                                           QtWidgets.QSizePolicy.Minimum)
        self.top_layout.addItem(spacerItem, 0, 3, 1, 1)

        # Invert button
        self.invert_criteria = QtWidgets.QPushButton(self)
        self.invert_criteria.setText("Invert")
        self.invert_criteria.setToolTip("Invert selection.")
        self.invert_criteria.setWhatsThis("<b>Invert the list selection.</b>")
        self.invert_criteria.clicked.connect(self.invert_selection)
        self.top_layout.addWidget(self.invert_criteria, 1, 1, 1, 1)

        spacerItem1 = QtWidgets.QSpacerItem(20, 28, QtWidgets.QSizePolicy.Minimum,
                                            QtWidgets.QSizePolicy.Expanding)
        self.top_layout.addItem(spacerItem1, 3, 1, 1, 1)

        # Match any radio button.  This doesn't do anything by itself, as
        # "match any" means all of the matching boolean options are false.
        self.criteria_any = QtWidgets.QRadioButton(self)
        self.criteria_any.setText("Match any")
        self.criteria_any.setChecked(not any((EQUAL_DEFAULT_CHECKED, SUBSET_DEFAULT_CHECKED)))
        self.top_layout.addWidget(self.criteria_any, 0, 2, 1, 1)

        if enable_equal:
            self.criteria_equal = QtWidgets.QRadioButton(self)
            self.criteria_equal.setObjectName(f"{self.attrname}_equal")
            self.criteria_equal.setText("Match exact")
            self.top_layout.addWidget(self.criteria_equal, 1, 2, 1, 1)
            self.criteria_equal.toggled.connect(self._set_equal)
            self.criteria_equal.toggled.connect(self.equal_toggled)
            # set initial state:
            self.criteria_equal.setChecked(EQUAL_DEFAULT_CHECKED)
            self._set_equal(EQUAL_DEFAULT_CHECKED)

        if enable_subset:
            self.criteria_subset = QtWidgets.QRadioButton(self)
            self.criteria_subset.setObjectName(f"{self.attrname}_subset")
            self.criteria_subset.setText("Match subset")
            self.top_layout.addWidget(self.criteria_subset, 2, 2, 1, 1)
            self.criteria_subset.toggled.connect(self._set_subset)
            self.criteria_subset.toggled.connect(self.subset_toggled)
            # set initial state:
            self.criteria_subset.setChecked(SUBSET_DEFAULT_CHECKED)
            self._set_subset(SUBSET_DEFAULT_CHECKED)

        QtCore.QMetaObject.connectSlotsByName(self)

    @property
    def has_errors(self) -> bool:
        """
        Get error state of this widget.

        Cannot be in an error state(?)
        """
        return False

    def _selection_changed(self, _selected: QtCore.QItemSelection,
                           _deselected: QtCore.QItemSelection) -> None:
        """Set the query attribute based on the entire widget selection."""
        selection = list(self.selection())
        self.log.debug(f"Setting {self.criteria.objectName()} to {selection}.")
        setattr(self.query, self.criteria.objectName(), selection)
        self.selectionChanged.emit(selection)

    def set_selection(self, selections: "List[str]") -> None:
        """Set the selection."""
        selectionmodel = self.criteria.selectionModel()
        datamodel = self.criteria.selectionModel().model()

        new_selection = QtCore.QItemSelection()
        for row in range(datamodel.rowCount()):
            index = datamodel.createIndex(row, 0)
            item = datamodel.data(index, QtCore.Qt.ItemDataRole.DisplayRole)
            if item in selections:
                new_selection.select(index, index)

        selectionmodel.select(new_selection,
                              QtCore.QItemSelectionModel.SelectionFlag.ClearAndSelect)

    def invert_selection(self) -> None:
        """Invert the selection."""
        self.log.debug(f"Inverting {self.criteria.objectName()} selection.")
        selection_model = self.criteria.selectionModel()
        model = self.criteria.model()
        selection_model.select(model.createIndex(0, 0), INVERT_SELECTION_FLAGS)

    def selection(self,
                  role: QtCore.Qt.ItemDataRole = QtCore.Qt.ItemDataRole.UserRole) -> "Iterable":
        """
        Generator which returns the selection.

        By default this is the Qt.ItemDataRole.UserRole (returns SETools objects)
        """
        model = self.criteria.model()
        for index in self.criteria.selectionModel().selectedIndexes():
            yield model.data(index, role)

    def _set_equal(self, state: bool) -> None:
        """Set the equal boolean value."""
        name = self.criteria_equal.objectName()
        self.log.debug(f"Setting {name} {state}")
        setattr(self.query, name, state)

    def _set_subset(self, state: bool) -> None:
        """Set the subset boolean value."""
        name = self.criteria_subset.objectName()
        self.log.debug(f"Setting {name} {state}")
        setattr(self.query, name, state)

    #
    # Workspace methods
    #
    def save(self, settings: "Dict") -> None:
        settings[self.criteria.objectName()] = list(
            self.selection(QtCore.Qt.ItemDataRole.DisplayRole))

        with suppress(AttributeError):
            settings[self.criteria_equal.objectName()] = self.criteria_equal.isChecked()

        with suppress(AttributeError):
            settings[self.criteria_subset.objectName()] = self.criteria_subset.isChecked()

    def load(self, settings: "Dict") -> None:
        with suppress(KeyError):
            self.set_selection(settings[self.criteria.objectName()])

        with suppress(KeyError, AttributeError):
            self.criteria_equal.setChecked(settings[self.criteria_equal.objectName()])

        with suppress(KeyError, AttributeError):
            self.criteria_subset.setChecked(settings[self.criteria_subset.objectName()])
