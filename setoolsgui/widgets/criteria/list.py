# SPDX-License-Identifier: LGPL-2.1-only

from contextlib import suppress

from PyQt6 import QtCore, QtWidgets

from .. import models, views
from .criteria import CriteriaWidget

# equal/subset default setting.  At most one can be True
# as these are radio buttons.
EQUAL_DEFAULT_CHECKED = False
SUBSET_DEFAULT_CHECKED = False

__all__ = ('ListWidget',)


class ListWidget(CriteriaWidget):

    """Base class for QListView criteria widgets."""

    equal_toggled = QtCore.pyqtSignal(bool)
    selectionChanged = QtCore.pyqtSignal(list)
    subset_toggled = QtCore.pyqtSignal(bool)

    def __init__(self, title: str, query, attrname: str, model: models.SEToolsTableModel,
                 enable_equal: bool = False, enable_subset: bool = False,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(title, query, attrname, parent=parent)

        self.top_layout = QtWidgets.QGridLayout(self)
        self.criteria = views.SEToolsListView(self)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding,
                                           QtWidgets.QSizePolicy.Policy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.criteria.sizePolicy().hasHeightForWidth())
        self.criteria.setSizePolicy(sizePolicy)
        self.criteria.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.criteria.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.criteria.customContextMenuRequested.connect(self._criteria_context_menu)
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

        spacerItem = QtWidgets.QSpacerItem(4, 20, QtWidgets.QSizePolicy.Policy.Expanding,
                                           QtWidgets.QSizePolicy.Policy.Minimum)
        self.top_layout.addItem(spacerItem, 0, 3, 1, 1)

        # Invert button
        self.invert_criteria = QtWidgets.QPushButton(self)
        self.invert_criteria.setText("Invert")
        self.invert_criteria.setToolTip("Invert selection.")
        self.invert_criteria.setWhatsThis("<b>Invert the list selection.</b>")
        self.invert_criteria.clicked.connect(self.criteria.invert_selection)
        self.top_layout.addWidget(self.invert_criteria, 1, 1, 1, 1)

        spacerItem1 = QtWidgets.QSpacerItem(20, 28, QtWidgets.QSizePolicy.Policy.Minimum,
                                            QtWidgets.QSizePolicy.Policy.Expanding)
        self.top_layout.addItem(spacerItem1, 3, 1, 1, 1)

        # Match any radio button.  This doesn't do anything by itself, as
        # "match any" means all of the matching boolean options are false.
        self.criteria_any = QtWidgets.QRadioButton(self)
        self.criteria_any.setText("Match any")
        self.criteria_any.setChecked(not any((EQUAL_DEFAULT_CHECKED, SUBSET_DEFAULT_CHECKED)))
        self.top_layout.addWidget(self.criteria_any, 0, 2, 1, 1)

        # the rstrip("_") below is to aviod names like "name__equal"
        if enable_equal:
            self.criteria_equal = QtWidgets.QRadioButton(self)
            self.criteria_equal.setObjectName(f"{self.attrname.rstrip('_')}_equal")
            self.criteria_equal.setText("Match exact")
            self.top_layout.addWidget(self.criteria_equal, 1, 2, 1, 1)
            self.criteria_equal.toggled.connect(self._set_equal)
            self.criteria_equal.toggled.connect(self.equal_toggled)
            # set initial state:
            self.criteria_equal.setChecked(EQUAL_DEFAULT_CHECKED)
            self._set_equal(EQUAL_DEFAULT_CHECKED)

        if enable_subset:
            self.criteria_subset = QtWidgets.QRadioButton(self)
            self.criteria_subset.setObjectName(f"{self.attrname.rstrip('_')}_subset")
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

    def _criteria_context_menu(self, pos: QtCore.QPoint) -> None:
        """Collect actions from the model and display a context menu if there are any actions."""
        actionlist = []
        for actions in self.criteria.selection(models.ModelRoles.ContextMenuRole):
            actionlist.extend(actions)

        if not actionlist:
            return

        self.log.debug(f"Generating context menu with actions: {actionlist}")
        menu = QtWidgets.QMenu(self)
        menu.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose)
        menu.addActions(actionlist)
        menu.exec(self.criteria.mapToGlobal(pos))

    def _selection_changed(self, _selected: QtCore.QItemSelection,
                           _deselected: QtCore.QItemSelection) -> None:
        """Set the query attribute based on the entire widget selection."""
        selection = list(self.criteria.selection())
        self.log.debug(f"Setting {self.criteria.objectName()} to {selection}.")
        setattr(self.query, self.criteria.objectName(), selection)
        self.selectionChanged.emit(selection)

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
    def save(self, settings: dict) -> None:
        settings[self.criteria.objectName()] = list(
            self.criteria.selection(models.ModelRoles.DisplayRole))

        with suppress(AttributeError):
            settings[self.criteria_equal.objectName()] = self.criteria_equal.isChecked()

        with suppress(AttributeError):
            settings[self.criteria_subset.objectName()] = self.criteria_subset.isChecked()

    def load(self, settings: dict) -> None:
        with suppress(KeyError):
            self.criteria.set_selection(settings[self.criteria.objectName()])

        with suppress(KeyError, AttributeError):
            self.criteria_equal.setChecked(settings[self.criteria_equal.objectName()])

        with suppress(KeyError, AttributeError):
            self.criteria_subset.setChecked(settings[self.criteria_subset.objectName()])
