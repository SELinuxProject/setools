# Copyright 2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#

import copy
import logging
import typing

from PyQt6 import QtCore, QtGui, QtWidgets
import setools

from . import models, views

# "" to handle unset
AttrFilter = typing.Union[setools.TypeAttribute, typing.Literal[""]]

__all__ = ("ExcludeTypes",)

E = typing.TypeVar("E")


class ExcludeProtocol(typing.Protocol[E]):

    """Protocol for exclusion lists."""

    exclude: list[E]
    policy: setools.SELinuxPolicy


class ExcludeTypes(QtWidgets.QDialog):

    """Dialog for choosing excluded types."""

    def __init__(self, query: ExcludeProtocol[setools.Type],
                 parent: QtWidgets.QWidget | None = None):

        super().__init__(parent)
        self.log = logging.getLogger(__name__)
        self.query: typing.Final = query

        self.setWindowTitle("Exclude Types From Analysis")
        self.gridLayout = QtWidgets.QGridLayout(self)
        self.setSizeGripEnabled(True)

        #
        # Include side
        #

        included_label = QtWidgets.QLabel(self)
        included_label.setObjectName("header")
        included_label.setText("Included Types")
        header_sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred,
                                                  QtWidgets.QSizePolicy.Policy.Fixed)
        header_sizePolicy.setHorizontalStretch(0)
        header_sizePolicy.setVerticalStretch(0)
        header_sizePolicy.setHeightForWidth(included_label.sizePolicy().hasHeightForWidth())
        included_label.setSizePolicy(header_sizePolicy)
        self.gridLayout.addWidget(included_label, 0, 0, 1, 1)

        self.included_types = views.SEToolsListView(self)
        self.included_types.setObjectName("Included types list")
        self.included_types.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.included_model = models.TypeTable(self)
        self.included_model.item_list = [t for t in self.query.policy.types()
                                         if t not in self.query.exclude]
        self.included_sort = FilterByAttributeProxy(self)
        self.included_sort.setSourceModel(self.included_model)
        self.included_sort.sort(0, QtCore.Qt.SortOrder.AscendingOrder)
        self.included_types.setModel(self.included_sort)
        self.gridLayout.addWidget(self.included_types, 1, 0, 4, 1)

        #
        # Central include/exclude buttons
        #

        # spacer above exclude button
        spacerItem = QtWidgets.QSpacerItem(20, 40,
                                           QtWidgets.QSizePolicy.Policy.Minimum,
                                           QtWidgets.QSizePolicy.Policy.Expanding)
        self.gridLayout.addItem(spacerItem, 1, 1, 1, 1)

        # exclude button
        self.exclude_a_type = QtWidgets.QPushButton(self)
        self.exclude_a_type.setIcon(
            QtGui.QIcon.fromTheme("rightarrow-icon",
                                  self.style().standardIcon(
                                    QtWidgets.QStyle.StandardPixmap.SP_ArrowRight)))
        self.exclude_a_type.setToolTip("Exclude selected types.")
        self.gridLayout.addWidget(self.exclude_a_type, 2, 1, 1, 1)

        # include button
        self.include_a_type = QtWidgets.QPushButton(self)
        self.include_a_type.setIcon(
            QtGui.QIcon.fromTheme("leftarrow-icon",
                                  self.style().standardIcon(
                                    QtWidgets.QStyle.StandardPixmap.SP_ArrowLeft)))
        self.include_a_type.setToolTip("Include selected types.")
        self.gridLayout.addWidget(self.include_a_type, 3, 1, 1, 1)

        # spacer below include btton
        spacerItem1 = QtWidgets.QSpacerItem(20, 40,
                                            QtWidgets.QSizePolicy.Policy.Minimum,
                                            QtWidgets.QSizePolicy.Policy.Expanding)
        self.gridLayout.addItem(spacerItem1, 4, 1, 1, 1)

        #
        # Exclude side
        #
        excluded_label = QtWidgets.QLabel(self)
        excluded_label.setText("Excluded Types")
        excluded_label.setObjectName("header")
        excluded_label.setSizePolicy(header_sizePolicy)
        self.gridLayout.addWidget(excluded_label, 0, 2, 1, 1)

        self.excluded_types = views.SEToolsListView(self)
        self.excluded_types.setObjectName("Excluded types list")
        self.excluded_types.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.excluded_model = models.TypeTable(self)
        self.excluded_model.item_list = copy.copy(self.query.exclude)
        self.excluded_sort = FilterByAttributeProxy(self)
        self.excluded_sort.setSourceModel(self.excluded_model)
        self.excluded_sort.sort(0, QtCore.Qt.SortOrder.AscendingOrder)
        self.excluded_types.setModel(self.excluded_sort)
        self.gridLayout.addWidget(self.excluded_types, 1, 2, 4, 1)

        #
        # Attribute selection (under both sides)
        #

        attribute_label = QtWidgets.QLabel(self)
        attribute_label.setText("Filter types by attribute:")
        attribute_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight |
                                     QtCore.Qt.AlignmentFlag.AlignVCenter)
        attribute_label.setSizePolicy(header_sizePolicy)
        self.gridLayout.addWidget(attribute_label, 5, 0, 1, 1)

        literal_emptystr: typing.Literal[""] = ""  # for mypy to make Literal
        self.attr = QtWidgets.QComboBox(self)
        self.attr_model = models.SEToolsTableModel[AttrFilter](self)
        self.attr_model.headers = ["Attribute"]
        self.attr_model.item_list = [literal_emptystr] + sorted(self.query.policy.typeattributes())
        self.attr.setModel(self.attr_model)
        self.gridLayout.addWidget(self.attr, 5, 1, 1, 1)

        #
        # Bottom button box
        #
        self.buttonBox = QtWidgets.QDialogButtonBox(self)
        self.buttonBox.setOrientation(QtCore.Qt.Orientation.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.StandardButton.Cancel |
                                          QtWidgets.QDialogButtonBox.StandardButton.Ok)
        self.gridLayout.addWidget(self.buttonBox, 6, 2, 1, 1)

        #
        # connect signals
        #
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)
        self.exclude_a_type.clicked.connect(self.exclude_clicked)
        self.include_a_type.clicked.connect(self.include_clicked)
        self.attr.currentIndexChanged.connect(self.set_attr_filter)
        QtCore.QMetaObject.connectSlotsByName(self)

    def _move_selected_types(self, source: views.SEToolsListView,
                             dest: views.SEToolsListView) -> None:
        """Move types from one SEToolsListView to another."""
        source_scroll_pos = source.verticalScrollBar().value()
        dest_scroll_pos = dest.verticalScrollBar().value()

        source_proxy = typing.cast(FilterByAttributeProxy, source.model())
        source_model = typing.cast(models.TypeTable, source_proxy.sourceModel())
        dest_proxy = typing.cast(FilterByAttributeProxy, dest.model())
        dest_model = typing.cast(models.TypeTable, dest_proxy.sourceModel())
        selected_types: typing.List[setools.Type] = []
        for index in source.selectionModel().selectedIndexes():
            source_index = source_proxy.mapToSource(index)
            item = source_model.data(source_index, models.ModelRoles.PolicyObjRole)
            assert item, f"Selection error: {item}. This is an SETools bug."
            dest_model.append(item)
            selected_types.append(item)

        for item in selected_types:
            source_model.remove(item)

        # reset scroll positions
        source.verticalScrollBar().setValue(source_scroll_pos)
        dest.verticalScrollBar().setValue(dest_scroll_pos)

        self.log.debug(
            f"Moved selection from {source.objectName()} to {dest.objectName()}: {selected_types}")

    # @typing.override
    def accept(self) -> None:
        """Accept excluded types seelection and save to query."""
        self.log.debug(f"Chosen for exclusion: {self.excluded_model.item_list!r}")
        self.query.exclude = self.excluded_model.item_list
        return super().accept()

    def exclude_clicked(self) -> None:
        self._move_selected_types(self.included_types, self.excluded_types)

    def include_clicked(self) -> None:
        self._move_selected_types(self.excluded_types, self.included_types)

    def set_attr_filter(self, row):
        index = self.attr_model.index(row, 0)
        attr = self.attr_model.data(index, models.ModelRoles.PolicyObjRole)
        self.log.debug(f"Attribute set to {attr!r}")
        self.included_sort.attr = attr
        self.excluded_sort.attr = attr

    #
    # Overridden methods for typing purposes
    #

    # @typing.override
    def style(self) -> QtWidgets.QStyle:
        """Type-narrowed style() method.  Always returns a QStyle."""
        style = super().style()
        assert style, "No style set, this is an SETools bug"  # type narrowing
        return style


class FilterByAttributeProxy(QtCore.QSortFilterProxyModel):

    """Filter a list of types by attribute membership."""

    _attr: AttrFilter = ""

    @property
    def attr(self) -> AttrFilter:
        return self._attr

    @attr.setter
    def attr(self, value: AttrFilter) -> None:
        self._attr = value
        self.invalidateFilter()

    def filterAcceptsRow(self, row: int, parent: QtCore.QModelIndex) -> bool:
        if self.attr:
            model = self.sourceModel()
            assert model, "No source model, this is an SETools bug"  # type narrowing
            index = model.index(row, 0)
            type_ = model.data(index, models.ModelRoles.PolicyObjRole)
            if type_ not in self.attr:
                return False

        return True


if __name__ == '__main__':
    import sys
    import warnings

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    a = setools.InfoFlowAnalysis(setools.SELinuxPolicy(), setools.PermissionMap())
    app = QtWidgets.QApplication(sys.argv)
    widget = ExcludeTypes(a)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    widget.resize(620, 340)
    widget.show()
    sys.exit(app.exec())
