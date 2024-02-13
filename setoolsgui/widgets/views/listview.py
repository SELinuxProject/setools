# SPDX-License-Identifier: LGPL-2.1-only

import collections

from PyQt6 import QtCore, QtGui, QtWidgets

from .. import models

__all__ = ("SEToolsListView",)


INVERT_SELECTION_FLAGS = QtCore.QItemSelectionModel.SelectionFlag.Toggle | \
                         QtCore.QItemSelectionModel.SelectionFlag.Columns


class SEToolsListView(QtWidgets.QListView):

    """A list view for SETools."""

    def invert_selection(self) -> None:
        """Invert the selection."""
        data_model = self.model()
        selection_model = self.selectionModel()
        selection_model.select(data_model.createIndex(0, 0), INVERT_SELECTION_FLAGS)

    def selection(self, role: int = QtCore.Qt.ItemDataRole.UserRole) -> collections.abc.Iterable:
        """
        Generator which returns the selection.

        By default this is the Qt.ItemDataRole.UserRole (returns SETools objects)
        """
        data_model = self.model()
        selection_model = self.selectionModel()
        for index in selection_model.selectedIndexes():
            yield data_model.data(index, role)

    def set_selection(self, selections: list[str]) -> None:
        """Set the selection."""
        data_model = self.model()
        selection_model = self.selectionModel()
        new_selection = QtCore.QItemSelection()
        for row in range(data_model.rowCount()):
            index = data_model.createIndex(row, 0)
            item = data_model.data(index, models.ModelRoles.DisplayRole)
            if item in selections:
                new_selection.select(index, index)

        selection_model.select(new_selection,
                               QtCore.QItemSelectionModel.SelectionFlag.ClearAndSelect)

    #
    # Overridden methods
    #
    def contextMenuEvent(self, event: QtGui.QContextMenuEvent) -> None:  # type: ignore[override]
        """Handle the context menu event."""
        menu = QtWidgets.QMenu(self)
        menu.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose)

        # Add any actions provided by the model.
        index = self.indexAt(event.pos())
        if index.isValid():
            for action in self.model().data(index, models.ModelRoles.ContextMenuRole):
                action.setParent(menu)
                menu.addAction(action)

            menu.addSeparator()

        menu.exec(event.globalPos())
        return

    #
    # Overridden methods for typing purposes
    #

    # @typing.override
    def model(self) -> QtCore.QAbstractItemModel:
        """Type-narrowed model() method.  See QListView.model() for more info."""
        model = super().model()
        assert model, "No model set, this is an SETools bug"
        return model

    # @typing.override
    def selectionModel(self) -> QtCore.QItemSelectionModel:
        """Type-narrowed selectionModel() method.  See QListView.selectionModel() for more info."""
        selection_model = super().selectionModel()
        assert selection_model, "No selection model set, this is an SETools bug"
        return selection_model

    # @typing.override
    def verticalScrollBar(self) -> QtWidgets.QScrollBar:
        """
        Type-narrowed verticalScrollBar() method.  See QListView.verticalScrollBar() for more info.
        """
        scrollbar = super().verticalScrollBar()
        assert scrollbar, "No vertical scrollbar set, this is an SETools bug"
        return scrollbar
