# Copyright 2016, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt6 import QtCore, QtGui, QtWidgets

__all__ = ("SEToolsTreeWidget",)


class SEToolsTreeWidget(QtWidgets.QTreeWidget):

    """QTreeWidget class extended for SETools use."""

    def contextMenuEvent(self, event: QtGui.QContextMenuEvent) -> None:  # type: ignore[override]
        """Handle the context menu event."""
        copy_tree_action = QtGui.QAction("Copy Tree...", self)
        copy_tree_action.triggered.connect(self.copy)

        menu = QtWidgets.QMenu(self)
        menu.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose)
        menu.addAction(copy_tree_action)
        menu.exec(event.globalPos())
        return

    def copy(self) -> None:
        """Copy the tree to the clipboard."""
        items = list[str]()
        it = QtWidgets.QTreeWidgetItemIterator(self)
        prev_depth = 0
        while it.value():
            depth = 0
            item = it.value()
            assert item, "No item available, this is an SETools bug"  # type narrowing
            parent = item.parent()
            while parent:
                depth += 1
                parent = parent.parent()

            if depth < prev_depth:
                items.extend(["  |" * depth, "\n"])

            if depth:
                items.extend(["  |" * depth, "--", item.text(0), "\n"])
            else:
                items.extend([item.text(0), "\n"])

            prev_depth = depth
            it += 1

        cb = QtWidgets.QApplication.clipboard()
        assert cb, "No clipboard available, this is an SETools bug"  # type narrowing
        cb.setText("".join(items))

    def cut(self) -> None:
        """Copy the tree to the clipboard. Cut from the widget is not available."""
        self.copy()
