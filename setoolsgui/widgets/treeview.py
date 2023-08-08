# Copyright 2016, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5 import QtCore, QtGui, QtWidgets


class SEToolsTreeWidget(QtWidgets.QTreeWidget):

    """QTreeWidget class extended for SETools use."""

    def contextMenuEvent(self, event: QtGui.QContextMenuEvent) -> None:
        copy_tree_action = QtWidgets.QAction("Copy Tree...", self)
        copy_tree_action.triggered.connect(self.copy)

        menu = QtWidgets.QMenu(self)
        menu.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose)
        menu.addAction(copy_tree_action)
        menu.exec(event.globalPos())

    def copy(self) -> None:
        """Copy the tree to the clipboard."""
        items = []
        it = QtWidgets.QTreeWidgetItemIterator(self)
        prev_depth = 0
        while it.value():
            depth = 0
            item = it.value()
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

        QtWidgets.QApplication.clipboard().setText("".join(items))

    def cut(self) -> None:
        self.copy()
