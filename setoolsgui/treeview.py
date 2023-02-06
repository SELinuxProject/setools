# Copyright 2016, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5.QtCore import Qt, QModelIndex
from PyQt5.QtGui import QKeySequence, QCursor
from PyQt5.QtWidgets import QAction, QApplication, QFileDialog, QMenu, QTreeWidget, \
    QTreeWidgetItemIterator


class SEToolsTreeWidget(QTreeWidget):

    """QTreeWidget class extended for SETools use."""

    def __init__(self, parent):
        super(SEToolsTreeWidget, self).__init__(parent)

        # set up right-click context menu
        self.copy_tree_action = QAction("Copy Tree...", self)
        self.menu = QMenu(self)
        self.menu.addAction(self.copy_tree_action)

        # connect signals
        self.copy_tree_action.triggered.connect(self.copy)

    def contextMenuEvent(self, event):
        self.menu.popup(QCursor.pos())

    def copy(self):
        """Copy the tree to the clipboard."""

        items = []
        inval_index = QModelIndex()
        it = QTreeWidgetItemIterator(self)
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

        QApplication.clipboard().setText("".join(items))

    def cut(self):
        self.copy()
