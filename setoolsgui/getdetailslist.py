# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt6.QtGui import QCursor, QAction
from PyQt6.QtWidgets import QListView, QMenu


class GetDetailsListView(QListView):

    """A QListView widget with more details context menu."""

    def __init__(self, parent):
        super(GetDetailsListView, self).__init__(parent)

        # set up right-click context menu
        self.get_detail = QAction("More details...", self)
        self.menu = QMenu(self)
        self.menu.addAction(self.get_detail)

    def contextMenuEvent(self, event):
        self.menu.popup(QCursor.pos())
