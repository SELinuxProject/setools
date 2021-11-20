# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from PyQt5.QtGui import QCursor
from PyQt5.QtWidgets import QAction, QListView, QMenu


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
