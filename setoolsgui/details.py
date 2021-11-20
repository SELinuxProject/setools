# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
import logging

from PyQt5.QtGui import QFont, QTextCursor
from PyQt5.QtWidgets import QDialog

from .widget import SEToolsWidget


class DetailsPopup(SEToolsWidget, QDialog):

    """A generic non-modal popup with a text field to write detailed info."""
    # TODO: make the font changes relative
    # instead of setting absolute values

    def __init__(self, parent, title=None):
        super(DetailsPopup, self).__init__(parent)
        self.log = logging.getLogger(__name__)
        self.setupUi(title)

    def setupUi(self, title):
        self.load_ui("detail_popup.ui")

        if title:
            self.title = title

    @property
    def title(self):
        self.windowTitle(self)

    @title.setter
    def title(self, text):
        self.setWindowTitle(text)

    def append(self, text):
        self.contents.setFontWeight(QFont.Normal)
        self.contents.setFontPointSize(9)
        self.contents.append(text)

    def append_header(self, text):
        self.contents.setFontWeight(QFont.Black)
        self.contents.setFontPointSize(11)
        self.contents.append(text)

    def show(self):
        self.contents.moveCursor(QTextCursor.Start)
        super(DetailsPopup, self).show()
