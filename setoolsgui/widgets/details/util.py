# SPDX-License-Identifier: LGPL-2.1-only

from typing import Optional

from PyQt5 import QtCore, QtWidgets


def display_object_details(title: str, html_text: str,
                           parent: Optional[QtWidgets.QWidget] = None) -> None:

    """Display a non-modal dialog box with information in HTML."""

    if parent is None:
        # details requests from models can't provide a parent widget, afaict
        # suppress mypy error: "QCoreApplication" has no attribute "focusWidget"
        parent = QtWidgets.QApplication.instance().focusWidget()  # type: ignore

    popup = QtWidgets.QDialog(parent=parent)
    popup.setWindowTitle(title)
    popup.setObjectName("details_popup")
    popup.setModal(False)

    layout = QtWidgets.QVBoxLayout(popup)

    contents = QtWidgets.QTextBrowser(popup)
    contents.setObjectName("details_contents")
    contents.setHtml(html_text)
    contents.setReadOnly(True)
    layout.addWidget(contents)

    buttonBox = QtWidgets.QDialogButtonBox(popup)
    buttonBox.setOrientation(QtCore.Qt.Orientation.Horizontal)
    buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.StandardButton.Close)
    buttonBox.clicked.connect(popup.close)  # type: ignore
    layout.addWidget(buttonBox)

    QtCore.QMetaObject.connectSlotsByName(popup)
    popup.show()