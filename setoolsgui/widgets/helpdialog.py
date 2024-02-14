# SPDX-License-Identifier: LGPL-2.1-only

from importlib import resources as pkg_resources

from PyQt6 import QtCore, QtWidgets

__all__ = ("HtmlHelpDialog",)


class HtmlHelpDialog(QtWidgets.QDialog):

    """Simple dialog to display HTML help files."""

    def __init__(self, title: str, html: str, /,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(parent)
        self.setWindowTitle(title)

        self.verticalLayout = QtWidgets.QVBoxLayout(self)

        self.textBrowser = QtWidgets.QTextBrowser(self)
        self.textBrowser.setOpenExternalLinks(True)
        self.textBrowser.setHtml(html)
        self.textBrowser.setReadOnly(True)
        self.verticalLayout.addWidget(self.textBrowser)

        self.buttonBox = QtWidgets.QDialogButtonBox(self)
        self.buttonBox.setOrientation(QtCore.Qt.Orientation.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.StandardButton.Ok)
        self.buttonBox.accepted.connect(self.accept)
        self.verticalLayout.addWidget(self.buttonBox)

    @classmethod
    def from_file(cls, title: str, filename: str, /,
                  parent: QtWidgets.QWidget | None = None) -> "HtmlHelpDialog":

        """Load HTML from a file and return a new HtmlHelpDialog instance."""

        with open(filename, "r", encoding="utf-8") as fd:
            html = fd.read()

        return cls(title, html, parent)

    @classmethod
    def from_package_file(cls, title: str, filename: str, /,
                          parent: QtWidgets.QWidget | None = None) -> "HtmlHelpDialog":

        """Load HTML from a file in the package and return a new HtmlHelpDialog instance."""

        package_location = pkg_resources.files("setoolsgui")
        with pkg_resources.as_file(package_location / filename) as path:
            with open(path, "r", encoding="utf-8") as fd:
                return cls(title, fd.read(), parent)


if __name__ == '__main__':
    import sys
    import logging
    import warnings

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    app = QtWidgets.QApplication(sys.argv)
    widget = HtmlHelpDialog.from_package_file("Test help window", "apol.html")
    widget.resize(1024, 768)
    widget.show()
    rc = app.exec()
    sys.exit(rc)
