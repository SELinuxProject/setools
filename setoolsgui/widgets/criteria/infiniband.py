# SPDX-License-Identifier: LGPL-2.1-only

import typing

from PyQt6 import QtWidgets
import setools

from .name import NameCriteriaWidget

ENDPORT_VALIDATION: typing.Final[str] = r"[0-9]+"

__all__ = ("IB_EndPortName",)


class IB_EndPortName(NameCriteriaWidget):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of infiniband endports.
    """

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 required: bool = False,
                 parent: QtWidgets.QWidget | None = None):

        super().__init__(title, query, attrname, [], validation=ENDPORT_VALIDATION,
                         enable_regex=False, required=required, parent=parent)

        self.criteria.setPlaceholderText("e.g. 80")
        self.setToolTip("The endport of the infiniband port range.")


if __name__ == '__main__':
    import sys
    import logging
    import warnings

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.IbendportconQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    widget = IB_EndPortName("Test endport", q, "port", parent=mw)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    sys.exit(app.exec())
