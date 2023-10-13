# SPDX-License-Identifier: LGPL-2.1-only

from PyQt5 import QtWidgets
import setools

from .name import NameCriteriaWidget

__all__ = ("MLSLevelRangeWidget",)


class MLSLevelRangeWidget(NameCriteriaWidget):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of MLS levels and ranges.
    """

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str,
                 required: bool = False, parent: QtWidgets.QWidget | None = None):

        # Not much we can do here. Leave all validation to the query.
        super().__init__(title, query, attrname, [], "", enable_regex=False,
                         required=required, parent=parent)


if __name__ == '__main__':
    import sys
    import logging
    import warnings

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.MLSRuleQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    widget = MLSLevelRangeWidget("Test Range", q, "default", mw)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    sys.exit(app.exec_())
