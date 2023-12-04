# SPDX-License-Identifier: LGPL-2.1-only

import typing

from PyQt6 import QtWidgets
import setools

from .criteria import OptionsPlacement
from .ranged import RangedWidget

LEVEL_VALIDATION: typing.Final[str] = r"[A-Za-z0-9.,_:]+"
RANGE_VALIDATION: typing.Final[str] = r"[A-Za-z0-9.,_:]+ ?(- ?[A-Za-z0-9.,_:]+)?"

__all__ = ("MLSLevelName", "MLSRangeName")


class MLSLevelName(RangedWidget):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of MLS levels.

    While MLS levels are a single entity, they use the ranged criteria
    superclass because they can have ranges of categories.
    """

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 required: bool = False, enable_range_opts: bool = False,
                 options_placement: OptionsPlacement = OptionsPlacement.RIGHT,
                 parent: QtWidgets.QWidget | None = None):

        super().__init__(title, query, attrname, validation=LEVEL_VALIDATION,
                         enable_range_opts=enable_range_opts, required=required,
                         options_placement=options_placement, parent=parent)


class MLSRangeName(RangedWidget):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of MLS ranges.
    """

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 required: bool = False,
                 enable_range_opts: bool = False,
                 options_placement: OptionsPlacement = OptionsPlacement.RIGHT,
                 parent: QtWidgets.QWidget | None = None):

        super().__init__(title, query, attrname, validation=RANGE_VALIDATION,
                         enable_range_opts=enable_range_opts, required=required,
                         options_placement=options_placement, parent=parent)


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
    widget = MLSRangeName("Test Range", q, "default", enable_range_opts=True, parent=mw)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    sys.exit(app.exec())
