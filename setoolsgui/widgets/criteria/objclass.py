# SPDX-License-Identifier: LGPL-2.1-only

import logging
from typing import TYPE_CHECKING

from PyQt5 import QtCore, QtGui, QtWidgets

from .list import ListCriteriaWidget
from ..models.list import SEToolsListModel

if TYPE_CHECKING:
    from typing import Optional
    from setools import ObjClass


class ObjClassCriteriaWidget(ListCriteriaWidget):

    """A widget providing a QListView widget for selecting the object class."""

    def __init__(self, title: str, query, attrname: str,
                 enable_equal: bool = False, enable_subset: bool = False,
                 parent: "Optional[QtWidgets.QWidget]" = None) -> None:

        model: SEToolsListModel["ObjClass"] = SEToolsListModel()
        model.item_list = sorted(query.policy.classes())

        super().__init__(title, query, attrname, model, enable_equal=enable_equal,
                         enable_subset=enable_subset, parent=parent)

        self.criteria_any.setToolTip("Any selected object class will match.")
        self.criteria_any.setWhatsThis("<b>Any selected object class will match.</b>")


if __name__ == '__main__':
    import sys
    import warnings
    import setools
    import pprint

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.TERuleQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    widget = ObjClassCriteriaWidget("Test Classes", q, "tclass", mw)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)
    mw.show()
    rc = app.exec_()
    print("Query settings:")
    pprint.pprint(q.tclass)

    # basic test of save/load
    settings: dict = {}
    widget.save(settings)
    print("Widget save:")
    pprint.pprint(settings)
    try:
        settings["tclass"].pop()
    finally:
        settings["tclass"].append("file")
    widget.load(settings)

    print("Final query settings:")
    pprint.pprint(q.tclass)

    sys.exit(rc)
