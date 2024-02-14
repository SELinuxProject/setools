# SPDX-License-Identifier: LGPL-2.1-only
import typing

from PyQt6 import QtWidgets
import setools

from .. import models
from .criteria import OptionsPlacement
from .list import ListWidget
from .name import NameWidget

# Regex for exact matches to roles
VALIDATE_EXACT: typing.Final[str] = r"[A-Za-z0-9._-]*"

__all__ = ('ObjClassList', 'ObjClassName')


class ObjClassList(ListWidget):

    """A widget providing a QListView widget for selecting the object class."""

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str,
                 enable_equal: bool = False, enable_subset: bool = False,
                 parent: QtWidgets.QWidget | None = None) -> None:

        model = models.ObjClassTable(data=sorted(query.policy.classes()))

        super().__init__(title, query, attrname, model, enable_equal=enable_equal,
                         enable_subset=enable_subset, parent=parent)

        self.criteria_any.setToolTip("Any selected object class will match.")
        self.criteria_any.setWhatsThis("<b>Any selected object class will match.</b>")


class ObjClassName(NameWidget):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of object classes.
    """

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 parent: QtWidgets.QWidget | None = None,
                 options_placement: OptionsPlacement = OptionsPlacement.RIGHT,
                 required: bool = False, enable_regex: bool = True):

        # Create completion list
        completion = list[str](r.name for r in query.policy.classes())

        super().__init__(title, query, attrname, completion, VALIDATE_EXACT,
                         enable_regex=enable_regex, required=required, parent=parent,
                         options_placement=options_placement)


if __name__ == '__main__':
    import sys
    import warnings
    import pprint
    import logging

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.TERuleQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    widget = ObjClassList("Test Classes", q, "tclass", parent=mw)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.show()
    rc = app.exec()
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
