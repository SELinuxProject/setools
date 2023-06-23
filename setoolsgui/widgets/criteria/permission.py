# SPDX-License-Identifier: LGPL-2.1-only

import logging
from contextlib import suppress
from typing import TYPE_CHECKING

from PyQt5 import QtCore, QtGui, QtWidgets
from setools.exception import NoCommon

from .list import ListCriteriaWidget
from ..models.list import SEToolsListModel

if TYPE_CHECKING:
    from typing import Dict, List, Optional
    from setools import ObjClass


class PermissionCriteriaWidget(ListCriteriaWidget):

    """
    A widget providing a QListView widget for selecting permissions.

    Optionally the list can be filtered down by providing a list of
    classes using the set_classes() method.
    """

    def __init__(self, title: str, query, attrname: str, enable_equal: bool = True,
                 enable_subset: bool = False, parent: "Optional[QtWidgets.QWidget]" = None) -> None:

        self.perm_model: SEToolsListModel[str] = SEToolsListModel()

        super().__init__(title, query, attrname, self.perm_model, enable_equal=enable_equal,
                         enable_subset=enable_subset, parent=parent)

        self.set_classes()

        self.criteria_any.setToolTip("Any selected permission will match.")
        self.criteria_any.setWhatsThis("<b>Any selected permission will match.</b>")

        if enable_equal:
            self.criteria_equal.setToolTip("The selected permissions must exactly match.")
            self.criteria_equal.setWhatsThis("<b>The selected permissions must exactly match.</b>")

        if enable_subset:
            self.criteria_subset.setToolTip("The selected permissions must be a subset to match.")
            self.criteria_subset.setWhatsThis(
                "<b>The selected permissions must be a subset to match.</b>")

    def set_classes(self, classes: "Optional[List[ObjClass]]" = None) -> None:
        """
        Set classes.  The widget will show the intersection of all selected
        classes.
        """
        permlist = set()
        if classes is None:
            classes = []

        # start will all permissions.
        for cls in self.query.policy.classes():
            permlist.update(cls.perms)

            with suppress(NoCommon):
                permlist.update(cls.common.perms)

        # create intersection
        for cls in classes:
            cls_perms = set(cls.perms)

            with suppress(NoCommon):
                cls_perms.update(cls.common.perms)

            permlist.intersection_update(cls_perms)

        self.perm_model.item_list = sorted(permlist)
        # Changing the classes clears the perm selection.
        # Update query accordingly.
        setattr(self.query, self.criteria.objectName(), None)

    #
    # Workspace methods
    #

    def save(self, settings: "Dict") -> None:
        super().save(settings)
        with suppress(AttributeError):
            settings[self.criteria_equal.objectName()] = self.criteria_equal.isChecked()

    def load(self, settings: "Dict") -> None:
        with suppress(AttributeError, KeyError):
            self.criteria_equal.setChecked(settings[self.criteria_equal.objectName()])
        super().load(settings)
        # Changing the classes clears the perm selection.
        # Update query accordingly.
        setattr(self.query, self.criteria.objectName(), None)


if __name__ == '__main__':
    import sys
    import warnings
    import setools
    import pprint

    from .objclass import ObjClassCriteriaWidget

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.TERuleQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    window = QtWidgets.QWidget()
    layout = QtWidgets.QHBoxLayout(window)
    widget1 = ObjClassCriteriaWidget("Test Classes", q, "tclass", parent=window)
    widget2 = PermissionCriteriaWidget("Test Permissions", q, "perms", parent=window,
                                       enable_equal=True, enable_subset=True)
    widget1.selectionChanged.connect(widget2.set_classes)
    layout.addWidget(widget1)
    layout.addWidget(widget2)
    window.setToolTip("test tooltip")
    window.setWhatsThis("test whats this")
    mw.setCentralWidget(window)
    mw.resize(window.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)
    mw.show()
    rc = app.exec_()
    print("Classes:")
    pprint.pprint(q.tclass)
    sys.exit(rc)
