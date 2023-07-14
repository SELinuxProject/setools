# SPDX-License-Identifier: LGPL-2.1-only

import logging
from typing import TYPE_CHECKING

from PyQt5 import QtCore, QtGui, QtWidgets
from setools import RBACRuletype

from .checkboxset import CheckboxSetCriteriaWidget

if TYPE_CHECKING:
    from typing import Optional

# Checked by default:
DEFAULT_CHECKED = ("allow",)


class RBACRuleTypeCriteriaWidget(CheckboxSetCriteriaWidget):

    """
    Criteria selection widget presenting type enforcement rule types as a series
    of checkboxes.  The selected checkboxes are then merged into a single Python
    list consisting of object names (TE ruletypes) and stored in the query's
    specified attribute.
    """

    def __init__(self, title: str, query, attrname: str = "ruletype",
                 parent: "Optional[QtWidgets.QWidget]" = None) -> None:

        super().__init__(title, query, attrname, (rt.name for rt in RBACRuletype),
                         num_cols=1, parent=parent)

        for name, widget in self.criteria.items():
            widget.setChecked(name in DEFAULT_CHECKED)
            widget.setToolTip(f"Match {name} rules.")
            widget.setWhatsThis(
                f"""
                <p><b>Match {name} rules</b></p>

                <p>If a rule has the {name} rule type, it will be returned.</p>
                """)


if __name__ == '__main__':
    import sys
    import warnings
    import setools
    import pprint

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.RBACRuleQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    widget = RBACRuleTypeCriteriaWidget("Test RBAC ruletypes", q, parent=mw)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)
    mw.show()
    rc = app.exec_()
    print("Ruletypes set in query:")
    pprint.pprint(q.ruletype)
    sys.exit(rc)
