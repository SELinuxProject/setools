# SPDX-License-Identifier: LGPL-2.1-only
import typing

from PyQt6 import QtWidgets
import setools

from .checkboxset import CheckboxSetWidget

# Checked by default:
DEFAULT_CHECKED: typing.Final[tuple[str, ...]] = ("default_user", "default_role",
                                                  "default_type", "default_range")

__all__ = ('DefaultRuleType',)


class DefaultRuleType(CheckboxSetWidget):

    """
    Criteria selection widget presenting default_* rule types as a series
    of checkboxes.  The selected checkboxes are then merged into a single Python
    list consisting of object names (default ruletypes) and stored in the query's
    specified attribute.
    """

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str = "ruletype",
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(title, query, attrname, (rt.name for rt in setools.DefaultRuletype),
                         num_cols=2, parent=parent)

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
    import pprint
    import logging

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.DefaultQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    w = DefaultRuleType("Test default ruletypes", q, parent=mw)
    w.setToolTip("test tooltip")
    w.setWhatsThis("test what's this")
    mw.setCentralWidget(w)
    mw.resize(w.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.show()
    rc = app.exec()
    print("Ruletypes set in query:")
    pprint.pprint(q.ruletype)
    sys.exit(rc)
