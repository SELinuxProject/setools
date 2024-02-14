# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from .checkboxset import CheckboxSetWidget

# Checked by default:
DEFAULT_CHECKED = ("allow", "allowxperm")
# Not supported in binary policy:
NOT_IN_BINPOL = ("neverallow", "neverallowxperm")

__all__ = ('TERuleType',)


class TERuleType(CheckboxSetWidget):

    """
    Criteria selection widget presenting type enforcement rule types as a series
    of checkboxes.  The selected checkboxes are then merged into a single Python
    list consisting of object names (TE ruletypes) and stored in the query's
    specified attribute.
    """

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str = "ruletype",
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(title, query, attrname, (rt.name for rt in setools.TERuletype),
                         parent=parent)

        for name, widget in self.criteria.items():
            widget.setChecked(name in DEFAULT_CHECKED)

            if name in NOT_IN_BINPOL:
                widget.setEnabled(False)
                widget.setToolTip(f"{name} rules are not available in binary policies.")
                widget.setWhatsThis(
                    f"""
                    <p><b>Match {name} rules</b></p>

                    <p>If a rule has the {name} rule type, it will be returned.</p>

                    <p>This option is disabled because {name} rules are not available
                    in binary policies.</p>
                    """)
            else:
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
    import logging

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.TERuleQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    w = TERuleType("Test TE ruletypes", q, parent=mw)
    w.setToolTip("test tooltip")
    w.setWhatsThis("test whats this")
    mw.setCentralWidget(w)
    mw.resize(w.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.show()
    rc = app.exec()
    print("Ruletypes set in query:")
    pprint.pprint(q.ruletype)

    # basic test of save/load
    settings: dict = {}
    w.save(settings)
    print("Widget save:")
    pprint.pprint(settings)
    settings["type_member"] = True
    settings["neverallow"] = True
    w.load(settings)
    print("Final query settings:")
    pprint.pprint(q.ruletype)
    sys.exit(rc)
