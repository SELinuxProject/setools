# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from . import criteria, models, tab

__all__ = ("BoundsQueryTab",)


class BoundsQueryTab(tab.TableResultTabWidget):

    """A bounds query."""

    section = tab.AnalysisSection.Other
    tab_title = "Bounds"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(setools.BoundsQuery(policy), enable_criteria=True,
                         enable_browser=False, parent=parent)

        self.setWhatsThis("<b>Search bounds rules in an SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        rt = criteria.BoundsRuleType("Rule Type", self.query, "ruletype",
                                     parent=self.criteria_frame)
        rt.setToolTip("Search for bounds rules by rule type.")
        rt.setWhatsThis("<p>Search for bounds rules by rule type.</p>")

        parent_t = criteria.TypeName("Parent (Bounding) Type", self.query, "parent",
                                     enable_indirect=False,
                                     enable_regex=True,
                                     parent=self.criteria_frame)
        parent_t.setToolTip("Search bounds rules by its parent/bounding type.")
        parent_t.setWhatsThis("<p>Search bounds rules by its parent/bounding type.</p>")

        child_t = criteria.TypeName("Child (Bounded) Type", self.query, "child",
                                    enable_indirect=False,
                                    enable_regex=True,
                                    parent=self.criteria_frame)
        child_t.setToolTip("Search bounds rules by its child/bounded type.")
        child_t.setWhatsThis("<p>Search bounds rules by its child/bounded type.</p>")

        # Add widgets to layout
        self.criteria_frame_layout.addWidget(rt, 0, 0, 1, 1)
        self.criteria_frame_layout.addWidget(parent_t, 1, 0, 1, 1)
        self.criteria_frame_layout.addWidget(child_t, 1, 1, 1, 1)
        self.criteria_frame_layout.addWidget(self.buttonBox, 2, 0, 1, 2)

        # Save widget references
        self.criteria = (rt, parent_t, child_t)

        # Set result table's model
        self.table_results_model = models.BoundsTable(self.table_results)


if __name__ == '__main__':
    import sys
    import warnings
    import pprint
    import logging

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    widget = BoundsQueryTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(1280, 1024)
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
