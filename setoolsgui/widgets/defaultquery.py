# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from . import criteria, models, tab

__all__ = ("DefaultQueryTab",)


class DefaultQueryTab(tab.TableResultTabWidget[setools.DefaultQuery, setools.Default]):

    """A default_* query."""

    section = tab.AnalysisSection.Other
    tab_title = "Default_*"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(setools.DefaultQuery(policy), enable_criteria=True,
                         enable_browser=False, parent=parent)

        self.setWhatsThis("<b>Search default_* rules in an SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        rt = criteria.DefaultRuleType("Rule Type", self.query, "ruletype",
                                      parent=self.criteria_frame)
        rt.setToolTip("Search for default_* rules by rule type.")
        rt.setWhatsThis("<p>Search for default_* rules by rule type.</p>")

        tclass = criteria.ObjClassList("Object Class", self.query, "tclass",
                                       enable_equal=False, parent=self.criteria_frame)
        tclass.setToolTip("Search default_* rules by its object class.")
        tclass.setWhatsThis("<p>Search default_* rules by its object class.</p>")

        defl = criteria.DefaultValues("Default Value", self.query, "default", "default_range",
                                      parent=self.criteria_frame)
        defl.setToolTip("Search for default_* rules by value.")
        defl.setWhatsThis("<p>Search for default_* rules by value.</p>")

        # Add widgets to layout
        self.criteria_frame_layout.addWidget(rt, 0, 0, 1, 1)
        self.criteria_frame_layout.addWidget(tclass, 0, 1, 1, 1)
        self.criteria_frame_layout.addWidget(defl, 1, 0, 1, 1)
        self.criteria_frame_layout.addWidget(self.buttonBox, 2, 0, 1, 2)

        # Save widget references
        self.criteria = (rt, tclass, defl)

        # Set result table's model
        self.table_results_model = models.DefaultTable(self.table_results)


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
    widget = DefaultQueryTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(1280, 1024)
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
