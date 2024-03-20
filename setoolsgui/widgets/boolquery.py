# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from . import criteria, models, tab

__all__ = ("BoolQueryTab",)


class BoolQueryTab(tab.TableResultTabWidget[setools.BoolQuery, setools.Boolean]):

    """A boolean query."""

    section = tab.AnalysisSection.Components
    tab_title = "Booleans"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(setools.BoolQuery(policy), enable_criteria=True,
                         enable_browser=True, parent=parent)

        self.setWhatsThis("<b>Search Booleans in a SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        name = criteria.BooleanName("Name", self.query, "name",
                                    enable_regex=True,
                                    parent=self.criteria_frame)
        name.setToolTip("Search for Booleans by name.")
        name.setWhatsThis("<p>Search for Booleans by name.</p>")

        state = criteria.BooleanState("Default State", self.query, "default",
                                      enable_any=True,
                                      parent=self.criteria_frame)
        state.setToolTip("Search for Booleans by default state.")
        state.setWhatsThis("<p>Search for Booleans by default state.</p>")

        # Add widgets to layout
        self.criteria_frame_layout.addWidget(name, 0, 0, 1, 1)
        self.criteria_frame_layout.addWidget(state, 0, 1, 1, 1)
        self.criteria_frame_layout.addWidget(self.buttonBox, 1, 0, 1, 2)

        # Save widget references
        self.criteria = (name, state)

        # Set result table's model
        self.table_results_model = models.BooleanTable(self.table_results)

        #
        # Set up browser
        #
        self.browser.setModel(models.BooleanTable(self.browser,
                                                  data=sorted(self.query.policy.bools())))


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
    widget = BoolQueryTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(1280, 1024)
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
