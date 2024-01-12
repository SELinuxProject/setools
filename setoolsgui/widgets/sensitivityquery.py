# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from . import criteria, models, tab

__all__ = ("SensitivityQueryTab",)


class SensitivityQueryTab(tab.TableResultTabWidget):

    """A sensitivity query."""

    section = tab.AnalysisSection.Components
    tab_title = "Multi-Level Security (MLS) Sensitivities"
    mlsonly = True

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(setools.SensitivityQuery(policy), enable_criteria=True,
                         enable_browser=True, parent=parent)

        self.setWhatsThis("<b>Search MLS sensitivities in an SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        name = criteria.SensitivityName("Name", self.query, "name",
                                        enable_regex=True,
                                        parent=self.criteria_frame)
        name.setToolTip("Search MLS sensitivities by name.")
        name.setWhatsThis("<p>Search MLS sensitivities by name.</p>")

        # Add widgets to layout
        self.criteria_frame_layout.addWidget(name, 0, 0, 1, 1)
        self.criteria_frame_layout.addWidget(self.buttonBox, 1, 0, 1, 2)

        # Save widget references
        self.criteria = (name,)

        # Set result table's model
        self.table_results_model = models.SensitivityTable(self.table_results)

        #
        # Set up browser
        #
        self.browser.setModel(models.SensitivityTable(
            self.browser, data=sorted(self.query.policy.sensitivities())))


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
    widget = SensitivityQueryTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(1280, 1024)
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
