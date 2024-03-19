# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from . import criteria, models, tab

__all__ = ("InitialSIDQueryTab",)


class InitialSIDQueryTab(tab.TableResultTabWidget[setools.InitialSIDQuery, setools.InitialSID]):

    """An initial context (SID) query."""

    section = tab.AnalysisSection.Labeling
    tab_title = "Initial Contexts"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(setools.InitialSIDQuery(policy), enable_criteria=True, parent=parent)

        self.setWhatsThis("<b>Search initial context statements in a SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        name = criteria.NameWidget("Name", self.query, "name", [],
                                   enable_regex=True, parent=self.criteria_frame)
        name.setToolTip("The name of the initial context to search for.")
        name.setWhatsThis("<p>This is the name of the initial context to search for.</p>")

        context = criteria.ContextMatch("Context Matching",
                                        self.query,
                                        parent=self.criteria_frame)
        context.setToolTip("The context to use for initial context matching.")
        context.setWhatsThis("<p>This is the context used for initial context matching.</p>")

        # Add widgets to layout
        self.criteria_frame_layout.addWidget(name, 0, 0, 1, 2)
        self.criteria_frame_layout.addWidget(context, 1, 0, 1, 4)
        self.criteria_frame_layout.addWidget(self.buttonBox, 2, 0, 1, 4)

        # Save widget references
        self.criteria = (name, context)

        # Set result table's model
        self.table_results_model = models.InitialSIDTable(self.table_results)


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
    widget = InitialSIDQueryTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(1280, 1024)
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
