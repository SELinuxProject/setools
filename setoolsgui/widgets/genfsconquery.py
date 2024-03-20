# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from . import criteria, models, tab

__all__ = ("GenfsconQueryTab",)


class GenfsconQueryTab(tab.TableResultTabWidget[setools.GenfsconQuery, setools.Genfscon]):

    """An genfscon query."""

    section = tab.AnalysisSection.Labeling
    tab_title = "Genfscons"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(setools.GenfsconQuery(policy), enable_criteria=True, parent=parent)

        self.setWhatsThis("<b>Search genfscon statements in a SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        fs = criteria.NameWidget("Filesystem Type", self.query, "fs", [],
                                 enable_regex=True, parent=self.criteria_frame)
        fs.setToolTip("The name of the filesystem to search for.")
        fs.setWhatsThis("<p>This is the filesystem name of the genfscon to search for.</p>")

        path = criteria.NameWidget("Path", self.query, "path", [],
                                   enable_regex=True, parent=self.criteria_frame)
        path.setToolTip("The path to search for.")
        path.setWhatsThis("<p>This is the path of the genfscon to search for.</p>")

        context = criteria.ContextMatch("Context Matching",
                                        self.query,
                                        parent=self.criteria_frame)
        context.setToolTip("The context to use for genfscon matching.")
        context.setWhatsThis("<p>This is the context used for genfscon matching.</p>")

        # Add widgets to layout
        self.criteria_frame_layout.addWidget(fs, 0, 0, 1, 2)
        self.criteria_frame_layout.addWidget(path, 0, 2, 1, 2)
        self.criteria_frame_layout.addWidget(context, 1, 0, 1, 4)
        self.criteria_frame_layout.addWidget(self.buttonBox, 2, 0, 1, 4)

        # Save widget references
        self.criteria = (fs, path, context)

        # Set result table's model
        self.table_results_model = models.GenfsconTable(self.table_results)


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
    widget = GenfsconQueryTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(1280, 1024)
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
