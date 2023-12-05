# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from . import criteria, models, tab

__all__ = ("FSUseQueryTab",)


class FSUseQueryTab(tab.TableResultTabWidget):

    """An fs_use_* query."""

    section = tab.AnalysisSection.Labeling
    tab_title = "Fs_use_*"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(setools.FSUseQuery(policy), enable_criteria=True, parent=parent)

        self.setWhatsThis("<b>Search fs_use_* statements in a SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        ruletype = criteria.FSUseRuletype("Rule Type", self.query, "ruletype",
                                          parent=self.criteria_frame)
        ruletype.setToolTip("The type of fs_use rule to search for.")
        ruletype.setWhatsThis("<p>This is the rule type of the fs_use_* to search for.</p>")

        fs = criteria.NameWidget("Filesystem Type", self.query, "fs", [],
                                 enable_regex=True, parent=self.criteria_frame)
        fs.setToolTip("The name of the filesystem to search for.")
        fs.setWhatsThis("<p>This is the filesystem name of the fs_use_* to search for.</p>")
        fs.criteria.setPlaceholderText("e.g. ext4")

        context = criteria.ContextMatch("Context Matching",
                                        self.query,
                                        parent=self.criteria_frame)
        context.setToolTip("The context to use for fs_use_* matching.")
        context.setWhatsThis("<p>This is the context used for fs_use_* matching.</p>")

        # Add widgets to layout
        self.criteria_frame_layout.addWidget(ruletype, 0, 0, 1, 2)
        self.criteria_frame_layout.addWidget(fs, 0, 2, 1, 2)
        self.criteria_frame_layout.addWidget(context, 1, 0, 1, 4)
        self.criteria_frame_layout.addWidget(self.buttonBox, 2, 0, 1, 4)

        # Save widget references
        self.criteria = (ruletype, fs, context)

        # Set result table's model
        self.table_results_model = models.FSUseTable(self.table_results)


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
    widget = FSUseQueryTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(1280, 1024)
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
