# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from . import criteria, models, tab

__all__ = ("IbendportconQueryTab",)


class IbendportconQueryTab(tab.TableResultTabWidget[setools.IbendportconQuery,
                                                    setools.Ibendportcon]):

    """A ibendportcon query."""

    section = tab.AnalysisSection.Labeling
    tab_title = "Infiniband Endport Contexts"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(setools.IbendportconQuery(policy), enable_criteria=True, parent=parent)

        self.setWhatsThis("<b>Search ibendportcon statements in a SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        name = criteria.NameWidget("Device Name", self.query, "name", [],
                                   enable_regex=True, parent=self.criteria_frame)
        name.setToolTip("The name of the network interface to search for.")
        name.setWhatsThis("<p>This is the name of the network interface to search for.</p>")

        port = criteria.IB_EndPortName("Endport Number", self.query, "port",
                                       parent=self.criteria_frame)
        port.setToolTip("The name of the endport to search for.")
        port.setWhatsThis("<p>This is the endport of the infiniband device to search for.</p>")

        context = criteria.ContextMatch("Context Matching", self.query,
                                        parent=self.criteria_frame)
        context.setToolTip("The context to use for ibendportcon matching.")
        context.setWhatsThis("This is the context used for ibendportcon matching.")

        # Add widgets to layout
        self.criteria_frame_layout.addWidget(name, 0, 0, 1, 2)
        self.criteria_frame_layout.addWidget(port, 0, 2, 1, 2)
        self.criteria_frame_layout.addWidget(context, 1, 0, 1, 4)
        self.criteria_frame_layout.addWidget(self.buttonBox, 2, 0, 1, 4)

        # Save widget references
        self.criteria = (name, port, context)

        # Set result table's model
        self.table_results_model = models.IbendportconTable(self.table_results)


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
    widget = IbendportconQueryTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(1280, 1024)
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
