# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from . import criteria, models, tab

__all__ = ("NodeconQueryTab",)


class NodeconQueryTab(tab.TableResultTabWidget[setools.NodeconQuery, setools.Nodecon]):

    """A nodecon query."""

    section = tab.AnalysisSection.Labeling
    tab_title = "Network Node Contexts"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(setools.NodeconQuery(policy), enable_criteria=True, parent=parent)

        self.setWhatsThis("<b>Search nodecon statements in a SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        name = criteria.IP_NetworkName("Netwok", self.query, "network",
                                       enable_range_opts=True,
                                       parent=self.criteria_frame)
        name.setToolTip("The network to search for.")
        name.setWhatsThis("<p>This is the network to search for.</p>")

        ip_version = criteria.ComboEnumWidget("IP Version", self.query, "ip_version",
                                              setools.NodeconIPVersion,
                                              parent=self.criteria_frame)
        ip_version.setToolTip("The IP version to search for.")
        ip_version.setWhatsThis("<p>This is the IP version to search for.</p>")

        context = criteria.ContextMatch("Context Matching", self.query,
                                        parent=self.criteria_frame)
        context.setToolTip("The context to use for nodecon matching.")
        context.setWhatsThis("This is the context used for nodecon matching.")

        # Add widgets to layout
        self.criteria_frame_layout.addWidget(name, 0, 0, 1, 2)
        self.criteria_frame_layout.addWidget(ip_version, 0, 2, 1, 2)
        self.criteria_frame_layout.addWidget(context, 1, 0, 1, 4)
        self.criteria_frame_layout.addWidget(self.buttonBox, 2, 0, 1, 4)

        # Save widget references
        self.criteria = (name, ip_version, context)

        # Set result table's model
        self.table_results_model = models.NodeconTable(self.table_results)


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
    widget = NodeconQueryTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(1280, 1024)
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
