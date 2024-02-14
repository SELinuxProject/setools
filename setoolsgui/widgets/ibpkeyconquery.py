# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from . import criteria, models, tab

__all__ = ("IbpkeyconQueryTab",)


class IbpkeyconQueryTab(tab.TableResultTabWidget):

    """A ibpkeycon query."""

    section = tab.AnalysisSection.Labeling
    tab_title = "Infiniband Partition Key Contexts"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(setools.IbpkeyconQuery(policy), enable_criteria=True, parent=parent)

        self.setWhatsThis("<b>Search ibpkeycon statements in a SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        subnet = criteria.IB_PKeySubnetPrefixName("Subnet Prefix", self.query, "subnet_prefix",
                                                  enable_range_opts=False,
                                                  parent=self.criteria_frame)
        subnet.setWhatsThis("<p>This is the subnet prefix of the partition key.</p>")

        pkeys = criteria.IB_PKeyName("Partition Keys", self.query, "pkeys",
                                     parent=self.criteria_frame)
        pkeys.setWhatsThis("<p>This is the partition key number or range.</p>")

        context = criteria.ContextMatch("Context Matching", self.query,
                                        parent=self.criteria_frame)
        context.setToolTip("The context to use for ibpkeycon matching.")
        context.setWhatsThis("This is the context used for ibpkeycon matching.")

        # Add widgets to layout
        self.criteria_frame_layout.addWidget(subnet, 0, 0, 1, 2)
        self.criteria_frame_layout.addWidget(pkeys, 0, 2, 1, 2)
        self.criteria_frame_layout.addWidget(context, 1, 0, 1, 4)
        self.criteria_frame_layout.addWidget(self.buttonBox, 2, 0, 1, 4)

        # Save widget references
        self.criteria = (subnet, pkeys, context)

        # Set result table's model
        self.table_results_model = models.IbpkeyconTable(self.table_results)


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
    widget = IbpkeyconQueryTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(1280, 1024)
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
