# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from . import criteria, models, tab

__all__ = ("NetifconQueryTab",)


class NetifconQueryTab(tab.TableResultTabWidget):

    """A netifcon query."""

    section = tab.AnalysisSection.Labeling
    tab_title = "Network Interface Contexts"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(setools.NetifconQuery(policy), enable_criteria=True, parent=parent)

        self.setWhatsThis("<b>Search netifcon statements in a SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        name = criteria.NameWidget("Device Name", self.query, "name", [],
                                   enable_regex=True, parent=self.criteria_frame)
        name.setToolTip("The name of the network interface to search for.")
        name.setWhatsThis("<p>This is the name of the network interface to search for.</p>")

        dev_context = criteria.ContextMatch("Device Context Matching",
                                            self.query,
                                            parent=self.criteria_frame)
        dev_context.setToolTip("The context to use for netifcon device matching.")
        dev_context.setWhatsThis("""<p>This is the context used for netifcon device matching.""")

        # Add widgets to layout
        self.criteria_frame_layout.addWidget(name, 0, 0, 1, 2)
        self.criteria_frame_layout.addWidget(dev_context, 1, 0, 1, 4)
        self.criteria_frame_layout.addWidget(self.buttonBox, 2, 0, 1, 4)

        # Save widget references
        self.criteria = (name, dev_context)

        # Set result table's model
        self.table_results_model = models.NetifconTable(self.table_results)


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
    widget = NetifconQueryTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(1280, 1024)
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
