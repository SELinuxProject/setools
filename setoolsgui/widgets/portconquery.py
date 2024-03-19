# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from . import criteria, models, tab

__all__ = ("PortconQueryTab",)


class PortconQueryTab(tab.TableResultTabWidget[setools.PortconQuery, setools.Portcon]):

    """A portcon query."""

    section = tab.AnalysisSection.Labeling
    tab_title = "Network Port Contexts"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(setools.PortconQuery(policy), enable_criteria=True, parent=parent)

        self.setWhatsThis("<b>Search portcon statements in a SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        ports = criteria.IP_PortName("Port/Port Range",
                                     self.query,
                                     "ports",
                                     convert_range=True,
                                     enable_range_opts=True,
                                     parent=self.criteria_frame)
        ports.setToolTip("The port number or port number range for portcon matching.")
        ports.setWhatsThis(
            """
            <p>This is the the port number or port number range used for portcon matching.</p>
            """)
        ports.criteria_opts[""].setWhatsThis(
            """
            <p>The port number/range must be equal to the portcon's port number/range for the
            portcon to match.</p>
            """)
        ports.criteria_opts["ports_overlap"].setWhatsThis(
            """
            <p>The port number/range must overlap the portcon's port number/range for the
            portcon to match.</p>
            """)
        ports.criteria_opts["ports_subset"].setWhatsThis(
            """
            <p>The port number/range must be a subset of the portcon's port number/range for the
            portcon to match.</p>
            """)
        ports.criteria_opts["ports_superset"].setWhatsThis(
            """
            <p>The port number/range must be a superset of the portcon's port number/range for the
            portcon to match.</p>
            """)

        proto = criteria.ComboEnumWidget[setools.PortconProtocol]("Protocol",
                                                                  self.query,
                                                                  "protocol",
                                                                  setools.PortconProtocol,
                                                                  parent=self.criteria_frame)
        proto.setToolTip("The protocol to use for portcon matching.")
        proto.setWhatsThis(
            """
            <p>This is the protocol used for portcon matching.  The blank option will match any
            protocol.</p>
            """)

        context = criteria.ContextMatch("Context Matching",
                                        self.query,
                                        parent=self.criteria_frame)
        context.setToolTip("The context to use for portcon matching.")
        context.setWhatsThis("""<p>This is the context used for portcon matching.""")

        # Add widgets to layout
        self.criteria_frame_layout.addWidget(ports, 0, 0, 1, 2)
        self.criteria_frame_layout.addWidget(proto, 0, 2, 1, 2)
        self.criteria_frame_layout.addWidget(context, 1, 0, 1, 4)
        self.criteria_frame_layout.addWidget(self.buttonBox, 2, 0, 1, 4)

        # Save widget references
        self.criteria = (ports, proto, context)

        # Set result table's model
        self.table_results_model = models.PortconTable(self.table_results)


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
    widget = PortconQueryTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(1280, 1024)
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
