# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from . import criteria, models, tab

__all__ = ("TypeAttributeQueryTab",)


class TypeAttributeQueryTab(tab.TableResultTabWidget):

    """A type attribute query."""

    section = tab.AnalysisSection.Components
    tab_title = "Type Attributes"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(setools.TypeAttributeQuery(policy), enable_criteria=True,
                         enable_browser=True, parent=parent)

        self.setWhatsThis("<b>Search type attributes in an SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        name = criteria.TypeAttributeName("Name", self.query, "name", enable_regex=True,
                                          parent=self.criteria_frame)
        name.setToolTip("Search for type attributes by name.")
        name.setWhatsThis("<p>Search for type attributes by name.</p>")

        types = criteria.TypeList("Types", self.query, "types", enable_equal=True)
        types.setToolTip("Search for type attributes by types.")
        types.setWhatsThis("<p>Search for type attributes by types.</p>")

        # Add widgets to layout
        self.criteria_frame_layout.addWidget(name, 0, 0, 1, 1)
        self.criteria_frame_layout.addWidget(types, 0, 1, 1, 1)
        self.criteria_frame_layout.addWidget(self.buttonBox, 1, 0, 1, 2)

        # Save widget references
        self.criteria = (name, types)

        # Set result table's model
        self.table_results_model = models.TypeAttributeTable(self.table_results)

        #
        # Set up browser
        #
        self.browser.setModel(models.TypeAttributeTable(
            self.browser, data=sorted(self.query.policy.typeattributes())))


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
    widget = TypeAttributeQueryTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(1280, 1024)
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
