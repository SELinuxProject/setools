# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from . import criteria, models, tab

__all__ = ("TypeQueryTab",)


class TypeQueryTab(tab.TableResultTabWidget[setools.TypeQuery, setools.Type]):

    """A type query."""

    section = tab.AnalysisSection.Components
    tab_title = "Types"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(setools.TypeQuery(policy), enable_criteria=True,
                         enable_browser=True, parent=parent)

        self.setWhatsThis("<b>Search types in an SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        name = criteria.TypeName("Name", self.query, "name",
                                 enable_regex=True,
                                 parent=self.criteria_frame)
        name.setToolTip("Search for types by name.")
        name.setWhatsThis("<p>Search for types by name.</p>")

        attrs = criteria.TypeAttributeList("Attributes", self.query, "attrs", enable_equal=True)
        attrs.setToolTip("Search for types by its attributes.")
        attrs.setWhatsThis("<p>Search for types by its attributes.</p>")

        permissive = criteria.PermissiveType("Permissive", self.query, "permissive",
                                             parent=self.criteria_frame)
        permissive.setToolTip("Search for types by permissive state.")
        permissive.setWhatsThis("<p>Search for types by permissive state.</p>")

        # Add widgets to layout
        self.criteria_frame_layout.addWidget(name, 0, 0, 1, 1)
        self.criteria_frame_layout.addWidget(permissive, 0, 1, 1, 1)
        self.criteria_frame_layout.addWidget(attrs, 1, 0, 1, 1)
        self.criteria_frame_layout.addWidget(self.buttonBox, 2, 0, 1, 2)

        # Save widget references
        self.criteria = (name, attrs, permissive)

        # Set result table's model
        self.table_results_model = models.TypeTable(self.table_results)

        #
        # Set up browser
        #
        self.browser.setModel(models.TypeTable(
            self.browser, data=sorted(self.query.policy.types())))


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
    widget = TypeQueryTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(1280, 1024)
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
