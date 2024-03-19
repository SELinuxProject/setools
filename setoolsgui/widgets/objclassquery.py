# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from . import criteria, models, tab

__all__ = ("ObjClassQueryTab",)


class ObjClassQueryTab(tab.TableResultTabWidget[setools.ObjClassQuery, setools.ObjClass]):

    """An object class query."""

    section = tab.AnalysisSection.Components
    tab_title = "Object Classes"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(setools.ObjClassQuery(policy), enable_criteria=True,
                         enable_browser=True, parent=parent)

        self.setWhatsThis("<b>Search object classes in an SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        name = criteria.ObjClassName("Name", self.query, "name", enable_regex=True,
                                     parent=self.criteria_frame)
        name.setToolTip("Search for object classes by name.")
        name.setWhatsThis("<p>Search for object classes by name.</p>")

        perms = criteria.PermissionList("Permissions", self.query, "perms",
                                        enable_equal=True)
        perms.setToolTip("Search for object classes by permissions.")
        perms.setWhatsThis("<p>Search for object claasses by permissions.</p>")

        # Add widgets to layout
        self.criteria_frame_layout.addWidget(name, 0, 0, 1, 1)
        self.criteria_frame_layout.addWidget(perms, 0, 1, 1, 1)
        self.criteria_frame_layout.addWidget(self.buttonBox, 1, 0, 1, 2)

        # Save widget references
        self.criteria = (name, perms)

        # Set result table's model
        self.table_results_model = models.ObjClassTable(self.table_results)

        #
        # Set up browser
        #
        self.browser.setModel(models.ObjClassTable(self.browser,
                                                   data=sorted(self.query.policy.classes())))


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
    widget = ObjClassQueryTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(1280, 1024)
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
