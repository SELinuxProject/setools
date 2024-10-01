# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from . import criteria, models, tab

__all__ = ("UserQueryTab",)


class UserQueryTab(tab.TableResultTabWidget[setools.UserQuery, setools.User]):

    """A user query."""

    section = tab.AnalysisSection.Components
    tab_title = "Users"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(setools.UserQuery(policy), enable_criteria=True,
                         enable_browser=True, parent=parent)

        self.setWhatsThis("<b>Search users in an SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        name = criteria.UserName("Name", self.query, "name", enable_regex=True,
                                 parent=self.criteria_frame)
        name.setToolTip("Search for users by name.")
        name.setWhatsThis("<p>Search for user by name.</p>")

        roles = criteria.RoleList("Roles", self.query, "roles",
                                  enable_equal=True,
                                  parent=self.criteria_frame)
        roles.setToolTip("Search for users by role set.")
        roles.setWhatsThis("<p>Search for user by role set.</p>")

        lvl = criteria.MLSLevelName("Default MLS Level", self.query, "level",
                                    enable_opts=True,
                                    parent=self.criteria_frame)
        if policy.mls:
            lvl.setToolTip("Search for users by default MLS level.")
            lvl.setWhatsThis("<p>Search for user by default MLS level.</p>")
        else:
            lvl.setEnabled(False)
            lvl.setToolTip("MLS is disabled in this policy.")
            lvl.setWhatsThis(
                """
                <p>This MLS level for user matching is not available because
                MLS is disabled in this policy.</p>
                """)

        dft = criteria.MLSRangeName("MLS Range", self.query, "range_",
                                    enable_range_opts=True,
                                    parent=self.criteria_frame)
        if policy.mls:
            dft.setToolTip("Search for users by allowed MLS range.")
            dft.setWhatsThis("<p>Search for users by allowed MLS range.</p>")
        else:
            dft.setEnabled(False)
            dft.setToolTip("MLS is disabled in this policy.")
            dft.setWhatsThis(
                """
                <p>This MLS range for user matching is not available because
                MLS is disabled in this policy.</p>
                """)

        # Add widgets to layout
        self.criteria_frame_layout.addWidget(name, 0, 0, 1, 1)
        self.criteria_frame_layout.addWidget(roles, 0, 1, 1, 1)
        self.criteria_frame_layout.addWidget(lvl, 1, 0, 1, 1)
        self.criteria_frame_layout.addWidget(dft, 1, 1, 1, 1)
        self.criteria_frame_layout.addWidget(self.buttonBox, 2, 0, 1, 2)

        # Save widget references
        self.criteria = (name, roles, lvl, dft)

        # Set result table's model
        self.table_results_model = models.UserTable(self.table_results,
                                                    mls=self.query.policy.mls)

        #
        # Set up browser
        #
        self.browser.setModel(models.UserTable(self.browser,
                                               mls=self.query.policy.mls,
                                               data=sorted(self.query.policy.users())))


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
    widget = UserQueryTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(1280, 1024)
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
