# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from . import criteria, models, tab

__all__ = ("ConstraintQueryTab",)


class ConstraintQueryTab(tab.TableResultTabWidget):

    """A constraint query."""

    section = tab.AnalysisSection.Rules
    tab_title = "Constraints"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(setools.ConstraintQuery(policy), enable_criteria=True, parent=parent)

        self.setWhatsThis("<b>Search constraints in a SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        rt = criteria.ConstrainType("Rule Type", self.query, parent=self.criteria_frame)
        rt.setToolTip("The rule types for constraint matching.")
        rt.setWhatsThis(
            """
            <p><b>Select rule types for constraint matching.</b></p>

            <p>If a rule's has a one of the selected types, it will be returned.</p>
            """)

        user = criteria.UserName("User In Expression", self.query, "user",
                                 enable_regex=True,
                                 parent=self.criteria_frame)
        user.setToolTip("Search for a user in the expression.")
        user.setWhatsThis(
            """
            <p><b>Search for users in a constraint expression..</b></p>

            <p>If a constraint's expression has this user in its expression,
            it will be returned.</p>
            """)

        role = criteria.RoleName("Role In Expression", self.query, "role",
                                 enable_regex=True,
                                 parent=self.criteria_frame)
        role.setToolTip("Search for a role in the expression.")
        role.setWhatsThis(
            """
            <p><b>Search for roles in a constraint expression..</b></p>

            <p>If a constraint's expression has this role in its expression,
            it will be returned.</p>
            """)

        type_ = criteria.TypeName("Type In Expression", self.query, "type_",
                                  enable_regex=True,
                                  enable_indirect=False,
                                  parent=self.criteria_frame)
        type_.setToolTip("Search for a type in the expression.")
        type_.setWhatsThis(
            """
            <p><b>Search for types in a constraint expression..</b></p>

            <p>If a constraint's expression has this type in its expression,
            it will be returned.</p>
            """)

        tclass = criteria.ObjClassList("Object Class", self.query, "tclass",
                                       parent=self.criteria_frame)
        tclass.setToolTip("The object class(es) for constraint matching.")
        tclass.setWhatsThis(
            """
            <p><b>Select object classes for constraint matching.</b></p>

            <p>A rule will be returned if its object class is one of the selected
            classes</p>
            """)

        perms = criteria.PermissionList("Permission Set", self.query, "perms",
                                        enable_equal=True,
                                        enable_subset=True,
                                        parent=self.criteria_frame)
        perms.setToolTip("The permission(s) for constraint matching.")
        perms.setWhatsThis(
            """
            <p><b>Select permissions for constraint matching.</b></p>

            <p>Available permissions are dependent on the selected object
            classes.  If multiple classes are selected, only permissions
            available in all of the classes are available.</p>
            """)

        # Connect signals
        tclass.selectionChanged.connect(perms.set_classes)

        # Add widgets to layout
        self.criteria_frame_layout.addWidget(rt, 0, 0, 1, 1)
        self.criteria_frame_layout.addWidget(user, 0, 1, 1, 1)
        self.criteria_frame_layout.addWidget(role, 1, 0, 1, 1)
        self.criteria_frame_layout.addWidget(type_, 1, 1, 1, 1)
        self.criteria_frame_layout.addWidget(tclass, 2, 0, 1, 1)
        self.criteria_frame_layout.addWidget(perms, 2, 1, 1, 1)
        self.criteria_frame_layout.addWidget(self.buttonBox, 3, 0, 1, 2)

        # Save widget references
        self.criteria = (rt, user, role, type_, tclass, perms)

        # Set result table's model
        self.table_results_model = models.ConstraintTable(self.table_results)


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
    widget = ConstraintQueryTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
