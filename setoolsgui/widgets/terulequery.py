# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from . import criteria, models, tab

__all__ = ("TERuleQueryTab",)


class TERuleQueryTab(tab.TableResultTabWidget[setools.TERuleQuery, setools.AnyTERule]):

    """A Type Enforcement rule query."""

    section = tab.AnalysisSection.Rules
    tab_title = "Type Enforcement Rule Query"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(setools.TERuleQuery(policy), enable_criteria=True, parent=parent)

        self.setWhatsThis("<b>Search Type Enforcement rules in a SELinux policy.</b>")

        #
        # Set up criteria widgets
        #
        rt = criteria.TERuleType("Rule Type", self.query,
                                 parent=self.criteria_frame)
        rt.setToolTip("The rule types for rule matching.")
        rt.setWhatsThis(
            """
            <p><b>Select rule types for rule matching.</b></p>

            <p>If a rule's has a one of the selected types, it will be returned.</p>
            """)

        src = criteria.TypeOrAttrName("Source Type/Attribute", self.query, "source",
                                      enable_regex=True,
                                      enable_indirect=True,
                                      parent=self.criteria_frame)
        src.setToolTip("The source type/attribute for rule matching.")
        src.setWhatsThis(
            """
            <p><b>Enter the source type/attribute for rule matching.</b></p>

            <p>The behavior differs if a type or attribute is entered.</p>

            <p>For types, if a rule has this type as the source, it will be
            returned.  If indirect is enabled, rules that have an attribute as
            a source will be returned if the attribute contains this type.</p>

            <p>For attributes, if a rule has this attribute as the source, it
            will be returned.  If indirect is enabled, rules that have a source
            type that is contained by this attribute will be returned.</p>

            <p>If regex is enabled, a regular expression is used for matching
            the type/attribute name instead of direct string comparison.</p>
            """)

        dst = criteria.TypeOrAttrName("Target Type/Attribute", self.query, "target",
                                      enable_regex=True,
                                      enable_indirect=True,
                                      parent=self.criteria_frame)
        dst.setToolTip("The target type/attribute for rule matching.")
        dst.setWhatsThis(
            """
            <p><b>Enter the target type/attribute for rule matching.</b></p>

            <p>The behavior differs if a type or attribute is entered.</p>

            <p>For types, if a rule has this type as the target, it will be
            returned.  If indirect is enabled, rules that have an attribute as
            a target will be returned if the attribute contains this type.</p>

            <p>For attributes, if a rule has this attribute as the target, it
            will be returned.  If indirect is enabled, rules that have a target
            type that is contained by this attribute will be returned.</p>

            <p>If regex is enabled, a regular expression is used for matching
            the type/attribute name instead of direct string comparison.</p>
            """)

        tclass = criteria.ObjClassList("Object Class", self.query, "tclass",
                                       parent=self.criteria_frame)
        tclass.setToolTip("The object class(es) for rule matching.")
        tclass.setWhatsThis(
            """
            <p><b>Select object classes for rule matching.</b></p>

            <p>A rule will be returned if its object class is one of the selected
            classes</p>
            """)

        perms = criteria.PermissionList("Permission Set", self.query, "perms",
                                        enable_equal=True,
                                        enable_subset=True,
                                        parent=self.criteria_frame)
        perms.setToolTip("The permission(s) for rule matching.")
        perms.setWhatsThis(
            """
            <p><b>Select permissions for rule matching.</b></p>

            <p>Available permissions are dependent on the selected object
            classes.  If multiple classes are selected, only permissions
            available in all of the classes are available.</p>
            """)

        dflt = criteria.TypeName("Default Type", self.query, "default",
                                 enable_regex=True,
                                 enable_indirect=False,
                                 parent=self.criteria_frame)
        dflt.setToolTip("The default type for rule matching.")
        dflt.setWhatsThis(
            """
            <p><b>Enter the default type for rule matching.</b></p>

            <p>If a rule has this type as the default, it will be returned.</p>
            """)

        bools = criteria.BooleanList("Booleans in Conditional Expression", self.query, "boolean",
                                     enable_equal=True,
                                     parent=self.criteria_frame)
        bools.setToolTip("The Boolean(s) for rule matching.")
        bools.setWhatsThis(
            """
            <p><b>Select Booleans(s) in the conditional expression for rule matching.</b></p>

            <p>If Booleans are selected, unconditional rules will not be returned.</p>
            """)

        # Add widgets to layout
        self.criteria_frame_layout.addWidget(rt, 0, 0, 1, 2)
        self.criteria_frame_layout.addWidget(src, 1, 0, 1, 1)
        self.criteria_frame_layout.addWidget(dst, 1, 1, 1, 1)
        self.criteria_frame_layout.addWidget(tclass, 2, 0, 1, 1)
        self.criteria_frame_layout.addWidget(perms, 2, 1, 1, 1)
        self.criteria_frame_layout.addWidget(dflt, 3, 0, 1, 1)
        self.criteria_frame_layout.addWidget(bools, 3, 1, 1, 1)
        self.criteria_frame_layout.addWidget(self.buttonBox, 4, 0, 1, 2)

        # Save widget references
        self.criteria = (rt, src, dst, tclass, perms, dflt, bools)

        # Set result table's model
        self.table_results_model = models.TERuleTable(self.table_results)

        # Connect signals
        tclass.selectionChanged.connect(perms.set_classes)

    def run(self) -> None:
        # Check for potentially too many results
        max_results = 0
        ruletypes = self.criteria[0]
        assert isinstance(ruletypes, criteria.TERuleType)  # mypy type narrowing
        for r in ruletypes.selection():
            max_results += getattr(self.query.policy, f"{r}_count")

        self.log.debug(f"Calculated {max_results} max results for selected ruletypes.")
        assert isinstance(self.query, setools.TERuleQuery)  # mypy type narrowing
        if not any((self.query.source, self.query.target, self.query.tclass, self.query.perms,
                    self.query.xperms, self.query.default, self.query.boolean)) \
                and max_results > 1000:

            reply = QtWidgets.QMessageBox.question(
                self, "Continue?",
                f"This is a broad query, estimated to return {max_results} results.  Continue?",
                QtWidgets.QMessageBox.StandardButton.Yes |
                QtWidgets.QMessageBox.StandardButton.No)

            if reply == QtWidgets.QMessageBox.StandardButton.No:
                return

        super().run()


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
    widget = TERuleQueryTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
