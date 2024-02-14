# Copyright 2016, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtCore, QtGui, QtWidgets
import setools

from . import tab

__all__ = ("SummaryTab",)


class SummaryTab(tab.BaseAnalysisTabWidget):

    """An SELinux policy summary."""

    section = tab.AnalysisSection.General
    tab_title = "SELinux Policy Summary"
    mlsonly = False

    def __init__(self, policy: setools.SELinuxPolicy, /, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(policy, enable_criteria=False, parent=parent)
        self.policy = policy

        # font for labels
        font = QtGui.QFont()
        font.setBold(True)

        self.results = QtWidgets.QWidget(self)
        self.top_layout = QtWidgets.QGridLayout(self.results)
        self.top_layout.setContentsMargins(6, 6, 6, 6)
        self.top_layout.setSpacing(3)

        #
        # Policy Properties
        #
        properties_groupbox = QtWidgets.QGroupBox(self.results)
        properties_groupbox.setTitle("Policy Properties")
        properties_layout = QtWidgets.QFormLayout(properties_groupbox)
        self.top_layout.addWidget(properties_groupbox, 2, 0, 1, 2)

        for label_text, obj in (("Policy Version:", "version"),
                                ("Unknown Permissions:", "handle_unknown"),
                                ("MLS:", "mls")):

            self._add_row(properties_layout, label_text, obj)

        # Create policy capabilities list
        self.polcaps_label = QtWidgets.QLabel(properties_groupbox)
        self.polcaps_label.setFont(font)
        self.polcaps_label.setText("Policy Capabilities:")
        self.polcaps_value = QtWidgets.QListWidget(properties_groupbox)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum,
                                           QtWidgets.QSizePolicy.Policy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.polcaps_value.sizePolicy().hasHeightForWidth())
        self.polcaps_value.setSizePolicy(sizePolicy)
        self.polcaps_value.setSortingEnabled(True)
        self.polcaps_value.addItems([str(c) for c in self.policy.polcaps()])
        properties_layout.addRow(self.polcaps_label, self.polcaps_value)

        #
        # Other
        #
        other_groupbox = QtWidgets.QGroupBox(self.results)
        other_groupbox.setTitle("Other")
        other_layout = QtWidgets.QFormLayout(other_groupbox)
        self.top_layout.addWidget(other_groupbox, 2, 2, 1, 1)

        for label_text, obj in (("Permissive Types:", "permissives_count"),
                                ("Defaults:", "default_count"),
                                ("Typebounds:", "typebounds_count")):

            self._add_row(other_layout, label_text, obj)

        #
        # Constraints
        #
        constraints_groupbox = QtWidgets.QGroupBox(self.results)
        constraints_groupbox.setTitle("Constraint Counts")
        constraints_layout = QtWidgets.QFormLayout(constraints_groupbox)
        self.top_layout.addWidget(constraints_groupbox, 2, 3, 1, 1)

        for label_text, obj, req_mls in (("constrain:", "constraint_count", False),
                                         ("validatetrans:", "validatetrans_count", False),
                                         ("mlsconstrain:", "mlsconstraint_count", True),
                                         ("mlsvalidatetrans:", "mlsvalidatetrans_count", True)):

            self._add_row(constraints_layout, label_text, obj, req_mls)

        #
        # Components
        #
        components_groupbox = QtWidgets.QGroupBox(self.results)
        components_groupbox.setTitle("Component Counts")
        components_layout = QtWidgets.QFormLayout(components_groupbox)
        self.top_layout.addWidget(components_groupbox, 4, 0, 1, 2)

        for label_text, obj, req_mls in (("Classes:", "class_count", False),
                                         ("Permissions:", "permission_count", False),
                                         ("Types:", "type_count", False),
                                         ("Attributes:", "type_attribute_count", False),
                                         ("Roles:", "role_count", False),
                                         ("Users:", "user_count", False),
                                         ("Booleans:", "boolean_count", False),
                                         ("Sensitivities:", "level_count", True),
                                         ("Categories:", "category_count", True)):

            self._add_row(components_layout, label_text, obj, req_mls)

        #
        # Rules
        #
        rule_groupbox = QtWidgets.QGroupBox(self.results)
        rule_groupbox.setTitle("Rule Counts")
        rule_layout = QtWidgets.QFormLayout(rule_groupbox)
        self.top_layout.addWidget(rule_groupbox, 4, 2, 1, 1)

        for label_text, obj, req_mls in (("allow:", "allow_count", False),
                                         ("allowxperm:", "allowxperm_count", False),
                                         ("auditallow:", "auditallow_count", False),
                                         ("auditallowxperm:", "auditallowxperm_count", False),
                                         ("dontaudit:", "dontaudit_count", False),
                                         ("dontauditxperm:", "dontauditxperm_count", False),
                                         ("neverallow:", "neverallow_count", False),
                                         ("neverallowxperm:", "neverallowxperm_count", False),
                                         ("type_transition:", "type_transition_count", False),
                                         ("type_change:", "type_change_count", False),
                                         ("type_member:", "type_member_count", False),
                                         ("allow (role):", "role_allow_count", False),
                                         ("role_transition", "role_transition_count", False),
                                         ("range_transition", "range_transition_count", True)):

            self._add_row(rule_layout, label_text, obj, req_mls)

        #
        # Labeling
        #
        labeling_groupbox = QtWidgets.QGroupBox(self.results)
        labeling_groupbox.setTitle("Labeling Counts")
        labeling_layout = QtWidgets.QFormLayout(labeling_groupbox)
        self.top_layout.addWidget(labeling_groupbox, 4, 3, 1, 1)

        for label_text, obj in (("ibendportcons:", "ibendportcon_count"),
                                ("ibpkeycons:", "ibpkeycon_count"),
                                ("initial SIDs:", "initialsids_count"),
                                ("fs_use_*:", "fs_use_count"),
                                ("genfscon:", "genfscon_count"),
                                ("netifcon:", "netifcon_count"),
                                ("nodecon:", "nodecon_count"),
                                ("portcon:", "portcon_count")):

            self._add_row(labeling_layout, label_text, obj)

        QtCore.QMetaObject.connectSlotsByName(self)

    def _add_row(self, layout: QtWidgets.QFormLayout, label_text: str, obj: str,
                 req_mls: bool = False) -> None:
        """Add a row a layout."""
        font = QtGui.QFont()
        font.setBold(True)

        label = QtWidgets.QLabel(layout.parentWidget())
        label.setFont(font)
        label.setText(label_text)
        value = QtWidgets.QLabel(layout.parentWidget())
        value.setText(str(getattr(self.policy, obj)))
        layout.addRow(label, value)

        if req_mls and not self.policy.mls:
            label.setEnabled(False)
            label.setToolTip("MLS is disabled in this policy.")
            value.setEnabled(False)
            value.setToolTip("MLS is disabled in this policy.")

        setattr(self, f"{obj}_label", label)
        setattr(self, f"{obj}_value", value)

    #
    # Unused abstract methods
    #
    def run(self) -> None:
        """Run the query."""
        pass

    def query_completed(self, count: int) -> None:
        """Handle successful query completion."""
        pass

    def query_failed(self, message: str) -> None:
        """Handle query failure."""
        pass


if __name__ == '__main__':
    import sys
    import warnings
    import pprint
    import logging
    import setools

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    widget = SummaryTab(setools.SELinuxPolicy(), parent=mw)
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    pprint.pprint(widget.save())
    sys.exit(rc)
