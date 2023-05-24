# Copyright 2016, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only

from typing import TYPE_CHECKING

from PyQt5 import QtCore, QtGui, QtWidgets

from . import tab

if TYPE_CHECKING:
    from typing import Final, Optional


class SummaryTab(tab.BaseAnalysisTabWidget):

    """An SELinux policy summary."""

    section = tab.AnalysisSection.General
    tab_title = "SELinux Policy Summary"
    mlsonly = False

    def __init__(self, policy: "setools.SELinuxPolicy", _,
                 parent: "Optional[QtWidgets.QWidget]" = None) -> None:

        super().__init__(enable_criteria=False, parent=parent)
        self.policy: "Final" = policy

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

            label = QtWidgets.QLabel(properties_groupbox)
            label.setFont(font)
            label.setText(label_text)
            value = QtWidgets.QLabel(properties_groupbox)
            value.setText(str(getattr(self.policy, obj)))
            properties_layout.addRow(label, value)
            setattr(self, f"{obj}_label", label)
            setattr(self, f"{obj}_value", value)

        self.mls_value.setText("enabled" if self.policy.mls else "disabled")

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

            label = QtWidgets.QLabel(other_groupbox)
            label.setFont(font)
            label.setText(label_text)
            value = QtWidgets.QLabel(other_groupbox)
            value.setText(str(getattr(self.policy, obj)))
            other_layout.addRow(label, value)
            setattr(self, f"{obj}_label", label)
            setattr(self, f"{obj}_value", value)

        #
        # Constraints
        #
        constraints_groupbox = QtWidgets.QGroupBox(self.results)
        constraints_groupbox.setTitle("Constraint Counts")
        constraints_layout = QtWidgets.QFormLayout(constraints_groupbox)
        self.top_layout.addWidget(constraints_groupbox, 2, 3, 1, 1)

        for label_text, obj in (("constrain:", "constraint_count"),
                                ("validatetrans:", "validatetrans_count"),
                                ("mlsconstrain:", "mlsconstraint_count"),
                                ("mlsvalidatetrans:", "mlsvalidatetrans_count")):

            label = QtWidgets.QLabel(constraints_groupbox)
            label.setFont(font)
            label.setText(label_text)
            value = QtWidgets.QLabel(constraints_groupbox)
            value.setText(str(getattr(self.policy, obj)))
            constraints_layout.addRow(label, value)
            setattr(self, f"{obj}_label", label)
            setattr(self, f"{obj}_value", value)

        if not self.policy.mls:
            self.mlsconstraint_count_label.setEnabled(False)
            self.mlsconstraint_count_label.setToolTip("MLS is disabled in this policy.")
            self.mlsconstraint_count_value.setEnabled(False)
            self.mlsconstraint_count_value.setToolTip("MLS is disabled in this policy.")
            self.mlsvalidatetrans_count_label.setEnabled(False)
            self.mlsvalidatetrans_count_label.setToolTip("MLS is disabled in this policy.")
            self.mlsvalidatetrans_count_value.setEnabled(False)
            self.mlsvalidatetrans_count_value.setToolTip("MLS is disabled in this policy.")

        #
        # Components
        #
        components_groupbox = QtWidgets.QGroupBox(self.results)
        components_groupbox.setTitle("Component Counts")
        components_layout = QtWidgets.QFormLayout(components_groupbox)
        self.top_layout.addWidget(components_groupbox, 4, 0, 1, 2)

        for label_text, obj in (("Classes:", "class_count"),
                                ("Permissions:", "permission_count"),
                                ("Types:", "type_count"),
                                ("Attributes:", "type_attribute_count"),
                                ("Roles:", "role_count"),
                                ("Users:", "user_count"),
                                ("Booleans:", "boolean_count"),
                                ("Sensitivities:", "level_count"),
                                ("Categories:", "category_count")):

            label = QtWidgets.QLabel(components_groupbox)
            label.setFont(font)
            label.setText(label_text)
            value = QtWidgets.QLabel(components_groupbox)
            value.setText(str(getattr(self.policy, obj)))
            components_layout.addRow(label, value)
            setattr(self, f"{obj}_label", label)
            setattr(self, f"{obj}_value", value)

        if not self.policy.mls:
            self.level_count_label.setEnabled(False)
            self.level_count_label.setToolTip("MLS is disabled in this policy.")
            self.level_count_value.setEnabled(False)
            self.level_count_value.setToolTip("MLS is disabled in this policy.")
            self.category_count_label.setEnabled(False)
            self.category_count_label.setToolTip("MLS is disabled in this policy.")
            self.category_count_value.setEnabled(False)
            self.category_count_value.setToolTip("MLS is disabled in this policy.")

        #
        # Rules
        #
        rule_groupbox = QtWidgets.QGroupBox(self.results)
        rule_groupbox.setTitle("Rule Counts")
        rule_layout = QtWidgets.QFormLayout(rule_groupbox)
        self.top_layout.addWidget(rule_groupbox, 4, 2, 1, 1)

        for label_text, obj in (("allow:", "allow_count"),
                                ("allowxperm:", "allowxperm_count"),
                                ("auditallow:", "auditallow_count"),
                                ("auditallowxperm:", "auditallowxperm_count"),
                                ("dontaudit:", "dontaudit_count"),
                                ("dontauditxperm:", "dontauditxperm_count"),
                                ("neverallow:", "neverallow_count"),
                                ("neverallowxperm:", "neverallowxperm_count"),
                                ("type_transition:", "type_transition_count"),
                                ("type_change:", "type_change_count"),
                                ("type_member:", "type_member_count"),
                                ("allow (role):", "role_allow_count"),
                                ("role_transition", "role_transition_count"),
                                ("range_transition", "range_transition_count")):

            label = QtWidgets.QLabel(rule_groupbox)
            label.setFont(font)
            label.setText(label_text)
            value = QtWidgets.QLabel(rule_groupbox)
            value.setText(str(getattr(self.policy, obj)))
            rule_layout.addRow(label, value)
            setattr(self, f"{obj}_label", label)
            setattr(self, f"{obj}_value", value)

        if not self.policy.mls:
            self.range_transition_count_label.setEnabled(False)
            self.range_transition_count_label.setToolTip("MLS is disabled in this policy.")
            self.range_transition_count_value.setEnabled(False)
            self.range_transition_count_value.setToolTip("MLS is disabled in this policy.")

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

            label = QtWidgets.QLabel(labeling_groupbox)
            label.setFont(font)
            label.setText(label_text)
            value = QtWidgets.QLabel(labeling_groupbox)
            value.setText(str(getattr(self.policy, obj)))
            labeling_layout.addRow(label, value)
            setattr(self, f"{obj}_label", label)
            setattr(self, f"{obj}_value", value)

        # Fill policy capabilities list
        QtCore.QMetaObject.connectSlotsByName(self)


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
    widget = SummaryTab(mw, setools.SELinuxPolicy(), None)
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec_()
    pprint.pprint(widget.save())
    sys.exit(rc)
