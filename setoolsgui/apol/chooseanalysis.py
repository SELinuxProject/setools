# Copyright 2016, Tresys Technology, LLC
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with SETools.  If not, see
# <http://www.gnu.org/licenses/>.
#

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QDialog, QTreeWidgetItem

from ..widget import SEToolsWidget

# Analysis tabs:
from .boolquery import BoolQueryTab
from .commonquery import CommonQueryTab
from .constraintquery import ConstraintQueryTab
from .dta import DomainTransitionAnalysisTab
from .fsusequery import FSUseQueryTab
from .genfsconquery import GenfsconQueryTab
from .infoflow import InfoFlowAnalysisTab
from .initsidquery import InitialSIDQueryTab
from .mlsrulequery import MLSRuleQueryTab
from .netifconquery import NetifconQueryTab
from .nodeconquery import NodeconQueryTab
from .objclassquery import ObjClassQueryTab
from .portconquery import PortconQueryTab
from .rbacrulequery import RBACRuleQueryTab
from .rolequery import RoleQueryTab
from .terulequery import TERuleQueryTab
from .typeattrquery import TypeAttributeQueryTab
from .typequery import TypeQueryTab
from .userquery import UserQueryTab


class ChooseAnalysis(SEToolsWidget, QDialog):

    """
    Dialog for choosing a new analysis

    The below class attributes are used for populating
    the GUI contents and mapping them to the appropriate
    tab widget class for the analysis.

    The item_mapping attribute will be populated to
    map the tree list items to the analysis tab widgets.
    """

    _analysis_map = {"Domain Transition Analysis": DomainTransitionAnalysisTab,
                     "Information Flow Analysis": InfoFlowAnalysisTab}
    _components_map = {"Booleans": BoolQueryTab,
                       "Commons": CommonQueryTab,
                       "Roles": RoleQueryTab,
                       "Object Classes": ObjClassQueryTab,
                       "Types": TypeQueryTab,
                       "Type Attributes": TypeAttributeQueryTab,
                       "Users": UserQueryTab}
    _rule_map = {"Constraints": ConstraintQueryTab,
                 "RBAC Rules": RBACRuleQueryTab,
                 "TE Rules": TERuleQueryTab}
    _labeling_map = {"Fs_use_* Statements": FSUseQueryTab,
                     "Genfscon Statements": GenfsconQueryTab,
                     "Initial SID Statements": InitialSIDQueryTab,
                     "Netifcon Statements": NetifconQueryTab,
                     "Nodecon Statements": NodeconQueryTab,
                     "Portcon Statements": PortconQueryTab}
    _analysis_choices = {"Components": _components_map,
                         "Rules": _rule_map,
                         "Analyses": _analysis_map,
                         "Labeling": _labeling_map}

    def __init__(self, parent, mls):
        super(ChooseAnalysis, self).__init__(parent)
        self.item_mapping = {}
        self.parent = parent
        self.setupUi(mls)

    def setupUi(self, mls):
        self.load_ui("choose_analysis.ui")
        self.buttonBox.accepted.connect(self.ok_clicked)
        self.analysisTypes.doubleClicked.connect(self.ok_clicked)

        if mls:
            self._rule_map["MLS Rules"] = MLSRuleQueryTab

        # populate the item list:
        self.analysisTypes.clear()
        for groupname, group in self._analysis_choices.items():
            groupitem = QTreeWidgetItem(self.analysisTypes)
            groupitem.setText(0, groupname)
            groupitem._tab_class = None
            for entryname, cls in group.items():
                item = QTreeWidgetItem(groupitem)
                item.setText(0, entryname)
                item._tab_class = cls
                groupitem.addChild(item)

        self.analysisTypes.expandAll()
        self.analysisTypes.sortByColumn(0, Qt.AscendingOrder)

    def ok_clicked(self):
        try:
            # .ui is set for single item selection.
            item = self.analysisTypes.selectedItems()[0]
            title = item.text(0)
            self.parent.create_new_analysis(title, item._tab_class)
        except (IndexError, TypeError):
            # IndexError: nothing is selected
            # TypeError: one of the group items was selected.
            pass
        else:
            self.accept()
