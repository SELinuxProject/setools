# Copyright 2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
#
from collections import defaultdict

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QDialog, QTreeWidgetItem

from ..widget import SEToolsWidget
from .analysistab import AnalysisSection, AnalysisTab, TAB_REGISTRY


class ChooseAnalysis(SEToolsWidget, QDialog):

    """
    Dialog for choosing a new analysis

    The below class attributes are used for populating
    the GUI contents and mapping them to the appropriate
    tab widget class for the analysis.
    """

    def __init__(self, parent):
        super(ChooseAnalysis, self).__init__(parent)
        self.parent = parent

        # populate the analysis choices tree:
        self.analysis_choices = defaultdict(dict)
        for clsobj in TAB_REGISTRY.values():
            self.analysis_choices[clsobj.section.name][clsobj.tab_title] = clsobj

        self.setupUi()

    def setupUi(self):
        self.load_ui("apol/choose_analysis.ui")

    def show(self, mls):
        self.analysisTypes.clear()
        for groupname, group in self.analysis_choices.items():
            groupitem = QTreeWidgetItem(self.analysisTypes)
            groupitem.setText(0, groupname)
            groupitem._tab_class = None
            for entryname, cls in group.items():
                if cls.mlsonly and not mls:
                    continue

                item = QTreeWidgetItem(groupitem)
                item.setText(0, entryname)
                item._tab_class = cls
                groupitem.addChild(item)

        self.analysisTypes.expandAll()
        self.analysisTypes.sortByColumn(0, Qt.AscendingOrder)
        super(ChooseAnalysis, self).show()

    def accept(self, item=None):
        try:
            if not item:
                # .ui is set for single item selection.
                item = self.analysisTypes.selectedItems()[0]

            title = item.text(0)
            self.parent.create_new_analysis(title, item._tab_class)
        except (IndexError, TypeError):
            # IndexError: nothing is selected
            # TypeError: one of the group items was selected.
            pass
        else:
            super(ChooseAnalysis, self).accept()
