# Copyright 2015, Tresys Technology, LLC
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

import logging

from PyQt5.QtWidgets import QDialog

from ..widget import SEToolsWidget


class ExcludeTypes(SEToolsWidget, QDialog):

    """Dialog for choosing excluded types."""

    def __init__(self, parent, policy):
        super(ExcludeTypes, self).__init__(parent)
        self.log = logging.getLogger(__name__)
        self.parent = parent
        self.policy = policy
        self.excluded_list = [str(e) for e in self.parent.query.exclude]
        self.setupUi()

    def setupUi(self):
        self.load_ui("exclude_types.ui")
        self.exclude_a_type.clicked.connect(self.exclude_clicked)
        self.include_a_type.clicked.connect(self.include_clicked)

        # populate the lists:
        self.included_types.clear()
        for item in self.policy.types():
            if item not in self.excluded_list:
                self.included_types.addItem(str(item))

        self.excluded_types.clear()
        for item in self.excluded_list:
            self.excluded_types.addItem(item)

    def include_clicked(self):
        for item in self.excluded_types.selectedItems():
            self.included_types.addItem(item.text())
            self.excluded_types.takeItem(self.excluded_types.row(item))

    def exclude_clicked(self):
        for item in self.included_types.selectedItems():
            self.excluded_types.addItem(item.text())
            self.included_types.takeItem(self.included_types.row(item))

    def accept(self):
        exclude = []

        item = self.excluded_types.takeItem(0)
        while item:
            exclude.append(item.text())
            item = self.excluded_types.takeItem(0)

        self.log.debug("Chosen for exclusion: {0!r}".format(exclude))

        self.parent.query.exclude = exclude
        super(ExcludeTypes, self).accept()
