# SPDX-License-Identifier: LGPL-2.1-only

from PyQt6 import QtWidgets
import setools

from .. import models
from .list import ListWidget

__all__ = ('TypeAttributeList',)


class TypeAttributeList(ListWidget):

    """A widget providing a QListView widget for selecting the type attributes."""

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str,
                 enable_equal: bool = False, enable_subset: bool = False,
                 parent: QtWidgets.QWidget | None = None) -> None:

        model = models.TypeAttributeTable(data=sorted(query.policy.typeattributes()))

        super().__init__(title, query, attrname, model, enable_equal=enable_equal,
                         enable_subset=enable_subset, parent=parent)

        self.criteria_any.setToolTip("Any selected type will match.")
        self.criteria_any.setWhatsThis("<b>Any selected type will match.</b>")
