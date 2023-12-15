# SPDX-License-Identifier: LGPL-2.1-only

import typing

from PyQt6 import QtWidgets
import setools

from .. import models
from .criteria import OptionsPlacement
from .list import ListWidget
from .name import NameWidget

# Regex for exact matches to types/attrs
VALIDATE_EXACT: typing.Final[str] = r"[A-Za-z0-9._-]*"

__all__ = ('TypeAttributeList', 'TypeAttributeName',)


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


class TypeAttributeName(NameWidget):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of type attributes.
    """

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 parent: QtWidgets.QWidget | None = None,
                 options_placement: OptionsPlacement = OptionsPlacement.RIGHT,
                 enable_regex: bool = False, required: bool = False):

        # Create completion list
        completion = list[str](t.name for t in query.policy.typeattributes())

        super().__init__(title, query, attrname, completion, VALIDATE_EXACT,
                         enable_regex=enable_regex, required=required,
                         options_placement=options_placement, parent=parent)
