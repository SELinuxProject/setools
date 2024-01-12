# SPDX-License-Identifier: LGPL-2.1-only
import typing

from PyQt6 import QtWidgets

from .name import NameWidget

# Regex for exact matches
CAT_VALIDATE_EXACT: typing.Final[str] = r"[A-Za-z0-9._-]*"
SEN_VALIDATE_EXACT: typing.Final[str] = r"[A-Za-z0-9._-]*"

__all__: typing.Final[tuple[str, ...]] = ("CategoryName", "SensitivityName")


class CategoryName(NameWidget):

    """
    Widget providing a QLineEdit for the user to enter a category name, with
    the criteria saved to the attributes of the specified query.
    """

    def __init__(self, title: str, query, attrname: str,
                 parent: QtWidgets.QWidget | None = None,
                 enable_regex: bool = True, required: bool = False):

        completion: list[str] = sorted(b.name for b in query.policy.categories())

        super().__init__(title, query, attrname, completion, CAT_VALIDATE_EXACT,
                         enable_regex=enable_regex, required=required, parent=parent)


class SensitivityName(NameWidget):

    """
    Widget providing a QLineEdit for the user to enter a sensitivity name, with
    the criteria saved to the attributes of the specified query.
    """

    def __init__(self, title: str, query, attrname: str,
                 parent: QtWidgets.QWidget | None = None,
                 enable_regex: bool = True, required: bool = False):

        completion: list[str] = sorted(b.name for b in query.policy.sensitivities())

        super().__init__(title, query, attrname, completion, SEN_VALIDATE_EXACT,
                         enable_regex=enable_regex, required=required, parent=parent)
