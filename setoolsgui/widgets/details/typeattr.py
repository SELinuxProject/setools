# SPDX-License-Identifier: LGPL-2.1-only
from typing import TYPE_CHECKING

from PyQt5 import QtCore, QtGui, QtWidgets

from .util import display_object_details

if TYPE_CHECKING:
    from typing import List, Optional
    from setools.policyrep import Type, TypeAttribute


def typeattr_detail(attr: "TypeAttribute", parent: "Optional[QtWidgets.QWidget]" = None) -> None:

    """Display a dialog with type attribute details."""

    types: "List[Type]" = sorted(attr.expand())

    display_object_details(
        f"{attr} Details",
        f"""
        <h1>Type Attribute Name</h1>
        <p>{attr}<p>

        <h2>Types ({len(types)})</h2>
        <ul>
        {"".join(f"<li>{t}</li>" for t in types)}
        </ul>
        """,
        parent)


def typeattr_tooltip(attr: "TypeAttribute") -> str:
    """Return tooltip text for this type attribute."""
    n_types = len(attr)
    if n_types == 0:
        return f"{attr.name} is an empty attribute."
    elif n_types > 5:
        return f"{attr.name} is an attribute consisting of {n_types} types."
    else:
        return f"{attr.name} is an attribute consisting of: " \
                f"{', '.join(t.name for t in attr.expand())}"
