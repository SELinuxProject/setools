# SPDX-License-Identifier: LGPL-2.1-only
from typing import TYPE_CHECKING

from PyQt5 import QtCore, QtGui, QtWidgets

from .typeattr import typeattr_detail, typeattr_tooltip
from .util import display_object_details

if TYPE_CHECKING:
    from typing import List, Optional, Union
    from setools.policyrep import Type, TypeAttribute


def type_detail(type_: "Type", parent: "Optional[QtWidgets.QWidget]" = None) -> None:

    """Display a dialog with type details."""

    attrs: "List[TypeAttribute]" = sorted(type_.attributes())
    aliases: "List[str]" = sorted(type_.aliases())

    display_object_details(
        f"{type_} Details",
        f"""
        <h1>Type Name</h1>
        <p>{type_}<p>

        <h2>Permissive:</h2>
        <p>{"Yes" if type_.ispermissive else "No"}</p>

        <h2>Attributes ({len(attrs)})</h2>
        <ul>
        {"".join(f"<li>{a}</li>" for a in attrs)}
        </ul>

        <h2>Aliases ({len(aliases)})</h2>
        <ul>
        {"".join(f"<li>{a}</li>" for a in aliases)}
        </ul>
        """,
        parent)


def type_detail_action(type_: "Type",
                       parent: "Optional[QtWidgets.QWidget]" = None) -> QtWidgets.QAction:

    """Return a QAction that, when triggered, opens an detail popup for the role."""

    a = QtWidgets.QAction(f"Properties of {type_}")
    a.triggered.connect(lambda x: type_detail(type_, parent))
    return a


def type_or_attr_detail(type_: "Union[Type, TypeAttribute]",
                        parent: "Optional[QtWidgets.QWidget]" = None) -> None:

    """Display a dialog with type or type attribute details."""

    try:
        type_detail(type_, parent)  # type: ignore
    except Exception:
        typeattr_detail(type_, parent)  # type: ignore


def type_or_attr_detail_action(type_: "Union[Type, TypeAttribute]",
                               parent: "Optional[QtWidgets.QWidget]" = None) -> QtWidgets.QAction:

    """Return a QAction that, when triggered, opens an detail popup for the type/attr."""

    a = QtWidgets.QAction(f"Properties of {type_}")
    a.triggered.connect(lambda x: type_or_attr_detail(type_, parent))
    return a


def type_tooltip(type_: "Type") -> str:
    """Return tooltip text for this type."""
    n_attrs = len(list(type_.attributes()))
    if n_attrs == 0:
        return f"{type_} is a type with no attributes."
    elif n_attrs > 5:
        return f"{type_} is a type with {n_attrs} attributes."
    else:
        return f"{type_} is a type with attributes: " \
                f"{', '.join(t.name for t in type_.attributes())}"


def type_or_attr_tooltip(type_: "Union[Type, TypeAttribute]") -> str:
    """Return tooltip text for this type or attribute."""
    try:
        return typeattr_tooltip(type_)  # type: ignore
    except Exception:
        return type_tooltip(type_)  # type: ignore
