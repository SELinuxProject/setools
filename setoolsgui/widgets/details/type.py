# SPDX-License-Identifier: LGPL-2.1-only
from typing import TYPE_CHECKING

from PyQt5 import QtCore, QtGui, QtWidgets

from .typeattr import typeattr_detail
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


def type_or_attr_detail(type_: "Union[Type, TypeAttribute]",
                        parent: "Optional[QtWidgets.QWidget]" = None) -> None:

    """Display a dialog with type or type attribute details."""

    try:
        type_detail(type_, parent)  # type: ignore
    except Exception:
        typeattr_detail(type_, parent)  # type: ignore
