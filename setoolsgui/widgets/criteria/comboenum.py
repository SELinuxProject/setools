# SPDX-License-Identifier: LGPL-2.1-only

import enum
import typing

from PyQt6 import QtWidgets
import setools

from .combobox import ComboBoxWidget

E = typing.TypeVar("E", bound=enum.Enum)

__all__ = ('ComboEnumWidget',)


class ComboEnumWidget(ComboBoxWidget, typing.Generic[E]):

    """Criteria selection widget presenting possible options a QComboxBox."""

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, enum_class: type[E],
                 enable_any: bool = True, parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(title, query, attrname, enable_any=enable_any, parent=parent)

        enu: E
        for enu in sorted(enum_class, key=lambda e: e.name):
            self.criteria.addItem(enu.name, enu)


if __name__ == '__main__':
    import sys
    import logging
    import pprint
    import warnings

    class local_enum_class(enum.Enum):
        """Enum for local testing"""
        Val1 = "Value 1"
        Val4 = "Value 4"
        Val2 = "Value 2"
        Val3 = "Value 3"

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.TERuleQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    widget = ComboEnumWidget("Test radio enum", q, "radioattrname", local_enum_class, parent=mw)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.show()
    rc = app.exec()
    local_settings: typing.Dict[str, str] = {}
    widget.save(local_settings)
    pprint.pprint(local_settings)
    sys.exit(rc)
