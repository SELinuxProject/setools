# SPDX-License-Identifier: LGPL-2.1-only

from contextlib import suppress
import enum
import typing

from PyQt6 import QtWidgets
import setools

from .criteria import CriteriaWidget

E = typing.TypeVar("E", bound=enum.Enum)

__all__ = ('ComboEnumCriteria',)


class ComboEnumCriteria(CriteriaWidget, typing.Generic[E]):

    """Criteria selection widget presenting possible options a QComboxBox."""

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, enum_class: type[E],
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(title, query, attrname, parent=parent)

        self.enum_class: typing.Final[type[E]] = enum_class
        self.top_layout = QtWidgets.QHBoxLayout(self)

        self.criteria = QtWidgets.QComboBox(self)
        self.criteria.setEditable(False)
        self.criteria.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum,
                                                          QtWidgets.QSizePolicy.Policy.Fixed))
        self.criteria.currentIndexChanged.connect(self._update_query)
        self.top_layout.addWidget(self.criteria)

        enu: E
        self.criteria.addItem("")  # Add entry for "match any"
        for enu in sorted(enum_class, key=lambda e: e.name):
            self.criteria.addItem(enu.name, enu)

        # add spacer so that the combo box is left-aligned
        spacerItem = QtWidgets.QSpacerItem(40, 20,
                                           QtWidgets.QSizePolicy.Policy.Expanding,
                                           QtWidgets.QSizePolicy.Policy.Minimum)
        self.top_layout.addItem(spacerItem)

    @property
    def has_errors(self) -> bool:
        """Get error state of this widget."""
        return False

    def _update_query(self, idx: int) -> None:
        """Update the query based on the combo box."""
        value = self.criteria.itemText(idx)
        if value:
            # get enum value from combo box
            value = self.criteria.itemData(idx)

        self.log.debug(f"Setting {self.attrname} to {value!r}")
        setattr(self.query, self.attrname, value)

    #
    # Workspace methods
    #

    def save(self, settings: dict) -> None:
        settings[self.attrname] = self.criteria.currentText()

    def load(self, settings: dict) -> None:
        with suppress(AttributeError, KeyError):
            idx = self.criteria.findText(settings[self.attrname])
            self.criteria.setCurrentIndex(idx)


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
    widget = ComboEnumCriteria("Test radio enum", q, "radioattrname", local_enum_class, parent=mw)
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
