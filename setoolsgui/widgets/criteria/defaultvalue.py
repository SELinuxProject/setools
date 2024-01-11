# SPDX-License-Identifier: LGPL-2.1-only
from contextlib import suppress
import typing

from PyQt6 import QtWidgets
import setools

from .combobox import ComboBoxWidget

__all__ = ("DefaultValues",)


class DefaultValues(ComboBoxWidget):

    """Criteria selection widget presenting possible default_* values."""

    def __init__(self, title: str, query: setools.PolicyQuery, value_attrname: str,
                 range_attrname: str, /, *, enable_any: bool = True,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(title, query, value_attrname, enable_any=enable_any, parent=parent)

        for e_val in setools.DefaultValue:
            self.criteria.addItem(e_val.name, e_val)

        #
        # Add default range value combo box
        #
        self.range_attrname: typing.Final[str] = range_attrname
        self.criteria_range = QtWidgets.QComboBox(self)
        self.criteria_range.setEditable(False)
        self.criteria_range.setSizePolicy(QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Policy.Minimum,
            QtWidgets.QSizePolicy.Policy.Fixed))
        self.criteria_range.currentIndexChanged.connect(self._apply_range)
        self.top_layout.insertWidget(1, self.criteria_range)

        if enable_any:
            self.criteria_range.addItem("[Any]", None)

        for e_rng in setools.DefaultRangeValue:
            self.criteria_range.addItem(e_rng.name, e_rng)

    def _apply_range(self, idx: int) -> None:
        """Update the query based on the combo box."""
        value = self.criteria_range.itemText(idx)
        if value:
            # get enum value from combo box
            value = self.criteria_range.itemData(idx)

        self.log.debug(f"Setting {self.range_attrname} to {value!r}")
        setattr(self.query, self.range_attrname, value)

    #
    # Workspace methods
    #

    def save(self, settings: dict) -> None:
        super().save(settings)
        settings[self.range_attrname] = self.criteria_range.currentText()

    def load(self, settings: dict) -> None:
        with suppress(AttributeError, KeyError):
            idx = self.criteria_range.findText(settings[self.range_attrname])
            self.criteria_range.setCurrentIndex(idx)
        super().load(settings)


if __name__ == '__main__':
    import sys
    import logging
    import warnings

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    p = setools.SELinuxPolicy()
    q1 = setools.DefaultQuery(p)

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    window = QtWidgets.QWidget(mw)
    layout = QtWidgets.QHBoxLayout(window)
    widget1 = DefaultValues("Test default values", q1, "default", "default_range", parent=window)
    layout.addWidget(widget1)
    window.setToolTip("test tooltip")
    window.setWhatsThis("test whats this")
    mw.setCentralWidget(window)
    mw.resize(window.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.show()
    rc = app.exec()
    sys.exit(rc)
