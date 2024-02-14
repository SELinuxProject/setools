
from contextlib import suppress

from PyQt6 import QtWidgets
import setools

from .criteria import CriteriaWidget

__all__ = ("ComboBoxWidget",)


class ComboBoxWidget(CriteriaWidget):

    """Criteria selection widget presenting options as a QComboBox."""

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 enable_any: bool = True, parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(title, query, attrname, parent=parent)
        self.top_layout = QtWidgets.QHBoxLayout(self)

        self.criteria = QtWidgets.QComboBox(self)
        self.criteria.setEditable(False)
        self.criteria.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum,
                                                          QtWidgets.QSizePolicy.Policy.Fixed))
        self.criteria.currentIndexChanged.connect(self._update_query)
        self.top_layout.addWidget(self.criteria)

        if enable_any:
            self.criteria.addItem("[Any]", None)

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
