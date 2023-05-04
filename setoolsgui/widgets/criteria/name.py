# SPDX-License-Identifier: LGPL-2.1-only

from contextlib import suppress
from typing import TYPE_CHECKING, cast

from PyQt5 import QtCore, QtGui, QtWidgets

from .criteria import CriteriaWidget

if TYPE_CHECKING:
    from typing import Dict, List, Optional

# regex default setting (unchecked)
REGEX_DEFAULT_CHECKED = False


class NameCriteriaWidget(CriteriaWidget):

    """
    Base class widget providing a QLineEdit that saves the input to the
    attributes of the specified query.
    """

    editingFinished = QtCore.pyqtSignal(object)
    # This signal is only emitted if the entered text is valid and
    # saved to the query.  The object saved in the query is provided.

    regex_toggled = QtCore.pyqtSignal(bool)

    def __init__(self, title: str, query, attrname: str, completion: "List[str]",
                 validation: str = "", enable_regex: bool = True,
                 parent: "Optional[QtWidgets.QWidget]" = None) -> None:

        super().__init__(title, query, attrname, parent=parent)

        # Create grid layout inside this groupbox
        self.top_layout = QtWidgets.QGridLayout(self)
        self.top_layout.setContentsMargins(6, 6, 6, 6)
        self.top_layout.setSpacing(3)
        spacerItem = QtWidgets.QSpacerItem(40, 20,
                                           QtWidgets.QSizePolicy.Policy.Expanding,
                                           QtWidgets.QSizePolicy.Policy.Minimum)
        self.top_layout.addItem(spacerItem, 0, 3)

        # Create criteria LineEdit
        self.criteria = QtWidgets.QLineEdit(self)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding,
                                           QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.criteria.sizePolicy().hasHeightForWidth())
        self.criteria.setSizePolicy(sizePolicy)
        self.criteria.setObjectName(self.attrname)
        self.criteria.setClearButtonEnabled(True)
        self.criteria.setDragEnabled(True)
        self.criteria.textChanged.connect(self.clear_criteria_error)
        self.criteria.editingFinished.connect(self.set_criteria)
        self.top_layout.addWidget(self.criteria, 0, 0)

        # Create completer for LineEdit
        if completion:
            completer_model = QtCore.QStringListModel(self)
            completer_model.setStringList(sorted(completion))
            completer = QtWidgets.QCompleter()
            completer.setModel(completer_model)
            self.criteria.setCompleter(completer)

        # Create validators for LineEdit
        if validation:
            self.exact_validator = QtGui.QRegularExpressionValidator(
                QtCore.QRegularExpression(validation))
            # TODO Regex validator. Probably validation plus regex chars.
            self.criteria.setValidator(self.exact_validator)

        # Add error message output
        self.error_text = QtWidgets.QLabel(self)
        self.error_text.setObjectName("error_message")
        self.error_text.setFixedHeight(self.criteria.size().height())
        self.error_text.setFixedWidth(self.criteria.size().height())
        self.top_layout.addWidget(self.error_text, 0, 2, 1, 1)

        # Enable configured checkboxes
        if enable_regex:
            self.criteria_regex = QtWidgets.QCheckBox(self)
            self.criteria_regex.setObjectName(f"{self.attrname}_regex")
            self.criteria_regex.setText("Regex")
            self.criteria_regex.setToolTip("Enables regular expression matching.")
            self.criteria_regex.setToolTip("Enables regular expression matching.")
            self.criteria_regex.setWhatsThis(
                """
                <p><b>Regular expression matching<b></p>

                <p>This will enable matching using regular expressions instead
                of direct string comparisons.</p>
                """)
            self.top_layout.addWidget(self.criteria_regex, 0, 1, 1, 1)
            self.criteria_regex.toggled.connect(self.set_regex)
            self.criteria_regex.toggled.connect(self.regex_toggled)
            # set initial state:
            self.criteria_regex.setChecked(REGEX_DEFAULT_CHECKED)
            self.set_regex(REGEX_DEFAULT_CHECKED)

        QtCore.QMetaObject.connectSlotsByName(self)

    @property
    def has_errors(self) -> bool:
        """
        Get error state of this widget.

        If the error text is set, there is an error.
        """
        return bool(self.error_text.pixmap())

    def set_criteria(self) -> None:
        """Set the criteria field in the query."""
        try:
            name = self.criteria.objectName()
            self.log.debug(f"Setting {name} {self.criteria.text()!r}")
            setattr(self.query, name, self.criteria.text())
            self.editingFinished.emit(getattr(self.query, name))
        except Exception as e:
            error_icon = QtGui.QIcon.fromTheme(
                "messagebox-critical-icon",
                self.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_MessageBoxCritical))
            self.error_text.setPixmap(error_icon.pixmap(self.error_text.size()))
            self.error_text.setToolTip(f"Error: {e}")
            self.setStatusTip(f"{self.criteria.objectName()}: {e}")

    def clear_criteria_error(self) -> None:
        """Clear the error output from the criteria"""
        self.error_text.clear()
        self.error_text.setToolTip("")
        self.setStatusTip("")

    def set_regex(self, state: bool) -> None:
        """Set the regex boolean value."""
        self.log.debug(f"Setting {self.criteria_regex.objectName()} {state}")
        setattr(self.query, self.criteria_regex.objectName(), state)

        # reset criteria for the regex mode change
        self.clear_criteria_error()
        self.set_criteria()

        # change line edit validator
        if state:
            self.criteria.setValidator(cast(QtGui.QValidator, None))  # need validator for regexes
        else:
            self.criteria.setValidator(self.exact_validator)

    #
    # Workspace methods
    #

    def save(self, settings: "Dict") -> None:
        settings[self.criteria.objectName()] = self.criteria.text()
        with suppress(AttributeError):
            settings[self.criteria_regex.objectName()] = self.criteria_regex.isChecked()

    def load(self, settings: "Dict") -> None:
        with suppress(AttributeError, KeyError):
            self.criteria_regex.setChecked(settings[self.criteria_regex.objectName()])
        self.criteria.setText(settings[self.criteria.objectName()])
        self.criteria.editingFinished.emit()
