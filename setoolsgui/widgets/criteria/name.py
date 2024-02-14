# SPDX-License-Identifier: LGPL-2.1-only

from contextlib import suppress

from PyQt6 import QtCore, QtGui, QtWidgets

from .criteria import CriteriaWidget, OptionsPlacement

# regex default setting (unchecked)
REGEX_DEFAULT_CHECKED = False

__all__ = ('NameWidget',)


class NameWidget(CriteriaWidget):

    """
    Base class widget providing a QLineEdit that saves the input to the
    attributes of the specified query.
    """

    # Is it required that this be filled out?
    required: bool = False

    editingFinished = QtCore.pyqtSignal(object)
    # This signal is only emitted if the entered text is valid and
    # saved to the query.  The object saved in the query is provided.

    regex_toggled = QtCore.pyqtSignal(bool)

    #
    # Overridden methods
    #

    def __init__(self, title: str, query, attrname: str, completion: list[str],
                 validation: str = "", enable_regex: bool = True,
                 required: bool = False,
                 options_placement: OptionsPlacement = OptionsPlacement.RIGHT,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(title, query, attrname, parent=parent)
        self.required = required

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

        # place error message widget
        match options_placement:
            case OptionsPlacement.BELOW:
                self.top_layout.addWidget(self.error_text, 0, 1, 1, 1)
            case OptionsPlacement.RIGHT:
                self.top_layout.addWidget(self.error_text, 1, 0, 1, 1)
            case _:
                raise AssertionError(
                    f"Invalid options placement {options_placement}, this is an SETools bug.")

        # Enable configured checkboxes
        if enable_regex:
            self.criteria_regex = QtWidgets.QCheckBox(self)
            # the rstrip(_) is to avoid names like "type__regex"
            self.criteria_regex.setObjectName(f"{self.attrname.rstrip('_')}_regex")
            self.criteria_regex.setText("Regex")
            self.criteria_regex.setToolTip("Enables regular expression matching.")
            self.criteria_regex.setToolTip("Enables regular expression matching.")
            self.criteria_regex.setWhatsThis(
                """
                <p><b>Regular expression matching<b></p>

                <p>This will enable matching using regular expressions instead
                of direct string comparisons.</p>
                """)
            self.criteria_regex.toggled.connect(self.set_regex)
            self.criteria_regex.toggled.connect(self.regex_toggled)
            # set initial state:
            self.criteria_regex.setChecked(REGEX_DEFAULT_CHECKED)
            self.set_regex(REGEX_DEFAULT_CHECKED)

            # place widget
            match options_placement:
                case OptionsPlacement.RIGHT:
                    self.top_layout.addWidget(self.criteria_regex, 0, 1, 1, 1)
                case OptionsPlacement.BELOW:
                    self.top_layout.addWidget(self.criteria_regex, 1, 0, 1, 1)
                case _:
                    raise AssertionError(
                        f"Invalid options placement {options_placement}, this is an SETools bug.")

        QtCore.QMetaObject.connectSlotsByName(self)

    def setDisabled(self, value: bool) -> None:
        super().setDisabled(value)
        if value:
            # clear error when disabling
            self.clear_criteria_error()
        else:
            # reapply criteria when enabling.
            self.set_criteria()

    def setEnabled(self, value: bool) -> None:
        super().setEnabled(value)
        if value:
            # reapply criteria when enabling.
            self.set_criteria()
        else:
            # clear error when disabling
            self.clear_criteria_error()

    #
    # Custom methods
    #

    @property
    def has_errors(self) -> bool:
        """
        Get error state of this widget.

        If the error text is set, there is an error.
        """
        if self.required and self.isEnabled() and not self.criteria.text().strip() \
                and not bool(self.error_text.pixmap()):

            self.set_criteria_error(f"{self.attrname} is required.")

        return bool(not self.error_text.pixmap().isNull())

    def clear_criteria_error(self) -> None:
        """Clear the error output from the criteria"""
        self.error_text.clear()
        self.error_text.setToolTip("")
        self.setStatusTip("")

    def set_criteria(self) -> None:
        """Set the criteria field in the query."""
        try:
            name = self.criteria.objectName()
            self.log.debug(f"Setting {name} {self.criteria.text()!r}")
            setattr(self.query, name, self.criteria.text())
            self.editingFinished.emit(getattr(self.query, name))
        except Exception as e:
            self.set_criteria_error(str(e))
            self.log.debug(f"Error setting {name}: {e}", exc_info=True)

    def set_criteria_error(self, message: str) -> None:
        """Set the error output from the criteria."""
        error_icon = QtGui.QIcon.fromTheme(
            "messagebox-critical-icon",
            self.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_MessageBoxCritical))
        self.error_text.setPixmap(error_icon.pixmap(self.error_text.size()))
        self.error_text.setToolTip(f"Error: {message}")
        self.setStatusTip(f"{self.criteria.objectName()}: {message}")

    def set_regex(self, state: bool) -> None:
        """Set the regex boolean value."""
        self.log.debug(f"Setting {self.criteria_regex.objectName()} {state}")
        setattr(self.query, self.criteria_regex.objectName(), state)

        # reset criteria for the regex mode change
        self.clear_criteria_error()
        self.set_criteria()

        # change line edit validator
        with suppress(AttributeError):  # May not have a validator
            if state:
                self.criteria.setValidator(None)
            else:
                self.criteria.setValidator(self.exact_validator)

    #
    # Workspace methods
    #

    def save(self, settings: dict) -> None:
        settings[self.criteria.objectName()] = self.criteria.text()
        with suppress(AttributeError):
            settings[self.criteria_regex.objectName()] = self.criteria_regex.isChecked()

    def load(self, settings: dict) -> None:
        with suppress(AttributeError, KeyError):
            self.criteria_regex.setChecked(settings[self.criteria_regex.objectName()])
        self.criteria.setText(settings[self.criteria.objectName()])
        self.criteria.editingFinished.emit()
