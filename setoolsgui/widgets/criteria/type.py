# SPDX-License-Identifier: LGPL-2.1-only

from contextlib import suppress
import itertools
import typing

from PyQt6 import QtCore, QtWidgets
import setools

from .. import models
from .criteria import CriteriaWidget, OptionsPlacement
from .list import ListWidget
from .name import NameWidget

# permissive default setting (not checked)
PERMISSIVE_DEFAULT_CHECKED: typing.Final[bool] = False

# Regex for exact matches to types/attrs
VALIDATE_EXACT: typing.Final[str] = r"[A-Za-z0-9._-]*"

# indirect default setting (checked)
INDIRECT_DEFAULT_CHECKED: typing.Final[bool] = True

__all__ = ('PermissiveType', 'TypeList', 'TypeName', 'TypeOrAttrName',)


class PermissiveType(CriteriaWidget):

    """A widget providing a QCheckBox widget for selecting permissive types."""

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(title, query, attrname, parent=parent)

        self.top_layout = QtWidgets.QHBoxLayout(self)

        self.criteria = QtWidgets.QCheckBox(self)
        self.criteria.setText("Permissive")
        self.criteria.setToolTip("Permissive types will match.")
        self.criteria.setWhatsThis("<b>Permissive types will match.</b>")
        self.criteria.toggled.connect(self._update_query)
        self.top_layout.addWidget(self.criteria)

        # set initial state:
        self.criteria.setChecked(PERMISSIVE_DEFAULT_CHECKED)

    @property
    def has_errors(self) -> bool:
        """Get error state of this widget."""
        return False

    def _update_query(self, state: bool) -> None:
        """Set the permissive boolean value."""
        self.log.debug(f"Setting {self.attrname} {state}")
        setattr(self.query, self.attrname, state)

    #
    # Save/Load field
    #

    def save(self, settings: dict) -> None:
        """Save the widget settings to the settings dictionary."""
        settings[self.attrname] = self.criteria.isChecked()

    def load(self, settings: dict) -> None:
        """Load the widget settings from the settings dictionary."""
        with suppress(KeyError):
            self.criteria.setChecked(settings[self.attrname])


class TypeList(ListWidget):

    """A widget providing a QListView widget for selecting the types."""

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str,
                 enable_equal: bool = False, enable_subset: bool = False,
                 parent: QtWidgets.QWidget | None = None) -> None:

        model = models.TypeTable(data=sorted(query.policy.types()))

        super().__init__(title, query, attrname, model, enable_equal=enable_equal,
                         enable_subset=enable_subset, parent=parent)

        self.criteria_any.setToolTip("Any selected type will match.")
        self.criteria_any.setWhatsThis("<b>Any selected type will match.</b>")


class TypeName(NameWidget):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of types.
    """

    indirect_toggled = QtCore.pyqtSignal(bool)

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 parent: QtWidgets.QWidget | None = None,
                 options_placement: OptionsPlacement = OptionsPlacement.RIGHT,
                 enable_indirect: bool = False, enable_regex: bool = False,
                 required: bool = False):

        # Create completion list
        completion = list[str](t.name for t in query.policy.types())

        super().__init__(title, query, attrname, completion, VALIDATE_EXACT,
                         enable_regex=enable_regex, required=required,
                         options_placement=options_placement, parent=parent)

        if enable_indirect:
            self.criteria_indirect = QtWidgets.QCheckBox(self)
            # the rstrip("_") is to avoid names like "type__indirect"
            self.criteria_indirect.setObjectName(f"{attrname.rstrip('_')}_indirect")
            self.criteria_indirect.setText("Indirect")
            self.criteria_indirect.setToolTip("Enables indirect matching.")
            self.criteria_indirect.setWhatsThis(
                """
                <p><b>Indirect matching<b></p>

                <p>If the criteria is an attribute, indirect will
                match the criteria against the contents of the
                attribute, rather than the attribute itself.</p>
                """)
            self.top_layout.addWidget(self.criteria_indirect, 1, 1, 1, 1)
            self.criteria_indirect.toggled.connect(self.set_indirect)
            self.criteria_indirect.toggled.connect(self.indirect_toggled)
            # set initial state:
            self.criteria_indirect.setChecked(INDIRECT_DEFAULT_CHECKED)
            self.set_indirect(INDIRECT_DEFAULT_CHECKED)

            # place widget.
            match options_placement:
                case OptionsPlacement.RIGHT | OptionsPlacement.BELOW:
                    self.top_layout.addWidget(self.criteria_indirect, 1, 1, 1, 1)
                case _:
                    raise AssertionError(
                        f"Invalid options placement {options_placement}, this is an SETools bug.")

    def set_indirect(self, state: bool) -> None:
        """Set the indirect boolean value."""
        self.log.debug(f"Setting {self.criteria_indirect.objectName()} {state}")
        setattr(self.query, self.criteria_indirect.objectName(), state)

    #
    # Workspace methods
    #

    def save(self, settings: dict) -> None:
        super().save(settings)
        with suppress(AttributeError):
            settings[self.criteria_indirect.objectName()] = self.criteria_indirect.isChecked()

    def load(self, settings: dict) -> None:
        with suppress(AttributeError, KeyError):
            self.criteria_indirect.setChecked(settings[self.criteria_indirect.objectName()])
        super().load(settings)


class TypeOrAttrName(TypeName):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of types or attributes.
    """

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 parent: QtWidgets.QWidget | None = None,
                 options_placement: OptionsPlacement = OptionsPlacement.RIGHT,
                 enable_indirect: bool = False, enable_regex: bool = False,
                 required: bool = False):

        super().__init__(title, query, attrname, options_placement=options_placement,
                         enable_indirect=enable_indirect, enable_regex=enable_regex,
                         required=required, parent=parent)

        # add attributes to completion list
        completer = self.criteria.completer()
        assert completer, "Completer not set, this is an SETools bug."
        model = typing.cast(QtCore.QStringListModel, completer.model())
        assert model, "Model not set, this is an SETools bug."
        model.setStringList(sorted(itertools.chain(
            (a.name for a in query.policy.typeattributes()),
            (t.name for t in query.policy.types())
        )))


if __name__ == '__main__':
    import sys
    import warnings
    import pprint
    import logging

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.TERuleQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    widget = TypeOrAttrName("Test Type/Attribute", q, "source", parent=mw,
                            enable_regex=True, enable_indirect=True)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
    print("source:", q.source)
    print("regex:", q.source_regex)
    print("indirect:", q.source_indirect)
    print("Errors?", widget.has_errors)

    # basic test of save/load
    saved_settings: dict = {}
    widget.save(saved_settings)
    pprint.pprint(saved_settings)
    saved_settings["source"] = "user_t"
    widget.load(saved_settings)

    print("Query final state")
    print("source:", q.source)
    print("regex:", q.source_regex)
    print("indirect:", q.source_indirect)
    print("Errors?", widget.has_errors)
    sys.exit(rc)
