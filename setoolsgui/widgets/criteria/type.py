# SPDX-License-Identifier: LGPL-2.1-only

from contextlib import suppress
import enum

from PyQt6 import QtCore, QtWidgets
import setools

from .criteria import OptionsPlacement
from .name import NameWidget

# Regex for exact matches to types/attrs
VALIDATE_EXACT = r"[A-Za-z0-9._-]*"

# indirect default setting (checked)
INDIRECT_DEFAULT_CHECKED = True

__all__ = ('TypeOrAttrName',)


class TypeOrAttrName(NameWidget):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of types, type attributes,
    or both.
    """

    indirect_toggled = QtCore.pyqtSignal(bool)

    class Mode(enum.Enum):

        """Enumeration of widget modes."""

        type_only = 1
        attribute_only = 2
        type_or_attribute = 3

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 parent: QtWidgets.QWidget | None = None,
                 options_placement: OptionsPlacement = OptionsPlacement.RIGHT,
                 mode: Mode = Mode.type_only,
                 enable_indirect: bool = False, enable_regex: bool = False,
                 required: bool = False):

        # Create completion list
        completion = list[str]()
        if mode in (TypeOrAttrName.Mode.type_only,
                    TypeOrAttrName.Mode.type_or_attribute):
            completion.extend(t.name for t in query.policy.types())
        if mode in (TypeOrAttrName.Mode.attribute_only,
                    TypeOrAttrName.Mode.type_or_attribute):
            completion.extend(a.name for a in query.policy.typeattributes())

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
                            mode=TypeOrAttrName.Mode.type_or_attribute,
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
