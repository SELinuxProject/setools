# SPDX-License-Identifier: LGPL-2.1-only

from contextlib import suppress
from enum import Enum
import logging
from typing import TYPE_CHECKING

from PyQt5 import QtCore, QtGui, QtWidgets

from .name import NameCriteriaWidget

if TYPE_CHECKING:
    from typing import Dict, List, Optional

# Regex for exact matches to types/attrs
VALIDATE_EXACT = r"[A-Za-z0-9._-]*"

# indirect default setting (checked)
INDIRECT_DEFAULT_CHECKED = True


class TypeOrAttrNameMode(Enum):

    type_only = 1
    attribute_only = 2
    type_or_attribute = 3


class TypeOrAttrNameWidget(NameCriteriaWidget):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of types, type attributes,
    or both.
    """

    indirect_toggled = QtCore.pyqtSignal(bool)

    def __init__(self, title: str, query, attrname: str,
                 parent: "Optional[QtWidgets.QWidget]" = None,
                 mode: TypeOrAttrNameMode = TypeOrAttrNameMode.type_only,
                 enable_indirect: bool = False, enable_regex: bool = False):

        # Create completion list
        completion: "List[str]" = []
        if mode in (TypeOrAttrNameMode.type_only, TypeOrAttrNameMode.type_or_attribute):
            completion.extend(t.name for t in query.policy.types())
        if mode in (TypeOrAttrNameMode.attribute_only, TypeOrAttrNameMode.type_or_attribute):
            completion.extend(a.name for a in query.policy.typeattributes())

        super().__init__(title, query, attrname, completion, VALIDATE_EXACT,
                         enable_regex=enable_regex, parent=parent)

        if enable_indirect:
            self.criteria_indirect = QtWidgets.QCheckBox(self)
            self.criteria_indirect.setObjectName(f"{attrname}_indirect")
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

    def set_indirect(self, state: bool) -> None:
        """Set the indirect boolean value."""
        self.log.debug(f"Setting {self.criteria_indirect.objectName()} {state}")
        setattr(self.query, self.criteria_indirect.objectName(), state)

    #
    # Workspace methods
    #

    def save(self, settings: "Dict") -> None:
        super().save(settings)
        with suppress(AttributeError):
            settings[self.criteria_indirect.objectName()] = self.criteria_indirect.isChecked()

    def load(self, settings: "Dict") -> None:
        with suppress(AttributeError, KeyError):
            self.criteria_indirect.setChecked(settings[self.criteria_indirect.objectName()])
        super().load(settings)


if __name__ == '__main__':
    import sys
    import warnings
    import setools
    import pprint

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.TERuleQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    widget = TypeOrAttrNameWidget("Test Type/Attribute", q, "source", mw,
                                  TypeOrAttrNameMode.type_or_attribute, True, True)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec_()
    print("source:", q.source)
    print("regex:", q.source_regex)
    print("indirect:", q.source_indirect)
    print("Errors?", widget.has_errors)

    # basic test of save/load
    settings: dict = {}
    widget.save(settings)
    pprint.pprint(settings)
    settings["source"] = "user_t"
    widget.load(settings)

    print("Query final state")
    print("source:", q.source)
    print("regex:", q.source_regex)
    print("indirect:", q.source_indirect)
    print("Errors?", widget.has_errors)
    sys.exit(rc)
