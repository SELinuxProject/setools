# SPDX-License-Identifier: LGPL-2.1-only

from collections import OrderedDict
from contextlib import suppress
import typing

from PyQt6 import QtWidgets
import setools

from .criteria import OptionsPlacement
from .name import NameWidget
from .ranged import RangedWidget

LEVEL_VALIDATION: typing.Final[str] = r"[A-Za-z0-9.,_:]+"
RANGE_VALIDATION: typing.Final[str] = r"[A-Za-z0-9.,_:]+ ?(- ?[A-Za-z0-9.,_:]+)?"

__all__ = ("MLSLevelName", "MLSRangeName")


class MLSLevelName(NameWidget):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of MLS levels.
    """

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 required: bool = False, enable_opts: bool = False,
                 options_placement: OptionsPlacement = OptionsPlacement.RIGHT,
                 parent: QtWidgets.QWidget | None = None):

        # Not much we can do here. Leave all validation to the query.
        super().__init__(title, query, attrname, [], LEVEL_VALIDATION, enable_regex=False,
                         options_placement=options_placement,
                         required=required, parent=parent)

        # the rstrip("_") below is to avoid names like "range__overlap"
        self.criteria_opts = OrderedDict[str, QtWidgets.QRadioButton]()
        if enable_opts:
            equ = QtWidgets.QRadioButton("Equal", parent=self)
            equ.setChecked(True)
            equ.setToolTip("The statement will match if the criteria is equal.")
            equ.toggled.connect(self._update_radio_opts)
            self.criteria_opts[""] = equ

            dom = QtWidgets.QRadioButton("Dominate", parent=self)
            dom.setChecked(False)
            dom.setToolTip("The statement will match if the criteria dominates the level.")
            dom.toggled.connect(self._update_radio_opts)
            self.criteria_opts[f"{attrname.rstrip('_')}_dom"] = dom

            domby = QtWidgets.QRadioButton("Dominated By", parent=self)
            domby.setChecked(False)
            domby.setToolTip("The statement will match if the criteria is dominated by the level.")
            domby.toggled.connect(self._update_radio_opts)
            self.criteria_opts[f"{attrname.rstrip('_')}_domby"] = domby

            incomp = QtWidgets.QRadioButton("Imcomparable", parent=self)
            incomp.setChecked(False)
            incomp.setToolTip("The statement will match if the criteria is "
                              "incomparable to the level.")
            incomp.toggled.connect(self._update_radio_opts)
            self.criteria_opts[f"{attrname.rstrip('_')}_incomp"] = incomp

            # place option radio buttons
            match options_placement:
                case OptionsPlacement.BELOW:
                    self.top_layout.addWidget(equ, 1, 0, 1, 1)
                    self.top_layout.addWidget(dom, 1, 1, 1, 1)
                    self.top_layout.addWidget(domby, 2, 0, 1, 1)
                    self.top_layout.addWidget(incomp, 2, 1, 1, 1)

                case OptionsPlacement.RIGHT:
                    self.top_layout.addWidget(equ, 0, 1, 1, 1)
                    self.top_layout.addWidget(dom, 0, 2, 1, 1)
                    self.top_layout.addWidget(domby, 1, 1, 1, 1)
                    self.top_layout.addWidget(incomp, 1, 2, 1, 1)

                case _:
                    raise AssertionError("Invalid options placement, this is an SETools bug.")

    def _update_radio_opts(self, value: bool = True) -> None:
        """Update the query based on the range opts radio button state."""
        if not value:
            return  # only apply updates once per radio button switch

        for name, w in self.criteria_opts.items():
            if name:  # empty means equal, which is the default
                self.log.debug(f"Setting {name} to {w.isChecked()}")
                setattr(self.query, name, w.isChecked())

    def save(self, settings: dict) -> None:
        super().save(settings)
        for name, w in self.criteria_opts.items():
            if name:
                settings[name] = w.isChecked()

    def load(self, settings: dict) -> None:
        for name, w in self.criteria_opts.items():
            if name:
                with suppress(AttributeError, KeyError):
                    w.setChecked(settings[name])

        super().load(settings)


class MLSRangeName(RangedWidget):

    """
    Widget providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of MLS ranges.
    """

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 required: bool = False,
                 enable_range_opts: bool = False,
                 options_placement: OptionsPlacement = OptionsPlacement.RIGHT,
                 parent: QtWidgets.QWidget | None = None):

        super().__init__(title, query, attrname, validation=RANGE_VALIDATION,
                         enable_range_opts=enable_range_opts, required=required,
                         options_placement=options_placement, parent=parent)


if __name__ == '__main__':
    import sys
    import logging
    import warnings

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.MLSRuleQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    widget = MLSRangeName("Test Range", q, "default", enable_range_opts=True, parent=mw)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    sys.exit(app.exec())
