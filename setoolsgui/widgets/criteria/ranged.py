# SPDX-License-Identifier: LGPL-2.1-only

from collections import OrderedDict
from contextlib import suppress

from PyQt6 import QtWidgets
import setools

from .criteria import OptionsPlacement
from .name import NameWidget


class RangedWidget(NameWidget):

    """
    Base classs for widgets providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of ranges, e.g. port ranges and MLS ranges.
    """

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 required: bool = False,
                 validation: str = "",
                 enable_range_opts: bool = False,
                 options_placement: OptionsPlacement = OptionsPlacement.RIGHT,
                 parent: QtWidgets.QWidget | None = None):

        # Not much we can do here. Leave all validation to the query.
        super().__init__(title, query, attrname, [], validation, enable_regex=False,
                         options_placement=options_placement,
                         required=required, parent=parent)

        # the rstrip("_") below is to avoid names like "range__overlap"
        self.criteria_opts = OrderedDict[str, QtWidgets.QRadioButton]()
        if enable_range_opts:
            equ = QtWidgets.QRadioButton("Equal", parent=self)
            equ.setChecked(True)
            equ.toggled.connect(self._update_range_opts)
            self.criteria_opts[""] = equ

            ovl = QtWidgets.QRadioButton("Overlap", parent=self)
            ovl.setChecked(False)
            ovl.toggled.connect(self._update_range_opts)
            self.criteria_opts[f"{attrname.rstrip('_')}_overlap"] = ovl

            sub = QtWidgets.QRadioButton("Subset", parent=self)
            sub.setChecked(False)
            sub.toggled.connect(self._update_range_opts)
            self.criteria_opts[f"{attrname.rstrip('_')}_subset"] = sub

            sup = QtWidgets.QRadioButton("Superset", parent=self)
            sup.setChecked(False)
            sup.toggled.connect(self._update_range_opts)
            self.criteria_opts[f"{attrname.rstrip('_')}_superset"] = sup

            # place option radio buttons
            match options_placement:
                case OptionsPlacement.BELOW:
                    self.top_layout.addWidget(equ, 1, 0, 1, 1)
                    self.top_layout.addWidget(ovl, 1, 1, 1, 1)
                    self.top_layout.addWidget(sub, 2, 0, 1, 1)
                    self.top_layout.addWidget(sup, 2, 1, 1, 1)

                case OptionsPlacement.RIGHT:
                    self.top_layout.addWidget(equ, 0, 1, 1, 1)
                    self.top_layout.addWidget(ovl, 0, 2, 1, 1)
                    self.top_layout.addWidget(sub, 1, 1, 1, 1)
                    self.top_layout.addWidget(sup, 1, 2, 1, 1)

                case _:
                    raise AssertionError("Invalid options placement, this is an SETools bug.")

    def _update_range_opts(self, value: bool = True) -> None:
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
