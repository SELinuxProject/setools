# SPDX-License-Identifier: LGPL-2.1-only

from collections import OrderedDict
from contextlib import suppress
import enum
import typing

from PyQt6 import QtWidgets
import setools

from .criteria import OptionsPlacement
from .name import NameWidget

IPV4_VALIDATION: typing.Final[str] = r"([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]+)?"
IPV6_VALIDATION: typing.Final[str] = r"[0-9a-fA-F:/]+"
IPV4_OR_IPV6_VALIDATION: typing.Final[str] = f"({IPV4_VALIDATION}|{IPV6_VALIDATION})"

__all__ = ("IP_NetworkName",)


class IP_NetworkName(NameWidget):

    """
    Base classs for widgets providing a QLineEdit that saves the input to the attributes
    of the specified query.  This supports inputs of IP networks, IPv4 or IPv6.
    """

    class Mode(enum.Enum):

        """Enumeration of widget modes."""

        IPV4_ONLY = IPV4_VALIDATION
        IPV6_ONLY = IPV6_VALIDATION
        IPV4_OR_IPV6 = IPV4_OR_IPV6_VALIDATION

    def __init__(self, title: str, query: setools.PolicyQuery, attrname: str, /, *,
                 required: bool = False,
                 mode: Mode = Mode.IPV4_OR_IPV6,
                 enable_range_opts: bool = False,
                 options_placement: OptionsPlacement = OptionsPlacement.RIGHT,
                 parent: QtWidgets.QWidget | None = None):

        super().__init__(title, query, attrname, [], mode.value, enable_regex=False,
                         options_placement=options_placement,
                         required=required, parent=parent)

        match mode:
            case IP_NetworkName.Mode.IPV4_ONLY:
                self.criteria.setPlaceholderText("e.g. 192.168.1.0/24")
                self.criteria.setToolTip("The IPv4 network to search for.")
            case IP_NetworkName.Mode.IPV6_ONLY:
                self.criteria.setPlaceholderText("e.g. 2001:db8::/64")
                self.criteria.setToolTip("The IPv6 network to search for.")
            case IP_NetworkName.Mode.IPV4_OR_IPV6:
                self.criteria.setPlaceholderText("e.g. 192.168.1.0/24 or 2001:db8::/64")
                self.criteria.setToolTip("The IPv4 or IPv6 network to search for.")
            case _:
                raise AssertionError("Invalid mode, this is an SETools bug.")

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

            # place option radio buttons
            match options_placement:
                case OptionsPlacement.BELOW:
                    self.top_layout.addWidget(equ, 1, 0, 1, 1)
                    self.top_layout.addWidget(ovl, 1, 1, 1, 1)

                case OptionsPlacement.RIGHT:
                    self.top_layout.addWidget(equ, 0, 1, 1, 1)
                    self.top_layout.addWidget(ovl, 0, 2, 1, 1)

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
