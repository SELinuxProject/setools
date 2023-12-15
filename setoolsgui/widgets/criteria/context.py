# SPDX-License-Identifier: LGPL-2.1-only
import typing

from PyQt6 import QtWidgets
import setools

from .. import criteria

SETTINGS_USER: typing.Final[str] = "user"
SETTINGS_ROLE: typing.Final[str] = "role"
SETTINGS_TYPE: typing.Final[str] = "type_"
SETTINGS_RANGE: typing.Final[str] = "range_"

__all__ = ("ContextMatch",)


class ContextMatch(criteria.CriteriaWidget):

    """Widget for providing criteria to match a context (labeling) statement."""

    def __init__(self, title: str, query: setools.PolicyQuery, /,
                 user_attrname: str = SETTINGS_USER,
                 role_attrname: str = SETTINGS_ROLE,
                 type_attrname: str = SETTINGS_TYPE,
                 range_attrname: str = SETTINGS_RANGE, *,
                 parent: QtWidgets.QWidget | None = None) -> None:

        super().__init__(title, query, "", parent=parent)

        self.user_attrname: typing.Final = user_attrname
        self.role_attrname: typing.Final = role_attrname
        self.type_attrname: typing.Final = type_attrname
        self.range_attrname: typing.Final = range_attrname

        self.top_layout = QtWidgets.QHBoxLayout(self)
        self.top_layout.setContentsMargins(6, 6, 6, 6)
        self.top_layout.setSpacing(3)

        user = criteria.UserName("Context User", self.query, user_attrname,
                                 enable_regex=True,
                                 options_placement=criteria.OptionsPlacement.BELOW,
                                 parent=self)
        user.setToolTip("The user for context matching.")
        user.setWhatsThis(
            """
            <p><b>Enter the user for context matching.</b></p>

            <p>If regex is enabled, a regular expression is used for matching
            the user name instead of direct string comparison.</p>
            """)

        role = criteria.RoleName("Context Role", self.query, role_attrname,
                                 enable_regex=True,
                                 options_placement=criteria.OptionsPlacement.BELOW,
                                 parent=self)
        role.setToolTip("The role for context matching.")
        role.setWhatsThis(
            """
            <p><b>Enter the role for context matching.</b></p>

            <p>If regex is enabled, a regular expression is used for matching
            the role name instead of direct string comparison.</p>
            """)

        type_ = criteria.TypeName("Context Type", self.query, type_attrname,
                                  enable_regex=True,
                                  enable_indirect=False,
                                  required=False,
                                  options_placement=criteria.OptionsPlacement.BELOW,
                                  parent=self)
        type_.setToolTip("The type for context matching.")
        type_.setWhatsThis(
            """
            <p>The type for context matching.</p>

            <p>If regex is enabled, a regular expression is used for matching
            the type name instead of direct string comparison.</p>
            """)

        rng = criteria.MLSRangeName("Context MLS Range",
                                    self.query,
                                    range_attrname,
                                    enable_range_opts=True,
                                    options_placement=criteria.OptionsPlacement.BELOW,
                                    parent=self)
        if query.policy.mls:
            rng.setToolTip("The MLS range for context matching.")
            rng.setWhatsThis(
                """
                <p>The MLS range for context matching.</p>
                """)
        else:
            rng.setEnabled(False)
            rng.setToolTip("MLS is disabled in this policy.")
            rng.setWhatsThis(
                """
                <p>This MLS range for context matching is not available because
                MLS is disabled in this policy.</p>
                """)

        #
        # Add widgets to layout
        #
        self.top_layout.addWidget(user)
        self.top_layout.addWidget(role)
        self.top_layout.addWidget(type_)
        self.top_layout.addWidget(rng)

        self.criteria = (user, role, type_, rng)

    @property
    def has_errors(self) -> bool:
        """Get error state of this widget."""
        return any(c.has_errors for c in self.criteria)

    #
    # Save/Load field
    #

    def save(self, settings: dict) -> None:
        """Save the widget settings to the settings dictionary."""
        for c in self.criteria:
            c.save(settings)

    def load(self, settings: dict) -> None:
        """Load the widget settings from the settings dictionary."""
        for c in self.criteria:
            c.load(settings)


if __name__ == '__main__':
    import sys
    import logging
    import warnings

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
    warnings.simplefilter("default")

    q = setools.PortconQuery(setools.SELinuxPolicy())

    app = QtWidgets.QApplication(sys.argv)
    mw = QtWidgets.QMainWindow()
    widget = ContextMatch("Test Context Match", q, parent=mw)
    widget.setToolTip("test tooltip")
    widget.setWhatsThis("test whats this")
    mw.setCentralWidget(widget)
    mw.resize(widget.size())
    whatsthis = QtWidgets.QWhatsThis.createAction(mw)
    mw.menuBar().addAction(whatsthis)  # type: ignore[union-attr]
    mw.setStatusBar(QtWidgets.QStatusBar(mw))
    mw.show()
    rc = app.exec()
