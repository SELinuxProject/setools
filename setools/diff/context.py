# Copyright 2016, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#

from ..exception import MLSDisabled
from ..policyrep import Context

from .difference import Wrapper
from .mls import RangeWrapper
from .roles import role_wrapper_factory
from .types import type_wrapper_factory
from .users import user_wrapper_factory


class ContextWrapper(Wrapper[Context]):

    """Wrap contexts to allow comparisons."""

    __slots__ = ("user", "role", "type_", "range_")

    def __init__(self, ctx: Context) -> None:
        self.origin = ctx
        self.user = user_wrapper_factory(ctx.user)
        self.role = role_wrapper_factory(ctx.role)
        self.type_ = type_wrapper_factory(ctx.type_)
        self.range_: RangeWrapper | None

        try:
            self.range_ = RangeWrapper(ctx.range_)
        except MLSDisabled:
            self.range_ = None

    def __hash__(self):
        return hash(self.origin)

    def __eq__(self, other):
        return self.user == other.user and \
            self.role == other.role and \
            self.type_ == other.type_ and \
            self.range_ == other.range_

    def __lt__(self, other):
        return self.user < other.user and \
            self.role < other.role and \
            self.type_ < other.type_ and \
            self.range_ < other.range_
