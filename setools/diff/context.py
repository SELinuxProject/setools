# Copyright 2016, Tresys Technology, LLC
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with SETools.  If not, see
# <http://www.gnu.org/licenses/>.
#
from ..policyrep.exception import MLSDisabled

from .difference import SymbolWrapper, Wrapper
from .mls import RangeWrapper


class ContextWrapper(Wrapper):

    """Wrap contexts to allow comparisons."""

    def __init__(self, ctx):
        self.origin = ctx
        self.user = SymbolWrapper(ctx.user)
        self.role = SymbolWrapper(ctx.role)
        self.type_ = SymbolWrapper(ctx.type_)

        try:
            self.range_ = RangeWrapper(ctx.range_)
        except MLSDisabled:
            self.range_ = None

    def __eq__(self, other):
        return self.user == other.user and \
               self.role == other.role and \
               self.type_ == other.type_ and \
               self.range_ == other.range_
