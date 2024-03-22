# SPDX-License-Identifier: LGPL-2.1-only
#
from collections import defaultdict
import typing

from . import difference
from .. import policyrep


PE = typing.TypeVar("PE", bound=policyrep.PolicyEnum)
PO = typing.TypeVar("PO", bound=policyrep.PolicyObject)
PS = typing.TypeVar("PS", bound=policyrep.PolicySymbol)
PR = typing.TypeVar("PR", bound=policyrep.AnyConstraint | policyrep.PolicyRule)
WR = typing.TypeVar("WR", bound=difference.Wrapper)

Cache = defaultdict[policyrep.SELinuxPolicy, dict[PO, WR]]
SymbolCache = Cache[PS, difference.SymbolWrapper[PS]]

RuleList = defaultdict[PE, list[PR]] | None
