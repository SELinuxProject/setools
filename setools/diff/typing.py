# SPDX-License-Identifier: LGPL-2.1-only
#
from typing import DefaultDict, Dict, List, Optional, TypeVar, Union

from ..policyrep import AnyConstraint, PolicyEnum, PolicyObject, PolicyRule, PolicySymbol, \
                        SELinuxPolicy

from .difference import Wrapper, SymbolWrapper


PE = TypeVar("PE", bound=PolicyEnum)
PO = TypeVar("PO", bound=PolicyObject)
PS = TypeVar("PS", bound=PolicySymbol)
PR = TypeVar("PR", bound=Union[AnyConstraint, PolicyRule])
WR = TypeVar("WR", bound=Wrapper)

Cache = DefaultDict[SELinuxPolicy, Dict[PO, WR]]
SymbolCache = Cache[PS, SymbolWrapper[PS]]

RuleList = Optional[DefaultDict[PE, List[PR]]]
