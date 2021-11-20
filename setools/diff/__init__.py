# Copyright 2015-2016, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from .bool import BooleansDifference
from .bounds import BoundsDifference
from .commons import CommonDifference
from .constraints import ConstraintsDifference
from .default import DefaultsDifference
from .fsuse import FSUsesDifference
from .genfscon import GenfsconsDifference
from .ibendportcon import IbendportconsDifference
from .ibpkeycon import IbpkeyconsDifference
from .initsid import InitialSIDsDifference
from .mls import CategoriesDifference, LevelDeclsDifference, SensitivitiesDifference
from .mlsrules import MLSRulesDifference
from .netifcon import NetifconsDifference
from .nodecon import NodeconsDifference
from .objclass import ObjClassDifference
from .polcap import PolCapsDifference
from .portcon import PortconsDifference
from .properties import PropertiesDifference
from .rbacrules import RBACRulesDifference
from .roles import RolesDifference
from .terules import TERulesDifference
from .typeattr import TypeAttributesDifference
from .types import TypesDifference
from .users import UsersDifference

__all__ = ['PolicyDifference']


class PolicyDifference(BooleansDifference,
                       BoundsDifference,
                       CategoriesDifference,
                       CommonDifference,
                       ConstraintsDifference,
                       DefaultsDifference,
                       FSUsesDifference,
                       GenfsconsDifference,
                       IbendportconsDifference,
                       IbpkeyconsDifference,
                       InitialSIDsDifference,
                       LevelDeclsDifference,
                       MLSRulesDifference,
                       NetifconsDifference,
                       NodeconsDifference,
                       ObjClassDifference,
                       PolCapsDifference,
                       PortconsDifference,
                       PropertiesDifference,
                       RBACRulesDifference,
                       RolesDifference,
                       SensitivitiesDifference,
                       TERulesDifference,
                       TypeAttributesDifference,
                       TypesDifference,
                       UsersDifference):

    """
    Determine the differences from the left policy to the right policy.

    Parameters:
    left    A policy
    right   A policy
    """

    def _reset_diff(self):
        """Reset diff results on policy changes."""
        for c in PolicyDifference.__bases__:
            c._reset_diff(self)
