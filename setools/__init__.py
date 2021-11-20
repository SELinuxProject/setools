"""The SETools SELinux policy analysis library."""
# Copyright 2014-2015, Tresys Technology, LLC
# Copyright 2016, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
try:
    import pkg_resources
    # pylint: disable=no-member
    __version__ = pkg_resources.get_distribution("setools").version
except ImportError:  # pragma: no cover
    __version__ = "unknown"

import logging

# Python classes for policy representation
from .policyrep import SELinuxPolicy, BoundsRuletype, ConstraintRuletype, DefaultRuletype, \
    DefaultRangeValue, DefaultValue, FSUseRuletype, HandleUnknown, IbpkeyconRange, MLSRuletype, \
    NodeconIPVersion, PolicyTarget, PortconProtocol, RBACRuletype, TERuletype

# Policy representation classes for type checking purposes.  Few can be instantiated
# outside of this library.
from .policyrep import AnyConstraint, AnyDefault, AnyRBACRule, AnyTERule, AVRule, AVRuleXperm, \
    Boolean, Bounds, Category, Common, Conditional, Constraint, Context, Default, DefaultRange, \
    Devicetreecon, FSUse, FileNameTERule, Genfscon, Ibendportcon, Ibpkeycon, InitialSID, \
    IoctlSet, Iomemcon, IomemconRange, Ioportcon, IoportconRange, Level, LevelDecl, MLSRule, \
    Netifcon, Nodecon, ObjClass, Pcidevicecon, Pirqcon, PolicyCapability, Portcon, PortconRange, \
    Range, Role, RoleAllow, RoleTransition, Sensitivity, TERule, TruthTableRow, Type, \
    TypeAttribute, User, Validatetrans

# Exceptions
from . import exception

# Base class for policy queries for type checking purposes
from .query import PolicyQuery

# utility functions
from .util import xperm_str_to_tuple_ranges

# Component Queries
from .boolquery import BoolQuery
from .categoryquery import CategoryQuery
from .commonquery import CommonQuery
from .objclassquery import ObjClassQuery
from .polcapquery import PolCapQuery
from .rolequery import RoleQuery
from .sensitivityquery import SensitivityQuery
from .typequery import TypeQuery
from .typeattrquery import TypeAttributeQuery
from .userquery import UserQuery

# Rule Queries
from .mlsrulequery import MLSRuleQuery
from .rbacrulequery import RBACRuleQuery
from .terulequery import TERuleQuery

# Constraint queries
from .constraintquery import ConstraintQuery

# Other queries
from .boundsquery import BoundsQuery
from .defaultquery import DefaultQuery

# In-policy Context Queries
from .fsusequery import FSUseQuery
from .genfsconquery import GenfsconQuery
from .ibendportconquery import IbendportconQuery
from .ibpkeyconquery import IbpkeyconQuery
from .initsidquery import InitialSIDQuery
from .netifconquery import NetifconQuery
from .nodeconquery import NodeconQuery
from .portconquery import PortconQuery
from .ioportconquery import IoportconQuery
from .iomemconquery import IomemconQuery
from .pirqconquery import PirqconQuery
from .pcideviceconquery import PcideviceconQuery
from .devicetreeconquery import DevicetreeconQuery

# Information Flow Analysis
from .infoflow import InfoFlowAnalysis
from .permmap import PermissionMap, RuleWeight, Mapping

# Domain Transition Analysis
from .dta import DomainTransitionAnalysis, DomainEntrypoint, DomainTransition

# Policy difference
from .diff import PolicyDifference

# Policy checker
from .checker import PolicyChecker

logging.getLogger(__name__).addHandler(logging.NullHandler())
