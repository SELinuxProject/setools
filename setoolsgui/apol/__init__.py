# Copyright 2015, Tresys Technology, LLC
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

from .mainwindow import ApolMainWindow

# Analysis tabs:
from .boolquery import BoolQueryTab
from .boundsquery import BoundsQueryTab
from .categoryquery import CategoryQueryTab
from .commonquery import CommonQueryTab
from .constraintquery import ConstraintQueryTab
from .defaultquery import DefaultQueryTab
from .dta import DomainTransitionAnalysisTab
from .fsusequery import FSUseQueryTab
from .genfsconquery import GenfsconQueryTab
from .ibendportconquery import IbendportconQueryTab
from .ibpkeyconquery import IbpkeyconQueryTab
from .infoflow import InfoFlowAnalysisTab
from .initsidquery import InitialSIDQueryTab
from .mlsrulequery import MLSRuleQueryTab
from .netifconquery import NetifconQueryTab
from .nodeconquery import NodeconQueryTab
from .objclassquery import ObjClassQueryTab
from .portconquery import PortconQueryTab
from .rbacrulequery import RBACRuleQueryTab
from .rolequery import RoleQueryTab
from .sensitivityquery import SensitivityQueryTab
from .summary import SummaryTab
from .terulequery import TERuleQueryTab
from .typeattrquery import TypeAttributeQueryTab
from .typequery import TypeQueryTab
from .userquery import UserQueryTab
