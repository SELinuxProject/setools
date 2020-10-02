# Copyright 2015-2016, Tresys Technology, LLC
# Copyright 2016, 2018, Chris PeBenito <pebenito@ieee.org>
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
import logging
from collections import defaultdict
from sys import intern
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, NamedTuple, Optional, Set, Tuple, Union

from ..exception import RuleNotConditional, RuleUseError, TERuleNoFilename
from ..policyrep import AnyTERule, AVRule, AVRuleXperm, Conditional, IoctlSet, TERuletype, Type

from .conditional import conditional_wrapper_factory
from .descriptors import DiffResultDescriptor
from .difference import Difference, Wrapper
from .types import type_wrapper_factory, type_or_attr_wrapper_factory
from .typing import RuleList
from .objclass import class_wrapper_factory

TERULES_UNCONDITIONAL = intern("<<unconditional>>")
TERULES_UNCONDITIONAL_BLOCK = intern("True")


class ModifiedAVRule(NamedTuple):

    """Difference details for a modified access vector rule."""

    rule: AVRule
    added_perms: Union[Set[str], IoctlSet]
    removed_perms: Union[Set[str], IoctlSet]
    matched_perms: Union[Set[str], IoctlSet]


class ModifiedTERule(NamedTuple):

    """Difference details for a modified type_* rule."""

    rule: AVRule
    added_default: Type
    removed_default: Type


#
# Internal datastructure types
#
class Side(Enum):
    left = 0
    right = 1


class RuleDBSideDataRecord(NamedTuple):
    perms: Set[str]
    orig_rule: AVRule


class RuleDBSidesRecord(NamedTuple):
    left: Optional[RuleDBSideDataRecord]
    right: Optional[RuleDBSideDataRecord]


class TypeDBRecord(NamedTuple):
    left: Dict[str, Type]
    right: Dict[str, Type]


# These conditional items are unioned with str to handle unconditional rules
CondExp = Union[Conditional, str]
CondBlock = Union[bool, str]
RuleDB = Dict[CondExp, Dict[CondBlock, Dict[str, Dict[str, Dict[str, RuleDBSidesRecord]]]]]


def _avrule_expand_generator(rule_list: List[AVRule], rule_db: RuleDB, type_db: TypeDBRecord,
                             side: Side) -> None:
    """
    Using rule_list, build up rule_db which is a data structure which consists
    of nested dicts that store BOTH the left and the right policies. All of the
    keys are interned strings. The permissions are stored as a set. The basic
    structure is rule_db[cond_exp][block_bool][src][tgt][tclass] = sides
    where:
      cond_exp is a boolean expression
      block_bool is either true or false
      src is the source type
      tgt is the target type
      tclass is the target class
      sides is a named tuple with attributes "left" and "right" referring to the
        left or right policy. Each attribute in the sides named tuple refers to a
        named tuple with attributes "perms" and "orig_rule" which refer to a
        permission set and the original unexpanded rule.
        sides = ((left_perms, left_orig_rule),(right_perms, right_orig_rule))
    There are a few advantages to this structure. First, it takes up way less
    memory. Second, it allows redundant rules to be easily eliminated. And,
    third, it makes it easy to create the added, removed, and modified rules.
    """
    if side == Side.left:
        types = type_db.left
    else:
        types = type_db.right

    for unexpanded_rule in rule_list:
        try:
            cond_exp = intern(str(unexpanded_rule.conditional))
            block_bool = intern(str(unexpanded_rule.conditional_block))
        except RuleNotConditional:
            cond_exp = TERULES_UNCONDITIONAL
            block_bool = TERULES_UNCONDITIONAL_BLOCK

        if cond_exp not in rule_db:
            rule_db[cond_exp] = dict()
            rule_db[cond_exp][block_bool] = dict()
        elif block_bool not in rule_db[cond_exp]:
            rule_db[cond_exp][block_bool] = dict()

        tclass = unexpanded_rule.tclass.name
        perms = set(unexpanded_rule.perms)
        side_data = RuleDBSideDataRecord(perms, unexpanded_rule)

        block = rule_db[cond_exp][block_bool]
        for src in unexpanded_rule.source.expand():
            src_str = src.name
            if src_str not in types:
                types[src_str] = src
            if src_str not in block:
                block[src_str] = dict()
            for tgt in unexpanded_rule.target.expand():
                tgt_str = tgt.name
                if tgt_str not in types:
                    types[tgt_str] = tgt
                if tgt_str not in block[src_str]:
                    block[src_str][tgt_str] = dict()
                left_side = None
                right_side = None
                if tclass in block[src_str][tgt_str]:
                    sides = block[src_str][tgt_str][tclass]
                    left_side = sides.left
                    right_side = sides.right
                if side == Side.left:
                    if not left_side:
                        left_side = side_data
                    else:
                        """
                        The original tuple and perm set might be shared with many
                        expanded rules so a new ones must created.
                        Using "|=" would cause the old perm set to be modified
                        instead of creating a new one.
                        """
                        p = left_side.perms | perms
                        orig = left_side.orig_rule
                        left_side = RuleDBSideDataRecord(p, orig)
                else:
                    if not right_side:
                        right_side = side_data
                    else:
                        """
                        Must create new tuple and perm set as explained above.
                        """
                        p = right_side.perms | perms
                        orig = right_side.orig_rule
                        right_side = RuleDBSideDataRecord(p, orig)

                block[src_str][tgt_str][tclass] = RuleDBSidesRecord(left_side, right_side)


def _av_remove_redundant_rules(rule_db: RuleDB) -> None:
    uncond_block = rule_db[TERULES_UNCONDITIONAL][TERULES_UNCONDITIONAL_BLOCK]
    for cond_exp, cond_blocks in rule_db.items():
        if cond_exp == TERULES_UNCONDITIONAL:
            continue
        for block in cond_blocks.values():
            for src, src_data in block.items():
                if src not in uncond_block:
                    continue
                for tgt, tgt_data in src_data.items():
                    if tgt not in uncond_block[src]:
                        continue
                    for tclass, side_data in tgt_data.items():
                        if tclass not in uncond_block[src][tgt]:
                            continue
                        uncond_side_data = uncond_block[src][tgt][tclass]
                        left_side = side_data.left
                        right_side = side_data.right
                        if uncond_side_data.left and left_side:
                            c = left_side.perms & uncond_side_data.left.perms
                            if c:
                                p = left_side.perms - c
                                if p:
                                    left_side = RuleDBSideDataRecord(p, left_side.orig_rule)
                                else:
                                    left_side = None
                                tgt_data[tclass] = RuleDBSidesRecord(left_side, right_side)
                        if uncond_side_data.right and right_side:
                            c = right_side.perms & uncond_side_data.right.perms
                            if c:
                                p = right_side.perms - c
                                if p:
                                    right_side = RuleDBSideDataRecord(p, right_side.orig_rule)
                                else:
                                    right_side = None
                                tgt_data[tclass] = RuleDBSidesRecord(left_side, right_side)


def _av_generate_diffs(rule_db: RuleDB, type_db: TypeDBRecord) -> \
        Tuple[List[AVRule], List[AVRule], List[ModifiedAVRule]]:

    added: List[AVRule] = []
    removed: List[AVRule] = []
    modified: List[ModifiedAVRule] = []
    for cond_blocks in rule_db.values():
        for block in cond_blocks.values():
            for src, src_data in block.items():
                for tgt, tgt_data in src_data.items():
                    for side_data in tgt_data.values():
                        if side_data.left and side_data.right:
                            common_perms = side_data.left.perms & side_data.right.perms
                            left_perms = side_data.left.perms - common_perms
                            right_perms = side_data.right.perms - common_perms
                            if left_perms or right_perms:
                                original_rule = side_data.left.orig_rule
                                rule = original_rule.derive_expanded(
                                    type_db.left[src], type_db.left[tgt],
                                    side_data.left.perms)
                                modified.append(ModifiedAVRule(rule, right_perms,
                                                               left_perms,
                                                               common_perms))
                        elif side_data.left:
                            original_rule = side_data.left.orig_rule
                            rule = original_rule.derive_expanded(
                                type_db.left[src], type_db.left[tgt],
                                side_data.left.perms)
                            removed.append(rule)
                        elif side_data.right:
                            original_rule = side_data.right.orig_rule
                            rule = original_rule.derive_expanded(
                                type_db.right[src], type_db.right[tgt],
                                side_data.right.perms)
                            added.append(rule)

    return added, removed, modified


def av_diff_template(ruletype: str) -> Callable[["TERulesDifference"], None]:

    """
    This is a template for the access vector diff functions.

    Parameters:
    ruletype    The rule type, e.g. "allow".
    """
    ruletype = TERuletype.lookup(ruletype)

    def diff(self) -> None:
        """Generate the difference in rules between the policies."""

        self.log.info(
            "Generating {0} differences from {1.left_policy} to {1.right_policy}".
            format(ruletype, self))

        if self._left_te_rules is None or self._right_te_rules is None:
            self._create_te_rule_lists()

        type_db = TypeDBRecord(dict(), dict())
        rule_db: RuleDB = dict()
        rule_db[TERULES_UNCONDITIONAL] = dict()
        rule_db[TERULES_UNCONDITIONAL][TERULES_UNCONDITIONAL_BLOCK] = dict()

        self.log.info("Expanding AV rules from {0.left_policy}.".format(self))
        _avrule_expand_generator(self._left_te_rules[ruletype], rule_db, type_db, Side.left)

        self.log.info("Expanding AV rules from {0.right_policy}.".format(self))
        _avrule_expand_generator(self._right_te_rules[ruletype], rule_db, type_db, Side.right)

        self.log.info("Removing redundant AV rules.")
        _av_remove_redundant_rules(rule_db)

        self.log.info("Generating AV rule diff.")
        added, removed, modified = _av_generate_diffs(rule_db, type_db)

        type_db.left.clear()
        type_db.right.clear()
        rule_db.clear()

        setattr(self, "added_{0}s".format(ruletype), added)
        setattr(self, "removed_{0}s".format(ruletype), removed)
        setattr(self, "modified_{0}s".format(ruletype), modified)

    return diff


def _avxrule_expand_generator(rule_list: Iterable[AVRuleXperm]) -> Iterable["AVRuleXpermWrapper"]:
    """
    Generator that yields wrapped, expanded, av(x) rules with
    unioned permission sets.
    """
    items: Dict["AVRuleXpermWrapper", "AVRuleXpermWrapper"] = dict()

    for unexpanded_rule in rule_list:
        for expanded_rule in unexpanded_rule.expand():
            expanded_wrapped_rule = AVRuleXpermWrapper(expanded_rule)

            # create a hash table (dict) with the first rule
            # as the key and value.  Rules where permission sets should
            # be unioned together have the same hash, so this will union
            # the permissions together.
            try:
                items[expanded_wrapped_rule].perms |= expanded_wrapped_rule.perms
            except KeyError:
                items[expanded_wrapped_rule] = expanded_wrapped_rule

    if items:
        logging.getLogger(__name__).debug(
            "Expanded {0.ruletype} rules for {0.policy}: {1}".format(
                unexpanded_rule, len(items)))

    return items.keys()


def avx_diff_template(ruletype: str) -> Callable[["TERulesDifference"], None]:

    """
    This is a template for the extended permission access vector diff functions.

    Parameters:
    ruletype    The rule type, e.g. "allowxperm".
    """
    ruletype = TERuletype.lookup(ruletype)

    def diff(self) -> None:
        """Generate the difference in rules between the policies."""

        self.log.info(
            "Generating {0} differences from {1.left_policy} to {1.right_policy}".
            format(ruletype, self))

        if not self._left_te_rules or not self._right_te_rules:
            self._create_te_rule_lists()

        added, removed, matched = self._set_diff(
            _avxrule_expand_generator(self._left_te_rules[ruletype]),
            _avxrule_expand_generator(self._right_te_rules[ruletype]),
            unwrap=False)

        modified = []
        for left_rule, right_rule in matched:
            # Criteria for modified rules
            # 1. change to permissions
            added_perms, removed_perms, matched_perms = self._set_diff(left_rule.perms,
                                                                       right_rule.perms,
                                                                       unwrap=False)

            # the final set comprehension is to avoid having lists
            # like [("perm1", "perm1"), ("perm2", "perm2")], as the
            # matched_perms return from _set_diff is a set of tuples
            if added_perms or removed_perms:
                modified.append(ModifiedAVRule(left_rule.origin,
                                               IoctlSet(added_perms),
                                               IoctlSet(removed_perms),
                                               IoctlSet(p[0] for p in matched_perms)))

        setattr(self, "added_{0}s".format(ruletype), set(a.origin for a in added))
        setattr(self, "removed_{0}s".format(ruletype), set(r.origin for r in removed))
        setattr(self, "modified_{0}s".format(ruletype), modified)

    return diff


def te_diff_template(ruletype: str) -> Callable[[Any], None]:

    """
    This is a template for the type_* diff functions.

    Parameters:
    ruletype    The rule type, e.g. "type_transition".
    """
    ruletype = TERuletype.lookup(ruletype)

    def diff(self) -> None:
        """Generate the difference in rules between the policies."""

        self.log.info(
            "Generating {0} differences from {1.left_policy} to {1.right_policy}".
            format(ruletype, self))

        if self._left_te_rules is None or self._right_te_rules is None:
            self._create_te_rule_lists()

        added, removed, matched = self._set_diff(
            self._expand_generator(self._left_te_rules[ruletype], TERuleWrapper),
            self._expand_generator(self._right_te_rules[ruletype], TERuleWrapper))

        modified = []
        for left_rule, right_rule in matched:
            # Criteria for modified rules
            # 1. change to default type
            if type_wrapper_factory(left_rule.default) != type_wrapper_factory(right_rule.default):
                modified.append(ModifiedTERule(left_rule,
                                               right_rule.default,
                                               left_rule.default))

        setattr(self, "added_{0}s".format(ruletype), added)
        setattr(self, "removed_{0}s".format(ruletype), removed)
        setattr(self, "modified_{0}s".format(ruletype), modified)

    return diff


class TERulesDifference(Difference):

    """
    Determine the difference in type enforcement rules
    between two policies.
    """

    diff_allows = av_diff_template("allow")
    added_allows = DiffResultDescriptor("diff_allows")
    removed_allows = DiffResultDescriptor("diff_allows")
    modified_allows = DiffResultDescriptor("diff_allows")

    diff_auditallows = av_diff_template("auditallow")
    added_auditallows = DiffResultDescriptor("diff_auditallows")
    removed_auditallows = DiffResultDescriptor("diff_auditallows")
    modified_auditallows = DiffResultDescriptor("diff_auditallows")

    diff_neverallows = av_diff_template("neverallow")
    added_neverallows = DiffResultDescriptor("diff_neverallows")
    removed_neverallows = DiffResultDescriptor("diff_neverallows")
    modified_neverallows = DiffResultDescriptor("diff_neverallows")

    diff_dontaudits = av_diff_template("dontaudit")
    added_dontaudits = DiffResultDescriptor("diff_dontaudits")
    removed_dontaudits = DiffResultDescriptor("diff_dontaudits")
    modified_dontaudits = DiffResultDescriptor("diff_dontaudits")

    diff_allowxperms = avx_diff_template("allowxperm")
    added_allowxperms = DiffResultDescriptor("diff_allowxperms")
    removed_allowxperms = DiffResultDescriptor("diff_allowxperms")
    modified_allowxperms = DiffResultDescriptor("diff_allowxperms")

    diff_auditallowxperms = avx_diff_template("auditallowxperm")
    added_auditallowxperms = DiffResultDescriptor("diff_auditallowxperms")
    removed_auditallowxperms = DiffResultDescriptor("diff_auditallowxperms")
    modified_auditallowxperms = DiffResultDescriptor("diff_auditallowxperms")

    diff_neverallowxperms = avx_diff_template("neverallowxperm")
    added_neverallowxperms = DiffResultDescriptor("diff_neverallowxperms")
    removed_neverallowxperms = DiffResultDescriptor("diff_neverallowxperms")
    modified_neverallowxperms = DiffResultDescriptor("diff_neverallowxperms")

    diff_dontauditxperms = avx_diff_template("dontauditxperm")
    added_dontauditxperms = DiffResultDescriptor("diff_dontauditxperms")
    removed_dontauditxperms = DiffResultDescriptor("diff_dontauditxperms")
    modified_dontauditxperms = DiffResultDescriptor("diff_dontauditxperms")

    diff_type_transitions = te_diff_template("type_transition")
    added_type_transitions = DiffResultDescriptor("diff_type_transitions")
    removed_type_transitions = DiffResultDescriptor("diff_type_transitions")
    modified_type_transitions = DiffResultDescriptor("diff_type_transitions")

    diff_type_changes = te_diff_template("type_change")
    added_type_changes = DiffResultDescriptor("diff_type_changes")
    removed_type_changes = DiffResultDescriptor("diff_type_changes")
    modified_type_changes = DiffResultDescriptor("diff_type_changes")

    diff_type_members = te_diff_template("type_member")
    added_type_members = DiffResultDescriptor("diff_type_members")
    removed_type_members = DiffResultDescriptor("diff_type_members")
    modified_type_members = DiffResultDescriptor("diff_type_members")

    _left_te_rules: RuleList[TERuletype, AnyTERule] = None
    _right_te_rules: RuleList[TERuletype, AnyTERule] = None

    #
    # Internal functions
    #
    def _create_te_rule_lists(self) -> None:
        """Create rule lists for both policies."""
        # do not expand yet, to keep memory
        # use down as long as possible
        self.log.debug("Building TE rule lists from {0.left_policy}".format(self))
        self._left_te_rules = defaultdict(list)
        for rule in self.left_policy.terules():
            self._left_te_rules[rule.ruletype].append(rule)

        for ruletype, rules in self._left_te_rules.items():
            self.log.debug("Loaded {0} {1} rules.".format(len(rules), ruletype))

        self.log.debug("Building TE rule lists from {0.right_policy}".format(self))
        self._right_te_rules = defaultdict(list)
        for rule in self.right_policy.terules():
            self._right_te_rules[rule.ruletype].append(rule)

        for ruletype, rules in self._right_te_rules.items():
            self.log.debug("Loaded {0} {1} rules.".format(len(rules), ruletype))

        self.log.debug("Completed building TE rule lists.")

    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting TE rule differences")
        self.added_allows = None
        self.removed_allows = None
        self.modified_allows = None
        self.added_auditallows = None
        self.removed_auditallows = None
        self.modified_auditallows = None
        self.added_neverallows = None
        self.removed_neverallows = None
        self.modified_neverallows = None
        self.added_dontaudits = None
        self.removed_dontaudits = None
        self.modified_dontaudits = None
        self.added_allowxperms = None
        self.removed_allowxperms = None
        self.modified_allowxperms = None
        self.added_auditallowxperms = None
        self.removed_auditallowxperms = None
        self.modified_auditallowxperms = None
        self.added_neverallowxperms = None
        self.removed_neverallowxperms = None
        self.modified_neverallowxperms = None
        self.added_dontauditxperms = None
        self.removed_dontauditxperms = None
        self.modified_dontauditxperms = None
        self.added_type_transitions = None
        self.removed_type_transitions = None
        self.modified_type_transitions = None
        self.added_type_changes = None
        self.removed_type_changes = None
        self.modified_type_changes = None
        self.added_type_members = None
        self.removed_type_members = None
        self.modified_type_members = None

        # Lists of rules for each policy
        self._left_te_rules = None
        self._right_te_rules = None


# Pylint bug: https://github.com/PyCQA/pylint/issues/2822
class AVRuleXpermWrapper(Wrapper[AVRuleXperm]):  # pylint: disable=unsubscriptable-object

    """Wrap extended permission access vector rules to allow set operations."""

    __slots__ = ("source", "target", "tclass", "xperm_type", "perms")

    def __init__(self, rule: AVRuleXperm) -> None:
        self.origin = rule
        self.source = type_or_attr_wrapper_factory(rule.source)
        self.target = type_or_attr_wrapper_factory(rule.target)
        self.tclass = class_wrapper_factory(rule.tclass)
        self.xperm_type = rule.xperm_type
        self.perms = set(rule.perms)
        self.key = hash(rule)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        # because TERuleDifference groups rules by ruletype,
        # the ruletype always matches.
        return self.source == other.source and \
            self.target == other.target and \
            self.tclass == other.tclass and \
            self.xperm_type == other.xperm_type


# Pylint bug: https://github.com/PyCQA/pylint/issues/2822
class TERuleWrapper(Wrapper):  # pylint: disable=unsubscriptable-object

    """Wrap type_* rules to allow set operations."""

    __slots__ = ("source", "target", "tclass", "conditional", "conditional_block", "filename")

    def __init__(self, rule):
        self.origin = rule
        self.source = type_or_attr_wrapper_factory(rule.source)
        self.target = type_or_attr_wrapper_factory(rule.target)
        self.tclass = class_wrapper_factory(rule.tclass)
        self.key = hash(rule)

        try:
            self.conditional = conditional_wrapper_factory(rule.conditional)
            self.conditional_block = rule.conditional_block
        except RuleNotConditional:
            self.conditional = None
            self.conditional_block = None

        try:
            self.filename = rule.filename
        except (RuleUseError, TERuleNoFilename):
            self.filename = None

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        # because TERuleDifference groups rules by ruletype,
        # the ruletype always matches.
        return self.source == other.source and \
            self.target == other.target and \
            self.tclass == other.tclass and \
            self.conditional == other.conditional and \
            self.conditional_block == other.conditional_block and \
            self.filename == other.filename
