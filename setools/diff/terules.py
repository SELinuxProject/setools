# Copyright 2015-2016, Tresys Technology, LLC
# Copyright 2016, 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
import logging
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from sys import intern
from enum import Enum
import typing

from .. import exception, policyrep

from .conditional import conditional_wrapper_factory
from .descriptors import DiffResultDescriptor
from .difference import Difference, DifferenceResult, Wrapper
from .types import type_wrapper_factory, type_or_attr_wrapper_factory
from .typing import RuleList
from .objclass import class_wrapper_factory

TERULES_UNCONDITIONAL = intern("<<unconditional>>")
TERULES_UNCONDITIONAL_BLOCK = intern("True")


@dataclass(frozen=True, order=True)
class ModifiedAVRule(DifferenceResult):

    """Difference details for a modified access vector rule."""

    rule: policyrep.AVRule
    added_perms: set[str]
    removed_perms: set[str]
    matched_perms: set[str]


@dataclass(frozen=True, order=True)
class ModifiedAVRuleXperm(DifferenceResult):

    """Difference details for a modified access vector rule."""

    rule: policyrep.AVRuleXperm
    added_perms: policyrep.IoctlSet
    removed_perms: policyrep.IoctlSet
    matched_perms: policyrep.IoctlSet


@dataclass(frozen=True, order=True)
class ModifiedTERule(DifferenceResult):

    """Difference details for a modified type_* rule."""

    rule: policyrep.AVRule
    added_default: policyrep.Type
    removed_default: policyrep.Type


#
# Internal datastructure types
#
class Side(Enum):
    left = 0
    right = 1


@dataclass
class RuleDBSideDataRecord:
    perms: set[str]
    orig_rule: policyrep.AVRule


@dataclass
class RuleDBSidesRecord:
    left: RuleDBSideDataRecord | None
    right: RuleDBSideDataRecord | None


@dataclass
class TypeDBRecord:
    left: dict[str, policyrep.Type]
    right: dict[str, policyrep.Type]


# These conditional items are unioned with str to handle unconditional rules
CondExp = policyrep.Conditional | str
CondBlock = bool | str
RuleDB = dict[CondExp, dict[CondBlock, dict[str, dict[str, dict[str, RuleDBSidesRecord]]]]]


def _avrule_expand_generator(rule_list: list[policyrep.AVRule], rule_db: RuleDB,
                             type_db: TypeDBRecord, side: Side) -> None:
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
        except exception.RuleNotConditional:
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
        tuple[list[policyrep.AVRule], list[policyrep.AVRule], list[ModifiedAVRule]]:

    added: list[policyrep.AVRule] = []
    removed: list[policyrep.AVRule] = []
    modified: list[ModifiedAVRule] = []
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


def av_diff_template(ruletype: policyrep.TERuletype) -> Callable[["TERulesDifference"], None]:

    """
    This is a template for the access vector diff functions.

    Parameters:
    ruletype    The rule type, e.g. "allow".
    """
    def diff(self) -> None:
        """Generate the difference in rules between the policies."""

        self.log.info(
            f"Generating {ruletype} differences from {self.left_policy} to {self.right_policy}")

        if self._left_te_rules is None or self._right_te_rules is None:
            self._create_te_rule_lists()

        type_db = TypeDBRecord(dict(), dict())
        rule_db: RuleDB = dict()
        rule_db[TERULES_UNCONDITIONAL] = dict()
        rule_db[TERULES_UNCONDITIONAL][TERULES_UNCONDITIONAL_BLOCK] = dict()

        self.log.info(f"Expanding AV rules from {self.left_policy}.")
        _avrule_expand_generator(self._left_te_rules[ruletype], rule_db, type_db, Side.left)

        self.log.info(f"Expanding AV rules from {self.right_policy}.")
        _avrule_expand_generator(self._right_te_rules[ruletype], rule_db, type_db, Side.right)

        self.log.info("Removing redundant AV rules.")
        _av_remove_redundant_rules(rule_db)

        self.log.info("Generating AV rule diff.")
        added, removed, modified = _av_generate_diffs(rule_db, type_db)

        type_db.left.clear()
        type_db.right.clear()
        rule_db.clear()

        setattr(self, f"added_{ruletype}s", added)
        setattr(self, f"removed_{ruletype}s", removed)
        setattr(self, f"modified_{ruletype}s", modified)

    return diff


def _avxrule_expand_generator(rule_list: Iterable[policyrep.AVRuleXperm]
                              ) -> Iterable["AVRuleXpermWrapper"]:
    """
    Generator that yields wrapped, expanded, av(x) rules with
    unioned permission sets.
    """
    items: dict["AVRuleXpermWrapper", "AVRuleXpermWrapper"] = dict()

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
        logging.getLogger(__name__).debug(f"Expanded {len(items)} rules")

    return items.keys()


def avx_diff_template(ruletype: policyrep.TERuletype) -> Callable[["TERulesDifference"], None]:

    """
    This is a template for the extended permission access vector diff functions.

    Parameters:
    ruletype    The rule type, e.g. "allowxperm".
    """
    def diff(self) -> None:
        """Generate the difference in rules between the policies."""

        self.log.info(
            f"Generating {ruletype} differences from {self.left_policy} "
            f"to {self.right_policy}")

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
                modified.append(
                    ModifiedAVRuleXperm(left_rule.origin,
                                        policyrep.IoctlSet(added_perms),
                                        policyrep.IoctlSet(removed_perms),
                                        policyrep.IoctlSet(p[0] for p in matched_perms)))

        setattr(self, f"added_{ruletype}s", set(a.origin for a in added))
        setattr(self, f"removed_{ruletype}s", set(r.origin for r in removed))
        setattr(self, f"modified_{ruletype}s", modified)

    return diff


def te_diff_template(ruletype: policyrep.TERuletype) -> Callable[[typing.Any], None]:

    """
    This is a template for the type_* diff functions.

    Parameters:
    ruletype    The rule type, e.g. "type_transition".
    """
    def diff(self) -> None:
        """Generate the difference in rules between the policies."""

        self.log.info(
            f"Generating {ruletype} differences from {self.left_policy} to {self.right_policy}")

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

        setattr(self, f"added_{ruletype}s", added)
        setattr(self, f"removed_{ruletype}s", removed)
        setattr(self, f"modified_{ruletype}s", modified)

    return diff


class TERulesDifference(Difference):

    """
    Determine the difference in type enforcement rules
    between two policies.
    """

    diff_allows = av_diff_template(policyrep.TERuletype.allow)
    added_allows = DiffResultDescriptor[policyrep.AVRule](diff_allows)
    removed_allows = DiffResultDescriptor[policyrep.AVRule](diff_allows)
    modified_allows = DiffResultDescriptor[ModifiedAVRule](diff_allows)

    diff_auditallows = av_diff_template(policyrep.TERuletype.auditallow)
    added_auditallows = DiffResultDescriptor[policyrep.AVRule](diff_auditallows)
    removed_auditallows = DiffResultDescriptor[policyrep.AVRule](diff_auditallows)
    modified_auditallows = DiffResultDescriptor[ModifiedAVRule](diff_auditallows)

    diff_neverallows = av_diff_template(policyrep.TERuletype.neverallow)
    added_neverallows = DiffResultDescriptor[policyrep.AVRule](diff_neverallows)
    removed_neverallows = DiffResultDescriptor[policyrep.AVRule](diff_neverallows)
    modified_neverallows = DiffResultDescriptor[ModifiedAVRule](diff_neverallows)

    diff_dontaudits = av_diff_template(policyrep.TERuletype.dontaudit)
    added_dontaudits = DiffResultDescriptor[policyrep.AVRule](diff_dontaudits)
    removed_dontaudits = DiffResultDescriptor[policyrep.AVRule](diff_dontaudits)
    modified_dontaudits = DiffResultDescriptor[ModifiedAVRule](diff_dontaudits)

    diff_allowxperms = avx_diff_template(policyrep.TERuletype.allowxperm)
    added_allowxperms = DiffResultDescriptor[policyrep.AVRuleXperm](diff_allowxperms)
    removed_allowxperms = DiffResultDescriptor[policyrep.AVRuleXperm](diff_allowxperms)
    modified_allowxperms = DiffResultDescriptor[ModifiedAVRuleXperm](diff_allowxperms)

    diff_auditallowxperms = avx_diff_template(policyrep.TERuletype.auditallowxperm)
    added_auditallowxperms = DiffResultDescriptor[policyrep.AVRuleXperm](diff_auditallowxperms)
    removed_auditallowxperms = DiffResultDescriptor[policyrep.AVRuleXperm](diff_auditallowxperms)
    modified_auditallowxperms = DiffResultDescriptor[ModifiedAVRuleXperm](diff_auditallowxperms)

    diff_neverallowxperms = avx_diff_template(policyrep.TERuletype.neverallowxperm)
    added_neverallowxperms = DiffResultDescriptor[policyrep.AVRuleXperm](diff_neverallowxperms)
    removed_neverallowxperms = DiffResultDescriptor[policyrep.AVRuleXperm](diff_neverallowxperms)
    modified_neverallowxperms = DiffResultDescriptor[ModifiedAVRuleXperm](diff_neverallowxperms)

    diff_dontauditxperms = avx_diff_template(policyrep.TERuletype.dontauditxperm)
    added_dontauditxperms = DiffResultDescriptor[policyrep.AVRuleXperm](diff_dontauditxperms)
    removed_dontauditxperms = DiffResultDescriptor[policyrep.AVRuleXperm](diff_dontauditxperms)
    modified_dontauditxperms = DiffResultDescriptor[ModifiedAVRuleXperm](diff_dontauditxperms)

    diff_type_transitions = te_diff_template(policyrep.TERuletype.type_transition)
    added_type_transitions = DiffResultDescriptor[policyrep.TERule](diff_type_transitions)
    removed_type_transitions = DiffResultDescriptor[policyrep.TERule](diff_type_transitions)
    modified_type_transitions = DiffResultDescriptor[ModifiedTERule](diff_type_transitions)

    diff_type_changes = te_diff_template(policyrep.TERuletype.type_change)
    added_type_changes = DiffResultDescriptor[policyrep.TERule](diff_type_changes)
    removed_type_changes = DiffResultDescriptor[policyrep.TERule](diff_type_changes)
    modified_type_changes = DiffResultDescriptor[ModifiedTERule](diff_type_changes)

    diff_type_members = te_diff_template(policyrep.TERuletype.type_member)
    added_type_members = DiffResultDescriptor[policyrep.TERule](diff_type_members)
    removed_type_members = DiffResultDescriptor[policyrep.TERule](diff_type_members)
    modified_type_members = DiffResultDescriptor[ModifiedTERule](diff_type_members)

    _left_te_rules: RuleList[policyrep.TERuletype, policyrep.AnyTERule] = None
    _right_te_rules: RuleList[policyrep.TERuletype, policyrep.AnyTERule] = None

    #
    # Internal functions
    #
    def _create_te_rule_lists(self) -> None:
        """Create rule lists for both policies."""
        # do not expand yet, to keep memory
        # use down as long as possible
        self.log.debug(f"Building TE rule lists from {self.left_policy}")
        self._left_te_rules = defaultdict(list)
        for rule in self.left_policy.terules():
            self._left_te_rules[rule.ruletype].append(rule)

        for ruletype, rules in self._left_te_rules.items():
            self.log.debug(f"Loaded {len(rules)} {ruletype} rules.")

        self.log.debug(f"Building TE rule lists from {self.right_policy}")
        self._right_te_rules = defaultdict(list)
        for rule in self.right_policy.terules():
            self._right_te_rules[rule.ruletype].append(rule)

        for ruletype, rules in self._right_te_rules.items():
            self.log.debug(f"Loaded {len(rules)} {ruletype} rules.")

        self.log.debug("Completed building TE rule lists.")

    def _reset_diff(self) -> None:
        """Reset diff results on policy changes."""
        self.log.debug("Resetting TE rule differences")
        del self.added_allows
        del self.removed_allows
        del self.modified_allows
        del self.added_auditallows
        del self.removed_auditallows
        del self.modified_auditallows
        del self.added_neverallows
        del self.removed_neverallows
        del self.modified_neverallows
        del self.added_dontaudits
        del self.removed_dontaudits
        del self.modified_dontaudits
        del self.added_allowxperms
        del self.removed_allowxperms
        del self.modified_allowxperms
        del self.added_auditallowxperms
        del self.removed_auditallowxperms
        del self.modified_auditallowxperms
        del self.added_neverallowxperms
        del self.removed_neverallowxperms
        del self.modified_neverallowxperms
        del self.added_dontauditxperms
        del self.removed_dontauditxperms
        del self.modified_dontauditxperms
        del self.added_type_transitions
        del self.removed_type_transitions
        del self.modified_type_transitions
        del self.added_type_changes
        del self.removed_type_changes
        del self.modified_type_changes
        del self.added_type_members
        del self.removed_type_members
        del self.modified_type_members

        # Lists of rules for each policy
        self._left_te_rules = None
        self._right_te_rules = None


class AVRuleXpermWrapper(Wrapper[policyrep.AVRuleXperm]):

    """Wrap extended permission access vector rules to allow set operations."""

    __slots__ = ("source", "target", "tclass", "xperm_type", "perms")

    def __init__(self, rule: policyrep.AVRuleXperm) -> None:
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


class TERuleWrapper(Wrapper):

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
        except exception.RuleNotConditional:
            self.conditional = None
            self.conditional_block = None

        try:
            self.filename = rule.filename
        except (exception.RuleUseError, exception.TERuleNoFilename):
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
