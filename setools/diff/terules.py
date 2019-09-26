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
from collections import defaultdict, namedtuple
from sys import intern

from ..exception import RuleNotConditional, RuleUseError, TERuleNoFilename
from ..policyrep import IoctlSet, TERuletype

from .conditional import conditional_wrapper_factory
from .descriptors import DiffResultDescriptor
from .difference import Difference, Wrapper
from .types import type_wrapper_factory, type_or_attr_wrapper_factory
from .objclass import class_wrapper_factory

terules_unconditional = intern("<<unconditional>>")
terules_unconditional_block = intern("True")

modified_avrule_record = namedtuple("modified_avrule", ["rule",
                                                        "added_perms",
                                                        "removed_perms",
                                                        "matched_perms"])

modified_terule_record = namedtuple("modified_terule", ["rule", "added_default", "removed_default"])


def _avrule_expand_generator(rule_list, rule_db, type_db, side):
    """
    Using rule_list, build up rule_db which is a data structure which consists
    of nested dicts that store BOTH the left and the right policies. All of the
    keys are interned strings. The permissions are stored as a set. The basic
    structure is rule_db[cond_exp][block_bool][src][tgt][tclass][side]=perms
    where:
      cond_exp is a boolean expression
      block_bool is either true or false
      src is the source type
      tgt is the target type
      tclass is the target class
      side is either left or right
      perms is the set of permissions for this rule
    There are a few advantages to this structure. First, it takes up way less
    memory. Second, it allows redundant rules to be easily eliminated. And,
    third, it makes it easy to create the added, removed, and modified rules.
    """
    if side not in type_db:
        type_db[side] = dict()

    for unexpanded_rule in rule_list:
        cond_exp = terules_unconditional
        block_bool = terules_unconditional_block
        try:
            cond_exp = intern(str(unexpanded_rule.conditional))
            block_bool = intern(str(unexpanded_rule.conditional_block))
        except RuleNotConditional:
            pass

        if cond_exp not in rule_db:
            rule_db[cond_exp] = dict()
            rule_db[cond_exp][block_bool] = dict()
        elif block_bool not in rule_db[cond_exp]:
            rule_db[cond_exp][block_bool] = dict()

        tclass = intern(str(unexpanded_rule.tclass))
        perms = {intern(str(p)) for p in unexpanded_rule.perms}
        side_data = (perms, unexpanded_rule)

        block = rule_db[cond_exp][block_bool]
        for src in unexpanded_rule.source.expand():
            src_str = intern(str(src))
            if src_str not in type_db[side]:
                type_db[side][src_str] = src
            if src_str not in block:
                block[src_str] = dict()
            for tgt in unexpanded_rule.target.expand():
                tgt_str = intern(str(tgt))
                if tgt_str not in type_db[side]:
                    type_db[side][tgt_str] = tgt
                if tgt_str not in block[src_str]:
                    block[src_str][tgt_str] = dict()
                if tclass not in block[src_str][tgt_str]:
                    block[src_str][tgt_str][tclass] = dict()
                rule = block[src_str][tgt_str][tclass]
                if side not in rule:
                    rule[side] = side_data
                else:
                    """
                    Need to create a new tuple and a new perm set when adding perms.
                    Must not use "|=" to add the new perms because that would modify
                    the perms in all the rules that originally shared side_data.
                    """
                    p = rule[side][0] | perms
                    rule[side] = (p, rule[side][1])

def _av_remove_redundant_rules(rule_db):
    uncond_block = rule_db[terules_unconditional][terules_unconditional_block]
    for cond_exp, cond_blocks in rule_db.items():
        if cond_exp == terules_unconditional:
            continue
        for block_bool, block in cond_blocks.items():
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
                        if "left" in uncond_side_data and "left" in side_data:
                            p = side_data["left"][0] - uncond_side_data["left"][0]
                            if p:
                                side_data["left"] = (p, side_data["left"][1])
                            else:
                                del side_data["left"]
                        if "right" in uncond_side_data and "right" in side_data:
                            p = side_data["right"][0] - uncond_side_data["right"][0]
                            if p:
                                side_data["right"] = (p, side_data["right"][1])
                            else:
                                del side_data["right"]

def _av_generate_diffs(ruletype, rule_db, type_db):
    added = []
    removed = []
    modified = []
    for cond_exp, cond_blocks in rule_db.items():
        for block_bool, block in cond_blocks.items():
            for src, src_data in block.items():
                for tgt, tgt_data in src_data.items():
                    for tclass, side_data in tgt_data.items():
                        if "left" in side_data and "right" in side_data:
                            common_perms = side_data["left"][0] & side_data["right"][0]
                            left_perms = side_data["left"][0] - common_perms
                            right_perms = side_data["right"][0] - common_perms
                            if left_perms or right_perms:
                                original_rule = side_data["left"][1]
                                rule = original_rule.create_expanded(
                                    type_db["left"][src], type_db["left"][tgt],
                                    side_data["left"][0])
                                modified.append(modified_avrule_record(rule, right_perms,
                                                                       left_perms,
                                                                       common_perms))
                        elif "left" in side_data:
                            original_rule = side_data["left"][1]
                            rule = original_rule.create_expanded(
                                type_db["left"][src], type_db["left"][tgt],
                                side_data["left"][0])
                            removed.append(rule)
                        elif "right" in side_data:
                            original_rule = side_data["right"][1]
                            rule = original_rule.create_expanded(
                                type_db["right"][src], type_db["right"][tgt],
                                side_data["right"][0])
                            added.append(rule)
    return added, removed, modified

def av_diff_template(ruletype):

    """
    This is a template for the access vector diff functions.

    Parameters:
    ruletype    The rule type, e.g. "allow".
    """
    ruletype = TERuletype.lookup(ruletype)

    def diff(self):
        """Generate the difference in rules between the policies."""

        self.log.info(
            "Generating {0} differences from {1.left_policy} to {1.right_policy}".
            format(ruletype, self))

        if not self._left_te_rules or not self._right_te_rules:
            self._create_te_rule_lists()

        type_db = dict()
        rule_db = dict()
        rule_db[terules_unconditional] = dict()
        rule_db[terules_unconditional][terules_unconditional_block] = dict()

        logging.info("Expanding left policy")
        _avrule_expand_generator(self._left_te_rules[ruletype], rule_db, type_db, "left")

        logging.info("Expanding right policy")
        _avrule_expand_generator(self._right_te_rules[ruletype], rule_db, type_db, "right")

        logging.info("Removing redundant rules")
        _av_remove_redundant_rules(rule_db)

        logging.info("Generating added, removed, and modified av rules")
        added, removed, modified = _av_generate_diffs(ruletype, rule_db, type_db)

        type_db.clear()
        rule_db.clear()

        setattr(self, "added_{0}s".format(ruletype), added)
        setattr(self, "removed_{0}s".format(ruletype), removed)
        setattr(self, "modified_{0}s".format(ruletype), modified)

    return diff

def _avxrule_expand_generator(rule_list, WrapperClass):
    """
    Generator that yields wrapped, expanded, av(x) rules with
    unioned permission sets.
    """
    items = dict()

    for unexpanded_rule in rule_list:
        for expanded_rule in unexpanded_rule.expand():
            expanded_wrapped_rule = WrapperClass(expanded_rule)

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

def avx_diff_template(ruletype):

    """
    This is a template for the extended permission access vector diff functions.

    Parameters:
    ruletype    The rule type, e.g. "allowxperm".
    """
    ruletype = TERuletype.lookup(ruletype)

    def diff(self):
        """Generate the difference in rules between the policies."""

        self.log.info(
            "Generating {0} differences from {1.left_policy} to {1.right_policy}".
            format(ruletype, self))

        if not self._left_te_rules or not self._right_te_rules:
            self._create_te_rule_lists()

        added, removed, matched = self._set_diff(
            _avxrule_expand_generator(self._left_te_rules[ruletype], AVRuleXpermWrapper),
            _avxrule_expand_generator(self._right_te_rules[ruletype], AVRuleXpermWrapper),
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
                modified.append(modified_avrule_record(left_rule.origin,
                                                       IoctlSet(added_perms),
                                                       IoctlSet(removed_perms),
                                                       IoctlSet(p[0] for p in matched_perms)))

        setattr(self, "added_{0}s".format(ruletype), set(a.origin for a in added))
        setattr(self, "removed_{0}s".format(ruletype), set(r.origin for r in removed))
        setattr(self, "modified_{0}s".format(ruletype), modified)

    return diff


def te_diff_template(ruletype):

    """
    This is a template for the type_* diff functions.

    Parameters:
    ruletype    The rule type, e.g. "type_transition".
    """
    ruletype = TERuletype.lookup(ruletype)

    def diff(self):
        """Generate the difference in rules between the policies."""

        self.log.info(
            "Generating {0} differences from {1.left_policy} to {1.right_policy}".
            format(ruletype, self))

        if not self._left_te_rules or not self._right_te_rules:
            self._create_te_rule_lists()

        added, removed, matched = self._set_diff(
            self._expand_generator(self._left_te_rules[ruletype], TERuleWrapper),
            self._expand_generator(self._right_te_rules[ruletype], TERuleWrapper))

        modified = []
        for left_rule, right_rule in matched:
            # Criteria for modified rules
            # 1. change to default type
            if type_wrapper_factory(left_rule.default) != type_wrapper_factory(right_rule.default):
                modified.append(modified_terule_record(left_rule,
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

    # Lists of rules for each policy
    _left_te_rules = defaultdict(list)
    _right_te_rules = defaultdict(list)

    #
    # Internal functions
    #
    def _create_te_rule_lists(self):
        """Create rule lists for both policies."""
        # do not expand yet, to keep memory
        # use down as long as possible
        self.log.debug("Building TE rule lists from {0.left_policy}".format(self))
        for rule in self.left_policy.terules():
            self._left_te_rules[rule.ruletype].append(rule)

        for ruletype, rules in self._left_te_rules.items():
            self.log.debug("Loaded {0} {1} rules.".format(len(rules), ruletype))

        self.log.debug("Building TE rule lists from {0.right_policy}".format(self))
        for rule in self.right_policy.terules():
            self._right_te_rules[rule.ruletype].append(rule)

        for ruletype, rules in self._right_te_rules.items():
            self.log.debug("Loaded {0} {1} rules.".format(len(rules), ruletype))

        self.log.debug("Completed building TE rule lists.")

    def _reset_diff(self):
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

        # Sets of rules for each policy
        self._left_te_rules.clear()
        self._right_te_rules.clear()


class AVRuleXpermWrapper(Wrapper):

    """Wrap extended permission access vector rules to allow set operations."""

    __slots__ = ("source", "target", "tclass", "xperm_type", "perms")

    def __init__(self, rule):
        self.origin = rule
        self.source = type_or_attr_wrapper_factory(rule.source)
        self.target = type_or_attr_wrapper_factory(rule.target)
        self.tclass = class_wrapper_factory(rule.tclass)
        self.xperm_type = rule.xperm_type
        self.perms = rule.perms
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
