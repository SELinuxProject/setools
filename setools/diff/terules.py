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
from itertools import chain
from contextlib import suppress
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

def _avrule_expand_generator(rule_list, rule_db, side):
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

        block = rule_db[cond_exp][block_bool]
        for src in unexpanded_rule.source.expand():
            src_str = intern(str(src))
            if src_str not in block:
                block[src_str] = dict()
            for tgt in unexpanded_rule.target.expand():
                tgt_str = intern(str(tgt))
                if tgt_str not in block[src_str]:
                    block[src_str][tgt_str] = dict()
                if tclass not in block[src_str][tgt_str]:
                    block[src_str][tgt_str][tclass] = dict()
                rule = block[src_str][tgt_str][tclass]
                if side not in rule:
                    rule[side] = perms
                else:
                    """
                    Must not use "|=" because that would modify rule[side] which
                    is shared with all of the rules expanded from the same initial
                    rule. So all uses of rule[side] would be effected.
                    Using "rule[side] | perms" causes a new set to be created and
                    assigned to rule[side] instead of just modifying the old
                    rule[side]. So all the other uses of the old rule[side] will
                    not be effected.
                    """
                    rule[side] = rule[side] | perms

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
                    for tclass, perm_data in tgt_data.items():
                        if tclass not in uncond_block[src][tgt]:
                            continue
                        uncond_perm_data = uncond_block[src][tgt][tclass]
                        if "left" in uncond_perm_data and "left" in perm_data:
                            perm_data["left"] = perm_data["left"] - uncond_perm_data["left"]
                            if not perm_data["left"]:
                                del perm_data["left"]
                        if "right" in uncond_perm_data and "right" in perm_data:
                            perm_data["right"] = perm_data["right"] - uncond_perm_data["right"]
                            if not perm_data["right"]:
                                del perm_data["right"]

def _av_create_rule_str(ruletype, cond_exp, block_bool, src, tgt, tclass, perms):
    perms_str = "{ "
    perms_str += ' '.join(sorted(perms))
    perms_str += " }"
    rule_str = "{0} {1} {2}:{3} {4};".format(ruletype, src, tgt, tclass, perms_str)
    if cond_exp != terules_unconditional:
        rule_str += " [ {0} ]:{1}".format(cond_exp, block_bool)
    return rule_str

def _av_create_mod_rule_str(ruletype, cond_exp, block_bool, src, tgt, tclass,
                            unchanged_perms, added_perms, removed_perms):
    perms_str = "{ "
    perms_str += " ".join(chain((p for p in sorted(unchanged_perms)),
                                ("+" + p for p in sorted(added_perms)),
                                ("-" + p for p in sorted(removed_perms))))
    perms_str += " }"
    rule_str = "{0} {1} {2}:{3} {4};".format(ruletype, src, tgt, tclass, perms_str)
    if cond_exp != terules_unconditional:
        rule_str += " [ {0} ]:{1}".format(cond_exp, block_bool)
    return rule_str

def _av_generate_diffs(ruletype, rule_db):
    added = []
    removed = []
    modified = []
    for cond_exp, cond_blocks in rule_db.items():
        for block_bool, block in cond_blocks.items():
            for src, src_data in block.items():
                for tgt, tgt_data in src_data.items():
                    for tclass, perm_data in tgt_data.items():
                        if "left" in perm_data and "right" in perm_data:
                            common_perms = perm_data["left"] & perm_data["right"]
                            left_perms = perm_data["left"] - common_perms
                            right_perms = perm_data["right"] - common_perms
                            if left_perms or right_perms:
                                modified.append(_av_create_mod_rule_str(ruletype,
                                                                        cond_exp,
                                                                        block_bool, src,
                                                                        tgt, tclass,
                                                                        common_perms,
                                                                        right_perms,
                                                                        left_perms))
                        elif "left" in perm_data:
                            removed.append(_av_create_rule_str(ruletype, cond_exp,
                                                               block_bool, src, tgt,
                                                               tclass,
                                                               perm_data["left"]))
                        elif "right" in perm_data:
                            added.append(_av_create_rule_str(ruletype, cond_exp,
                                                             block_bool, src, tgt,
                                                             tclass,
                                                             perm_data["right"]))
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

        rule_db = dict()
        rule_db[terules_unconditional] = dict()
        rule_db[terules_unconditional][terules_unconditional_block] = dict()

        logging.info("Expanding left policy")
        _avrule_expand_generator(self._left_te_rules[ruletype], rule_db, "left")

        logging.info("Expanding right policy")
        _avrule_expand_generator(self._right_te_rules[ruletype], rule_db, "right")

        logging.info("Removing redundant rules")
        _av_remove_redundant_rules(rule_db)

        logging.info("Generating added, removed, and modified av rules")
        added, removed, modified = _av_generate_diffs(ruletype, rule_db)

        rule_db.clear()

        setattr(self, "added_{0}s".format(ruletype), added)
        setattr(self, "removed_{0}s".format(ruletype), removed)
        setattr(self, "modified_{0}s".format(ruletype), modified)

    return diff

def _avxrule_expand_generator(rule_list, rule_db, side):
    """
    Using rule_list, build up rule_db which is a data structure which consists
    of nested dicts that store BOTH the left and the right policies. All of the
    keys are interned strings. The permissions are stored as a set. The basic
    structure is rule_db[src][tgt][tclass][xperm_type][side]=xperms
    where:
      src is the source type
      tgt is the target type
      tclass is the target class
      xperm_type is ioctl
      side is either left or right
      xperms is the set of extended permissions for this rule
    Unlike normal avrules, avx rules cannot be conditional. This simplifies the
    data structure and means that there are no redundant rules to remove.
    There are a few advantages to this structure. First, it takes up way less
    memory. And, second, it makes it easy to create the added, removed, and
    modified rules.
    """
    for unexpanded_rule in rule_list:
        tclass = intern(str(unexpanded_rule.tclass))
        xperm_type = intern(str(unexpanded_rule.xperm_type))
        for src in unexpanded_rule.source.expand():
            src_str = intern(str(src))
            if src_str not in rule_db:
                rule_db[src_str] = dict()
            for tgt in unexpanded_rule.target.expand():
                tgt_str = intern(str(tgt))
                if tgt_str not in rule_db[src_str]:
                    rule_db[src_str][tgt_str] = dict()
                if tclass not in rule_db[src_str][tgt_str]:
                    rule_db[src_str][tgt_str][tclass] = dict()
                if xperm_type not in rule_db[src_str][tgt_str][tclass]:
                    rule_db[src_str][tgt_str][tclass][xperm_type] = dict()
                rule = rule_db[src_str][tgt_str][tclass][xperm_type]
                if side not in rule:
                    rule[side] = unexpanded_rule.perms
                else:
                    """
                    Must not use "|=" because that would modify rule[side] which
                    is shared with all of the rules expanded from the same initial
                    rule. So all uses of rule[side] would be effected.
                    Using "rule[side] | perms" causes a new set to be created and
                    assigned to rule[side] instead of just modifying the old
                    rule[side]. So all the other uses of the old rule[side] will
                    not be effected.
                    """
                    rule[side] = rule[side] | unexpanded_rule.perms

def _avx_create_rule_str(ruletype, src, tgt, tclass, xperm_type, perms):
    rule_str = "{0} {1} {2}:{3} {4} {{ {5} }};".format(ruletype, src, tgt, tclass,
                                                       xperm_type, perms)
    return rule_str

def _avx_create_mod_rule_str(ruletype, src, tgt, tclass, xperm_type,
                             unchanged_perms, added_perms, removed_perms):
    perms = []
    if unchanged_perms:
        for p in str(unchanged_perms).split(" "):
            perms.append(p)
    if added_perms:
        for p in str(added_perms).split(" "):
            if '-' in p:
                perms.append("+[{0}]".format(p))
            else:
                perms.append("+{0}".format(p))
    if removed_perms:
        for p in str(removed_perms).split(" "):
            if '-' in p:
                perms.append("-[{0}]".format(p))
            else:
                perms.append("-{0}".format(p))
    perms_str = "{ "
    perms_str += " ".join(perms)
    perms_str += " }"

    rule_str = "{0} {1} {2}:{3} {4} {5};".format(ruletype, src, tgt, tclass,
                                                 xperm_type, perms_str)
    return rule_str

def _avx_generate_diffs(ruletype, rule_db):
    added = []
    removed = []
    modified = []
    for src, src_data in rule_db.items():
        for tgt, tgt_data in src_data.items():
            for tclass, tclass_data in tgt_data.items():
                for xperm_type, xperm_data in tclass_data.items():
                    if "left" in xperm_data and "right" in xperm_data:
                        common_perms = xperm_data["left"] & xperm_data["right"]
                        left_perms = xperm_data["left"] - common_perms
                        right_perms = xperm_data["right"] - common_perms
                        if left_perms or right_perms:
                            common_perms = IoctlSet(common_perms)
                            left_perms = IoctlSet(left_perms)
                            right_perms = IoctlSet(right_perms)
                            modified.append(_avx_create_mod_rule_str(ruletype, src, tgt,
                                                                     tclass, xperm_type,
                                                                     common_perms,
                                                                     right_perms,
                                                                     left_perms))
                    elif "left" in xperm_data:
                        left_perms = IoctlSet(xperm_data["left"])
                        removed.append(_avx_create_rule_str(ruletype, src, tgt, tclass,
                                                            xperm_type, left_perms))
                    elif "right" in xperm_data:
                        right_perms = IoctlSet(xperm_data["right"])
                        added.append(_avx_create_rule_str(ruletype, src, tgt, tclass,
                                                          xperm_type, right_perms))
    return added, removed, modified

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

        rule_db = dict()

        logging.info("Expanding left avx rules")
        _avxrule_expand_generator(self._left_te_rules[ruletype], rule_db, "left")

        logging.info("Expanding right avx rules")
        _avxrule_expand_generator(self._right_te_rules[ruletype], rule_db, "right")

        logging.info("Generating added, removed, and modified avx rules")
        added, removed, modified = _avx_generate_diffs(ruletype, rule_db)

        rule_db.clear()

        setattr(self, "added_{0}s".format(ruletype), added)
        setattr(self, "removed_{0}s".format(ruletype), removed)
        setattr(self, "modified_{0}s".format(ruletype), modified)

    return diff

def _terule_expand_generator(ruletype, rule_list, rule_db, side):
    """
    Using rule_list, build up rule_db which is a data structure which consists
    of nested dicts that store BOTH the left and the right policies. All of the
    keys are interned strings. The default type is stored as a string. The basic
    structure is
    rule_db[cond_exp][block_bool][src][tgt][tclass][filename][side]=default
    where:
      cond_exp is a boolean expression
      block_bool is either true or false
      src is the source type
      tgt is the target type
      tclass is the target class
      filename is the filename for type_transitions using a filename, otherwise
        it is "<<NONE>>"
      side is either left or right
      default is the default type for the rule
    There are a few advantages to this structure. First, it takes up way less
    memory. And,second, it makes it easy to create the added, removed, and
    modified rules.
    """
    for unexpanded_rule in rule_list:
        try:
            cond_exp = intern(str(unexpanded_rule.conditional))
            block_bool = intern(str(unexpanded_rule.conditional_block))
        except RuleNotConditional:
            cond_exp = terules_unconditional
            block_bool = terules_unconditional_block

        if cond_exp not in rule_db:
            rule_db[cond_exp] = dict()
            rule_db[cond_exp][block_bool] = dict()
        elif block_bool not in rule_db[cond_exp]:
            rule_db[cond_exp][block_bool] = dict()

        tclass = intern(str(unexpanded_rule.tclass))
        default = intern(str(unexpanded_rule.default))

        try:
            filename = intern(str(unexpanded_rule.filename))
        except (TERuleNoFilename, RuleUseError):
            filename = intern(str("<<NONE>>"))

        block = rule_db[cond_exp][block_bool]
        for src in unexpanded_rule.source.expand():
            src_str = intern(str(src))
            if src_str not in block:
                block[src_str] = dict()
            for tgt in unexpanded_rule.target.expand():
                tgt_str = intern(str(tgt))
                if tgt_str not in block[src_str]:
                    block[src_str][tgt_str] = dict()
                if tclass not in block[src_str][tgt_str]:
                    block[src_str][tgt_str][tclass] = dict()
                if filename not in block[src_str][tgt_str][tclass]:
                    block[src_str][tgt_str][tclass][filename] = dict()
                if side in block[src_str][tgt_str][tclass][filename]:
                    prev_default = block[src_str][tgt_str][tclass][filename][side]
                    if prev_default != default:
                        print("Error TE rule can have only one default")
                        print("{0} {1} {2}:{3} {4}".format(ruletype, src, tgt, tclass,
                                                           filename))
                        print("for ",side, " rules has ", prev_default, " and ", default)
                else:
                    block[src_str][tgt_str][tclass][filename][side] = default

def _te_create_rule_str(ruletype, cond_exp, block_bool, src, tgt, tclass, filename,
                        default):
    rule_str = "{0} {1} {2}:{3} {4}".format(ruletype, src, tgt, tclass, default)
    if filename != "<<NONE>>":
        rule_str += " \"{0}\"".format(filename)
    rule_str += ";"
    if cond_exp != terules_unconditional:
        rule_str += " [ {0} ]:{1}".format(cond_exp, block_bool)
    return rule_str

def _te_create_mod_rule_str(ruletype, cond_exp, block_bool, src, tgt, tclass, filename,
                            added_default, removed_default):
    rule_str = "{0} {1} {2}:{3} +{4} -{5}".format(ruletype, src, tgt, tclass,
                                                  added_default, removed_default)
    if filename != "<<NONE>>":
        rule_str += " \"{0}\"".format(filename)
    rule_str += ";"
    if cond_exp != terules_unconditional:
        rule_str += " [ {0} ]:{1}".format(cond_exp, block_bool)
    return rule_str

def _te_generate_diffs(ruletype, rule_db):
    added = []
    removed = []
    modified = []
    for cond_exp, cond_blocks in rule_db.items():
        for block_bool, block in cond_blocks.items():
            for src, src_data in block.items():
                for tgt, tgt_data in src_data.items():
                    for tclass, tclass_data in tgt_data.items():
                        for filename, default_data in tclass_data.items():
                            if "left" in default_data and "right" in default_data:
                                left_default = default_data["left"]
                                right_default = default_data["right"]
                                if left_default != right_default:
                                    lstr = _te_create_mod_rule_str(ruletype, cond_exp,
                                                                   block_bool, src, tgt,
                                                                   tclass, filename,
                                                                   right_default,
                                                                   left_default)
                                    modified.append(lstr)
                            elif "left" in default_data:
                                left_default = default_data["left"]
                                removed.append(_te_create_rule_str(ruletype, cond_exp,
                                                                   block_bool, src, tgt,
                                                                   tclass, filename,
                                                                   left_default))
                            elif "right" in default_data:
                                right_default = default_data["right"]
                                added.append(_te_create_rule_str(ruletype, cond_exp,
                                                                 block_bool, src, tgt,
                                                                 tclass, filename,
                                                                 right_default))
    return added, removed, modified

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

        rule_db = dict()
        rule_db[terules_unconditional] = dict()
        rule_db[terules_unconditional][terules_unconditional_block] = dict()

        logging.info("Expanding left te rules")
        _terule_expand_generator(ruletype, self._left_te_rules[ruletype], rule_db,
                                 "left")

        logging.info("Expanding right te rules")
        _terule_expand_generator(ruletype, self._right_te_rules[ruletype], rule_db,
                                 "right")

        logging.info("Generating added, removed, and modified te rules")
        added, removed, modified = _te_generate_diffs(ruletype, rule_db)

        rule_db.clear()

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


class AVRuleWrapper(Wrapper):

    """Wrap access vector rules to allow set operations."""

    __slots__ = ("source", "target", "tclass", "perms", "conditional", "conditional_block")

    def __init__(self, rule):
        self.origin = rule
        self.source = type_or_attr_wrapper_factory(rule.source)
        self.target = type_or_attr_wrapper_factory(rule.target)
        self.tclass = class_wrapper_factory(rule.tclass)
        self.perms = rule.perms
        self.key = hash(rule)

        try:
            self.conditional = conditional_wrapper_factory(rule.conditional)
            self.conditional_block = rule.conditional_block
        except RuleNotConditional:
            self.conditional = None
            self.conditional_block = None

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
            self.conditional_block == other.conditional_block


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
