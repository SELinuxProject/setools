# Copyright 2014-2015, Tresys Technology, LLC
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
import re

from . import compquery


class UserQuery(compquery.ComponentQuery):

    """Query SELinux policy users."""

    def __init__(self, policy,
                 name=None, name_regex=False,
                 roles=None, roles_equal=False, roles_regex=False,
                 level=None, level_dom=False, level_domby=False, level_incomp=False,
                 range_=None, range_overlap=False, range_subset=False,
                 range_superset=False, range_proper=False):
        """
        Parameter:
        policy          The policy to query.
        name            The user name to match.
        name_regex      If true, regular expression matching
                        will be used on the user names.
        roles           The attribute to match.
        roles_equal     If true, only types with role sets
                        that are equal to the criteria will
                        match.  Otherwise, any intersection
                        will match.
        roles_regex     If true, regular expression matching
                        will be used on the role names instead
                        of set logic.
        level           The criteria to match the user's default level.
        level_dom       If true, the criteria will match if it dominates
                        the user's default level.
        level_domby     If true, the criteria will match if it is dominated
                        by the user's default level.
        level_incomp    If true, the criteria will match if it is incomparable
                        to the user's default level.
        range_          The criteria to match the user's range.
        range_subset    If true, the criteria will match if it is a subset
                        of the user's range.
        range_overlap   If true, the criteria will match if it overlaps
                        any of the user's range.
        range_superset  If true, the criteria will match if it is a superset
                        of the user's range.
        range_proper    If true, use proper superset/subset operations.
                        No effect if not using set operations.
        """
        self.log = logging.getLogger(self.__class__.__name__)

        self.policy = policy
        self.set_name(name, regex=name_regex)
        self.set_roles(roles, regex=roles_regex, equal=roles_equal)
        self.set_level(level, dom=level_dom, domby=level_domby, incomp=level_incomp)
        self.set_range(range_, overlap=range_overlap, subset=range_subset,
                       superset=range_superset, proper=range_proper)

    def results(self):
        """Generator which yields all matching users."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("Name: {0.name_cmp!r}, regex: {0.name_regex}".format(self))
        self.log.debug("Roles: {0.roles_cmp!r}, regex: {0.roles_regex}, "
                       "eq: {0.roles_equal}".format(self))
        self.log.debug("Level: {0.level!r}, dom: {0.level_dom}, domby: {0.level_domby}, "
                       "incomp: {0.level_incomp}".format(self))
        self.log.debug("Range: {0.range_!r}, subset: {0.range_subset}, overlap: {0.range_overlap}, "
                       "superset: {0.range_superset}, proper: {0.range_proper}".format(self))

        for u in self.policy.users():
            if self.name and not self._match_regex(
                    u,
                    self.name_cmp,
                    self.name_regex):
                continue

            if self.roles and not self._match_regex_or_set(
                    u.roles,
                    self.roles_cmp,
                    self.roles_equal,
                    self.roles_regex):
                continue

            if self.level and not self._match_level(
                    u.mls_level,
                    self.level,
                    self.level_dom,
                    self.level_domby,
                    self.level_incomp):
                continue

            if self.range_ and not self._match_range(
                    (u.mls_range.low, u.mls_range.high),
                    (self.range_.low, self.range_.high),
                    self.range_subset,
                    self.range_overlap,
                    self.range_superset,
                    self.range_proper):
                continue

            yield u

    def set_level(self, level, **opts):
        """
        Set the criteria for matching the user's default level.

        Parameter:
        level       Criteria to match the user's default level.

        Keyword Parameters:
        dom         If true, the criteria will match if it dominates the user's default level.
        domby       If true, the criteria will match if it is dominated by the user's default level.
        incomp      If true, the criteria will match if it incomparable to the user's default level.

        Exceptions:
        NameError   Invalid keyword option.
        """

        if level:
            self.level = self.policy.lookup_level(level)
        else:
            self.level = None

        for k in list(opts.keys()):
            if k == "dom":
                self.level_dom = opts[k]
            elif k == "domby":
                self.level_domby = opts[k]
            elif k == "incomp":
                self.level_incomp = opts[k]
            else:
                raise NameError("Invalid name option: {0}".format(k))

    def set_range(self, range_, **opts):
        """
        Set the criteria for matching the user's range.

        Parameter:
        range_      Criteria to match the user's range.

        Keyword Parameters:
        subset      If true, the criteria will match if it is a subset
                    of the user's range.
        overlap     If true, the criteria will match if it overlaps
                    any of the user's range.
        superset    If true, the criteria will match if it is a superset
                    of the user's range.
        proper      If true, use proper superset/subset operations.
                    No effect if not using set operations.

        Exceptions:
        NameError   Invalid keyword option.
        """

        if range_:
            self.range_ = self.policy.lookup_range(range_)
        else:
            self.range_ = None

        for k in list(opts.keys()):
            if k == "subset":
                self.range_subset = opts[k]
            elif k == "overlap":
                self.range_overlap = opts[k]
            elif k == "superset":
                self.range_superset = opts[k]
            elif k == "proper":
                self.range_proper = opts[k]
            else:
                raise NameError("Invalid name option: {0}".format(k))

    def set_roles(self, roles, **opts):
        """
        Set the criteria for the users's roles.

        Parameter:
        roles       Name to match the component's attributes.

        Keyword Options:
        regex       If true, regular expression matching will be used
                    instead of set logic.
        equal       If true, the role set of the user
                    must equal the attributes criteria to
                    match. If false, any intersection in the
                    critera will cause a rule match.

        Exceptions:
        NameError   Invalid keyword option.
        """

        self.roles = roles

        for k in list(opts.keys()):
            if k == "regex":
                self.roles_regex = opts[k]
            elif k == "equal":
                self.roles_equal = opts[k]
            else:
                raise NameError("Invalid roles option: {0}".format(k))

        if not self.roles:
            self.roles_cmp = None
        elif self.roles_regex:
            self.roles_cmp = re.compile(self.roles)
        else:
            self.roles_cmp = set(self.policy.lookup_role(r) for r in self.roles)
