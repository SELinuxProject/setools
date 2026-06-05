# SPDX-License-Identifier: LGPL-2.1-only

from __future__ import annotations

import enum
import ipaddress
import itertools
import json
import logging
from typing import Annotated, Any, Final, Literal

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as iex:
    logging.getLogger(__name__).debug(f"{iex.name} failed to import.")

from .. import (BoolQuery, BoundsQuery, BoundsRuletype, CategoryQuery, CommonQuery,
                ConstraintQuery, ConstraintRuletype, DefaultQuery, DefaultRuletype,
                DevicetreeconQuery, DomainTransitionAnalysis, FSUseQuery, FSUseRuletype,
                GenfsconQuery, IbendportconQuery, IbpkeyconQuery, IbpkeyconRange,
                InfoFlowAnalysis, InitialSIDQuery, IomemconQuery, IomemconRange,
                IoportconQuery, IoportconRange, MLSRuleQuery, MLSRuletype, NetifconQuery,
                NodeconIPVersion, NodeconQuery, ObjClassQuery, PcideviceconQuery,
                PermissionMap, PolCapQuery, PolicyDifference, PolicyQuery, PortconProtocol,
                PortconQuery, PortconRange, PirqconQuery, RBACRuleQuery, RBACRuletype, RoleQuery,
                RoleTypesQuery, SELinuxPolicy, SensitivityQuery, TERuleQuery, TERuletype,
                TypeAttributeQuery, TypeQuery, UserQuery)
from .encoder import MCPEncoder

__all__ = ("MCPEncoder",)

TOOL_PREFIX: Final[str] = "setools_"


class DiffComponent(str, enum.Enum):

    """Policy components that can be compared in a policy difference analysis."""

    TE_RULES = "te_rules"
    RBAC_RULES = "rbac_rules"
    TYPES = "types"
    ROLES = "roles"
    USERS = "users"
    PORTCONS = "portcons"
    MLS_RULES = "mls_rules"


class PolicyCache(dict):
    """Simple cache for loaded policies"""
    def __missing__(self, key: str | None) -> SELinuxPolicy:
        self[key] = SELinuxPolicy(key)
        return self[key]


class SEToolsMCPServer:
    """
    MCP server encapsulating all setools policy analysis tools.

    All mutable state (policy cache, default policy path, FastMCP instance)
    is held as instance attributes; there are no module-level globals.
    """

    def __init__(self, default_policy: str | None = None) -> None:
        self.log: logging.Logger = logging.getLogger(__name__)
        self.default_policy: str | None = default_policy
        self._policy_cache: PolicyCache = PolicyCache()

        try:
            # Init the policy cache.  Load the default policy as the None key and its path.
            policy = self._load_policy()
            # Use policy.path to handle the case where default_policy is None.
            self._policy_cache[policy.path] = policy
            self.log.debug(f"Loaded default policy from {policy.path}")
        except (OSError, RuntimeError) as err:
            self.log.error(f"Failed to load default policy: {err}")

        self.mcp: FastMCP = FastMCP(
            "setools",
            instructions=(
                "SELinux policy analysis tools built on the setools library.  "
                "Supports querying TE/RBAC/MLS rules, enumerating policy components, "
                "domain transition analysis, information flow analysis, and policy diffing."
            ),
        )

        for name in dir(self):
            if name.startswith(TOOL_PREFIX) and callable(getattr(self, name)):
                self.mcp.tool()(getattr(self, name))

    def run(self, transport: Literal["stdio", "sse", "streamable-http"] = "stdio",
            host: str = "127.0.0.1", port: int = 8000) -> None:
        """Start the MCP server with the given transport."""
        if transport == "sse":
            self.mcp.settings.host = host
            self.mcp.settings.port = port
        self.mcp.run(transport=transport)

    #
    # Helpers
    #
    @staticmethod
    def _collect_results(query: PolicyQuery, *, max_results: int = 32768) -> str:
        """
        Collect results from *query* up to *max_results* and return a JSON string.

        The returned object always has 'count', 'truncated', and 'result' fields.
        """
        results: list[Any] = list(itertools.islice(query.results(), 0, max_results+1))
        truncated: bool = len(results) > max_results
        returned_count = len(results) if not truncated else max_results
        return SEToolsMCPServer._serialize_results(results[:max_results],
                                                   returned_count,
                                                   truncated)

    def _load_policy(self, policy: str | None = None) -> SELinuxPolicy:
        """
        Return a (cached) SELinuxPolicy for policy at path *policy*.
        If *policy* is None, uses the server default or the running system policy.
        """
        return self._policy_cache[policy if policy else self.default_policy]

    @staticmethod
    def _serialize_results(result: Any, count: int, truncated: bool) -> str:
        """Serialize results to JSON."""
        return json.dumps({"count": count,
                           "truncated": truncated,
                           "result": result},
                          cls=MCPEncoder,
                          indent=2)

    #
    # MCP Tools
    #
    def setools_get_policy_info(
        self,
        policy_path: Annotated[
            str | None,
            "Path to a compiled policy file (e.g. /etc/selinux/targeted/policy/policy.33). "
            "If omitted, uses the server default or the running system policy.",
        ] = None,
    ) -> str:
        """Return statistics and metadata about an SELinux policy."""
        return self._serialize_results(self._load_policy(policy_path), 1, False)

    def setools_search_te_rules(
        self,
        ruletypes: Annotated[
            list[str] | None,
            "TE rule types to match. Valid values: allow, auditallow, dontaudit, "
            "type_transition, type_change, type_member, neverallow, allowxperm, "
            "auditallowxperm, dontauditxperm, neverallowxperm. "
            "If omitted, all rule types are searched.",
        ] = None,
        source: Annotated[str | None, "Source type or attribute name to match."] = None,
        source_regex: Annotated[bool, "Treat source as a regular expression."] = False,
        source_indirect: Annotated[
            bool, "Expand type attributes to their member types (default True)."
        ] = True,
        target: Annotated[str | None, "Target type or attribute name to match."] = None,
        target_regex: Annotated[bool, "Treat target as a regular expression."] = False,
        target_indirect: Annotated[
            bool, "Expand type attributes to their member types (default True)."
        ] = True,
        tclass: Annotated[
            list[str] | None, "Object class(es) to match, e.g. ['file', 'dir']."
        ] = None,
        tclass_regex: Annotated[bool, "Treat tclass as a regular expression."] = False,
        perms: Annotated[
            list[str] | None, "Permission(s) that must be present in the rule."
        ] = None,
        perms_equal: Annotated[
            bool, "If True, the rule's permission set must exactly match perms."
        ] = False,
        perms_regex: Annotated[bool, "Treat permission names as regular expressions."] = False,
        default: Annotated[
            str | None,
            "Default type to match (type_transition / type_change / type_member rules).",
        ] = None,
        default_regex: Annotated[bool, "Treat default as a regular expression."] = False,
        boolean: Annotated[
            list[str] | None,
            "Boolean(s) that must appear in the rule's conditional expression.",
        ] = None,
        boolean_regex: Annotated[bool, "Treat boolean names as regular expressions."] = False,
        max_results: Annotated[int, "Maximum number of matching rules to return."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """
        Search Type Enforcement (TE) rules in an SELinux policy.

        Equivalent to the sesearch command-line tool.  All criteria are AND-ed
        together.  Returns a JSON object with a 'rules' list, a 'count', and a
        'truncated' flag that is true when max_results was reached.
        """
        q = TERuleQuery(self._load_policy(policy_path),
                        ruletype=[TERuletype.lookup(r) for r in ruletypes] if ruletypes else None,
                        source=source,
                        source_regex=source_regex,
                        source_indirect=source_indirect,
                        target=target,
                        target_regex=target_regex,
                        target_indirect=target_indirect,
                        tclass=tclass,
                        tclass_regex=tclass_regex,
                        perms=set(perms) if perms else None,
                        perms_equal=perms_equal,
                        perms_regex=perms_regex,
                        default=default,
                        default_regex=default_regex,
                        boolean=boolean,
                        boolean_regex=boolean_regex)

        return self._collect_results(q, max_results=max_results)

    def setools_search_rbac_rules(
        self,
        ruletypes: Annotated[
            list[str] | None,
            "RBAC rule types to match: allow (role_allow), role_transition. "
            "If omitted, all types are searched.",
        ] = None,
        source: Annotated[str | None, "Source role name to match."] = None,
        source_regex: Annotated[bool, "Treat source as a regular expression."] = False,
        target: Annotated[str | None, "Target role or type/attribute name to match."] = None,
        target_regex: Annotated[bool, "Treat target as a regular expression."] = False,
        tclass: Annotated[
            list[str] | None,
            "Object class(es) to match (applies to role_transition rules).",
        ] = None,
        tclass_regex: Annotated[bool, "Treat tclass as a regular expression."] = False,
        default: Annotated[
            str | None, "Default role to match (applies to role_transition rules)."
        ] = None,
        default_regex: Annotated[bool, "Treat default as a regular expression."] = False,
        max_results: Annotated[int, "Maximum number of results to return."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """
        Search Role-Based Access Control (RBAC) rules in an SELinux policy.

        Covers both role_allow and role_transition rules.
        """
        q = RBACRuleQuery(self._load_policy(policy_path),
                          ruletype=[RBACRuletype.lookup(r) for r in ruletypes]
                          if ruletypes else None,
                          source=source,
                          source_regex=source_regex,
                          target=target,
                          target_regex=target_regex,
                          tclass=tclass,
                          tclass_regex=tclass_regex,
                          default=default,
                          default_regex=default_regex)

        return self._collect_results(q, max_results=max_results)

    def setools_search_mls_rules(
        self,
        ruletypes: Annotated[
            list[str] | None,
            "MLS rule types to match: range_transition. "
            "If omitted, all types are searched.",
        ] = None,
        source: Annotated[str | None, "Source type or attribute name to match."] = None,
        source_regex: Annotated[bool, "Treat source as a regular expression."] = False,
        target: Annotated[str | None, "Target type or attribute name to match."] = None,
        target_regex: Annotated[bool, "Treat target as a regular expression."] = False,
        tclass: Annotated[list[str] | None, "Object class(es) to match."] = None,
        tclass_regex: Annotated[bool, "Treat tclass as a regular expression."] = False,
        max_results: Annotated[int, "Maximum number of results to return."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """Search Multi-Level Security (MLS) rules (range_transition) in an SELinux policy."""
        q = MLSRuleQuery(self._load_policy(policy_path),
                         ruletype=[MLSRuletype.lookup(r) for r in ruletypes]
                         if ruletypes else None,
                         source=source,
                         source_regex=source_regex,
                         target=target,
                         target_regex=target_regex,
                         tclass=tclass,
                         tclass_regex=tclass_regex)

        return self._collect_results(q, max_results=max_results)

    def setools_list_types(
        self,
        name: Annotated[str | None, "Type name (or regex pattern) to filter by. "] = None,
        name_regex: Annotated[bool, "Treat name as a regular expression."] = False,
        permissive: Annotated[
            bool | None,
            "Filter by permissive status. True = permissive only, "
            "False = enforcing only, None (default) = all types.",
        ] = None,
        attrs: Annotated[
            list[str] | None,
            "Return only types that are members of all listed attributes.",
        ] = None,
        attrs_regex: Annotated[bool, "Treat attribute names as regular expressions."] = False,
        max_results: Annotated[int, "Maximum number of results."] = 500,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """
        List SELinux types, including their attributes and aliases.

        Each result includes the type name, permissive status, all attributes
        the type belongs to, and any aliases.
        """
        q = TypeQuery(self._load_policy(policy_path),
                      name=name,
                      name_regex=name_regex,
                      permissive=permissive,
                      attrs=attrs,
                      attrs_regex=attrs_regex)

        return self._collect_results(q, max_results=max_results)

    def setools_list_type_attributes(
        self,
        name: Annotated[str | None, "Attribute name (or regex pattern) to filter by."] = None,
        name_regex: Annotated[bool, "Treat name as a regular expression."] = False,
        max_results: Annotated[int, "Maximum number of results."] = 500,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """
        List SELinux type attributes and their member types.

        Each result includes the attribute name and a sorted list of all types
        that are members of the attribute.
        """
        q = TypeAttributeQuery(self._load_policy(policy_path),
                               name=name,
                               name_regex=name_regex)

        return self._collect_results(q, max_results=max_results)

    def setools_list_roles(
        self,
        name: Annotated[str | None, "Role name (or regex pattern) to filter by."] = None,
        name_regex: Annotated[bool, "Treat name as a regular expression."] = False,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """
        List SELinux roles and their assigned types.

        Each result includes the role name and the sorted list of types that
        can be associated with that role.
        """
        q = RoleQuery(self._load_policy(policy_path),
                      name=name,
                      name_regex=name_regex)

        return self._collect_results(q, max_results=max_results)

    def setools_list_role_types(
        self,
        type_name: Annotated[str, "Type name (or regex pattern) to find associated roles for."],
        type_regex: Annotated[bool, "Treat type_name as a regular expression."] = False,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """
        List all roles that are associated with a given type.

        Equivalent to seinfo --role_types <type>.  Returns every role whose
        type set includes a type matching the given name/pattern.
        """
        q = RoleTypesQuery(self._load_policy(policy_path),
                           name=type_name,
                           name_regex=type_regex)

        return self._collect_results(q, max_results=max_results)

    def setools_list_users(
        self,
        name: Annotated[
            str | None, "User name (or regex pattern) to filter by."
        ] = None,
        name_regex: Annotated[bool, "Treat name as a regular expression."] = False,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """
        List SELinux users and their assigned roles.

        Each result includes the user name, the set of roles assigned to
        the user, and (if MLS is enabled) the default MLS level and range.
        """
        q = UserQuery(self._load_policy(policy_path),
                      name=name,
                      name_regex=name_regex)

        return self._collect_results(q, max_results=max_results)

    def setools_list_classes(
        self,
        name: Annotated[
            str | None, "Class name (or regex pattern) to filter by."
        ] = None,
        name_regex: Annotated[bool, "Treat name as a regular expression."] = False,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """
        List SELinux object classes and their permissions.

        Each result includes the class name, its own permissions, and (if it
        inherits from a common) the name of the common and its permissions.
        """
        q = ObjClassQuery(self._load_policy(policy_path),
                          name=name,
                          name_regex=name_regex)

        return self._collect_results(q, max_results=max_results)

    def setools_list_commons(
        self,
        name: Annotated[
            str | None, "Common name (or regex pattern) to filter by."
        ] = None,
        name_regex: Annotated[bool, "Treat name as a regular expression."] = False,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List common permission sets and their permissions."""
        q = CommonQuery(self._load_policy(policy_path),
                        name=name,
                        name_regex=name_regex)

        return self._collect_results(q, max_results=max_results)

    def setools_list_booleans(
        self,
        name: Annotated[
            str | None, "Boolean name (or regex pattern) to filter by."
        ] = None,
        name_regex: Annotated[bool, "Treat name as a regular expression."] = False,
        state: Annotated[
            bool | None,
            "Filter by default state: True = enabled by default, "
            "False = disabled by default, None (default) = return all booleans.",
        ] = None,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List SELinux booleans and their default (compile-time) states."""
        # BoolQuery uses 'default' for the state filter
        q = BoolQuery(self._load_policy(policy_path),
                      name=name,
                      name_regex=name_regex,
                      default=state)

        return self._collect_results(q, max_results=max_results)

    def setools_list_sensitivities(
        self,
        name: Annotated[
            str | None, "Sensitivity name (or regex pattern) to filter by."
        ] = None,
        name_regex: Annotated[bool, "Treat name as a regular expression."] = False,
        alias: Annotated[
            str | None, "Alias name (or regex pattern) to filter by."
        ] = None,
        alias_regex: Annotated[bool, "Treat alias as a regular expression."] = False,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List MLS sensitivities and their aliases (requires an MLS policy)."""
        q = SensitivityQuery(self._load_policy(policy_path),
                             name=name,
                             name_regex=name_regex,
                             alias=alias,
                             alias_regex=alias_regex,
                             alias_deref=True)

        return self._collect_results(q, max_results=max_results)

    def setools_list_categories(
        self,
        name: Annotated[
            str | None, "Category name (or regex pattern) to filter by."
        ] = None,
        name_regex: Annotated[bool, "Treat name as a regular expression."] = False,
        alias: Annotated[
            str | None, "Alias name (or regex pattern) to filter by."
        ] = None,
        alias_regex: Annotated[bool, "Treat alias as a regular expression."] = False,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List MLS categories and their aliases (requires an MLS policy)."""
        q = CategoryQuery(self._load_policy(policy_path),
                          name=name,
                          name_regex=name_regex,
                          alias=alias,
                          alias_regex=alias_regex,
                          alias_deref=True)

        return self._collect_results(q, max_results=max_results)

    def setools_list_polcaps(
        self,
        name: Annotated[
            str | None, "Policy capability name (or regex pattern) to filter by."
        ] = None,
        name_regex: Annotated[bool, "Treat name as a regular expression."] = False,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List policy capabilities declared in the policy."""
        q = PolCapQuery(self._load_policy(policy_path),
                        name=name,
                        name_regex=name_regex)

        return self._collect_results(q, max_results=max_results)

    def setools_list_permissive_types(
        self,
        name: Annotated[
            str | None, "Type name (or regex pattern) to filter by."
        ] = None,
        name_regex: Annotated[bool, "Treat name as a regular expression."] = False,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List types declared as permissive (i.e. not enforcing access controls)."""
        q = TypeQuery(self._load_policy(policy_path),
                      name=name,
                      name_regex=name_regex,
                      permissive=True,
                      match_permissive=True)

        return self._collect_results(q, max_results=max_results)

    def setools_list_typebounds(
        self,
        child: Annotated[
            str | None, "Bound (child) type name (or regex pattern) to filter by."
        ] = None,
        child_regex: Annotated[bool, "Treat child as a regular expression."] = False,
        parent: Annotated[
            str | None, "Parent type name (or regex pattern) to filter by."
        ] = None,
        parent_regex: Annotated[bool, "Treat parent as a regular expression."] = False,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """
        List typebounds statements.

        A typebounds statement constrains a child type so that it can only have
        permissions that its parent type also has.
        """
        q = BoundsQuery(self._load_policy(policy_path),
                        ruletype=[BoundsRuletype.typebounds],
                        child=child,
                        child_regex=child_regex,
                        parent=parent,
                        parent_regex=parent_regex)

        return self._collect_results(q, max_results=max_results)

    def setools_list_constraints(
        self,
        tclass: Annotated[
            list[str] | None,
            "Object class(es) to filter by (e.g. ['file', 'process']).",
        ] = None,
        tclass_regex: Annotated[bool, "Treat tclass as a regular expression."] = False,
        ruletypes: Annotated[
            list[str] | None,
            "Constraint rule types to return.  Valid values: constrain, mlsconstrain, "
            "validatetrans, mlsvalidatetrans.  Defaults to all constraint types.",
        ] = None,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """
        List constraint and validatetrans rules.

        Covers constrain, mlsconstrain, validatetrans, and mlsvalidatetrans statements.
        By default all constraints are returned.
        """
        q = ConstraintQuery(self._load_policy(policy_path),
                            ruletype=[ConstraintRuletype.lookup(r) for r in ruletypes]
                            if ruletypes else None,
                            tclass=tclass,
                            tclass_regex=tclass_regex)

        return self._collect_results(q, max_results=max_results)

    def setools_list_defaults(
        self,
        tclass: Annotated[
            list[str] | None, "Object class(es) to filter by."
        ] = None,
        tclass_regex: Annotated[bool, "Treat tclass as a regular expression."] = False,
        ruletypes: Annotated[
            list[str] | None,
            "Rule types to filter by.  Valid values: default_user, default_role, "
            "default_type, default_range.  If omitted, all default_* types are returned.",
        ] = None,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List default_user, default_role, default_type, and default_range statements."""
        q = DefaultQuery(self._load_policy(policy_path),
                         ruletype=[DefaultRuletype.lookup(r) for r in ruletypes]
                         if ruletypes else None,
                         tclass=tclass,
                         tclass_regex=tclass_regex)

        return self._collect_results(q, max_results=max_results)

    def setools_list_fs_uses(
        self,
        fs: Annotated[
            str | None, "Filesystem type name (or regex pattern) to filter by."
        ] = None,
        fs_regex: Annotated[bool, "Treat fs as a regular expression."] = False,
        ruletypes: Annotated[
            list[str] | None,
            "fs_use rule types: fs_use_xattr, fs_use_trans, fs_use_task. "
            "If omitted, all types are returned.",
        ] = None,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List fs_use_* statements (SELinux policies only)."""
        q = FSUseQuery(self._load_policy(policy_path),
                       fs=fs,
                       fs_regex=fs_regex,
                       ruletype=[FSUseRuletype.lookup(r) for r in ruletypes]
                       if ruletypes else None)

        return self._collect_results(q, max_results=max_results)

    def setools_list_genfscons(
        self,
        fs: Annotated[
            str | None, "Filesystem type name (or regex pattern) to filter by."
        ] = None,
        fs_regex: Annotated[bool, "Treat fs as a regular expression."] = False,
        path: Annotated[
            str | None, "Path prefix (or regex pattern) to filter by."
        ] = None,
        path_regex: Annotated[bool, "Treat path as a regular expression."] = False,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List genfscon statements (SELinux policies only)."""
        q = GenfsconQuery(self._load_policy(policy_path),
                          fs=fs,
                          fs_regex=fs_regex,
                          path=path,
                          path_regex=path_regex)

        return self._collect_results(q, max_results=max_results)

    def setools_list_initialsids(
        self,
        name: Annotated[
            str | None, "Initial SID name (or regex pattern) to filter by."
        ] = None,
        name_regex: Annotated[bool, "Treat name as a regular expression."] = False,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List initial SID context statements (SELinux policies only)."""
        q = InitialSIDQuery(self._load_policy(policy_path),
                            name=name,
                            name_regex=name_regex)

        return self._collect_results(q, max_results=max_results)

    def setools_list_portcons(
        self,
        ports: Annotated[
            str | None,
            "Port number or range to filter by, e.g. '80' or '8000-8080'. "
            "Matches portcons whose range overlaps the given value.",
        ] = None,
        protocol: Annotated[
            str | None,
            "Protocol to filter by: tcp, udp, dccp, or sctp. "
            "If omitted, all protocols match.",
        ] = None,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List portcon statements (SELinux policies only)."""
        if ports:
            parts = [int(p) for p in ports.split("-")]
            if len(parts) == 1:
                port_range: PortconRange | None = PortconRange(parts[0], parts[0])
            elif len(parts) == 2:
                port_range = PortconRange(parts[0], parts[1])
            else:
                raise ValueError(
                    "ports must be a single number or a low-high range, e.g. '80-443'"
                )
        else:
            port_range = None

        q = PortconQuery(self._load_policy(policy_path),
                         ports=port_range,
                         ports_subset=True,
                         protocol=PortconProtocol[protocol] if protocol else None)

        return self._collect_results(q, max_results=max_results)

    def setools_list_netifcons(
        self,
        name: Annotated[
            str | None, "Network interface name (or regex pattern) to filter by."
        ] = None,
        name_regex: Annotated[bool, "Treat name as a regular expression."] = False,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List netifcon statements (SELinux policies only)."""
        q = NetifconQuery(self._load_policy(policy_path),
                          name=name,
                          name_regex=name_regex)

        return self._collect_results(q, max_results=max_results)

    def setools_list_nodecons(
        self,
        network: Annotated[
            str | None,
            "IP network address to filter by, e.g. '192.168.1.0/24' or '::1/128'. "
            "Matches nodecons whose network overlaps the given address.",
        ] = None,
        ip_version: Annotated[
            str | None, "IP version to filter by: ipv4 or ipv6."
        ] = None,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List nodecon statements (SELinux policies only)."""
        q = NodeconQuery(self._load_policy(policy_path),
                         network=ipaddress.ip_network(network, strict=False) if network else None,
                         network_overlap=bool(network),
                         ip_version=NodeconIPVersion[ip_version] if ip_version else None)

        return self._collect_results(q, max_results=max_results)

    def setools_list_ibpkeycons(
        self,
        pkeys: Annotated[
            str | None,
            "Infiniband pkey or range to filter by in hex, "
            "e.g. '0x22' or '0x6000-0x6020'.",
        ] = None,
        subnet_prefix: Annotated[
            str | None, "IPv6 subnet prefix to filter by, e.g. 'fe80::'."
        ] = None,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List Infiniband pkey context (ibpkeycon) statements (SELinux policies only)."""
        if pkeys:
            parts = [int(p, 16) for p in pkeys.split("-")]
            if len(parts) == 1:
                pkey_range: IbpkeyconRange | None = IbpkeyconRange(parts[0], parts[0])
            elif len(parts) == 2:
                pkey_range = IbpkeyconRange(parts[0], parts[1])
            else:
                raise ValueError("pkeys must be a single hex value or low-high range")
        else:
            pkey_range = None

        q = IbpkeyconQuery(self._load_policy(policy_path),
                           pkeys=pkey_range,
                           subnet_prefix=ipaddress.IPv6Address(subnet_prefix)
                           if subnet_prefix else None)

        return self._collect_results(q, max_results=max_results)

    def setools_list_ibendportcons(
        self,
        name: Annotated[
            str | None, "Infiniband device name (or regex pattern) to filter by."
        ] = None,
        name_regex: Annotated[bool, "Treat name as a regular expression."] = False,
        port: Annotated[int | None, "Specific end port number to filter by."] = None,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List Infiniband end port context (ibendportcon) statements (SELinux only)."""
        q = IbendportconQuery(self._load_policy(policy_path),
                              name=name,
                              name_regex=name_regex,
                              port=port)

        return self._collect_results(q, max_results=max_results)

    def setools_list_iomemcons(
        self,
        addr: Annotated[
            str | None,
            "I/O memory address or range to filter by in hex, "
            "e.g. '0x22' or '0x6000-0x6020'.",
        ] = None,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List iomemcon statements (Xen policies only)."""
        if addr:
            parts = [int(p, 16) for p in addr.split("-")]
            if len(parts) == 1:
                addr_range: IomemconRange | None = IomemconRange(parts[0], parts[0])
            elif len(parts) == 2:
                addr_range = IomemconRange(parts[0], parts[1])
            else:
                raise ValueError("addr must be a single hex value or low-high range")
        else:
            addr_range = None

        q = IomemconQuery(self._load_policy(policy_path),
                          addr=addr_range)

        return self._collect_results(q, max_results=max_results)

    def setools_list_ioportcons(
        self,
        ports: Annotated[
            str | None,
            "I/O port number or range to filter by in hex, "
            "e.g. '0x80' or '0x3f8-0x3ff'.",
        ] = None,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List ioportcon statements (Xen policies only)."""
        if ports:
            parts = [int(p, 16) for p in ports.split("-")]
            if len(parts) == 1:
                port_range: IoportconRange | None = IoportconRange(parts[0], parts[0])
            elif len(parts) == 2:
                port_range = IoportconRange(parts[0], parts[1])
            else:
                raise ValueError("ports must be a single hex value or low-high range")
        else:
            port_range = None

        q = IoportconQuery(self._load_policy(policy_path),
                           ports=port_range,
                           ports_subset=True)

        return self._collect_results(q, max_results=max_results)

    def setools_list_pcidevicecons(
        self,
        device: Annotated[
            str | None, "PCI device address in hex to filter by, e.g. '0xc800'."
        ] = None,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List pcidevicecon statements (Xen policies only)."""
        q = PcideviceconQuery(self._load_policy(policy_path),
                              device=int(device, 16) if device else None)

        return self._collect_results(q, max_results=max_results)

    def setools_list_pirqcons(
        self,
        irq: Annotated[int | None, "IRQ number to filter by."] = None,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List pirqcon statements (Xen policies only)."""
        q = PirqconQuery(self._load_policy(policy_path),
                         irq=irq)

        return self._collect_results(q, max_results=max_results)

    def setools_list_devicetreecons(
        self,
        path: Annotated[
            str | None, "Device tree path (or regex pattern) to filter by."
        ] = None,
        path_regex: Annotated[bool, "Treat path as a regular expression."] = False,
        max_results: Annotated[int, "Maximum number of results."] = 200,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """List devicetreecon statements (Xen policies only)."""
        q = DevicetreeconQuery(self._load_policy(policy_path),
                               path=path,
                               path_regex=path_regex)

        return self._collect_results(q, max_results=max_results)

    def setools_analyze_dta(
        self,
        mode: Annotated[
            str,
            "Analysis mode.  One of:\n"
            "  ShortestPaths  — all shortest transition paths from source to target\n"
            "  AllPaths       — all paths up to depth_limit from source to target\n"
            "  TransitionsOut — all transitions that originate from the source domain\n"
            "  TransitionsIn  — all transitions that arrive at the target domain",
        ] = "ShortestPaths",
        source: Annotated[
            str | None,
            "Source domain type.  Required for ShortestPaths, AllPaths, "
            "and TransitionsOut.",
        ] = None,
        target: Annotated[
            str | None,
            "Target domain type.  Required for ShortestPaths, AllPaths, "
            "and TransitionsIn.",
        ] = None,
        reverse: Annotated[
            bool,
            "If True, reverse the transition graph (follow transitions backwards).",
        ] = False,
        depth_limit: Annotated[
            int | None,
            "Maximum path depth.  Defaults to 5 to prevent runaway searches.  "
            "Set to None for unlimited (use with caution on large policies).",
        ] = 5,
        exclude: Annotated[
            list[str] | None,
            "Type names to exclude from the transition graph.",
        ] = None,
        max_results: Annotated[
            int,
            "Maximum number of transitions or paths to return.",
        ] = 50,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """
        Perform Domain Transition Analysis (DTA) on an SELinux policy.

        Equivalent to the sedta command-line tool.  Finds the domains that a
        process running as *source* can transition to (directly or via
        intermediaries), and the SELinux rules that enable each transition.

        For transitive modes (ShortestPaths / AllPaths) each result is a
        'path' — an ordered list of transition steps.  For direct modes
        (TransitionsOut / TransitionsIn) each result is a single transition step.

        Each transition step contains the source and target domain, the
        allow/type_transition rules that permit the transition, the entrypoint
        executables, setexec rules, and dynamic transition rules.

        If the required dependency (NetworkX) is not installed, this method will
        raise a NameError.
        """
        analysis = DomainTransitionAnalysis(self._load_policy(policy_path),
                                            source=source,
                                            target=target,
                                            mode=DomainTransitionAnalysis.Mode.lookup(mode),
                                            reverse=reverse,
                                            depth_limit=depth_limit,
                                            exclude=exclude)

        results: list[Any] = []
        truncated = False

        if analysis.mode in DomainTransitionAnalysis.TRANSITIVE_MODES:
            for path in analysis.results():
                if len(results) >= max_results:
                    truncated = True
                    break
                results.append({"path": [p for p in path]})  # type: ignore[union-attr]
        else:
            for transition in analysis.results():
                if len(results) >= max_results:
                    truncated = True
                    break
                results.append(transition)

        return self._serialize_results(results, len(results), truncated)

    def setools_analyze_info_flow(
        self,
        mode: Annotated[
            str,
            "Analysis mode.  One of:\n"
            "  ShortestPaths — all shortest information flow paths from source to target\n"
            "  AllPaths      — all paths up to depth_limit from source to target\n"
            "  FlowsOut      — all information flows originating from source\n"
            "  FlowsIn       — all information flows arriving at target",
        ] = "ShortestPaths",
        source: Annotated[
            str | None,
            "Source type.  Required for ShortestPaths, AllPaths, and FlowsOut.",
        ] = None,
        target: Annotated[
            str | None,
            "Target type.  Required for ShortestPaths, AllPaths, and FlowsIn.",
        ] = None,
        min_weight: Annotated[
            int,
            "Minimum information flow weight to include (1-10).  Higher values restrict "
            "results to more significant flows.  Default is 3.",
        ] = 3,
        depth_limit: Annotated[
            int | None,
            "Maximum path length.  Defaults to 3.  "
            "Set to None for unlimited (use with caution).",
        ] = 3,
        exclude: Annotated[
            list[str] | None, "Type names to exclude from the flow graph."
        ] = None,
        perm_map_path: Annotated[
            str | None,
            "Path to a custom permission map file.  If omitted, the setools built-in "
            "permission map is used.",
        ] = None,
        max_results: Annotated[
            int, "Maximum number of flows or paths to return."
        ] = 50,
        policy_path: Annotated[str | None, "Path to the policy file."] = None,
    ) -> str:
        """
        Perform Information Flow Analysis on an SELinux policy.

        Equivalent to the seinfoflow command-line tool.  Traces how information
        can move between types through the allow rules weighted by the permission
        map.

        For transitive modes (ShortestPaths / AllPaths) each result is a
        'path' — an ordered list of flow steps.  For direct modes (FlowsOut /
        FlowsIn) each result is a single flow step.

        Each step includes the source and target types, the combined flow weight,
        and the allow rules that create the flow.

        If the required dependency (NetworkX) is not installed, this method will
        raise a NameError.
        """
        analysis = InfoFlowAnalysis(self._load_policy(policy_path),
                                    PermissionMap(perm_map_path),
                                    source=source,
                                    target=target,
                                    mode=InfoFlowAnalysis.Mode.lookup(mode),
                                    min_weight=min_weight,
                                    depth_limit=depth_limit,
                                    exclude=exclude)

        results: list[Any] = []
        truncated = False

        if analysis.mode in InfoFlowAnalysis.TRANSITIVE_MODES:
            for path in analysis.results():
                if len(results) >= max_results:
                    truncated = True
                    break
                results.append({"path": [p for p in path]})  # type: ignore[union-attr]
        else:
            for step in analysis.results():
                if len(results) >= max_results:
                    truncated = True
                    break
                results.append(step)

        return self._serialize_results(results, len(results), truncated)

    def setools_diff_policies(
        self,
        left_policy: Annotated[str, "Path to the left (baseline) policy file."],
        right_policy: Annotated[str, "Path to the right (new) policy file."],
        components: Annotated[
            list[str] | None,
            "Components to compare.  If omitted, defaults to: te_rules, rbac_rules, "
            "types, roles, users.  Available components: "
            + ", ".join(sorted(DiffComponent)),
        ] = None,
        max_per_component: Annotated[
            int,
            "Maximum number of added/removed/modified items to return per component.",
        ] = 100,
    ) -> str:
        """
        Compare two SELinux policies and report their differences.

        Equivalent to the sediff command-line tool.  For each selected component,
        returns the items that were added to the right policy, removed from the
        left policy, and (for TE allow rules) modified.

        Policies are loaded fresh — not from the server cache — so this tool
        can be used to compare any two policy files regardless of which policy
        the server was started with.
        """
        left = SELinuxPolicy(left_policy)
        right = SELinuxPolicy(right_policy)
        diff = PolicyDifference(left, right)

        selected: set[DiffComponent] = {DiffComponent(c) for c in components} if components \
            else {DiffComponent.TE_RULES}

        def _cap(items: Any, limit: int) -> tuple[list[Any], bool]:
            lst = sorted(items)
            return lst[:limit], len(lst) > limit

        count = 0
        any_truncated = False
        differences: dict[str, Any] = {}

        if DiffComponent.TE_RULES in selected:
            added, trunc_a = _cap(diff.added_allows, max_per_component)
            removed, trunc_r = _cap(diff.removed_allows, max_per_component)
            modified, trunc_m = _cap(diff.modified_allows, max_per_component)
            count += len(added) + len(removed) + len(modified)
            any_truncated = any_truncated or trunc_a or trunc_r or trunc_m
            differences["te_rules"] = {
                "added_allows": {
                    "rules": sorted(added),
                    "truncated": trunc_a,
                },
                "removed_allows": {
                    "rules": sorted(removed),
                    "truncated": trunc_r,
                },
                "modified_allows": {
                    "rules": [
                        {
                            "rule": m.rule,
                            "added_perms": sorted(m.added_perms),
                            "removed_perms": sorted(m.removed_perms),
                            "matched_perms": sorted(m.matched_perms),
                        }
                        for m in modified
                    ],
                    "truncated": trunc_m,
                },
            }

        if DiffComponent.TYPES in selected:
            added, trunc_a = _cap(diff.added_types, max_per_component)
            removed, trunc_r = _cap(diff.removed_types, max_per_component)
            count += len(added) + len(removed)
            any_truncated = any_truncated or trunc_a or trunc_r
            differences["types"] = {
                "added": [str(t) for t in added],
                "added_truncated": trunc_a,
                "removed": [str(t) for t in removed],
                "removed_truncated": trunc_r,
            }

        if DiffComponent.ROLES in selected:
            added, trunc_a = _cap(diff.added_roles, max_per_component)
            removed, trunc_r = _cap(diff.removed_roles, max_per_component)
            count += len(added) + len(removed)
            any_truncated = any_truncated or trunc_a or trunc_r
            differences["roles"] = {
                "added": [str(r) for r in added],
                "added_truncated": trunc_a,
                "removed": [str(r) for r in removed],
                "removed_truncated": trunc_r,
            }

        if DiffComponent.USERS in selected:
            added, trunc_a = _cap(diff.added_users, max_per_component)
            removed, trunc_r = _cap(diff.removed_users, max_per_component)
            count += len(added) + len(removed)
            any_truncated = any_truncated or trunc_a or trunc_r
            differences["users"] = {
                "added": [str(u) for u in added],
                "added_truncated": trunc_a,
                "removed": [str(u) for u in removed],
                "removed_truncated": trunc_r,
            }

        if DiffComponent.RBAC_RULES in selected:
            added_ra, trunc_a = _cap(diff.added_role_allows, max_per_component)
            removed_ra, trunc_r = _cap(diff.removed_role_allows, max_per_component)
            added_rt, trunc_at = _cap(diff.added_role_transitions, max_per_component)
            removed_rt, trunc_rt = _cap(diff.removed_role_transitions, max_per_component)
            count += len(added_ra) + len(removed_ra) + len(added_rt) + len(removed_rt)
            any_truncated = any_truncated or trunc_a or trunc_r or trunc_at or trunc_rt
            differences["rbac_rules"] = {
                "added_role_allows": {
                    "rules": sorted(added_ra),
                    "truncated": trunc_a,
                },
                "removed_role_allows": {
                    "rules": sorted(removed_ra),
                    "truncated": trunc_r,
                },
                "added_role_transitions": {
                    "rules": sorted(added_rt),
                    "truncated": trunc_at,
                },
                "removed_role_transitions": {
                    "rules": sorted(removed_rt),
                    "truncated": trunc_rt,
                },
            }

        if DiffComponent.MLS_RULES in selected:
            added, trunc_a = _cap(diff.added_range_transitions, max_per_component)
            removed, trunc_r = _cap(diff.removed_range_transitions, max_per_component)
            count += len(added) + len(removed)
            any_truncated = any_truncated or trunc_a or trunc_r
            differences["mls_rules"] = {
                "added_range_transitions": {
                    "rules": sorted(added),
                    "truncated": trunc_a,
                },
                "removed_range_transitions": {
                    "rules": sorted(removed),
                    "truncated": trunc_r,
                },
            }

        if DiffComponent.PORTCONS in selected:
            added, trunc_a = _cap(diff.added_portcons, max_per_component)
            removed, trunc_r = _cap(diff.removed_portcons, max_per_component)
            count += len(added) + len(removed)
            any_truncated = any_truncated or trunc_a or trunc_r
            differences["portcons"] = {
                "added": [r.statement() for r in added],
                "added_truncated": trunc_a,
                "removed": [r.statement() for r in removed],
                "removed_truncated": trunc_r,
            }

        return self._serialize_results(differences, count, any_truncated)
