# SPDX-License-Identifier: LGPL-2.1-only

from contextlib import suppress
import json
from typing import Any

from .. import dta, exception, infoflow, policyrep

__all__ = ("MCPEncoder",)


class MCPEncoder(json.JSONEncoder):

    """Policy object encoder for MCP server responses."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, policyrep.BaseTERule):
            d: dict[str, Any] = {
                "statement": obj.statement(),
                "ruletype": obj.ruletype.name,
                "source": obj.source.name,
                "target": obj.target.name,
                "tclass": obj.tclass.name,
            }
            with suppress(exception.RuleUseError):
                d["xperm_type"] = str(obj.xperm_type)
            with suppress(exception.RuleUseError):
                d["perms"] = sorted(obj.perms)
            with suppress(exception.RuleUseError):
                d["default"] = str(obj.default)
                with suppress(exception.RuleUseError, exception.TERuleNoFilename):
                    d["filename"] = str(obj.filename)
            with suppress(exception.RuleNotConditional):
                cond = obj.conditional
                d["conditional"] = str(cond)
                d["conditional_block"] = obj.conditional_block
            return d

        if isinstance(obj, policyrep.Boolean):
            return {"name": obj.name, "default_state": obj.state, "statement": obj.statement()}

        if isinstance(obj, policyrep.Bounds):
            return {
                "statement": obj.statement(),
                "ruletype": obj.ruletype.name,
                "parent": obj.parent.name,
                "child": obj.child.name,
            }

        if isinstance(obj, (policyrep.Category, policyrep.Sensitivity)):
            return {"name": obj.name,
                    "statement": obj.statement(),
                    "aliases": sorted(obj.aliases())}

        if isinstance(obj, policyrep.Common):
            return {"name": obj.name, "perms": sorted(obj.perms), "statement": obj.statement()}

        if isinstance(obj, (policyrep.Constraint, policyrep.Validatetrans)):
            d = {
                "statement": obj.statement(),
                "ruletype": obj.ruletype.name,
                "tclass": obj.tclass.name,
                "expression": str(obj.expression),
            }
            with suppress(exception.ConstraintUseError):
                d["perms"] = sorted(str(p) for p in obj.perms)
            return d

        if isinstance(obj, policyrep.Context):
            d = {
                "user": obj.user.name,
                "role": obj.role.name,
                "type": obj.type_.name,
            }
            with suppress(exception.MLSDisabled):
                d["range"] = str(obj.range_)
            return d

        if isinstance(obj, policyrep.DefaultRange):
            return {
                "statement": obj.statement(),
                "ruletype": obj.ruletype.name,
                "tclass": obj.tclass.name,
                "default": obj.default.name,
                "default_range": obj.default_range.name,
            }

        if isinstance(obj, policyrep.Default):
            return {
                "statement": obj.statement(),
                "ruletype": obj.ruletype.name,
                "tclass": obj.tclass.name,
                "default": obj.default.name,
            }

        if isinstance(obj, policyrep.Devicetreecon):
            return {
                "statement": obj.statement(),
                "path": obj.path,
                "context": str(obj.context),
            }

        if isinstance(obj, dta.DomainEntrypoint):
            return {
                "name": obj.name.name,
                "entrypoint_rules": sorted(r.statement() for r in obj.entrypoint),
                "execute_rules": sorted(r.statement() for r in obj.execute),
                "type_transition_rules": sorted(r.statement() for r in obj.type_transition),
            }

        if isinstance(obj, dta.DomainTransition):
            return {
                "source": obj.source.name,
                "target": obj.target.name,
                "transition_rules": sorted(r.statement() for r in obj.transition),
                "entrypoints": [self.default(e) for e in sorted(obj.entrypoints)],
                "setexec_rules": sorted(r.statement() for r in obj.setexec),
                "dyntransition_rules": sorted(r.statement() for r in obj.dyntransition),
                "setcurrent_rules": sorted(r.statement() for r in obj.setcurrent),
            }

        if isinstance(obj, policyrep.FSUse):
            return {
                "statement": obj.statement(),
                "ruletype": obj.ruletype.name,
                "fs": obj.fs,
                "context": str(obj.context),
            }

        if isinstance(obj, policyrep.Genfscon):
            d = {
                "statement": obj.statement(),
                "fs": obj.fs,
                "path": obj.path,
                "context": str(obj.context),
            }
            if obj.tclass:
                d["tclass"] = obj.tclass.name
            if obj.filetype:
                d["filetype"] = str(obj.filetype)
            return d

        if isinstance(obj, policyrep.Ibendportcon):
            return {
                "statement": obj.statement(),
                "name": obj.name,
                "port": obj.port,
                "context": str(obj.context),
            }

        if isinstance(obj, policyrep.Ibpkeycon):
            return {
                "statement": obj.statement(),
                "subnet_prefix": str(obj.subnet_prefix),
                "pkeys": str(obj.pkeys),
                "context": str(obj.context),
            }

        if isinstance(obj, infoflow.InfoFlowStep):
            return {
                "source": obj.source.name,
                "target": obj.target.name,
                "weight": obj.weight,
                "rules": sorted(r.statement() for r in obj.rules),
            }

        if isinstance(obj, policyrep.InitialSID):
            return {
                "statement": obj.statement(),
                "name": obj.name,
                "context": str(obj.context),
            }

        if isinstance(obj, policyrep.Iomemcon):
            return {
                "statement": obj.statement(),
                "addr": str(obj.addr),
                "context": str(obj.context),
            }

        if isinstance(obj, policyrep.Ioportcon):
            return {
                "statement": obj.statement(),
                "ports": str(obj.ports),
                "context": str(obj.context),
            }

        if isinstance(obj, (policyrep.Level, policyrep.LevelDecl, policyrep.Range)):
            return str(obj)

        if isinstance(obj, policyrep.MLSRule):
            return {
                "statement": obj.statement(),
                "ruletype": obj.ruletype.name,
                "source": obj.source.name,
                "target": obj.target.name,
                "tclass": obj.tclass.name,
                "default": str(obj.default),
            }

        if isinstance(obj, policyrep.Netifcon):
            return {
                "statement": obj.statement(),
                "netif": obj.netif,
                "context": str(obj.context),
                "packet_context": str(obj.packet),
            }

        if isinstance(obj, policyrep.Nodecon):
            return {
                "statement": obj.statement(),
                "network": str(obj.network),
                "ip_version": obj.ip_version.name,
                "context": str(obj.context),
            }

        if isinstance(obj, policyrep.ObjClass):
            d = {"name": obj.name}
            try:
                # Do not use obj.commmon.name as it presents a difficulty for
                # unit testing (__getattr__ exception on a mock)
                d["common"] = str(obj.common)
                d["perms"] = sorted(obj.perms | obj.common.perms)
            except exception.NoCommon:
                d["perms"] = sorted(obj.perms)

            return d

        if isinstance(obj, policyrep.Pcidevicecon):
            return {
                "statement": obj.statement(),
                "device": str(obj.device),
                "context": str(obj.context),
            }

        if isinstance(obj, policyrep.Pirqcon):
            return {
                "statement": obj.statement(),
                "irq": obj.irq,
                "context": str(obj.context),
            }

        if isinstance(obj, policyrep.PolicyCapability):
            return {"name": obj.name, "statement": obj.statement()}

        if isinstance(obj, policyrep.Portcon):
            return {
                "statement": obj.statement(),
                "protocol": obj.protocol.name,
                "ports_low": obj.ports.low,
                "ports_high": obj.ports.high,
                "context": str(obj.context),
            }

        if isinstance(obj, policyrep.Role):
            return {"name": obj.name,
                    "types": sorted(t.name for t in obj.types()),
                    "statement": obj.statement()}

        if isinstance(obj, policyrep.RoleAllow):
            return {
                "statement": obj.statement(),
                "ruletype": obj.ruletype.name,
                "source": obj.source.name,
                "target": obj.target.name}

        if isinstance(obj, policyrep.RoleTransition):
            return {
                "statement": obj.statement(),
                "ruletype": obj.ruletype.name,
                "source": obj.source.name,
                "target": obj.target.name,
                "tclass": obj.tclass.name,
                "default": obj.default.name}

        if isinstance(obj, policyrep.SELinuxPolicy):
            return {
                "path": obj.path,
                "version": obj.version,
                "target_platform": str(obj.target_platform),
                "handle_unknown": str(obj.handle_unknown),
                "mls": obj.mls,
                "counts": {
                    "types": obj.type_count,
                    "type_attributes": obj.type_attribute_count,
                    "roles": obj.role_count,
                    "users": obj.user_count,
                    "booleans": obj.boolean_count,
                    "classes": obj.class_count,
                    "commons": obj.common_count,
                    "allow_rules": obj.allow_count,
                    "auditallow_rules": obj.auditallow_count,
                    "dontaudit_rules": obj.dontaudit_count,
                    "neverallow_rules": obj.neverallow_count,
                    "type_transition_rules": obj.type_transition_count,
                    "type_change_rules": obj.type_change_count,
                    "type_member_rules": obj.type_member_count,
                    "role_allow_rules": obj.role_allow_count,
                    "role_transitions": obj.role_transition_count,
                    "range_transitions": obj.range_transition_count,
                    "constraints": obj.constraint_count,
                    "portcons": obj.portcon_count,
                    "netifcons": obj.netifcon_count,
                    "nodecons": obj.nodecon_count,
                    "genfscons": obj.genfscon_count,
                    "fs_uses": obj.fs_use_count,
                    "initialsids": obj.initialsids_count,
                    "polcaps": obj.polcap_count,
                    "permissive_domains": obj.permissives_count,
                    "conditionals": obj.conditional_count,
                },
            }

        if isinstance(obj, policyrep.Type):
            return {"name": obj.name,
                    "statement": obj.statement(),
                    "attributes": sorted(a.name for a in obj.attributes()),
                    "aliases": sorted(obj.aliases()),
                    "permissive": bool(obj.ispermissive)}

        if isinstance(obj, policyrep.TypeAttribute):
            return {"name": obj.name,
                    "statement": obj.statement(),
                    "types": sorted(t.name for t in obj.expand())}

        if isinstance(obj, policyrep.User):
            d = {"name": obj.name, "roles": sorted(r.name for r in obj.roles)}
            with suppress(exception.MLSDisabled):
                d["mls_level"] = str(obj.mls_level)
                d["mls_range"] = str(obj.mls_range)
            return d

        return super().default(obj)
