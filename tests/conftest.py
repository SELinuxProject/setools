# SPDX-License-Identifier: GPL-2.0-only
# pylint: disable=attribute-defined-outside-init
# mypy: disable-error-code="attr-defined"
import os
from collections.abc import Iterable
from contextlib import suppress
import ipaddress
import subprocess
import tempfile
from unittest.mock import Mock, MagicMock

import pytest
import setools


class SortableMock(MagicMock):

    """Mock class that can be sorted."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # MagicMock._mock_set_magics() replaces magic methods (including __lt__)
        # on the per-instance dynamic class, overriding any class-body definition.
        # Re-establish __lt__ here, after that setup, so instances sort by name.
        type(self).__lt__ = lambda self, other: str(self.name) < str(other.name)

    def __repr__(self):
        return f"<{self.__class__} name={self.name}>"


@pytest.fixture
def mock_common():
    generated_common: dict[str, setools.Common] = {}

    def _factory(name: str, perms: Iterable[str] | None = None) -> setools.Common:
        """Factory function for Common objects, using a mock object."""
        with suppress(KeyError):
            return generated_common[name]

        common = SortableMock(setools.Common)
        common.name = name
        common.__str__.return_value = name
        common.perms = frozenset(perms) if perms is not None else frozenset()
        common.statement.return_value = "common {}\n{{\n\t{}\n}}".format(
            name, '\n\t'.join(sorted(common.perms)))
        generated_common[name] = common
        return common

    return _factory


@pytest.fixture
def mock_class():
    generated_class: dict[str, setools.ObjClass] = {}

    def _factory(name: str, common: setools.Common | None = None,
                 perms: Iterable[str] | None = None) -> setools.ObjClass:
        """Factory function for ObjClass objects, using a mock object."""
        with suppress(KeyError):
            return generated_class[name]

        obj_class = SortableMock(setools.ObjClass)
        obj_class.name = name
        obj_class.__str__.return_value = name
        class_perms = frozenset(perms) if perms is not None else frozenset()
        if common:
            obj_class.common = common
            obj_class.perms = frozenset(class_perms | common.perms)
        else:
            obj_class.common.name = MagicMock()
            obj_class.common.name.__str__.side_effect = setools.exception.NoCommon
            obj_class.common.perms = MagicMock()
            obj_class.common.perms.__iter__.side_effect = setools.exception.NoCommon
            obj_class.perms = class_perms
        generated_class[name] = obj_class
        return obj_class

    return _factory


@pytest.fixture
def mock_role():
    generated_roles: dict[str, setools.Role] = {}

    def _factory(name: str, /, *, types: frozenset[setools.Type] | None = None) -> setools.Role:
        """Factory function for Role objects."""
        with suppress(KeyError):
            return generated_roles[name]

        role = SortableMock(setools.Role)
        role.name = name
        role.__str__.return_value = name

        if types is not None:
            role.types.return_value = types
            type_names = sorted(t.name for t in types)
            if len(type_names) == 1:
                stmt = f"role {name} types {type_names[0]};"
            elif len(type_names) > 1:
                stmt = f"role {name} types {{ {' '.join(type_names)} }};"
            else:
                stmt = f"role {name};"
        else:
            stmt = f"role {name};"
        role.statement.return_value = stmt

        generated_roles[name] = role
        return role

    return _factory


@pytest.fixture
def mock_type():
    generated_types: dict[str, setools.Type] = {}

    def _factory(name: str, attrs: Iterable[setools.TypeAttribute] | None = None,
                 alias: Iterable[str] | None = None, perm: bool = False) -> setools.Type:
        """Factory function for Type objects."""
        with suppress(KeyError):
            return generated_types[name]

        type_ = SortableMock(setools.Type)
        type_.name = name
        type_.ispermissive = perm
        type_.attributes.return_value = attrs if attrs is not None else ()
        type_.aliases.return_value = alias if alias is not None else ()
        type_.__str__.return_value = name
        aliases_list = list(alias) if alias is not None else []
        attrs_list = list(attrs) if attrs is not None else []
        stmt = f"type {name}"
        if len(aliases_list) > 1:
            stmt += f" alias {{ {' '.join(sorted(aliases_list))} }}"
        elif len(aliases_list) == 1:
            stmt += f" alias {aliases_list[0]}"
        if attrs_list:
            stmt += f", {', '.join(a.name for a in sorted(attrs_list, key=lambda a: a.name))}"
        stmt += ";"
        type_.statement.return_value = stmt
        generated_types[name] = type_
        return type_

    return _factory


@pytest.fixture
def mock_typeattr():
    generated_attrs: dict[str, setools.TypeAttribute] = {}

    def _factory(name: str, types: Iterable[setools.Type] | None = None) -> setools.TypeAttribute:
        """Factory function for TypeAttribute objects, using a mock qpol object."""
        attr = SortableMock(setools.TypeAttribute)
        attr.name = name
        attr.expand.return_value = types if types is not None else ()
        attr.__str__.return_value = name
        attr.statement.return_value = f"attribute {name};"
        generated_attrs[name] = attr
        return attr

    return _factory


@pytest.fixture
def mock_user(mock_role):
    generated_users: dict[str, setools.User] = {}

    def _factory(name: str, roles: frozenset[setools.Role] | None = None,
                 level: setools.Level | None = None,
                 range_: setools.Range | None = None) -> setools.User:
        """Factory function for User objects."""
        with suppress(KeyError):
            return generated_users[name]

        assert (level and range_) or (not level and not range_)

        user = SortableMock(setools.User)
        user.name = name
        user.__str__.return_value = name

        if roles is not None:
            # inject object_r, like the compiler does
            full_roles = {mock_role("object_r"), *roles}
            user.roles = frozenset(full_roles)

        if level:
            assert range_
            user.mls_level = level
            user.mls_range = range_
        else:
            user.mls_level = MagicMock()
            user.mls_level.__str__.side_effect = setools.exception.MLSDisabled
            user.mls_range = MagicMock()
            user.mls_range.__str__.side_effect = setools.exception.MLSDisabled

        generated_users[name] = user
        return user

    return _factory


@pytest.fixture
def mock_sens():
    generated_sensitivities: dict[str, setools.Sensitivity] = {}

    def _factory(name: str, aliases: Iterable[str] | None = None) -> setools.Sensitivity:
        """Factory function for Sensitivity objects."""
        with suppress(KeyError):
            return generated_sensitivities[name]

        sens = SortableMock(setools.Sensitivity)
        sens.name = name
        sens.aliases.return_value = aliases if aliases is not None else ()
        sens.__str__.return_value = name
        aliases_list = list(aliases) if aliases is not None else []
        if len(aliases_list) == 0:
            stmt = f"sensitivity {name};"
        elif len(aliases_list) == 1:
            stmt = f"sensitivity {name} alias {aliases_list[0]};"
        else:
            stmt = f"sensitivity {name} alias {{ {' '.join(sorted(aliases_list))} }};"
        sens.statement.return_value = stmt
        generated_sensitivities[name] = sens
        return sens

    return _factory


@pytest.fixture
def mock_cat():
    generated_categories: dict[str, setools.Category] = {}

    def _factory(name: str, aliases: Iterable[str] | None = None) -> setools.Category:
        """Factory function for Category objects."""
        with suppress(KeyError):
            return generated_categories[name]

        cat = SortableMock(setools.Category)
        cat.name = name
        cat.aliases.return_value = aliases if aliases is not None else ()
        cat.__str__.return_value = name
        aliases_list = list(aliases) if aliases is not None else []
        if len(aliases_list) == 0:
            stmt = f"category {name};"
        elif len(aliases_list) == 1:
            stmt = f"category {name} alias {aliases_list[0]};"
        else:
            stmt = f"category {name} alias {{ {' '.join(sorted(aliases_list))} }};"
        cat.statement.return_value = stmt
        generated_categories[name] = cat
        return cat

    return _factory


@pytest.fixture
def mock_level():
    def _factory(sens: setools.Sensitivity,
                 cats: Iterable[setools.Category] | None = None) -> setools.Level:
        """Factory function for Level objects."""
        level = MagicMock(setools.Level)
        level.sensitivity = sens
        level._categories = cats if cats is not None else ()
        level.categories = lambda self: iter(self._categories)
        level.statement.side_effect = setools.exception.NoStatement
        if cats:
            cats_str = ",".join(c.name for c in cats)
            level.__str__.return_value = f"{sens.name}:{cats_str}"
        else:
            level.__str__.return_value = sens.name
        return level

    return _factory


@pytest.fixture
def mock_range():
    def _factory(low: setools.Level, high: setools.Level | None = None) -> setools.Range:
        """Factory function for Range objects."""
        range_ = MagicMock(setools.Range)
        range_.low = low
        range_.high = high if high is not None else low
        range_.statement.side_effect = setools.exception.NoStatement
        if high is None:
            range_.__str__.return_value = str(low)
        else:
            range_.__str__.return_value = f"{low} - {high}"
        return range_

    return _factory


@pytest.fixture
def mock_context():
    def _factory(user: setools.User, role: setools.Role, type_: setools.Type,
                 range_: setools.Range | None = None) -> setools.Context:
        """Factory function for Context objects."""
        context = MagicMock(setools.Context)
        context.user = user
        context.role = role
        context.type_ = type_
        context.statement.side_effect = setools.exception.NoStatement
        if range_:
            context.range_ = range_
            context.__str__.return_value = f"{user}:{role}:{type_}:{range_}"
        else:
            context.range_ = MagicMock()
            context.range_.__iter__.side_effect = setools.exception.MLSDisabled
            context.range_.__str__.side_effect = setools.exception.MLSDisabled
            context.__str__.return_value = f"{user}:{role}:{type_}"
        return context

    return _factory


@pytest.fixture()
def mock_conditional():
    """Factory for Conditional mocks."""
    def _factory(booleans: Iterable[str]) -> setools.Conditional:
        conditional = MagicMock(setools.Conditional)
        conditional.booleans = frozenset(booleans)
        conditional.__str__.return_value = " && ".join(sorted(conditional.booleans))
        return conditional
    return _factory


@pytest.fixture()
def mock_av_rule():
    """Factory for AV rule mocks."""
    def _factory(ruletype: setools.TERuletype, source: setools.Type, target: setools.Type,
                 tclass: setools.ObjClass, perms: Iterable[str] | setools.XpermSet,
                 xperm_type: str | None = None, conditional: setools.Conditional | None = None,
                 conditional_block: bool = True) -> setools.AnyTERule:

        rule = MagicMock(setools.TERule)
        rule.ruletype = ruletype
        rule.source = source
        rule.target = target
        rule.tclass = tclass
        rule.perms = frozenset(perms)
        rule.default = MagicMock()
        rule.default.__str__.side_effect = setools.exception.RuleUseError
        rule.default.name = MagicMock()
        rule.default.name.__str__.side_effect = setools.exception.RuleUseError
        rule.filename = MagicMock()
        rule.filename.__str__.side_effect = setools.exception.RuleUseError

        if xperm_type:
            rule.xperm_type = xperm_type
            statement = f"{rule.ruletype} {source} {target}:{tclass} " \
                f"{xperm_type} {rule.perms};"
        else:
            rule.xperm_type = MagicMock()
            rule.xperm_type.__str__.side_effect = setools.exception.RuleUseError
            if len(rule.perms) > 1:
                statement = f"{rule.ruletype} {source} {target}:{tclass} "\
                     f"{{ {' '.join(sorted(rule.perms))} }};"
            else:
                statement = f"{rule.ruletype} {source} {target}:{tclass} {list(rule.perms)[0]};"

        if conditional:
            rule.conditional = conditional
            rule.conditional_block = conditional_block
            statement += f" [{conditional}]:{conditional_block}"
        else:
            rule.conditional = MagicMock()
            rule.conditional.__str__.side_effect = setools.exception.RuleNotConditional
            rule.conditional_block = MagicMock()
            rule.conditional_block.__str__.side_effect = setools.exception.RuleNotConditional

        rule.__lt__ = lambda self, other: str(self) < str(other)
        rule.__str__.return_value = statement
        rule.statement.return_value = statement
        return rule
    return _factory


@pytest.fixture()
def mock_te_rule():
    """Factory for TE rule mocks."""
    def _factory(ruletype: setools.TERuletype, source: setools.Type, target: setools.Type,
                 tclass: setools.ObjClass, dflt: setools.Type,
                 condition: setools.Conditional | None = None, block: bool = True,
                 filename: str | None = None) -> setools.AnyTERule:

        rule = MagicMock(setools.TERule)
        rule.ruletype = ruletype
        rule.source = source
        rule.target = target
        rule.tclass = tclass
        rule.default = dflt
        rule.xperm_type = MagicMock()
        rule.xperm_type.__str__.side_effect = setools.exception.RuleUseError
        rule.perms = MagicMock()
        rule.perms.__iter__.side_effect = setools.exception.RuleUseError

        if filename:
            rule.filename = filename
            statement = f"{rule.ruletype} {source} {target}:{tclass} {dflt} \"{filename}\";"
        else:
            rule.filename = MagicMock()
            if ruletype == setools.TERuletype.type_transition:
                rule.filename.__str__.side_effect = setools.exception.TERuleNoFilename
            else:
                rule.filename.__str__.side_effect = setools.exception.RuleUseError
            statement = f"{rule.ruletype} {source} {target}:{tclass} {dflt};"

        if condition:
            rule.conditional = condition
            rule.conditional_block = block
            statement += f" [{condition}]:{block}"
        else:
            rule.conditional = MagicMock()
            rule.conditional.__str__.side_effect = setools.exception.RuleNotConditional
            rule.conditional_block = MagicMock()
            rule.conditional_block.__str__.side_effect = setools.exception.RuleNotConditional

        rule.__lt__ = lambda self, other: str(self) < str(other)
        rule.__str__.return_value = statement
        rule.statement.return_value = statement
        return rule
    return _factory


@pytest.fixture()
def mock_role_allow_rule():
    """Factory for RoleAllow mocks."""
    def _factory(source: setools.Role, target: setools.Role) -> setools.RoleAllow:

        rule = MagicMock(setools.RoleAllow)
        rule.ruletype = setools.RBACRuletype.allow
        rule.source = source
        rule.target = target
        rule.tclass.side_effect = setools.exception.RuleUseError
        rule.default.side_effect = setools.exception.RuleUseError
        statement = f"{rule.ruletype} {source} {target};"
        rule.__lt__ = lambda self, other: str(self) < str(other)
        rule.__str__.return_value = statement
        rule.statement.return_value = statement
        return rule
    return _factory


@pytest.fixture()
def mock_role_transition_rule():
    """Factory for RoleTransition mocks."""
    def _factory(source: setools.Role, target: setools.Type, tclass: setools.ObjClass,
                 dflt: setools.Role) -> setools.RoleTransition:

        rule = MagicMock(setools.RoleTransition)
        rule.ruletype = setools.RBACRuletype.role_transition
        rule.source = source
        rule.target = target
        rule.tclass = tclass
        rule.default = dflt
        statement = f"{rule.ruletype} {source} {target}:{tclass} {dflt};"
        rule.__lt__ = lambda self, other: str(self) < str(other)
        rule.__str__.return_value = statement
        rule.statement.return_value = statement
        return rule
    return _factory


@pytest.fixture
def mock_bool():
    def _factory(name: str, state: bool = True) -> setools.Boolean:
        """Factory function for Boolean objects."""
        b = MagicMock(setools.Boolean)
        b.name = name
        b.state = state
        b.__str__.return_value = name
        b.statement.return_value = f"bool {name} {'true' if state else 'false'};"
        return b
    return _factory


@pytest.fixture
def mock_bounds_rule():
    def _factory(ruletype: setools.BoundsRuletype,
                 parent: setools.Type, child: setools.Type) -> setools.Bounds:
        """Factory function for Bounds rule objects."""
        rule = MagicMock(setools.Bounds)
        rule.ruletype = ruletype
        rule.parent = parent
        rule.child = child
        statement = f"{ruletype} {parent} {child};"
        rule.statement.return_value = statement
        rule.__str__.return_value = statement
        return rule
    return _factory


@pytest.fixture
def mock_constraint_rule():
    def _factory(ruletype: setools.ConstraintRuletype, tclass: setools.ObjClass,
                 expression: str,
                 perms: Iterable[str] | None = None) -> setools.Constraint:
        """Factory function for Constraint/Validatetrans rule objects."""
        if ruletype in (setools.ConstraintRuletype.validatetrans,
                        setools.ConstraintRuletype.mlsvalidatetrans):
            rule = MagicMock(setools.Validatetrans)
        else:
            rule = MagicMock(setools.Constraint)
        rule.ruletype = ruletype
        rule.tclass = tclass
        rule.expression.__str__.return_value = expression
        if perms is not None:
            rule.perms = frozenset(perms)
        else:
            rule.perms.__iter__.side_effect = setools.exception.ConstraintUseError
        statement = f"{ruletype} {tclass} {expression};"
        rule.statement.return_value = statement
        rule.__str__.return_value = statement
        return rule
    return _factory


@pytest.fixture
def mock_default_rule():
    def _factory(ruletype: setools.DefaultRuletype, tclass: setools.ObjClass,
                 default: setools.DefaultValue,
                 default_range: setools.DefaultRangeValue | None = None) -> setools.Default:
        """Factory function for Default rule objects."""
        if default_range:
            rule = MagicMock(setools.DefaultRange)
            rule.default_range = default_range
            statement = f"{ruletype} {tclass} {default} {default_range};"
        else:
            rule = MagicMock(setools.Default)
            rule.default_range = MagicMock()
            rule.default_range.__str__.side_effect = setools.exception.RuleUseError
            statement = f"{ruletype} {tclass} {default};"

        rule.ruletype = ruletype
        rule.tclass = tclass
        rule.default = default
        rule.statement.return_value = statement
        rule.__str__.return_value = statement
        return rule
    return _factory


@pytest.fixture
def mock_devicetreecon():
    def _factory(path: str, context: setools.Context) -> setools.Devicetreecon:
        """Factory function for Devicetreecon objects."""
        d = MagicMock(setools.Devicetreecon)
        d.path = path
        d.context = context
        statement = f"devicetreecon {path} {context};"
        d.statement.return_value = statement
        d.__str__.return_value = statement
        return d
    return _factory


@pytest.fixture
def mock_fs_use():
    def _factory(ruletype: setools.FSUseRuletype, fs: str,
                 context: setools.Context) -> setools.FSUse:
        """Factory function for FSUse objects."""
        f = MagicMock(setools.FSUse)
        f.ruletype = ruletype
        f.fs = fs
        f.context = context
        statement = f"{ruletype} {fs} {context};"
        f.statement.return_value = statement
        f.__str__.return_value = statement
        return f
    return _factory


@pytest.fixture
def mock_genfscon():
    def _factory(fs: str, path: str, context: setools.Context,
                 tclass: setools.ObjClass | str = "") -> setools.Genfscon:
        """Factory function for Genfscon objects."""
        g = MagicMock(setools.Genfscon)
        g.fs = fs
        g.path = path
        g.context = context
        g.tclass = tclass
        g.filetype = setools.policyrep.GenfsFiletype.from_class(tclass)
        statement = f"genfscon {fs} {path} {g.filetype} {context};"
        g.statement.return_value = statement
        g.__str__.return_value = statement
        return g
    return _factory


@pytest.fixture
def mock_ibendportcon():
    def _factory(name: str, port: int, context: setools.Context) -> setools.Ibendportcon:
        """Factory function for Ibendportcon objects."""
        i = MagicMock(setools.Ibendportcon)
        i.name = name
        i.port = port
        i.context = context
        statement = f"ibendportcon {name} {port} {context};"
        i.statement.return_value = statement
        i.__str__.return_value = statement
        return i
    return _factory


@pytest.fixture
def mock_ibpkeycon():
    import ipaddress

    def _factory(subnet_prefix: str, pkeys: str,
                 context: setools.Context) -> setools.Ibpkeycon:
        """Factory function for Ibpkeycon objects."""
        i = MagicMock(setools.Ibpkeycon)
        i.subnet_prefix = ipaddress.IPv6Address(subnet_prefix)
        i.pkeys.__str__.return_value = pkeys
        i.context = context
        statement = f"ibpkeycon {subnet_prefix} {pkeys} {context};"
        i.statement.return_value = statement
        i.__str__.return_value = statement
        return i
    return _factory


@pytest.fixture
def mock_infoflow_step():
    from setools.infoflow import InfoFlowStep

    def _factory(source: setools.Type, target: setools.Type,
                 weight: int, rules: list) -> InfoFlowStep:
        """Factory function for InfoFlowStep objects.

        InfoFlowStep is a dataclass; instance fields are absent from dir(), so
        Mock(spec=InfoFlowStep) blocks attribute access. Set _spec_class directly
        so isinstance() works without the attribute restriction.
        """
        from unittest.mock import Mock
        step = Mock()
        step._spec_class = InfoFlowStep
        step.source = source
        step.target = target
        step.weight = weight
        step.rules = rules
        return step
    return _factory


@pytest.fixture
def mock_initialsid():
    def _factory(name: str, context: setools.Context) -> setools.InitialSID:
        """Factory function for InitialSID objects."""
        sid = MagicMock(setools.InitialSID)
        sid.name = name
        sid.context = context
        sid.__str__.return_value = name
        sid.statement.return_value = f"sid {name} {context};"
        return sid
    return _factory


@pytest.fixture
def mock_iomemcon():
    def _factory(addr: str, context: setools.Context) -> setools.Iomemcon:
        """Factory function for Iomemcon objects."""
        i = MagicMock(setools.Iomemcon)
        i.addr.__str__.return_value = addr
        i.context = context
        statement = f"iomemcon {addr} {context};"
        i.statement.return_value = statement
        i.__str__.return_value = statement
        return i
    return _factory


@pytest.fixture
def mock_ioportcon():
    def _factory(ports: str, context: setools.Context) -> setools.Ioportcon:
        """Factory function for Ioportcon objects."""
        i = MagicMock(setools.Ioportcon)
        i.ports.__str__.return_value = ports
        i.context = context
        statement = f"ioportcon {ports} {context};"
        i.statement.return_value = statement
        i.__str__.return_value = statement
        return i
    return _factory


@pytest.fixture
def mock_netifcon():
    def _factory(netif: str, context: setools.Context,
                 packet: setools.Context) -> setools.Netifcon:
        """Factory function for Netifcon objects."""
        n = MagicMock(setools.Netifcon)
        n.netif = netif
        n.context = context
        n.packet = packet
        statement = f"netifcon {netif} {context} {packet};"
        n.statement.return_value = statement
        n.__str__.return_value = statement
        return n
    return _factory


@pytest.fixture
def mock_nodecon():
    def _factory(network: str, ip_version: setools.NodeconIPVersion,
                 context: setools.Context) -> setools.Nodecon:
        """Factory function for Nodecon objects."""
        n = MagicMock(setools.Nodecon)
        n.network = ipaddress.ip_network(network)
        n.ip_version = ip_version
        n.context = context
        statement = f"nodecon {network} {context};"
        n.statement.return_value = statement
        n.__str__.return_value = statement
        return n
    return _factory


@pytest.fixture
def mock_pcidevicecon():
    def _factory(device: str, context: setools.Context) -> setools.Pcidevicecon:
        """Factory function for Pcidevicecon objects."""
        p = MagicMock(setools.Pcidevicecon)
        p.device = device
        p.context = context
        statement = f"pcidevicecon {device} {context};"
        p.statement.return_value = statement
        p.__str__.return_value = statement
        return p
    return _factory


@pytest.fixture
def mock_pirqcon():
    def _factory(irq: int, context: setools.Context) -> setools.Pirqcon:
        """Factory function for Pirqcon objects."""
        p = MagicMock(setools.Pirqcon)
        p.irq = irq
        p.context = context
        statement = f"pirqcon {irq} {context};"
        p.statement.return_value = statement
        p.__str__.return_value = statement
        return p
    return _factory


@pytest.fixture
def mock_polcap():
    def _factory(name: str) -> setools.PolicyCapability:
        """Factory function for PolicyCapability objects."""
        p = MagicMock(setools.PolicyCapability)
        p.name = name
        p.__str__.return_value = name
        p.statement.return_value = f"policycap {name};"
        return p
    return _factory


@pytest.fixture
def mock_portcon():
    def _factory(protocol: setools.PortconProtocol, low: int, high: int,
                 context: setools.Context) -> setools.Portcon:
        """Factory function for Portcon objects."""
        p = MagicMock(setools.Portcon)
        p.protocol = protocol
        p.ports.low = low
        p.ports.high = high
        p.context = context
        ports_str = str(low) if low == high else f"{low}-{high}"
        statement = f"portcon {protocol} {ports_str} {context};"
        p.statement.return_value = statement
        p.__str__.return_value = statement
        return p
    return _factory


@pytest.fixture()
def mock_range_transition_rule():
    """Factory for RangeTransition mocks."""
    def _factory(source: setools.Type, target: setools.Type, tclass: setools.ObjClass,
                 dflt: setools.Range) -> setools.MLSRule:

        rule = MagicMock(setools.MLSRule)
        rule.ruletype = setools.MLSRuletype.range_transition
        rule.source = source
        rule.target = target
        rule.tclass = tclass
        rule.default = dflt
        statement = f"{rule.ruletype} {source} {target}:{tclass} {dflt};"
        rule.__str__.return_value = statement
        rule.statement.return_value = statement
        return rule
    return _factory


@pytest.fixture
def mock_policy(mock_type, mock_typeattr, mock_user, mock_role) -> setools.SELinuxPolicy:
    """Build a mock policy."""
    foo_bool = SortableMock(setools.Boolean)
    foo_bool.name = "foo_bool"
    bar_bool = SortableMock(setools.Boolean)
    bar_bool.name = "bar_bool"

    common = SortableMock(setools.Common)
    common.name = "common_perm_set"
    common.perms = frozenset(("common_perm",))

    foo_class = SortableMock(setools.ObjClass)
    foo_class.name = "foo_class"
    foo_class.perms = frozenset(("foo_perm1", "foo_perm2"))
    foo_class.common = common
    bar_class = SortableMock(setools.ObjClass)
    bar_class.name = "bar_class"
    bar_class.perms = frozenset(("bar_perm1", "bar_perm2"))
    bar_class.common = common

    fooattr = mock_typeattr("foo_type")
    barattr = mock_typeattr("bar_type")

    foo_t = mock_type("foo_t", attrs=(fooattr,))
    fooattr.expand.return_value = (foo_t,)
    bar_t = mock_type("bar_t", attrs=(barattr,))
    barattr.expand.return_value = (bar_t,)

    foo_r = mock_role("foo_r", types=frozenset((foo_t,)))
    bar_r = mock_role("bar_r", types=frozenset((bar_t,)))

    foo_u = mock_user("foo_u", roles=frozenset((foo_r,)))
    bar_u = mock_user("bar_u", roles=frozenset((bar_r,)))

    foo_cat = SortableMock(setools.Category)
    foo_cat.name = "foo_cat"
    foo_cat.aliases.return_value = ("foo_cat_alias",)
    bar_cat = SortableMock(setools.Category)
    bar_cat.name = "bar_cat"
    bar_cat.aliases.return_value = ("bar_cat_alias",)

    foo_sen = SortableMock(setools.Sensitivity)
    foo_sen.name = "foo_sen"
    foo_sen.aliases.return_value = ("foo_sen_alias",)
    bar_sen = SortableMock(setools.Sensitivity)
    bar_sen.name = "bar_sen"
    bar_sen.aliases.return_value = ("bar_sen_alias",)

    policy = Mock(setools.SELinuxPolicy)
    policy.mls = False
    policy.path = "/etc/selinux/targeted/policy/policy.33"
    policy.version = 33
    policy.handle_unknown = setools.HandleUnknown.deny
    policy.target_platform = setools.PolicyTarget.selinux
    policy.bools.return_value = (foo_bool, bar_bool)
    policy.categories.return_value = (foo_cat, bar_cat)
    policy.classes.return_value = (foo_class, bar_class)
    policy.commons.return_value = (common,)
    policy.roles.return_value = (foo_r, bar_r)
    policy.sensitivities.return_value = (foo_sen, bar_sen)
    policy.types.return_value = (foo_t, bar_t)
    policy.typeattributes.return_value = (fooattr, barattr)
    policy.users.return_value = (foo_u, bar_u)

    for key, value in {"type_count": 2,
                       "type_attribute_count": 3,
                       "role_count": 5,
                       "user_count": 7,
                       "boolean_count": 11,
                       "class_count": 13,
                       "common_count": 17,
                       "allow_count": 19,
                       "auditallow_count": 23,
                       "dontaudit_count": 29,
                       "neverallow_count": 31,
                       "type_transition_count": 37,
                       "type_change_count": 41,
                       "type_member_count": 43,
                       "role_allow_count": 47,
                       "role_transition_count": 53,
                       "range_transition_count": 59,
                       "constraint_count": 61,
                       "portcon_count": 67,
                       "netifcon_count": 71,
                       "nodecon_count": 73,
                       "genfscon_count": 79,
                       "fs_use_count": 83,
                       "initialsids_count": 89,
                       "polcap_count": 97,
                       "permissives_count": 101,
                       "conditional_count": 103}.items():
        setattr(policy, key, value)
    return policy


@pytest.fixture
def mock_query(mock_policy) -> setools.PolicyQuery:
    """Build a mock query with mocked policy."""
    query = Mock(setools.PolicyQuery)
    query.policy = mock_policy
    return query


def _do_compile(source_file: str, output_file: str, /, *, mls: bool = True,
                xen: bool = False) -> setools.SELinuxPolicy:
    """
    Compile the specified source policy.  Checkpolicy is
    assumed to be /usr/bin/checkpolicy.  Otherwise the path
    must be specified in the CHECKPOLICY environment variable.

    Return:
    A SELinuxPolicy object.
    """
    user_src = os.getenv("USERSPACE_SRC")
    checkpol = os.getenv("CHECKPOLICY")

    if user_src:
        command = [user_src + "/checkpolicy/checkpolicy"]
    elif checkpol:
        command = [checkpol]
    else:
        command = ["/usr/bin/checkpolicy"]

    if mls:
        command.append("-M")

    if xen:
        command.extend(["-t", "xen", "-c", "30"])

    command.extend(["-o", output_file, "-U", "reject", source_file])

    with open(os.devnull, "w") as null:
        subprocess.check_call(command, stdout=null, shell=False, close_fds=True)

    return setools.SELinuxPolicy(output_file)


@pytest.fixture(scope="class")
def compiled_policy(request: pytest.FixtureRequest) -> Iterable[setools.SELinuxPolicy]:
    """Build a compiled policy."""
    marker = request.node.get_closest_marker("obj_args")
    args = marker.args if marker else ()
    kwargs = marker.kwargs if marker else {}

    assert len(args) == 1
    source_file = args[0]  # type: ignore

    with tempfile.NamedTemporaryFile("w") as fd:
        yield _do_compile(source_file, fd.name, mls=kwargs.get("mls", True),
                          xen=kwargs.get("xen", False))


@pytest.fixture(scope="class")
def policy_pair(request: pytest.FixtureRequest) -> \
        Iterable[tuple[setools.SELinuxPolicy, setools.SELinuxPolicy]]:
    """Build a compiled policy."""
    marker = request.node.get_closest_marker("obj_args")
    args = marker.args if marker else ()
    kwargs = marker.kwargs if marker else {}

    assert len(args) == 2
    source_file_left = args[0]  # type: ignore
    source_file_right = args[1]  # type: ignore

    with tempfile.NamedTemporaryFile("w") as fd_left:
        with tempfile.NamedTemporaryFile("w") as fd_right:
            left = _do_compile(source_file_left, fd_left.name,
                               mls=kwargs.get("mls_left", True),
                               xen=kwargs.get("xen_left", False))
            right = _do_compile(source_file_right, fd_right.name,
                                mls=kwargs.get("mls_right", True),
                                xen=kwargs.get("xen_right", False))
            yield left, right
