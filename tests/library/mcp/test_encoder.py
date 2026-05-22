# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for setools.mcp.encoder.MCPEncoder."""

import setools
from setools.dta import DomainEntrypoint, DomainTransition
from setools.mcp.encoder import MCPEncoder


class TestMCPEncoderTERule:
    """Tests for the BaseTERule branch (allow, type_transition, etc.)."""

    def test_av_rule(self, mock_type, mock_class, mock_av_rule):
        """All required top-level fields are present for an AVRule; perms are sorted."""
        rule = mock_av_rule(setools.TERuletype.allow, mock_type("src_t"), mock_type("tgt_t"),
                            mock_class("foo_class"), ("perm2", "perm1"))

        assert {"statement": "allow src_t tgt_t:foo_class { perm1 perm2 };",
                "ruletype": "allow",
                "source": "src_t",
                "target": "tgt_t",
                "tclass": "foo_class",
                "perms": ["perm1", "perm2"]} == MCPEncoder().default(rule)

    def test_conditional_av_rule(self, mock_type, mock_class, mock_av_rule, mock_conditional):
        """Conditional rules include conditional and conditional_block."""
        rule = mock_av_rule(setools.TERuletype.allow, mock_type("src_t"), mock_type("tgt_t"),
                            mock_class("foo_class"), ("perm1",),
                            conditional=mock_conditional(("some_bool",)),
                            conditional_block=True)
        assert {"statement": "allow src_t tgt_t:foo_class perm1; [some_bool]:True",
                "ruletype": "allow",
                "source": "src_t",
                "target": "tgt_t",
                "tclass": "foo_class",
                "perms": ["perm1"],
                "conditional": "some_bool",
                "conditional_block": True} == MCPEncoder().default(rule)

    def test_te_rule(self, mock_type, mock_class, mock_te_rule):
        """TERules have a default type but no perms."""
        rule = mock_te_rule(setools.TERuletype.type_transition, mock_type("src_t"),
                            mock_type("tgt_t"), mock_class("process"), mock_type("default_t"))

        assert {"ruletype": "type_transition",
                "source": "src_t",
                "target": "tgt_t",
                "tclass": "process",
                "default": "default_t",
                "statement": "type_transition src_t tgt_t:process default_t;"} \
            == MCPEncoder().default(rule)

    def test_filename_te_rule(self, mock_type, mock_class, mock_te_rule):
        """FileNameTERules carry both a default type and a filename."""
        rule = mock_te_rule(setools.TERuletype.type_transition, mock_type("src_t"),
                            mock_type("tgt_t"), mock_class("process"), mock_type("default_t"),
                            filename="my_script")

        assert {"ruletype": "type_transition",
                "source": "src_t",
                "target": "tgt_t",
                "tclass": "process",
                "default": "default_t",
                "filename": "my_script",
                "statement": "type_transition src_t tgt_t:process default_t \"my_script\";"} \
            == MCPEncoder().default(rule)


class TestMCPEncoderBoolean:
    def test_boolean_true(self, mock_bool):
        b = mock_bool("my_bool", state=True)

        assert {"name": "my_bool",
                "default_state": True,
                "statement": "bool my_bool true;"} == MCPEncoder().default(b)

    def test_boolean_false(self, mock_bool):
        b = mock_bool("my_bool", state=False)

        assert {"name": "my_bool",
                "default_state": False,
                "statement": "bool my_bool false;"} == MCPEncoder().default(b)


class TestMCPEncoderBounds:
    def test_bounds(self, mock_type, mock_bounds_rule):
        parent = mock_type("parent_t")
        child = mock_type("child_t")
        rule = mock_bounds_rule(setools.BoundsRuletype.typebounds, parent, child)

        assert {"statement": "typebounds parent_t child_t;",
                "ruletype": "typebounds",
                "parent": "parent_t",
                "child": "child_t"} == MCPEncoder().default(rule)


class TestMCPEncoderCategorySensitivity:
    def test_category(self, mock_cat):
        cat = mock_cat("c1")

        assert {"name": "c1",
                "aliases": [],
                "statement": "category c1;"} == MCPEncoder().default(cat)

    def test_category_with_aliases(self, mock_cat):
        cat = mock_cat("c0", aliases=["c0_alias2", "c0_alias1"])

        assert {"name": "c0",
                "aliases": ["c0_alias1", "c0_alias2"],
                "statement": "category c0 alias { c0_alias1 c0_alias2 };"} \
            == MCPEncoder().default(cat)

    def test_sensitivity(self, mock_sens):
        s = mock_sens("s0")

        assert {"name": "s0",
                "aliases": [],
                "statement": "sensitivity s0;"} == MCPEncoder().default(s)

    def test_sensitivity_with_aliases(self, mock_sens):
        s = mock_sens("s0", aliases=["top_secret", "secret"])

        assert {"name": "s0",
                "aliases": ["secret", "top_secret"],
                "statement": "sensitivity s0 alias { secret top_secret };"} \
            == MCPEncoder().default(s)


class TestMCPEncoderCommon:
    def test_common(self, mock_common):
        c = mock_common("common_file", perms=["read", "ioctl", "write"])

        assert {"name": "common_file",
                "perms": ["ioctl", "read", "write"],
                "statement": "common common_file\n{\n\tioctl\n\tread\n\twrite\n}"} \
            == MCPEncoder().default(c)


class TestMCPEncoderConstraint:
    def test_constraint(self, mock_class, mock_constraint_rule):
        tclass = mock_class("foo_class")
        c = mock_constraint_rule(setools.ConstraintRuletype.constrain, tclass,
                                 "(u1 == u2)", perms=["perm1", "perm2"])

        assert {"statement": "constrain foo_class (u1 == u2);",
                "ruletype": "constrain",
                "tclass": "foo_class",
                "expression": "(u1 == u2)",
                "perms": ["perm1", "perm2"]} == MCPEncoder().default(c)

    def test_validatetrans(self, mock_class, mock_constraint_rule):
        tclass = mock_class("bar_class")
        v = mock_constraint_rule(setools.ConstraintRuletype.validatetrans, tclass, "(u1 == u2)")

        assert {"statement": "validatetrans bar_class (u1 == u2);",
                "ruletype": "validatetrans",
                "tclass": "bar_class",
                "expression": "(u1 == u2)"} == MCPEncoder().default(v)


class TestMCPEncoderContext:
    def test_context_standard(self, mock_user, mock_role, mock_type, mock_context):
        user = mock_user("user_u")
        role = mock_role("role_r")
        type_ = mock_type("type_t")
        ctx = mock_context(user, role, type_)

        assert {"user": "user_u",
                "role": "role_r",
                "type": "type_t"} == MCPEncoder().default(ctx)

    def test_context_with_mls(self, mock_user, mock_role, mock_type, mock_sens, mock_cat,
                              mock_range, mock_level, mock_context):
        user = mock_user("user2_u")
        role = mock_role("role2_r")
        type_ = mock_type("type2_t")
        sens = mock_sens("s0")
        cat0 = mock_cat("c0")
        cat1 = mock_cat("c1")
        level = mock_level(sens, (cat0, cat1))
        range_ = mock_range(level)
        ctx = mock_context(user, role, type_, range_)

        assert {"user": "user2_u",
                "role": "role2_r",
                "type": "type2_t",
                "range": "s0:c0,c1"} == MCPEncoder().default(ctx)


class TestMCPEncoderDefault:
    def test_default(self, mock_class, mock_default_rule):
        tclass = mock_class("foo_class")
        rule = mock_default_rule(setools.DefaultRuletype.default_type, tclass,
                                 setools.DefaultValue.source)

        assert {"statement": "default_type foo_class source;",
                "ruletype": "default_type",
                "tclass": "foo_class",
                "default": "source"} == MCPEncoder().default(rule)

    def test_default_range(self, mock_class, mock_default_rule):
        tclass = mock_class("bar_class")
        rule = mock_default_rule(setools.DefaultRuletype.default_range, tclass,
                                 setools.DefaultValue.target, setools.DefaultRangeValue.low_high)

        assert {"statement": "default_range bar_class target low_high;",
                "ruletype": "default_range",
                "tclass": "bar_class",
                "default": "target",
                "default_range": "low_high"} == MCPEncoder().default(rule)


class TestMCPEncoderDevicetreecon:
    def test_devicetreecon(self, mock_user, mock_role, mock_type, mock_context,
                           mock_devicetreecon):
        ctx = mock_context(mock_user("u"), mock_role("r"), mock_type("t"))
        d = mock_devicetreecon("/some/path", ctx)

        assert {"statement": "devicetreecon /some/path u:r:t;",
                "path": "/some/path",
                "context": "u:r:t"} == MCPEncoder().default(d)


class TestMCPEncoderDTA:
    def test_domain_entrypoint_keys(self, mock_type, mock_class, mock_av_rule, mock_te_rule):
        src = mock_type("src_t")
        entry = mock_type("entry_t")
        ep_rule = mock_av_rule(setools.TERuletype.allow, src, entry,
                               mock_class("file"), ("entrypoint",))
        exec_rule = mock_av_rule(setools.TERuletype.allow, src, entry,
                                 mock_class("file"), ("execute",))
        tt_rule = mock_te_rule(setools.TERuletype.type_transition, src, entry,
                               mock_class("process"), mock_type("tgt_t"))
        ep = DomainEntrypoint(name=entry,
                              entrypoint=[ep_rule],
                              execute=[exec_rule],
                              type_transition=[tt_rule])

        assert {"name": "entry_t",
                "entrypoint_rules": ["allow src_t entry_t:file entrypoint;"],
                "execute_rules": ["allow src_t entry_t:file execute;"],
                "type_transition_rules": ["type_transition src_t entry_t:process tgt_t;"]} \
            == MCPEncoder().default(ep)

    def test_domain_transition_keys(self, mock_type, mock_class, mock_av_rule, mock_te_rule):
        src = mock_type("src_t")
        tgt = mock_type("tgt_t")
        entry = mock_type("entry_t")
        trans_rule = mock_av_rule(setools.TERuletype.allow, src, tgt,
                                  mock_class("process"), ("transition",))
        setexec_rule = mock_av_rule(setools.TERuletype.allow, src, src,
                                    mock_class("process"), ("setexec",))
        dyntr_rule = mock_av_rule(setools.TERuletype.allow, src, tgt,
                                  mock_class("process"), ("dyntransition",))
        setcur_rule = mock_av_rule(setools.TERuletype.allow, src, src,
                                   mock_class("process"), ("setcurrent",))
        ep_rule = mock_av_rule(setools.TERuletype.allow, src, entry,
                               mock_class("file"), ("entrypoint",))
        exec_rule = mock_av_rule(setools.TERuletype.allow, src, entry,
                                 mock_class("file"), ("execute",))
        tt_rule = mock_te_rule(setools.TERuletype.type_transition, src, entry,
                               mock_class("process"), tgt)
        ep = DomainEntrypoint(name=entry,
                              entrypoint=[ep_rule],
                              execute=[exec_rule],
                              type_transition=[tt_rule])
        dt = DomainTransition(source=src,
                              target=tgt,
                              transition=[trans_rule],
                              entrypoints=[ep],
                              setexec=[setexec_rule],
                              dyntransition=[dyntr_rule],
                              setcurrent=[setcur_rule])

        assert {"source": "src_t",
                "target": "tgt_t",
                "transition_rules": ["allow src_t tgt_t:process transition;"],
                "entrypoints": [{"name": "entry_t",
                                 "entrypoint_rules": ["allow src_t entry_t:file entrypoint;"],
                                 "execute_rules": ["allow src_t entry_t:file execute;"],
                                 "type_transition_rules": [
                                     "type_transition src_t entry_t:process tgt_t;"]}],
                "setexec_rules": ["allow src_t src_t:process setexec;"],
                "dyntransition_rules": ["allow src_t tgt_t:process dyntransition;"],
                "setcurrent_rules": ["allow src_t src_t:process setcurrent;"]} \
            == MCPEncoder().default(dt)


class TestMCPEncoderFSUse:
    def test_fsuse(self, mock_user, mock_role, mock_type, mock_context, mock_fs_use):
        ctx = mock_context(mock_user("u"), mock_role("r"), mock_type("t"))
        f = mock_fs_use(setools.FSUseRuletype.fs_use_xattr, "ext4", ctx)

        assert {"statement": "fs_use_xattr ext4 u:r:t;",
                "ruletype": "fs_use_xattr",
                "fs": "ext4",
                "context": "u:r:t"} == MCPEncoder().default(f)


class TestMCPEncoderGenfscon:
    def test_genfscon(self, mock_user, mock_role, mock_type, mock_context, mock_genfscon):
        ctx = mock_context(mock_user("u"), mock_role("r"), mock_type("t"))
        g = mock_genfscon("proc", "/", ctx)

        assert {"statement": "genfscon proc /  u:r:t;",
                "fs": "proc",
                "path": "/",
                "context": "u:r:t"} == MCPEncoder().default(g)

    def test_genfscon_with_tclass(self, mock_user, mock_role, mock_type, mock_class,
                                  mock_context, mock_genfscon):
        ctx = mock_context(mock_user("u"), mock_role("r"), mock_type("t"))
        g = mock_genfscon("sysfs", "/", ctx, tclass=mock_class("file"))

        assert {"statement": "genfscon sysfs / -- u:r:t;",
                "fs": "sysfs",
                "path": "/",
                "context": "u:r:t",
                "tclass": "file",
                "filetype": "--"} == MCPEncoder().default(g)


class TestMCPEncoderIbendportcon:
    def test_ibendportcon(self, mock_user, mock_role, mock_type, mock_context, mock_ibendportcon):
        ctx = mock_context(mock_user("u"), mock_role("r"), mock_type("t"))
        i = mock_ibendportcon("mlx4_0", 1, ctx)

        assert {"statement": "ibendportcon mlx4_0 1 u:r:t;",
                "name": "mlx4_0",
                "port": 1,
                "context": "u:r:t"} == MCPEncoder().default(i)


class TestMCPEncoderIbpkeycon:
    def test_ibpkeycon(self, mock_user, mock_role, mock_type, mock_context, mock_ibpkeycon):
        ctx = mock_context(mock_user("u"), mock_role("r"), mock_type("t"))
        i = mock_ibpkeycon("fe80::", "0x0001-0x0002", ctx)

        assert {"statement": "ibpkeycon fe80:: 0x0001-0x0002 u:r:t;",
                "subnet_prefix": "fe80::",
                "pkeys": "0x0001-0x0002",
                "context": "u:r:t"} == MCPEncoder().default(i)


class TestMCPEncoderInfoFlowStep:
    def test_infoflow_step(self, mock_type, mock_class, mock_av_rule, mock_infoflow_step):
        rule1 = mock_av_rule(setools.TERuletype.allow, mock_type("src_t"), mock_type("tgt_t"),
                             mock_class("file"), ("read",))
        rule2 = mock_av_rule(setools.TERuletype.allow, mock_type("src_t"), mock_type("tgt_t"),
                             mock_class("lnk_file"), ("write",))
        rule3 = mock_av_rule(setools.TERuletype.allow, mock_type("src_t"), mock_type("tgt_t"),
                             mock_class("fifo_file"), ("ioctl",))
        step = mock_infoflow_step(mock_type("src_t"), mock_type("tgt_t"), weight=7,
                                  rules=[rule1, rule2, rule3])

        assert {"source": "src_t",
                "target": "tgt_t",
                "weight": 7,
                "rules": ["allow src_t tgt_t:fifo_file ioctl;",
                          "allow src_t tgt_t:file read;",
                          "allow src_t tgt_t:lnk_file write;"]} == MCPEncoder().default(step)


class TestMCPEncoderInitialSID:
    def test_initialsid(self, mock_user, mock_role, mock_type, mock_context,
                        mock_initialsid):
        ctx = mock_context(mock_user("u"), mock_role("r"), mock_type("t"))
        s = mock_initialsid("kernel", ctx)

        assert {"statement": "sid kernel u:r:t;",
                "name": "kernel",
                "context": "u:r:t"} == MCPEncoder().default(s)


class TestMCPEncoderIomemcon:
    def test_iomemcon(self, mock_user, mock_role, mock_type, mock_context, mock_iomemcon):
        ctx = mock_context(mock_user("u"), mock_role("r"), mock_type("t"))
        i = mock_iomemcon("0x100-0x1ff", ctx)

        assert {"statement": "iomemcon 0x100-0x1ff u:r:t;",
                "addr": "0x100-0x1ff",
                "context": "u:r:t"} == MCPEncoder().default(i)


class TestMCPEncoderIoportcon:
    def test_ioportcon(self, mock_user, mock_role, mock_type, mock_context, mock_ioportcon):
        ctx = mock_context(mock_user("u"), mock_role("r"), mock_type("t"))
        i = mock_ioportcon("0x80", ctx)

        assert {"statement": "ioportcon 0x80 u:r:t;",
                "ports": "0x80",
                "context": "u:r:t"} == MCPEncoder().default(i)


class TestMCPEncoderLevelRange:
    def test_level(self, mock_sens, mock_cat, mock_level):
        level = mock_level(mock_sens("s0"), (mock_cat("c0"), mock_cat("c1")))

        assert "s0:c0,c1" == MCPEncoder().default(level)

    def test_level_decl(self, mock_sens, mock_level):
        level = mock_level(mock_sens("s0"))

        assert "s0" == MCPEncoder().default(level)

    def test_range(self, mock_sens, mock_cat, mock_level, mock_range):
        low = mock_level(mock_sens("s0"), (mock_cat("c0"),))
        high = mock_level(mock_sens("s1"), (mock_cat("c0"), mock_cat("c1")))
        r = mock_range(low, high)

        assert "s0:c0 - s1:c0,c1" == MCPEncoder().default(r)


class TestMCPEncoderMLSRule:
    def test_mls_rule(self, mock_type, mock_class, mock_sens, mock_level, mock_range,
                      mock_range_transition_rule):
        src = mock_type("src_t")
        tgt = mock_type("tgt_t")
        tclass = mock_class("process")
        range_ = mock_range(mock_level(mock_sens(name="s1")))
        rule = mock_range_transition_rule(src, tgt, tclass, range_)
        assert {"ruletype": "range_transition",
                "source": "src_t",
                "target": "tgt_t",
                "tclass": "process",
                "default": "s1",
                "statement": "range_transition src_t tgt_t:process s1;"} \
            == MCPEncoder().default(rule)


class TestMCPEncoderNetifcon:
    def test_netifcon(self, mock_user, mock_role, mock_type, mock_context, mock_netifcon):
        ctx = mock_context(mock_user("u"), mock_role("r"), mock_type("t"))
        pkt = mock_context(mock_user("u2"), mock_role("r3"), mock_type("t2"))
        n = mock_netifcon("eth0", ctx, pkt)

        assert {"statement": "netifcon eth0 u:r:t u2:r3:t2;",
                "netif": "eth0",
                "context": "u:r:t",
                "packet_context": "u2:r3:t2"} == MCPEncoder().default(n)


class TestMCPEncoderNodecon:
    def test_nodecon_ipv4(self, mock_user, mock_role, mock_type, mock_context, mock_nodecon):
        ctx = mock_context(mock_user("u"), mock_role("r"), mock_type("t"))
        n = mock_nodecon("192.168.0.0/16", setools.NodeconIPVersion.ipv4, ctx)

        assert {"statement": "nodecon 192.168.0.0/16 u:r:t;",
                "network": "192.168.0.0/16",
                "ip_version": "ipv4",
                "context": "u:r:t"} == MCPEncoder().default(n)

    def test_nodecon_ipv6(self, mock_user, mock_role, mock_type, mock_context, mock_nodecon):
        ctx = mock_context(mock_user("u"), mock_role("r"), mock_type("t"))
        n = mock_nodecon("::1/128", setools.NodeconIPVersion.ipv6, ctx)

        assert {"statement": "nodecon ::1/128 u:r:t;",
                "network": "::1/128",
                "ip_version": "ipv6",
                "context": "u:r:t"} == MCPEncoder().default(n)


class TestMCPEncoderObjClass:
    def test_class(self, mock_class):
        cls = mock_class("tcp_socket", perms=frozenset(("connect",)))

        assert {"name": "tcp_socket",
                "perms": ["connect"]} == MCPEncoder().default(cls)

    def test_class_with_common(self, mock_common, mock_class):
        com = mock_common("common_file", perms=frozenset(("ioctl",)))
        cls = mock_class("file", common=com, perms=frozenset(("read", "write")))

        assert {"name": "file",
                "common": "common_file",
                "perms": ["ioctl", "read", "write"]} == MCPEncoder().default(cls)


class TestMCPEncoderPcidevicecon:
    def test_pcidevicecon(self, mock_user, mock_role, mock_type, mock_context, mock_pcidevicecon):
        ctx = mock_context(mock_user("u"), mock_role("r"), mock_type("t"))
        p = mock_pcidevicecon("0x1234", ctx)

        assert {"statement": "pcidevicecon 0x1234 u:r:t;",
                "device": "0x1234",
                "context": "u:r:t"} == MCPEncoder().default(p)


class TestMCPEncoderPirqcon:
    def test_pirqcon(self, mock_user, mock_role, mock_type, mock_context, mock_pirqcon):
        ctx = mock_context(mock_user("u"), mock_role("r"), mock_type("t"))
        p = mock_pirqcon(42, ctx)

        assert {"statement": "pirqcon 42 u:r:t;",
                "irq": 42,
                "context": "u:r:t"} == MCPEncoder().default(p)


class TestMCPEncoderPolicyCapability:
    def test_polcap(self, mock_polcap):
        p = mock_polcap("network_peer_controls")

        assert {"name": "network_peer_controls",
                "statement": "policycap network_peer_controls;"} == MCPEncoder().default(p)


class TestMCPEncoderPortcon:
    def test_portcon(self, mock_user, mock_role, mock_type, mock_context, mock_portcon):
        ctx = mock_context(mock_user("u"), mock_role("r"), mock_type("t"))
        p = mock_portcon(setools.PortconProtocol.tcp, 80, 80, ctx)

        assert {"statement": "portcon tcp 80 u:r:t;",
                "protocol": "tcp",
                "ports_low": 80,
                "ports_high": 80,
                "context": "u:r:t"} == MCPEncoder().default(p)

    def test_portcon_range(self, mock_user, mock_role, mock_type, mock_context, mock_portcon):
        ctx = mock_context(mock_user("u"), mock_role("r"), mock_type("t"))
        p = mock_portcon(setools.PortconProtocol.udp, 1024, 65535, ctx)

        assert {"statement": "portcon udp 1024-65535 u:r:t;",
                "protocol": "udp",
                "ports_low": 1024,
                "ports_high": 65535,
                "context": "u:r:t"} == MCPEncoder().default(p)


class TestMCPEncoderRole:
    def test_role(self, mock_role, mock_type):
        role = mock_role("staff_r",
                         types=frozenset((mock_type("zzz_t"), mock_type("aaa_t"))))

        assert {"name": "staff_r",
                "types": ["aaa_t", "zzz_t"],
                "statement": "role staff_r types { aaa_t zzz_t };"} == MCPEncoder().default(role)


class TestMCPEncoderRBACRule:
    def test_role_allow(self, mock_role, mock_role_allow_rule):
        src = mock_role("src_r")
        tgt = mock_role("tgt_r")
        rule = mock_role_allow_rule(src, tgt)

        assert {"ruletype": "allow",
                "source": "src_r",
                "target": "tgt_r",
                "statement": "allow src_r tgt_r;"} == MCPEncoder().default(rule)

    def test_role_transition(self, mock_role, mock_type, mock_class, mock_role_transition_rule):
        src = mock_role("src_r")
        tgt = mock_type("tgt_t")
        tclass = mock_class("process")
        dft = mock_role("new_r")
        rule = mock_role_transition_rule(src, tgt, tclass, dft)

        assert {"ruletype": "role_transition",
                "source": "src_r",
                "target": "tgt_t",
                "tclass": "process",
                "default": "new_r",
                "statement": "role_transition src_r tgt_t:process new_r;"} \
            == MCPEncoder().default(rule)


class TestMCPEncoderSELinuxPolicy:
    def test_selinux_policy(self, mock_policy):
        assert {"path": "/etc/selinux/targeted/policy/policy.33",
                "version": 33,
                "target_platform": "selinux",
                "handle_unknown": "deny",
                "mls": False,
                "counts": {"types": 2,
                           "type_attributes": 3,
                           "roles": 5,
                           "users": 7,
                           "booleans": 11,
                           "classes": 13,
                           "commons": 17,
                           "allow_rules": 19,
                           "auditallow_rules": 23,
                           "dontaudit_rules": 29,
                           "neverallow_rules": 31,
                           "type_transition_rules": 37,
                           "type_change_rules": 41,
                           "type_member_rules": 43,
                           "role_allow_rules": 47,
                           "role_transitions": 53,
                           "range_transitions": 59,
                           "constraints": 61,
                           "portcons": 67,
                           "netifcons": 71,
                           "nodecons": 73,
                           "genfscons": 79,
                           "fs_uses": 83,
                           "initialsids": 89,
                           "polcaps": 97,
                           "permissive_domains": 101,
                           "conditionals": 103}} == MCPEncoder().default(mock_policy)


class TestMCPEncoderType:
    def test_type_basic(self, mock_type):
        t = mock_type("foo_t")

        assert {"name": "foo_t",
                "attributes": [],
                "aliases": [],
                "permissive": False,
                "statement": "type foo_t;"} == MCPEncoder().default(t)

    def test_type_with_attributes_and_aliases(self, mock_type, mock_typeattr):
        attr = mock_typeattr("foo_attr")
        t = mock_type("foo_t", attrs=(attr,), alias=("foo_alias",))

        assert {"name": "foo_t",
                "attributes": ["foo_attr"],
                "aliases": ["foo_alias"],
                "permissive": False,
                "statement": "type foo_t alias foo_alias, foo_attr;"} == MCPEncoder().default(t)

    def test_permissive_type(self, mock_type):
        t = mock_type("permissive_t", perm=True)

        assert {"name": "permissive_t",
                "attributes": [],
                "aliases": [],
                "permissive": True,
                "statement": "type permissive_t;"} == MCPEncoder().default(t)

    def test_type_attributes_sorted(self, mock_type, mock_typeattr):
        a1 = mock_typeattr("zzz_attr")
        a2 = mock_typeattr("aaa_attr")
        t = mock_type("foo_t", attrs=(a1, a2))

        assert {"name": "foo_t",
                "attributes": ["aaa_attr", "zzz_attr"],
                "aliases": [],
                "permissive": False,
                "statement": "type foo_t, aaa_attr, zzz_attr;"} == MCPEncoder().default(t)


class TestMCPEncoderTypeAttribute:
    def test_typeattr(self, mock_type, mock_typeattr):
        a = mock_typeattr("domain", types=(mock_type("zzz_t"), mock_type("aaa_t")))

        assert {"name": "domain",
                "types": ["aaa_t", "zzz_t"],
                "statement": "attribute domain;"} == MCPEncoder().default(a)


class TestMCPEncoderUser:
    def test_user_without_mls(self, mock_user, mock_role):
        user = mock_user("sysadm_u", frozenset([mock_role("sysadm_r"), mock_role("staff_r")]))
        assert {"name": "sysadm_u",
                "roles": ["object_r", "staff_r", "sysadm_r"]} == MCPEncoder().default(user)

    def test_user_with_mls(self, mock_user, mock_role, mock_level, mock_range, mock_sens):
        role = mock_role("staff_r")
        level = mock_level(mock_sens("s0"))
        clearance = mock_level(mock_sens("s1"))
        range_ = mock_range(level, clearance)
        user = mock_user("staff_u", frozenset([role]), level, range_)

        assert {"name": "staff_u",
                "roles": ["object_r", "staff_r"],
                "mls_level": "s0",
                "mls_range": "s0 - s1"} == MCPEncoder().default(user)
