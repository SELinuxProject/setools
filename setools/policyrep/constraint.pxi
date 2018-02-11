# Copyright 2014-2016, Tresys Technology, LLC
# Copyright 2016-2017, Chris PeBenito <pebenito@ieee.org>
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

#
# Constraint factory functions
#
cdef inline Constraint constraint_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Constraint objects."""
    return constraint_factory(policy, <const qpol_constraint_t *> symbol.obj)


cdef inline Constraint constraint_factory(SELinuxPolicy policy, const qpol_constraint_t *symbol):
    """Factory function for creating Constraint objects."""
    r = Constraint()
    r.policy = policy
    r.handle = symbol

    for expr_node in r._expression_iterator():
        if expr_node.mls:
            r.ruletype = ConstraintRuletype.mlsconstrain
            break
    else:
        r.ruletype = ConstraintRuletype.constrain

    return r


#
# Constraint expression node factory functions
#
cdef inline ConstraintExprNode constraint_expr_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over ConstraintExprNode objects."""
    return constraint_expr_factory(policy, <const qpol_constraint_expr_node_t *> symbol.obj)


cdef inline ConstraintExprNode constraint_expr_factory(SELinuxPolicy policy, const qpol_constraint_expr_node_t *symbol):
    """Factory function for creating ConstraintExprNode objects."""
    r = ConstraintExprNode()
    r.policy = policy
    r.handle = symbol
    return r


#
# Validatetrans factory functions
#
cdef inline Validatetrans validatetrans_factory_iter(SELinuxPolicy policy, QpolIteratorItem symbol):
    """Factory function variant for iterating over Validatetrans objects."""
    return validatetrans_factory(policy, <const qpol_validatetrans_t *> symbol.obj)


cdef inline Validatetrans validatetrans_factory(SELinuxPolicy policy, const qpol_validatetrans_t *symbol):
    """Factory function for creating Validatetrans objects."""
    r = Validatetrans()
    r.policy = policy
    r.handle = symbol

    for expr_node in r._expression_iterator():
        if expr_node.mls:
            r.ruletype = ConstraintRuletype.mlsvalidatetrans
            break
    else:
        r.ruletype = ConstraintRuletype.validatetrans

    return r


#
# Classes
#
class ConstraintRuletype(PolicyEnum):

    """Enumeration of constraint types."""

    constrain = 1
    mlsconstrain = 2
    validatetrans = 3
    mlsvalidatetrans = 4


cdef class BaseConstraint(PolicySymbol):

    """Base class for constraint rules."""

    cdef readonly object ruletype

    def __str__(self):
        raise NotImplementedError

    # There is no levels function as specific
    # levels cannot be used in expressions, only
    # the l1, h1, etc. symbols

    @property
    def perms(self):
        raise NotImplementedError

    def statement(self):
        return str(self)

    def expression(self):
        """
        The constraint's expression in infix notation.

        Return: list
        """

        _precedence = {
            "not": 4,
            "and": 2,
            "or": 1,
            "==": 3,
            "!=": 3,
            "dom": 3,
            "domby": 3,
            "incomp": 3}

        _max_precedence = 4

        _operands = ["u1", "u2", "u3",
                     "r1", "r2", "r3",
                     "t1", "t2", "t3",
                     "l1", "l2",
                     "h1", "h2"]

        # qpol representation is in postfix notation.  This code
        # converts it to infix notation.  Parentheses are added
        # to ensure correct expressions, though they may end up
        # being overused.  Set previous operator at start to the
        # highest precedence (op) so if there is a single binary
        # operator, no parentheses are output
        stack = []
        prev_op_precedence = _max_precedence
        for op in self.postfix_expression():
            if isinstance(op, frozenset) or op in _operands:
                # operands
                stack.append(op)
            else:
                # operators
                if op == "not":
                    # unary operator
                    operator = op
                    operand = stack.pop()
                    op_precedence = _precedence[op]
                    stack.append([operator, "(", operand, ")"])
                else:
                    # binary operators
                    operand2 = stack.pop()
                    operand1 = stack.pop()
                    operator = op

                    # if previous operator is of higher precedence
                    # no parentheses are needed.
                    if _precedence[op] < prev_op_precedence:
                        stack.append([operand1, operator, operand2])
                    else:
                        stack.append(["(", operand1, operator, operand2, ")"])

                prev_op_precedence = _precedence[op]

        return self._flatten_expression(stack)

    def postfix_expression(self):
        """
        The constraint's expression in postfix notation.

        Return: list
        """
        expression = []
        for expr_node in self._expression_iterator():
            expression.extend(expr_node())

        return expression

    @property
    def roles(self):
        """The roles used in the expression."""
        roles = set()
        for expr_node in self._expression_iterator():
            if expr_node.roles:
                roles.update(expr_node.names)

        return roles

    @property
    def types(self):
        """The types and type attributes used in the expression."""
        types = set()
        for expr_node in self._expression_iterator():
            if expr_node.types:
                types.update(expr_node.names)

        return types

    @property
    def users(self):
        """The users used in the expression."""
        users = set()
        for expr_node in self._expression_iterator():
            if expr_node.users:
                users.update(expr_node.names)

        return users

    #
    # Internal functions
    #
    def _expression_iterator(self):
        """Internal function returning a low-level iterator of the expression."""
        raise NotImplementedError

    @staticmethod
    def _expression_str(expr):
        """Generate the string representation of the expression."""
        ret = []

        for item in expr:
            if isinstance(item, frozenset):
                if len(item) > 1:
                    ret.append("{{ {0} }} ".format(" ".join(str(j) for j in item)))
                else:
                    ret.append("{0}".format(" ".join(str(j) for j in item)))
            else:
                ret.append(item)

        return " ".join(ret)

    def _flatten_expression(self, expr):
        """Flatten the expression into a flat list."""
        ret = []

        for i in expr:
            if isinstance(i, list):
                ret.extend(self._flatten_expression(i))
            else:
                ret.append(i)

        return ret


cdef class Constraint(BaseConstraint):

    """A constraint rule (constrain/mlsconstrain)."""

    cdef const qpol_constraint_t *handle

    def __str__(self):
        rule_string = "{0.ruletype} {0.tclass} ".format(self)

        perms = self.perms
        if len(perms) > 1:
            rule_string += "{{ {0} }} (".format(' '.join(perms))
        else:
            # convert to list since sets cannot be indexed
            rule_string += "{0} (".format(list(perms)[0])

        rule_string += "{0});".format(self._expression_str(self.expression()))

        return rule_string

    def _eq(self, Constraint other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    def _expression_iterator(self):
        """Internal function returning a low-level iterator of the expression."""
        cdef qpol_iterator_t *iter
        if qpol_constraint_get_expr_iter(self.policy.handle, self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self.policy, iter, constraint_expr_factory_iter)

    @property
    def perms(self):
        """The constraint's permission set."""
        cdef qpol_iterator_t *iter
        if qpol_constraint_get_perm_iter(self.policy.handle, self.handle, &iter):
            raise MemoryError

        return set(qpol_iterator_factory(self.policy, iter, string_factory_iter))

    @property
    def tclass(self):
        """Object class for this constraint."""
        cdef const qpol_class_t *cls
        if qpol_constraint_get_class(self.policy.handle, self.handle, &cls):
            raise RuntimeError("Could not get class for constraint")

        return ObjClass.factory(self.policy, <sepol.class_datum_t *>cls)


cdef class Validatetrans(BaseConstraint):

    """A validatetrans rule (validatetrans/mlsvalidatetrans)."""

    cdef const qpol_validatetrans_t *handle

    def __str__(self):
        return "{0.ruletype} {0.tclass} ({1});".format(self,
                                                       self._expression_str(self.expression()))

    def _eq(self, Validatetrans other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

    def _expression_iterator(self):
        """Internal function returning a low-level iterator of the expression."""
        cdef qpol_iterator_t *iter
        if qpol_validatetrans_get_expr_iter(self.policy.handle, self.handle, &iter):
            raise MemoryError

        return qpol_iterator_factory(self.policy, iter, constraint_expr_factory_iter)

    @property
    def perms(self):
        raise ConstraintUseError("{0} rules do not have permissions.".format(self.ruletype))

    @property
    def tclass(self):
        """Object class for this constraint."""
        cdef const qpol_class_t *cls
        if qpol_validatetrans_get_class(self.policy.handle, self.handle, &cls):
            raise RuntimeError("Could not get class for validatetrans rule")

        return ObjClass.factory(self.policy, <sepol.class_datum_t *>cls)


cdef class ConstraintExprNode(PolicySymbol):

    """A node of a constraint expression."""

    cdef const qpol_constraint_expr_node_t *handle

    _expr_type_to_text = {
        QPOL_CEXPR_TYPE_NOT: "not",
        QPOL_CEXPR_TYPE_AND: "and",
        QPOL_CEXPR_TYPE_OR: "or"}

    _expr_op_to_text = {
        QPOL_CEXPR_OP_EQ: "==",
        QPOL_CEXPR_OP_NEQ: "!=",
        QPOL_CEXPR_OP_DOM: "dom",
        QPOL_CEXPR_OP_DOMBY: "domby",
        QPOL_CEXPR_OP_INCOMP: "incomp"}

    _sym_to_text = {
        QPOL_CEXPR_SYM_USER: "u1",
        QPOL_CEXPR_SYM_ROLE: "r1",
        QPOL_CEXPR_SYM_TYPE: "t1",
        QPOL_CEXPR_SYM_USER + QPOL_CEXPR_SYM_TARGET: "u2",
        QPOL_CEXPR_SYM_ROLE + QPOL_CEXPR_SYM_TARGET: "r2",
        QPOL_CEXPR_SYM_TYPE + QPOL_CEXPR_SYM_TARGET: "t2",
        QPOL_CEXPR_SYM_USER + QPOL_CEXPR_SYM_XTARGET: "u3",
        QPOL_CEXPR_SYM_ROLE + QPOL_CEXPR_SYM_XTARGET: "r3",
        QPOL_CEXPR_SYM_TYPE + QPOL_CEXPR_SYM_XTARGET: "t3",
        QPOL_CEXPR_SYM_L1L2: "l1",
        QPOL_CEXPR_SYM_L1H2: "l1",
        QPOL_CEXPR_SYM_H1L2: "h1",
        QPOL_CEXPR_SYM_H1H2: "h1",
        QPOL_CEXPR_SYM_L1H1: "l1",
        QPOL_CEXPR_SYM_L2H2: "l2",
        QPOL_CEXPR_SYM_L1L2 + QPOL_CEXPR_SYM_TARGET: "l2",
        QPOL_CEXPR_SYM_L1H2 + QPOL_CEXPR_SYM_TARGET: "h2",
        QPOL_CEXPR_SYM_H1L2 + QPOL_CEXPR_SYM_TARGET: "l2",
        QPOL_CEXPR_SYM_H1H2 + QPOL_CEXPR_SYM_TARGET: "h2",
        QPOL_CEXPR_SYM_L1H1 + QPOL_CEXPR_SYM_TARGET: "h1",
        QPOL_CEXPR_SYM_L2H2 + QPOL_CEXPR_SYM_TARGET: "h2"}

    _role_syms = [QPOL_CEXPR_SYM_ROLE,
                  QPOL_CEXPR_SYM_ROLE + QPOL_CEXPR_SYM_TARGET,
                  QPOL_CEXPR_SYM_ROLE + QPOL_CEXPR_SYM_XTARGET]

    _type_syms = [QPOL_CEXPR_SYM_TYPE,
                  QPOL_CEXPR_SYM_TYPE + QPOL_CEXPR_SYM_TARGET,
                  QPOL_CEXPR_SYM_TYPE + QPOL_CEXPR_SYM_XTARGET]

    _user_syms = [QPOL_CEXPR_SYM_USER,
                  QPOL_CEXPR_SYM_USER + QPOL_CEXPR_SYM_TARGET,
                  QPOL_CEXPR_SYM_USER + QPOL_CEXPR_SYM_XTARGET]

    def __call__(self):
        expression = []

        if self.expression_type == QPOL_CEXPR_TYPE_ATTR:
            # logical operator with symbols (e.g. u1 == u2)
            operand1 = self._sym_to_text[self.symbol_type]
            operand2 = self._sym_to_text[self.symbol_type + QPOL_CEXPR_SYM_TARGET]
            operator = self._expr_op_to_text[self.operator]

            expression.extend([operand1, operand2, operator])

        elif self.expression_type == QPOL_CEXPR_TYPE_NAMES:
            # logical operator with type or attribute list (e.g. t1 == { spam_t eggs_t })
            operand1 = self._sym_to_text[self.symbol_type]
            operator = self._expr_op_to_text[self.operator]
            operand2 = self.names

            expression.extend([operand1, operand2, operator])

        else:
            # individual operators (and/or/not)
            expression.append(self._expr_type_to_text[self.expression_type])

        return expression

    @property
    def expression_type(self):
        cdef uint32_t expr_type
        if qpol_constraint_expr_node_get_expr_type(self.policy.handle, self.handle, &expr_type):
            raise RuntimeError("Could not get expression type for node")

        return expr_type

    @property
    def mls(self):
        """T/F the node is an MLS expression."""
        try:
            return self.symbol_type >= QPOL_CEXPR_SYM_L1L2
        except AttributeError:
            return False

    @property
    def names(self):
        cdef qpol_iterator_t *iter

        if self.expression_type != QPOL_CEXPR_TYPE_NAMES:
            raise AttributeError("Names on expression type {}".format(self.expression_type))

        if qpol_constraint_expr_node_get_names_iter(self.policy.handle, self.handle, &iter):
            raise MemoryError

        name_iterator = qpol_iterator_factory(self.policy, iter, string_factory_iter)
        if self.symbol_type in self._role_syms:
            names = frozenset(self.policy.lookup_role(r) for r in name_iterator)
        elif self.symbol_type in self._type_syms:
            names = frozenset(self.policy.lookup_type_or_attr(t)
                              for t in name_iterator)
        else:
            names = frozenset(user_factory_lookup(self.policy, u) for u in name_iterator)

        return names

    @property
    def operator(self):
        cdef uint32_t op

        if self.expression_type not in (QPOL_CEXPR_TYPE_ATTR, QPOL_CEXPR_TYPE_NAMES):
            raise AttributeError("Operator on expression type {}".format(self.expression_type))

        if qpol_constraint_expr_node_get_op(self.policy.handle, self.handle, &op):
            raise RuntimeError("Could not get operator for node")

        return op

    @property
    def roles(self):
        """T/F the node has a role list."""
        return self.expression_type == QPOL_CEXPR_TYPE_NAMES and self.symbol_type in self._role_syms

    @property
    def symbol_type(self):
        cdef uint32_t sym_type

        if self.expression_type not in (QPOL_CEXPR_TYPE_ATTR, QPOL_CEXPR_TYPE_NAMES):
            raise AttributeError("Symbol type on expression type {}".format(self.expression_type))

        if qpol_constraint_expr_node_get_sym_type(self.policy.handle, self.handle, &sym_type):
            raise RuntimeError("Could not get symbol type for node")

        return sym_type

    @property
    def types(self):
        """T/F the node has a type list."""
        return self.expression_type == QPOL_CEXPR_TYPE_NAMES and self.symbol_type in self._type_syms

    @property
    def users(self):
        """T/F the node has a user list."""
        return self.expression_type == QPOL_CEXPR_TYPE_NAMES and self.symbol_type in self._user_syms
