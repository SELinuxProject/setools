# Copyright 2014-2016, Tresys Technology, LLC
# Copyright 2016-2018, Chris PeBenito <pebenito@ieee.org>
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

    cdef:
        sepol.constraint_node_t *handle
        readonly object ruletype
        readonly object tclass
        list _postfix_expression
        list _infix_expression
        readonly frozenset users
        readonly frozenset roles
        readonly frozenset types

    def __str__(self):
        raise NotImplementedError

    def _eq(self, BaseConstraint other):
        """Low-level equality check (C pointers)."""
        return self.handle == other.handle

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

        if self._infix_expression is None:
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

            # sepol representation is in postfix notation.  This code
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

            self._infix_expression = self._flatten_expression(stack)

        return self._infix_expression

    def postfix_expression(self):
        """
        The constraint's expression in postfix notation.

        Return: list
        """
        return self._postfix_expression

    #
    # Internal functions
    #
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

    cdef readonly frozenset perms

    @staticmethod
    cdef factory(SELinuxPolicy policy, ObjClass tclass, sepol.constraint_node_t *symbol):
        """Factory function for creating Constraint objects."""
        cdef:
            Constraint c = Constraint.__new__(Constraint)
            list users = []
            list roles = []
            list types = []

        c.policy = policy
        c.handle = symbol
        c.tclass = tclass
        c.perms = frozenset(PermissionVectorIterator.factory(policy, tclass, symbol.permissions))

        c.ruletype = ConstraintRuletype.constrain
        c._postfix_expression = []
        for expr_node in ConstraintExprIterator.factory(policy, symbol.expr):
            if expr_node.mls:
                c.ruletype = ConstraintRuletype.mlsconstrain

            if expr_node.types:
                types.extend(expr_node.names)
            elif expr_node.roles:
                roles.extend(expr_node.names)
            elif expr_node.users:
                users.extend(expr_node.names)

            c._postfix_expression.extend(expr_node())

        c.users = frozenset(users)
        c.roles = frozenset(roles)
        c.types = frozenset(types)


        return c

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


cdef class Validatetrans(BaseConstraint):

    """A validatetrans rule (validatetrans/mlsvalidatetrans)."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, ObjClass tclass, sepol.constraint_node_t *symbol):
        """Factory function for creating Validatetrans objects."""
        cdef:
            Validatetrans v = Validatetrans.__new__(Validatetrans)
            list users = []
            list roles = []
            list types = []

        v.policy = policy
        v.handle = symbol
        v.tclass = tclass

        v.ruletype = ConstraintRuletype.validatetrans
        v._postfix_expression = []
        for expr_node in ConstraintExprIterator.factory(policy, symbol.expr):
            if expr_node.mls:
                v.ruletype = ConstraintRuletype.mlsvalidatetrans

            if expr_node.types:
                types.extend(expr_node.names)
            elif expr_node.roles:
                roles.extend(expr_node.names)
            elif expr_node.users:
                users.extend(expr_node.names)

            v._postfix_expression.extend(expr_node())

        v.users = frozenset(users)
        v.roles = frozenset(roles)
        v.types = frozenset(types)

        return v

    def __str__(self):
        return "{0.ruletype} {0.tclass} ({1});".format(self,
                                                       self._expression_str(self.expression()))

    @property
    def perms(self):
        raise ConstraintUseError("{0} rules do not have permissions.".format(self.ruletype))


cdef class ConstraintExprNode(PolicySymbol):

    """A node of a constraint expression."""

    cdef sepol.constraint_expr_t *handle

    _expr_type_to_text = {
        sepol.CEXPR_NOT: "not",
        sepol.CEXPR_AND: "and",
        sepol.CEXPR_OR: "or"}

    _expr_op_to_text = {
        sepol.CEXPR_EQ: "==",
        sepol.CEXPR_NEQ: "!=",
        sepol.CEXPR_DOM: "dom",
        sepol.CEXPR_DOMBY: "domby",
        sepol.CEXPR_INCOMP: "incomp"}

    _sym_to_text = {
        sepol.CEXPR_USER: "u1",
        sepol.CEXPR_ROLE: "r1",
        sepol.CEXPR_TYPE: "t1",
        sepol.CEXPR_USER + sepol.CEXPR_TARGET: "u2",
        sepol.CEXPR_ROLE + sepol.CEXPR_TARGET: "r2",
        sepol.CEXPR_TYPE + sepol.CEXPR_TARGET: "t2",
        sepol.CEXPR_USER + sepol.CEXPR_XTARGET: "u3",
        sepol.CEXPR_ROLE + sepol.CEXPR_XTARGET: "r3",
        sepol.CEXPR_TYPE + sepol.CEXPR_XTARGET: "t3",
        sepol.CEXPR_L1L2: "l1",
        sepol.CEXPR_L1H2: "l1",
        sepol.CEXPR_H1L2: "h1",
        sepol.CEXPR_H1H2: "h1",
        sepol.CEXPR_L1H1: "l1",
        sepol.CEXPR_L2H2: "l2",
        sepol.CEXPR_L1L2 + sepol.CEXPR_TARGET: "l2",
        sepol.CEXPR_L1H2 + sepol.CEXPR_TARGET: "h2",
        sepol.CEXPR_H1L2 + sepol.CEXPR_TARGET: "l2",
        sepol.CEXPR_H1H2 + sepol.CEXPR_TARGET: "h2",
        sepol.CEXPR_L1H1 + sepol.CEXPR_TARGET: "h1",
        sepol.CEXPR_L2H2 + sepol.CEXPR_TARGET: "h2"}

    _role_syms = [sepol.CEXPR_ROLE,
                  sepol.CEXPR_ROLE + sepol.CEXPR_TARGET,
                  sepol.CEXPR_ROLE + sepol.CEXPR_XTARGET]

    _type_syms = [sepol.CEXPR_TYPE,
                  sepol.CEXPR_TYPE + sepol.CEXPR_TARGET,
                  sepol.CEXPR_TYPE + sepol.CEXPR_XTARGET]

    _user_syms = [sepol.CEXPR_USER,
                  sepol.CEXPR_USER + sepol.CEXPR_TARGET,
                  sepol.CEXPR_USER + sepol.CEXPR_XTARGET]

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.constraint_expr_t *symbol):
        """Factory function for creating ConstraintExprNode objects."""
        r = ConstraintExprNode()
        r.policy = policy
        r.handle = symbol
        return r

    def __call__(self):
        expression = []

        if self.expression_type == sepol.CEXPR_ATTR:
            # logical operator with symbols (e.g. u1 == u2)
            operand1 = self._sym_to_text[self.symbol_type]
            operand2 = self._sym_to_text[self.symbol_type + sepol.CEXPR_TARGET]
            operator = self._expr_op_to_text[self.operator]

            expression.extend([operand1, operand2, operator])

        elif self.expression_type == sepol.CEXPR_NAMES:
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
        return self.handle.expr_type

    @property
    def mls(self):
        """T/F the node is an MLS expression."""
        try:
            return self.symbol_type >= sepol.CEXPR_L1L2
        except AttributeError:
            return False

    @property
    def names(self):
        if self.expression_type != sepol.CEXPR_NAMES:
            raise AttributeError("Names on expression type {}".format(self.expression_type))

        if self.symbol_type in self._role_syms:
            return frozenset(r for r in RoleEbitmapIterator.factory(self.policy, &self.handle.names))
        elif self.symbol_type in self._type_syms:
            if self.policy.version > 28:
                return frozenset(t for t in TypeOrAttributeEbitmapIterator.factory_from_set(
                    self.policy, self.handle.type_names))
            else:
                return frozenset(t for t in TypeEbitmapIterator.factory(
                    self.policy, &self.handle.names))
        else:
            return frozenset(u for u in UserEbitmapIterator.factory(self.policy, &self.handle.names))

    @property
    def operator(self):
        return self.handle.op

    @property
    def roles(self):
        """T/F the node has a role list."""
        return self.expression_type == sepol.CEXPR_NAMES and self.symbol_type in self._role_syms

    @property
    def symbol_type(self):
        if self.expression_type not in (sepol.CEXPR_ATTR, sepol.CEXPR_NAMES):
            raise AttributeError("Symbol type on expression type {}".format(self.expression_type))

        return self.handle.attr

    @property
    def types(self):
        """T/F the node has a type list."""
        return self.expression_type == sepol.CEXPR_NAMES and self.symbol_type in self._type_syms

    @property
    def users(self):
        """T/F the node has a user list."""
        return self.expression_type == sepol.CEXPR_NAMES and self.symbol_type in self._user_syms


#
# Iterators
#
cdef class ConstraintIterator(PolicyIterator):

    """Constraint iterator."""

    cdef:
        sepol.constraint_node_t *head
        sepol.constraint_node_t *curr
        ObjClass tclass

    @staticmethod
    cdef factory(SELinuxPolicy policy, ObjClass tclass, sepol.constraint_node_t *head):
        """Constraint iterator factory."""
        c = ConstraintIterator()
        c.policy = policy
        c.head = head
        c.tclass = tclass
        c.reset()
        return c

    def __next__(self):
        if self.curr == NULL:
            raise StopIteration

        item = Constraint.factory(self.policy, self.tclass, self.curr)
        self.curr = self.curr.next
        return item

    def __len__(self):
        cdef:
            sepol.constraint_node_t *curr
            size_t count = 0

        curr = self.head
        while curr != NULL:
             count += 1
             curr = curr.next

        return count

    def reset(self):
        """Reset the iterator back to the start."""
        self.curr = self.head


cdef class ValidatetransIterator(ConstraintIterator):

    """Validatetrans iterator."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, ObjClass tclass, sepol.constraint_node_t *head):
        """Validatetrans iterator factory."""
        v = ValidatetransIterator()
        v.policy = policy
        v.head = head
        v.tclass = tclass
        v.reset()
        return v

    def __next__(self):
        if self.curr == NULL:
            raise StopIteration

        item = Validatetrans.factory(self.policy, self.tclass, self.curr)
        self.curr = self.curr.next
        return item


cdef class ConstraintExprIterator(PolicyIterator):

    """Constraint expression iterator."""

    cdef:
        sepol.constraint_expr_t *head
        sepol.constraint_expr_t *curr

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.constraint_expr_t *head):
        """Constraint expression iterator factory."""
        e = ConstraintExprIterator()
        e.policy = policy
        e.head = head
        e.reset()
        return e

    def __next__(self):
        if self.curr == NULL:
            raise StopIteration

        item = ConstraintExprNode.factory(self.policy, self.curr)
        self.curr = self.curr.next
        return item

    def __len__(self):
        cdef:
            sepol.constraint_expr_t *curr
            size_t count = 0

        curr = self.head
        while curr != NULL:
             count += 1
             curr = curr.next

        return count

    def reset(self):
        """Reset the iterator back to the start."""
        self.curr = self.head
