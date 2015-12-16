 /**
 *  @file
 *  Defines the public interface for searching and iterating over xperm rules.
 *
 *  @author Richard Haines richard_c_haines@btinternet.com
 *  Derived from avrule_query.h
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 */

#ifndef QPOL_XPRULE_QUERY_H
#define QPOL_XPRULE_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <qpol/policy.h>
#include <qpol/class_perm_query.h>
#include <qpol/type_query.h>

	typedef struct qpol_xprule qpol_xprule_t;

/* rule type defines (values copied from "sepol/policydb/policydb.h") */
#define QPOL_RULE_ALLOWXPERM		0x0100
#define QPOL_RULE_AUDITALLOWXPERM	0x0200
#define QPOL_RULE_DONTAUDITXPERM	0x0400
#define QPOL_RULE_NEVERALLOWXPERM	0x0800

/**
 *  Get an iterator over all xperm rules in a policy of a rule type in
 *  rule_type_mask.  It is an error to call this function if rules are
 *  not loaded.  Likewise, it is an error if neverallows are requested
 *  but they were not loaded.
 *  @param policy Policy from which to get the av rules.
 *  @param rule_type_mask Bitwise or'ed set of QPOL_RULE_* values.
 *  @param iter Iterator over items of type qpol_xprule_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodifed.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_xprule_iter(const qpol_policy_t *policy,
			    uint32_t rule_type_mask, qpol_iterator_t **iter);

/**
 *  Get the source type from an xperm rule.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the source type.
 *  @param source Pointer in which to store the source type.
 *  The caller should not free this pointer.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *source will be NULL.
 */
	extern int qpol_xprule_get_source_type(const qpol_policy_t *policy,
					    const qpol_xprule_t *rule,
					    const qpol_type_t **source);

/**
 *  Get the target type from an xperm rule.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the target type.
 *  @param target Pointer in which to store the target type.
 *  The caller should not free this pointer.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *target will be NULL.
 */
	extern int qpol_xprule_get_target_type(const qpol_policy_t *policy,
					    const qpol_xprule_t *rule,
					    const qpol_type_t **target);

/**
 *  Get the object class from an xperm rule.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the object class.
 *  @param obj_class Pointer in which to store the object class.
 *  The caller should not free this pointer.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *obj_class will be NULL.
 */
	extern int qpol_xprule_get_object_class(const qpol_policy_t *policy,
					    const qpol_xprule_t *rule,
					    const qpol_class_t **obj_class);

/**
 *  Get the extended permissions command from an xperm rule.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the permissions.
 *  @param xprule command Pointer to set to the string.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *perms will be NULL.
 */
	extern int qpol_xprule_get_command(const qpol_policy_t *policy,
					    const qpol_xprule_t *rule,
					    const char **xperm_command);


/**
 *  Get the extended IOCTL permissions from an xperm rule using
 *  sepol_extended_perms_to_string().
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the permissions.
 *  @param xperm_string Pointer to set to the string.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *perms will be NULL.
 */
	extern int qpol_xprule_get_xperm_string(const qpol_policy_t *policy,
					    const qpol_xprule_t *rule,
					    char **xperm_string);

/**
 *  Get the rule type value for an xperm rule.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the rule type.
 *  @param rule_type Integer in which to store the rule type value.
 *  The value will be one of the QPOL_RULE_* values above.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *rule_type will be 0.
 */
	extern int qpol_xprule_get_rule_type(const qpol_policy_t *policy,
						    const qpol_xprule_t *rule,
						    uint32_t *rule_type);

#ifdef	__cplusplus
}
#endif

#endif
