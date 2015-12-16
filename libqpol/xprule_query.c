 /**
 *  @file
 *  Implementation for the public interface for searching and iterating over
 *  xperm rules.
 *
 *  @author Richard Haines richard_c_haines@btinternet.com
 *  Derived from avrule_query.c
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

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

#include "iterator_internal.h"
#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <qpol/xprule_query.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/util.h>
#include <stdlib.h>
#include "qpol_internal.h"

int qpol_policy_get_xprule_iter(const qpol_policy_t *policy,
				    uint32_t rule_type_mask,
				    qpol_iterator_t **iter)
{
	policydb_t *db;
	avtab_state_t *state;

	if (iter)
		*iter = NULL;

	if (policy == NULL || iter == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	if ((rule_type_mask & QPOL_RULE_NEVERALLOWXPERM) &&
				    !qpol_policy_has_capability(policy,
				    QPOL_CAP_NEVERALLOW)) {
		ERR(policy, "%s", "Cannot get xperms: Neverallow rules requested but not available");
		errno = ENOTSUP;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	state = calloc(1, sizeof(avtab_state_t));
	if (state == NULL) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return STATUS_ERR;
	}

	state->ucond_tab = &db->te_avtab;
	state->cond_tab = &db->te_cond_avtab;
	state->rule_type_mask = rule_type_mask;
	state->node = db->te_avtab.htable[0];

	if (qpol_iterator_create
	    (policy, state, avtab_state_get_cur, avtab_state_next,
			    avtab_state_end, avtab_state_size, free, iter)) {
		free(state);
		return STATUS_ERR;
	}
	if (state->node == NULL ||
		    !(state->node->key.specified & state->rule_type_mask)) {
		avtab_state_next(*iter);
	}

	return STATUS_SUCCESS;
}

int qpol_xprule_get_source_type(const qpol_policy_t *policy,
					    const qpol_xprule_t *rule,
					    const qpol_type_t **source)
{
	policydb_t *db = NULL;
	avtab_ptr_t xperm = NULL;

	if (source)
		*source = NULL;

	if (!policy || !rule || !source) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	xperm = (avtab_ptr_t)rule;

	*source = (qpol_type_t *)
			    db->type_val_to_struct[xperm->key.source_type - 1];

	return STATUS_SUCCESS;
}

int qpol_xprule_get_target_type(const qpol_policy_t *policy,
					    const qpol_xprule_t *rule,
					    const qpol_type_t **target)
{
	policydb_t *db = NULL;
	avtab_ptr_t xperm = NULL;

	if (target)
		*target = NULL;

	if (!policy || !rule || !target) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	xperm = (avtab_ptr_t)rule;

	*target = (qpol_type_t *)
			    db->type_val_to_struct[xperm->key.target_type - 1];

	return STATUS_SUCCESS;
}

int qpol_xprule_get_object_class(const qpol_policy_t *policy,
					    const qpol_xprule_t *rule,
					    const qpol_class_t **obj_class)
{
	policydb_t *db = NULL;
	avtab_ptr_t xperm = NULL;

	if (obj_class)
		*obj_class = NULL;

	if (!policy || !rule || !obj_class) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	xperm = (avtab_ptr_t)rule;

	*obj_class = (qpol_class_t *)
			  db->class_val_to_struct[xperm->key.target_class - 1];

	return STATUS_SUCCESS;
}

int qpol_xprule_get_command(const qpol_policy_t *policy,
					    const qpol_xprule_t *rule,
					    const char **xprule_command)
{
	avtab_ptr_t xperm = NULL;

	if (xprule_command)
		*xprule_command = NULL;

	if (!policy || !rule || !xprule_command) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	xperm = (avtab_ptr_t)rule;

	switch (xperm->datum.xperms->specified) {
	case AVRULE_XPERMS_IOCTLFUNCTION:
	case AVRULE_XPERMS_IOCTLDRIVER:
		*xprule_command = "ioctl";
		break;
	default:
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_xprule_get_xperm_string(const qpol_policy_t *policy,
					    const qpol_xprule_t *rule,
					    char **xperm_string)
{
	avtab_ptr_t xperm = NULL;

	if (xperm_string)
		*xperm_string = NULL;

	if (!policy || !rule || !xperm_string) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	xperm = (avtab_ptr_t)rule;
	*xperm_string = sepol_extended_perms_to_string(xperm->datum.xperms);

	return STATUS_SUCCESS;
}

int qpol_xprule_get_rule_type(const qpol_policy_t *policy,
					    const qpol_xprule_t *rule,
					    uint32_t *rule_type)
{
	avtab_ptr_t xperm = NULL;

	if (rule_type)
		*rule_type = 0;

	if (!policy || !rule || !rule_type) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	xperm = (avtab_ptr_t)rule;

	*rule_type = (xperm->key.specified & (
					QPOL_RULE_ALLOWXPERM |
					QPOL_RULE_NEVERALLOWXPERM |
					QPOL_RULE_AUDITALLOWXPERM |
					QPOL_RULE_DONTAUDITXPERM));

	return STATUS_SUCCESS;
}
