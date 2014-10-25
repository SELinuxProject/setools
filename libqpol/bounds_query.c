/**
*  @file
*  Defines the public interface for searching and iterating over the permissive types.
*
*  @author Richard Haines richard_c_haines@btinternet.com
*
*  Copyright (C) 2006-2007 Tresys Technology, LLC
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
*
*  You should have received a copy of the GNU Lesser General Public
*  License along with this library; if not, write to the Free Software
*  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <qpol/bounds_query.h>
#include <sepol/policydb/policydb.h>
#include "qpol_internal.h"
#include "iterator_internal.h"

			/************ TYPEBOUNDS *************/
int qpol_typebounds_get_parent_name(const qpol_policy_t *policy, const qpol_typebounds_t * datum, const char **name)
{
	type_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;
	
	if (policy == NULL || datum == NULL || name == NULL) {
		if (name != NULL)
			*name = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}
	*name = NULL;

	/* The bounds rules started in ver 24 */
	if (!qpol_policy_has_capability(policy, QPOL_CAP_BOUNDS))
		return STATUS_SUCCESS;

	db = &policy->p->p;
	internal_datum = (type_datum_t *)datum;

	/* This will be zero if not a typebounds statement */
	if (internal_datum->flavor == TYPE_TYPE && internal_datum->bounds != 0) {
		*name = db->p_type_val_to_name[internal_datum->bounds - 1];
	}
	return STATUS_SUCCESS;
}

int qpol_typebounds_get_child_name(const qpol_policy_t *policy, const qpol_typebounds_t * datum, const char **name)
{
	type_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;
	
	if (policy == NULL || datum == NULL || name == NULL) {
		if (name != NULL)
			*name = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}
	*name = NULL;

	/* The bounds rules started in ver 24 */
	if (!qpol_policy_has_capability(policy, QPOL_CAP_BOUNDS))
		return STATUS_SUCCESS;

	db = &policy->p->p;
	internal_datum = (type_datum_t *)datum;

	if (internal_datum->flavor == TYPE_TYPE && internal_datum->bounds != 0) {
		*name = db->p_type_val_to_name[internal_datum->s.value - 1];
	}
	return STATUS_SUCCESS;
}

/* As type bounds are in types use these, however will need to calc number of bounds manually in top.tcl*/
int qpol_policy_get_typebounds_iter(const qpol_policy_t *policy, qpol_iterator_t **iter)
{
	policydb_t *db;
	int error = 0;
	hash_state_t *hs = NULL;

	if (policy == NULL || iter == NULL) {
		if (iter != NULL)
			*iter = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
/*
	struct type_datum *type;
	size_t i;
	int count = 0;

	for (i = 0; i < db->p_types.nprim - 1; i++) {
		type = db->type_val_to_struct[i];
		if (type->flavor == TYPE_TYPE && type->bounds != 0) {
			printf("PARENT DOMAIN: %s\n", db->p_type_val_to_name[type->bounds - 1]);
			printf("CHILD NAME: %s\n", db->p_type_val_to_name[type->s.value - 1]);
			count++;
		}
	}
	printf("Type Bounds count: %d\n", count);
*/
	hs = calloc(1, sizeof(hash_state_t));
	if (hs == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}
	hs->table = &db->p_types.table;
	hs->node = (*(hs->table))->htable[0];

	if (qpol_iterator_create(policy, (void *)hs, hash_state_get_cur,
				 hash_state_next, hash_state_end, hash_state_size, free, iter)) {
		free(hs);
		return STATUS_ERR;
	}

	if (hs->node == NULL)
		hash_state_next(*iter);

	return STATUS_SUCCESS;
}

			/************ ROLEBOUNDS *************/
int qpol_rolebounds_get_parent_name(const qpol_policy_t *policy, const qpol_rolebounds_t * datum, const char **name)
{
	role_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;
	
	if (policy == NULL || datum == NULL || name == NULL) {
		if (name != NULL)
			*name = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}
	*name = NULL;

	/* The bounds rules started in ver 24 */
	if (!qpol_policy_has_capability(policy, QPOL_CAP_BOUNDS))
		return STATUS_SUCCESS;

	db = &policy->p->p;
	internal_datum = (role_datum_t *)datum;

	/* This will be zero if not a rolebounds statement */
	if (internal_datum->flavor == ROLE_ROLE && internal_datum->bounds != 0) {
		*name = db->p_role_val_to_name[internal_datum->bounds - 1];
	}
	return STATUS_SUCCESS;
}

int qpol_rolebounds_get_child_name(const qpol_policy_t *policy, const qpol_rolebounds_t * datum, const char **name)
{
	role_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;
	
	if (policy == NULL || datum == NULL || name == NULL) {
		if (name != NULL)
			*name = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}
	*name = NULL;

	/* The bounds rules started in ver 24 */
	if (!qpol_policy_has_capability(policy, QPOL_CAP_BOUNDS))
		return STATUS_SUCCESS;

	db = &policy->p->p;
	internal_datum = (role_datum_t *)datum;

	if (internal_datum->flavor == ROLE_ROLE && internal_datum->bounds != 0) {
		*name = db->p_role_val_to_name[internal_datum->s.value - 1];
	}
	return STATUS_SUCCESS;
}

/* As rolebounds are in roles use these, however will need to calc number of bounds manually in top.tcl*/
int qpol_policy_get_rolebounds_iter(const qpol_policy_t *policy, qpol_iterator_t **iter)
{
	policydb_t *db;
	int error = 0;
	hash_state_t *hs = NULL;

	if (policy == NULL || iter == NULL) {
		if (iter != NULL)
			*iter = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	hs = calloc(1, sizeof(hash_state_t));
	if (hs == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}
	hs->table = &db->p_roles.table;
	hs->node = (*(hs->table))->htable[0];

	if (qpol_iterator_create(policy, (void *)hs, hash_state_get_cur,
				 hash_state_next, hash_state_end, hash_state_size, free, iter)) {
		free(hs);
		return STATUS_ERR;
	}

	if (hs->node == NULL)
		hash_state_next(*iter);

	return STATUS_SUCCESS;
}

			/************ USERBOUNDS *************/
int qpol_userbounds_get_parent_name(const qpol_policy_t *policy, const qpol_userbounds_t * datum, const char **name)
{
	user_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;
	
	if (policy == NULL || datum == NULL || name == NULL) {
		if (name != NULL)
			*name = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}
	*name = NULL;

	/* The bounds rules started in ver 24 */
	if (!qpol_policy_has_capability(policy, QPOL_CAP_BOUNDS))
		return STATUS_SUCCESS;

	db = &policy->p->p;
	internal_datum = (user_datum_t *)datum;

	/* This will be zero if not a userbounds statement */
	if (internal_datum->bounds != 0) {
		*name = db->p_user_val_to_name[internal_datum->bounds - 1];
	}
	return STATUS_SUCCESS;
}

int qpol_userbounds_get_child_name(const qpol_policy_t *policy, const qpol_userbounds_t * datum, const char **name)
{
	user_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;
	
	if (policy == NULL || datum == NULL || name == NULL) {
		if (name != NULL)
			*name = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}
	*name = NULL;

	/* The bounds rules started in ver 24 */
	if (!qpol_policy_has_capability(policy, QPOL_CAP_BOUNDS))
		return STATUS_SUCCESS;

	db = &policy->p->p;
	internal_datum = (user_datum_t *)datum;

	if (internal_datum->bounds != 0) {
		*name = db->p_user_val_to_name[internal_datum->s.value - 1];
	}
	return STATUS_SUCCESS;
}

/* As userbounds are in users use these, however will need to calc number of bounds manually in top.tcl*/
int qpol_policy_get_userbounds_iter(const qpol_policy_t *policy, qpol_iterator_t **iter)
{
	policydb_t *db;
	int error = 0;
	hash_state_t *hs = NULL;

	if (policy == NULL || iter == NULL) {
		if (iter != NULL)
			*iter = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	hs = calloc(1, sizeof(hash_state_t));
	if (hs == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}
	hs->table = &db->p_users.table;
	hs->node = (*(hs->table))->htable[0];

	if (qpol_iterator_create(policy, (void *)hs, hash_state_get_cur,
				 hash_state_next, hash_state_end, hash_state_size, free, iter)) {
		free(hs);
		return STATUS_ERR;
	}

	if (hs->node == NULL)
		hash_state_next(*iter);

	return STATUS_SUCCESS;
}

