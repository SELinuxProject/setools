/**
*  @file
*  Defines the public interface for searching and iterating over default objects.
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
#include <qpol/default_object_query.h>
#include <sepol/policydb/policydb.h>
#include "qpol_internal.h"
#include "iterator_internal.h"

int qpol_default_object_get_class(const qpol_policy_t *policy, const qpol_default_object_t * datum, const char **name)
{
	class_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;
	
	if (policy == NULL || datum == NULL || name == NULL) {
		if (name != NULL)
			*name = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}
	*name = NULL;

	db = &policy->p->p;
	internal_datum = (class_datum_t *)datum;

	/* These will be zero if no default_objects set */
	if (internal_datum->default_user || internal_datum->default_role ||
				internal_datum->default_type ||
				 internal_datum->default_range) {
		*name = db->p_class_val_to_name[internal_datum->s.value - 1];
	}
	return STATUS_SUCCESS;
}

int qpol_default_object_get_user_default(const qpol_policy_t *policy, const qpol_default_object_t * datum, const char **value)
{
	class_datum_t *internal_datum = NULL;
	
	if (policy == NULL || datum == NULL || value == NULL) {
		if (value != NULL)
			*value = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}
	*value = NULL;

	/* The user default started in ver 27 */
	if (!qpol_policy_has_capability(policy, QPOL_CAP_DEFAULT_OBJECTS))
		return STATUS_SUCCESS;

	internal_datum = (class_datum_t *)datum;

	if (internal_datum->default_user == DEFAULT_SOURCE) {
		*value = "source";
	} else if (internal_datum->default_user == DEFAULT_TARGET) {
		*value = "target";
	}
	return STATUS_SUCCESS;
}

int qpol_default_object_get_role_default(const qpol_policy_t *policy, const qpol_default_object_t * datum, const char **value)
{
	class_datum_t *internal_datum = NULL;
	
	if (policy == NULL || datum == NULL || value == NULL) {
		if (value != NULL)
			*value = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}
	*value = NULL;

	/* The role default started in ver 27 */
	if (!qpol_policy_has_capability(policy, QPOL_CAP_DEFAULT_OBJECTS))
		return STATUS_SUCCESS;

	internal_datum = (class_datum_t *)datum;

	if (internal_datum->default_role == DEFAULT_SOURCE) {
		*value = "source";
	} else if (internal_datum->default_role == DEFAULT_TARGET) {
		*value = "target";
	}
	return STATUS_SUCCESS;
}

int qpol_default_object_get_type_default(const qpol_policy_t *policy, const qpol_default_object_t * datum, const char **value)
{
	class_datum_t *internal_datum = NULL;

	if (policy == NULL || datum == NULL || value == NULL) {
		if (value != NULL)
			*value = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}
	*value = NULL;

	/* The type default started in ver 28 */
	if (!qpol_policy_has_capability(policy, QPOL_CAP_DEFAULT_TYPE))
		return STATUS_SUCCESS;

	internal_datum = (class_datum_t *)datum;

	if (internal_datum->default_type == DEFAULT_SOURCE) {
		*value = "source";
	} else if (internal_datum->default_type == DEFAULT_TARGET) {
		*value = "target";
	}
	return STATUS_SUCCESS;
}

int qpol_default_object_get_range_default(const qpol_policy_t *policy, const qpol_default_object_t * datum, const char **value)
{
	class_datum_t *internal_datum = NULL;

	if (policy == NULL || datum == NULL || value == NULL) {
		if (value != NULL)
			*value = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}
	*value = NULL;

	/* The range default started in ver 27 */
	if (!qpol_policy_has_capability(policy, QPOL_CAP_DEFAULT_OBJECTS))
		return STATUS_SUCCESS;

	internal_datum = (class_datum_t *)datum;

	switch (internal_datum->default_range) {
		case DEFAULT_SOURCE_LOW:
			*value = "source low";
			break;
		case DEFAULT_SOURCE_HIGH:
			*value = "source high";
			break;
		case DEFAULT_SOURCE_LOW_HIGH:
			*value = "source low_high";
			break;
		case DEFAULT_TARGET_LOW:
			*value = "target low";
			break;
		case DEFAULT_TARGET_HIGH:
			*value = "target high";
			break;
		case DEFAULT_TARGET_LOW_HIGH:
			*value = "target low_high";
			break;
		default:
			break;
	}
	return STATUS_SUCCESS;
}

/* As default objects are in classes use these, however will need to calc number of default objects manually in top.tcl*/
int qpol_policy_get_default_object_iter(const qpol_policy_t *policy, qpol_iterator_t **iter)
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
	class_datum_t *cladatum;
	sepol_security_class_t tclass;
	char *class;

	for (tclass = 1; tclass <= db->p_classes.nprim; tclass++) {
		cladatum = db->class_val_to_struct[tclass - 1];
		class = db->p_class_val_to_name[tclass - 1];

		if (cladatum->default_user == DEFAULT_SOURCE) {
			printf("default_user %s source;\n", class);
		} else if (cladatum->default_user == DEFAULT_TARGET) {
			printf("default_user %s target;\n", class);
		}

		if (cladatum->default_role == DEFAULT_SOURCE) {
			printf("default_role %s source;\n", class);
		} else if (cladatum->default_role == DEFAULT_TARGET) {
			printf("default_role %s target;\n", class);
		}

		if (cladatum->default_type == DEFAULT_SOURCE) {
			printf("default_type %s source;\n", class);
		} else if (cladatum->default_type == DEFAULT_TARGET) {
			printf("default_type %s target;\n", class);
		}

		switch (cladatum->default_range) {
			case DEFAULT_SOURCE_LOW:
				printf("default_range %s source low;\n", class);
				break;
			case DEFAULT_SOURCE_HIGH:
				printf("default_range %s source high;\n", class);
				break;
			case DEFAULT_SOURCE_LOW_HIGH:
				printf("default_range %s source low_high;\n", class);
				break;
			case DEFAULT_TARGET_LOW:
				printf("default_range %s target low;\n", class);
				break;
			case DEFAULT_TARGET_HIGH:
				printf("default_range %s target high;\n", class);
				break;
			case DEFAULT_TARGET_LOW_HIGH:
				printf("default_range %s target low_high;\n", class);
				break;
			default:
				break;
		}
	}
*/
	hs = calloc(1, sizeof(hash_state_t));
	if (hs == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}
	hs->table = &db->p_classes.table;
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
