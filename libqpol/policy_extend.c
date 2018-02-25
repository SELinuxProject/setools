/**
 *  @file
 *  Implementation of the interface for loading and using an extended
 *  policy image.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Jeremy Solt jsolt@tresys.com
 *
 *  Copyright (C) 2006-2008 Tresys Technology, LLC
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

#include <config.h>

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/flask.h>
#include <sepol/policydb/ebitmap.h>
#include <sepol/policydb/expand.h>
#ifdef HAVE_SEPOL_ERRCODES
#include <sepol/errcodes.h>
#endif
#include <qpol/policy.h>
#include <qpol/policy_extend.h>
#include <qpol/iterator.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "qpol_internal.h"
#include "iterator_internal.h"

struct extend_bogus_alias_struct
{
	qpol_policy_t *q;
	int num_bogus_aliases;
};

static int extend_find_bogus_alias(hashtab_key_t key __attribute__ ((unused)), hashtab_datum_t datum, void *args)
{
	type_datum_t *type = (type_datum_t *) datum;

	unsigned char isalias = 0;
	if ((type->primary == 0 && type->flavor == TYPE_TYPE) || type->flavor == TYPE_ALIAS)
		isalias = 1;

	return isalias && type->s.value == 0;
}

static void extend_remove_bogus_alias(hashtab_key_t key, hashtab_datum_t datum, void *args)
{
	struct extend_bogus_alias_struct *e = (struct extend_bogus_alias_struct *)args;
	free(key);
	type_datum_t *type = (type_datum_t *) datum;
	type_datum_destroy(type);
	free(type);
	e->num_bogus_aliases++;
}

/**
 *  Search the policy for aliases that have a value of 0.  These come
 *  from modular policies with disabled aliases, but end up being
 *  written to the policy anyways due to a bug in libsepol.  These
 *  bogus aliases are removed from the policy.
 *  @param policy Policy that may contain broken aliases.  This policy
 *  will be altered by this function.
 *  @return 0 on success and < 0 on failure; if the call fails, errno
 *  will be set.  On failure, the policy state may be inconsistent.
 */
static int qpol_policy_remove_bogus_aliases(qpol_policy_t * policy)
{
	policydb_t *db = NULL;

	if (policy == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	struct extend_bogus_alias_struct e = { policy, 0 };
	hashtab_map_remove_on_error(db->p_types.table, extend_find_bogus_alias, extend_remove_bogus_alias, &e);

	if (e.num_bogus_aliases > 0) {
		WARN(policy, "%s", "This policy contained disabled aliases; they have been removed.");
	}

	return 0;
}

/**
 *  Builds data for the attributes and inserts them into the policydb.
 *  This function modifies the policydb. Names created for attributes
 *  are of the form @ttr<value> where value is the value of the attribute
 *  as a ten digit number (prepended with 0's as needed).
 *  @param policy The policy from which to read the attribute map and
 *  create the type data for the attributes. This policy will be altered
 *  by this function.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set. On failure, the policy state may be inconsistent
 *  especially in the case where the hashtab functions return the error.
 */
static int qpol_policy_build_attrs_from_map(qpol_policy_t * policy)
{
	policydb_t *db = NULL;
	size_t i;
	uint32_t bit = 0, count = 0;
	ebitmap_node_t *node = NULL;
	type_datum_t *tmp_type = NULL, *orig_type;
	char *tmp_name = NULL, buff[16];
	int error = 0, retv;

	INFO(policy, "%s", "Generating attributes for policy. (Step 4 of 5)");
	if (policy == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	db = &policy->p->p;

	memset(&buff, 0, 16 * sizeof(char));

	for (i = 0; i < db->p_types.nprim; i++) {
		/* skip types */
		if (db->type_val_to_struct[i]->flavor == TYPE_TYPE)
			continue;

		count = 0;
		ebitmap_for_each_bit(&db->attr_type_map[i], node, bit) {
			if (ebitmap_node_get_bit(node, bit))
				count++;
		}
		if (count == 0) {
			continue;
		}

		/* first create a new type_datum_t for the attribute,
		 * with the attribute's type_list consisting of types
		 * with this attribute */
		/* Does not exist */
		if (db->p_type_val_to_name[i] == NULL){
			snprintf(buff, 15, "@ttr%010zd", i + 1);
			tmp_name = strdup(buff);
			if (!tmp_name) {
				error = errno;
				goto err;
			}
		}

		/* Already exists */
		else
			tmp_name = db->p_type_val_to_name[i];

		tmp_type = calloc(1, sizeof(type_datum_t));
		if (!tmp_type) {
			error = errno;
			goto err;
		}
		tmp_type->primary = 1;
		tmp_type->flavor = TYPE_ATTRIB;
		tmp_type->s.value = i + 1;
		if (ebitmap_cpy(&tmp_type->types, &db->attr_type_map[i])) {
			error = ENOMEM;
			goto err;
		}

		/* now go through each of the member types, and set
		 * their type_list bit to point back */
		ebitmap_for_each_bit(&tmp_type->types, node, bit) {
			if (ebitmap_node_get_bit(node, bit)) {
				orig_type = db->type_val_to_struct[bit];
				if (ebitmap_set_bit(&orig_type->types, tmp_type->s.value - 1, 1)) {
					error = ENOMEM;
					goto err;
				}
			}
		}
		/* Does not exist - insert new */
		if (db->p_type_val_to_name[i] == NULL){
			retv = hashtab_insert(db->p_types.table, (hashtab_key_t) tmp_name, (hashtab_datum_t) tmp_type);
			if (retv) {
				if (retv == SEPOL_ENOMEM)
					error = db->p_types.table ? ENOMEM : EINVAL;
				else
					error = EEXIST;
				goto err;
			}
		}
		/* Already exists - replace old */
		else {
			retv = hashtab_replace(db->p_types.table, (hashtab_key_t) tmp_name, (hashtab_datum_t) tmp_type, NULL, NULL);
			if (retv) {
				if (retv == SEPOL_ENOMEM)
					error = db->p_types.table ? ENOMEM : EINVAL;
				else
					error = EEXIST;
				goto err;
			}
		}

		db->p_type_val_to_name[i] = tmp_name;
		db->type_val_to_struct[i] = tmp_type;

		/* memory now owned by symtab do not free */
		tmp_name = NULL;
		tmp_type = NULL;
	}

	return STATUS_SUCCESS;

      err:
	free(tmp_name);
	type_datum_destroy(tmp_type);
	free(tmp_type);
	ERR(policy, "%s", strerror(error));
	errno = error;
	return STATUS_ERR;
}

/**
 *  Builds data for empty attributes and inserts them into the policydb.
 *  This function modifies the policydb. Names created for the attributes
 *  are of the form @ttr<value> where value is the value of the attribute
 *  as a ten digit number (prepended with 0's as needed).
 *  @param policy The policy to which to add type data for attributes.
 *  This policy will be altered by this function.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set. On failure, the policy state may be inconsistent
 *  especially in the case where the hashtab functions return the error.
 */

static int qpol_policy_fill_attr_holes(qpol_policy_t * policy)
{
	policydb_t *db = NULL;
	char *tmp_name = NULL, buff[16];
	int error = 0, retv = 0;
	ebitmap_t tmp_bmap = { NULL, 0 };
	type_datum_t *tmp_type = NULL;
	size_t i;

	if (policy == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	memset(&buff, 0, 16 * sizeof(char));

	for (i = 0; i < db->p_types.nprim; i++) {
		if (db->type_val_to_struct[i])
			continue;
		snprintf(buff, 15, "@ttr%010zd", i + 1);
		tmp_name = strdup(buff);
		if (!tmp_name) {
			error = errno;
			goto err;
		}
		tmp_type = calloc(1, sizeof(type_datum_t));
		if (!tmp_type) {
			error = errno;
			goto err;
		}
		tmp_type->primary = 1;
		tmp_type->flavor = TYPE_ATTRIB;
		tmp_type->s.value = i + 1;
		tmp_type->types = tmp_bmap;

		retv = hashtab_insert(db->p_types.table, (hashtab_key_t) tmp_name, (hashtab_datum_t) tmp_type);
		if (retv) {
			if (retv == SEPOL_ENOMEM)
				error = db->p_types.table ? ENOMEM : EINVAL;
			else
				error = EEXIST;
			goto err;
		}
		db->p_type_val_to_name[i] = tmp_name;
		db->type_val_to_struct[i] = tmp_type;

		/* memory now owned by symtab do not free */
		tmp_name = NULL;
		tmp_type = NULL;
	}

	return STATUS_SUCCESS;

      err:
	free(tmp_type);
	free(tmp_name);
	ERR(policy, "%s", strerror(error));
	errno = error;
	return STATUS_ERR;
}


int policy_extend(qpol_policy_t * policy)
{
	int retv, error;
	policydb_t *db = NULL;

	if (policy == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	db = &policy->p->p;

	retv = qpol_policy_remove_bogus_aliases(policy);
	if (retv) {
		error = errno;
		goto err;
	}

	if (db->attr_type_map) {
		retv = qpol_policy_build_attrs_from_map(policy);
		if (retv) {
			error = errno;
			goto err;
		}
		if (db->policy_type == POLICY_KERN) {
			retv = qpol_policy_fill_attr_holes(policy);
			if (retv) {
				error = errno;
				goto err;
			}
		}
	}

	return STATUS_SUCCESS;

      err:
	/* no need to call ERR here as it will already have been called */
	errno = error;
	return STATUS_ERR;
}
