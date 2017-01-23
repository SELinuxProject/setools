/**
 *  @file
 *  Defines public interface for iterating over filename transition rules.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
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

#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <qpol/ftrule_query.h>
#include <stdlib.h>
#include "iterator_internal.h"
#include "qpol_internal.h"
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/hashtab.h>

typedef struct filename_trans_state
{
	unsigned int bucket;
	hashtab_ptr_t cur_item;
	filename_trans_t *cur;
} filename_trans_state_t;

static int filename_trans_state_end(const qpol_iterator_t * iter)
{
	filename_trans_state_t *fts = NULL;

	if (!iter || !(fts = qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	return fts->cur ? 0 : 1;
}

static void *filename_trans_state_get_cur(const qpol_iterator_t * iter)
{
	filename_trans_state_t *fts = NULL;
	const policydb_t *db = NULL;

	if (!iter || !(fts = qpol_iterator_state(iter)) || !(db = qpol_iterator_policy(iter)) || filename_trans_state_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	return fts->cur;
}

static int filename_trans_state_next(qpol_iterator_t * iter)
{
	filename_trans_state_t *fts = NULL;
	const policydb_t *db = NULL;

	if (!iter || !(fts = qpol_iterator_state(iter)) || !(db = qpol_iterator_policy(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (filename_trans_state_end(iter)) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	fts->cur_item = fts->cur_item->next;
	while (fts->cur_item == NULL) {
		fts->bucket++;
		if (fts->bucket >= db->filename_trans->size) {
            break;
		}

		fts->cur_item = db->filename_trans->htable[fts->bucket];
	}

    if (fts->cur_item == NULL) {
        fts->cur = NULL;
    } else {
        fts->cur = (filename_trans_t*)fts->cur_item->key;
    }

	return STATUS_SUCCESS;
}

static size_t filename_trans_state_size(const qpol_iterator_t * iter)
{
	filename_trans_state_t *fts = NULL;
	const policydb_t *db = NULL;
	size_t count = 0;
    unsigned int i = 0;

	if (!iter || !(fts = qpol_iterator_state(iter)) || !(db = qpol_iterator_policy(iter))) {
		errno = EINVAL;
		return 0;
	}

	hashtab_ptr_t cur = NULL;
	for (i = 0; i < db->filename_trans->size; i++) {
		cur = db->filename_trans->htable[i];
		while (cur != NULL) {
			count++;
			cur = cur->next;
		}
	}

	return count;
}

int qpol_policy_get_filename_trans_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
{
	policydb_t *db = NULL;
	filename_trans_state_t *fts = NULL;
	int error = 0;

	if (iter)
		*iter = NULL;

	if (!policy || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	fts = calloc(1, sizeof(filename_trans_state_t));
	if (!fts) {
		/* errno set by calloc */
		ERR(policy, "%s", strerror(errno));
		return STATUS_ERR;
	}

	fts->bucket = 0;
	fts->cur_item = db->filename_trans->htable[0];
	fts->cur = NULL;

	fts->cur_item = db->filename_trans->htable[fts->bucket];
	while (fts->cur_item == NULL) {
		fts->bucket++;
		if (fts->bucket >= db->filename_trans->size) {
			break;
		}

		fts->cur_item = db->filename_trans->htable[fts->bucket];
	}

	if (fts->cur_item != NULL) {
		fts->cur = (filename_trans_t*)fts->cur_item->key;
	}
	
	if (qpol_iterator_create
	    (policy, (void *)fts, filename_trans_state_get_cur, filename_trans_state_next, filename_trans_state_end, filename_trans_state_size,
	     free, iter)) {
		error = errno;
		free(fts);
		errno = error;
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_filename_trans_get_source_type(const qpol_policy_t * policy, const qpol_filename_trans_t * rule, const qpol_type_t ** source)
{
	policydb_t *db = NULL;
	filename_trans_t *ft = NULL;

	if (source) {
		*source = NULL;
	}

	if (!policy || !rule || !source) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	ft = (filename_trans_t *) rule;

	*source = (qpol_type_t *) db->type_val_to_struct[ft->stype - 1];

	return STATUS_SUCCESS;
}

int qpol_filename_trans_get_target_type(const qpol_policy_t * policy, const qpol_filename_trans_t * rule, const qpol_type_t ** target)
{
	policydb_t *db = NULL;
	filename_trans_t *ft = NULL;

	if (target) {
		*target = NULL;
	}

	if (!policy || !rule || !target) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	ft = (filename_trans_t *) rule;

	*target = (qpol_type_t *) db->type_val_to_struct[ft->ttype - 1];

	return STATUS_SUCCESS;
}

int qpol_filename_trans_get_object_class(const qpol_policy_t * policy, const qpol_filename_trans_t * rule,
						const qpol_class_t ** obj_class)
{
	policydb_t *db = NULL;
	filename_trans_t *ft = NULL;

	if (obj_class) {
		*obj_class = NULL;
	}

	if (!policy || !rule || !obj_class) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	ft = (filename_trans_t *) rule;

	*obj_class = (qpol_class_t *) db->class_val_to_struct[ft->tclass - 1];

	return STATUS_SUCCESS;
}

int qpol_filename_trans_get_default_type(const qpol_policy_t * policy, const qpol_filename_trans_t * rule, const qpol_type_t ** dflt)
{
	policydb_t *db = NULL;
	filename_trans_t *ft = NULL;

	if (dflt) {
		*dflt = NULL;
	}

	if (!policy || !rule || !dflt) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	ft = (filename_trans_t *) rule;

	/* Since the filename_trans rules were converted to being stored in a hashtab, otype was moved to the datum of the hashtab.
	 * So we just look it up here.
	 */
	filename_trans_datum_t *datum = hashtab_search(db->filename_trans, (hashtab_key_t)ft);

	if (datum == NULL) {
		return STATUS_ERR;
	}

	*dflt = (qpol_type_t *) db->type_val_to_struct[datum->otype - 1];

	return STATUS_SUCCESS;
}

int qpol_filename_trans_get_filename(const qpol_policy_t * policy, const qpol_filename_trans_t * rule, const char ** name)
{
	filename_trans_t *ft = NULL;

	if (name) {
		*name = NULL;
	}

	if (!policy || !rule || !name) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	ft = (filename_trans_t *) rule;

	*name = ft->name;

	return STATUS_SUCCESS;
}

