/**
 *  @file
 *  Defines the public interface for searching and iterating over
 *  Xen statements.
 *
 *  @author Richard Haines richard_c_haines@btinternet.com
 *  Derived from portcon_query.c
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

#include <config.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <qpol/context_query.h>
#include <qpol/xen_query.h>
#include <sepol/policydb/policydb.h>
#include "qpol_internal.h"
#include "iterator_internal.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

/******************************* iomemcon **************************/
int qpol_policy_get_iomemcon_by_addr(const qpol_policy_t *policy,
				    uint64_t low, uint64_t high,
				    const qpol_iomemcon_t **ocon)
{
	ocontext_t *tmp = NULL;
	policydb_t *db = NULL;

	if (ocon != NULL)
		*ocon = NULL;

	if (policy == NULL || ocon == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	for (tmp = db->ocontexts[OCON_XEN_IOMEM]; tmp; tmp = tmp->next) {
		if (tmp->u.iomem.low_iomem == low &&
					    tmp->u.iomem.high_iomem == high)
			break;
	}

	*ocon = (qpol_iomemcon_t *) tmp;

	if (*ocon == NULL) {
		ERR(policy, "could not find iomemcon statement for %" PRIu64 "-%" PRIu64,
								    low, high);
		errno = ENOENT;
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_policy_get_iomemcon_iter(const qpol_policy_t *policy,
					    qpol_iterator_t **iter)
{
	policydb_t *db = NULL;
	int error = 0;
	ocon_state_t *os = NULL;

	if (iter != NULL)
		*iter = NULL;

	if (policy == NULL || iter == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	os = calloc(1, sizeof(ocon_state_t));
	if (os == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}

	os->head = os->cur = db->ocontexts[OCON_XEN_IOMEM];

	if (qpol_iterator_create(policy, (void *)os, ocon_state_get_cur,
			    ocon_state_next, ocon_state_end, ocon_state_size,
			    free, iter)) {
		free(os);
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_iomemcon_get_low_addr(const qpol_policy_t *policy,
				    const qpol_iomemcon_t *ocon,
				    uint64_t *addr)
{
	ocontext_t *internal_ocon = NULL;

	if (addr != NULL)
		*addr = 0;

	if (policy == NULL || ocon == NULL || addr == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;

	*addr = internal_ocon->u.iomem.low_iomem;

	return STATUS_SUCCESS;
}

int qpol_iomemcon_get_high_addr(const qpol_policy_t *policy,
					    const qpol_iomemcon_t *ocon,
					    uint64_t *addr)
{
	ocontext_t *internal_ocon = NULL;

	if (addr != NULL)
		*addr = 0;

	if (policy == NULL || ocon == NULL || addr == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;

	*addr = internal_ocon->u.iomem.high_iomem;

	return STATUS_SUCCESS;
}

int qpol_iomemcon_get_context(const qpol_policy_t *policy,
					    const qpol_iomemcon_t *ocon,
					    const qpol_context_t **context)
{
	ocontext_t *internal_ocon = NULL;

	if (context != NULL)
		*context = NULL;

	if (policy == NULL || ocon == NULL || context == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;
	*context = (qpol_context_t *) &(internal_ocon->context[0]);

	return STATUS_SUCCESS;
}


/******************************* ioportcon **************************/
int qpol_policy_get_ioportcon_by_port(const qpol_policy_t *policy,
				    uint32_t low, uint32_t high,
				    const qpol_ioportcon_t **ocon)
{
	ocontext_t *tmp = NULL;
	policydb_t *db = NULL;

	if (ocon != NULL)
		*ocon = NULL;

	if (policy == NULL || ocon == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	for (tmp = db->ocontexts[OCON_XEN_IOPORT]; tmp; tmp = tmp->next) {
		if (tmp->u.ioport.low_ioport == low &&
					    tmp->u.ioport.high_ioport == high)
			break;
	}

	*ocon = (qpol_ioportcon_t *) tmp;

	if (*ocon == NULL) {
		ERR(policy, "could not find ioportcon statement for %u-%u",
								    low, high);
		errno = ENOENT;
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_policy_get_ioportcon_iter(const qpol_policy_t *policy,
					    qpol_iterator_t **iter)
{
	policydb_t *db = NULL;
	int error = 0;
	ocon_state_t *os = NULL;

	if (iter != NULL)
		*iter = NULL;

	if (policy == NULL || iter == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	os = calloc(1, sizeof(ocon_state_t));
	if (os == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}

	os->head = os->cur = db->ocontexts[OCON_XEN_IOPORT];

	if (qpol_iterator_create(policy, (void *)os, ocon_state_get_cur,
				 ocon_state_next, ocon_state_end,
					    ocon_state_size, free, iter)) {
		free(os);
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_ioportcon_get_low_port(const qpol_policy_t *policy,
					    const qpol_ioportcon_t *ocon,
					    uint32_t *port)
{
	ocontext_t *internal_ocon = NULL;

	if (port != NULL)
		*port = 0;

	if (policy == NULL || ocon == NULL || port == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;

	*port = internal_ocon->u.ioport.low_ioport;

	return STATUS_SUCCESS;
}

int qpol_ioportcon_get_high_port(const qpol_policy_t *policy,
				    const qpol_ioportcon_t *ocon,
				    uint32_t *port)
{
	ocontext_t *internal_ocon = NULL;

	if (port != NULL)
		*port = 0;

	if (policy == NULL || ocon == NULL || port == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;

	*port = internal_ocon->u.ioport.high_ioport;

	return STATUS_SUCCESS;
}

int qpol_ioportcon_get_context(const qpol_policy_t *policy,
				    const qpol_ioportcon_t *ocon,
				    const qpol_context_t **context)
{
	ocontext_t *internal_ocon = NULL;

	if (context != NULL)
		*context = NULL;

	if (policy == NULL || ocon == NULL || context == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;
	*context = (qpol_context_t *) &(internal_ocon->context[0]);

	return STATUS_SUCCESS;
}


/******************************* pcidevicecon **************************/
int qpol_policy_get_pcidevicecon_iter(const qpol_policy_t *policy,
					     qpol_iterator_t **iter)
{
	policydb_t *db = NULL;
	int error = 0;
	ocon_state_t *os = NULL;

	if (iter != NULL)
		*iter = NULL;

	if (policy == NULL || iter == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	os = calloc(1, sizeof(ocon_state_t));
	if (os == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}

	os->head = os->cur = db->ocontexts[OCON_XEN_PCIDEVICE];

	if (qpol_iterator_create(policy, (void *)os, ocon_state_get_cur,
				    ocon_state_next, ocon_state_end,
				    ocon_state_size, free, iter)) {
		free(os);
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_pcidevicecon_get_device(const qpol_policy_t *policy,
					    const qpol_pcidevicecon_t *ocon,
					    uint32_t *device)
{
	ocontext_t *internal_ocon = NULL;

	if (device != NULL)
		*device = 0;

	if (policy == NULL || ocon == NULL || device == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;

	*device = internal_ocon->u.device;

	return STATUS_SUCCESS;
}

int qpol_pcidevicecon_get_context(const qpol_policy_t *policy,
				    const qpol_pcidevicecon_t *ocon,
				    const qpol_context_t **context)
{
	ocontext_t *internal_ocon = NULL;

	if (context != NULL)
		*context = NULL;

	if (policy == NULL || ocon == NULL || context == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;
	*context = (qpol_context_t *) &(internal_ocon->context[0]);

	return STATUS_SUCCESS;
}


/******************************* pirqcon **************************/
int qpol_policy_get_pirqcon_iter(const qpol_policy_t *policy,
					    qpol_iterator_t **iter)
{
	policydb_t *db = NULL;
	int error = 0;
	ocon_state_t *os = NULL;

	if (iter != NULL)
		*iter = NULL;

	if (policy == NULL || iter == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	os = calloc(1, sizeof(ocon_state_t));
	if (os == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}

	os->head = os->cur = db->ocontexts[OCON_XEN_PIRQ];

	if (qpol_iterator_create(policy, (void *)os, ocon_state_get_cur,
					    ocon_state_next, ocon_state_end,
					    ocon_state_size, free, iter)) {
		free(os);
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_pirqcon_get_irq(const qpol_policy_t *policy,
				    const qpol_pirqcon_t *ocon,
				    uint16_t *irq)
{
	ocontext_t *internal_ocon = NULL;

	if (irq != NULL)
		*irq = 0;

	if (policy == NULL || ocon == NULL || irq == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;

	*irq = internal_ocon->u.pirq;

	return STATUS_SUCCESS;
}

int qpol_pirqcon_get_context(const qpol_policy_t *policy,
				    const qpol_pirqcon_t *ocon,
				    const qpol_context_t **context)
{
	ocontext_t *internal_ocon = NULL;

	if (context != NULL)
		*context = NULL;

	if (policy == NULL || ocon == NULL || context == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;
	*context = (qpol_context_t *) &(internal_ocon->context[0]);

	return STATUS_SUCCESS;
}

/******************************* devicetreecon **************************/

int qpol_policy_get_devicetreecon_iter(const qpol_policy_t *policy,
					    qpol_iterator_t **iter)
{
	policydb_t *db = NULL;
	ocon_state_t *os = NULL;
	int error = 0;

	if (iter != NULL)
		*iter = NULL;

	if (policy == NULL || iter == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	os = calloc(1, sizeof(ocon_state_t));
	if (os == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}

	os->head = os->cur = db->ocontexts[OCON_XEN_DEVICETREE];
	if (qpol_iterator_create(policy, (void *)os, ocon_state_get_cur,
					    ocon_state_next, ocon_state_end,
					    ocon_state_size, free, iter)) {
		free(os);
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_devicetreecon_get_path(const qpol_policy_t *policy,
					    const qpol_devicetreecon_t *ocon,
					    char **path)
{
	ocontext_t *internal_ocon = NULL;

	if (path != NULL)
		*path = NULL;

	if (policy == NULL || ocon == NULL || path == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;

	*path = internal_ocon->u.name;

	return STATUS_SUCCESS;
}

int qpol_devicetreecon_get_context(const qpol_policy_t *policy,
					    const qpol_devicetreecon_t *ocon,
					    const qpol_context_t **context)
{
	ocontext_t *internal_ocon = NULL;

	if (context != NULL)
		*context = NULL;

	if (policy == NULL || ocon == NULL || context == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;
	*context = (qpol_context_t *) &(internal_ocon->context[0]);

	return STATUS_SUCCESS;
}
