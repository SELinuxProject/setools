/**
 *  @file
 *  Defines the public interface the QPol policy.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Brandon Whalen bwhalen@tresys.com
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

#include "qpol_internal.h"
#include <assert.h>
#include <byteswap.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

#ifdef DARWIN
# include <qpol/linux_types.h>
# include <machine/endian.h>
# include <sys/types.h>
#else
# include <endian.h>
# include <asm/types.h>
#endif

#include <sepol/debug.h>
#include <sepol/handle.h>
#include <sepol/policydb/flask_types.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb.h>
#include <sepol/module.h>
#include <sepol/policydb/module.h>
#include <sepol/policydb/avrule_block.h>

#include <stdbool.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <qpol/policy_extend.h>
#include "iterator_internal.h"

extern policydb_t *policydbp;
extern int mlspol;
extern int xenpol;

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le16(x) (x)
#define le16_to_cpu(x) (x)
#define cpu_to_le32(x) (x)
#define le32_to_cpu(x) (x)
#define cpu_to_le64(x) (x)
#define le64_to_cpu(x) (x)
#else
#define cpu_to_le16(x) bswap_16(x)
#define le16_to_cpu(x) bswap_16(x)
#define cpu_to_le32(x) bswap_32(x)
#define le32_to_cpu(x) bswap_32(x)
#define cpu_to_le64(x) bswap_64(x)
#define le64_to_cpu(x) bswap_64(x)
#endif

/* buffer for reading from file */
typedef struct fbuf
{
	char *buf;
	size_t sz;
	int err;
} qpol_fbuf_t;

__attribute__ ((format(printf, 4, 0)))
static void qpol_handle_route_to_callback(void *varg
					  __attribute__ ((unused)), const qpol_policy_t * p, int level, const char *fmt,
					  va_list va_args)
{
    char *msg;

    if (vasprintf(&msg, fmt, va_args) < 0)
        return;

	if (!p || !(p->fn)) {
		fprintf(stderr, "%s\n", msg);
	} else {
	    p->fn(p->varg, p, level, msg);
	}

	free(msg);
}

__attribute__ ((format(printf, 3, 4)))
static void sepol_handle_route_to_callback(void *varg, sepol_handle_t * sh, const char *fmt, ...)
{
	va_list ap;
	qpol_policy_t *p = varg;

	if (!sh) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fprintf(stderr, "\n");
		return;
	}

	va_start(ap, fmt);
	qpol_handle_route_to_callback(NULL, p, sepol_msg_get_level(sh), fmt, ap);
	va_end(ap);
}

__attribute__ ((format(printf, 3, 4)))
void qpol_handle_msg(const qpol_policy_t * p, int level, const char *fmt, ...)
{
	va_list ap;

	if (!p) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fprintf(stderr, "\n");
		return;
	}

	va_start(ap, fmt);
	/* explicit cast here to remove const for sepol handle */
	qpol_handle_route_to_callback((void *)p->varg, p, level, fmt, ap);
	va_end(ap);
}

static int qpol_init_fbuf(qpol_fbuf_t ** fb)
{
	if (fb == NULL)
		return -1;
	*fb = (qpol_fbuf_t *) malloc(sizeof(qpol_fbuf_t));
	if (*fb == NULL)
		return -1;
	(*fb)->buf = NULL;
	(*fb)->sz = 0;
	(*fb)->err = 0;
	return 0;
}

static void qpol_free_fbuf(qpol_fbuf_t ** fb)
{
	if (*fb == NULL)
		return;
	if ((*fb)->sz > 0 && (*fb)->buf != NULL)
		free((*fb)->buf);
	free(*fb);
	return;
}

static void *qpol_read_fbuf(qpol_fbuf_t * fb, size_t bytes, FILE * fp)
{
	size_t sz;

	assert(fb != NULL && fp != NULL);
	assert(!(fb->sz > 0 && fb->buf == NULL));

	if (fb->sz == 0) {
		fb->buf = (char *)malloc(bytes + 1);
		fb->sz = bytes + 1;
	} else if (bytes + 1 > fb->sz) {
		fb->buf = (char *)realloc(fb->buf, bytes + 1);
		fb->sz = bytes + 1;
	}

	if (fb->buf == NULL) {
		fb->err = -1;
		return NULL;
	}

	sz = fread(fb->buf, bytes, 1, fp);
	if (sz != 1) {
		fb->err = -3;
		return NULL;
	}
	fb->err = 0;
	return fb->buf;
}

int qpol_binpol_version(FILE * fp)
{
	__u32 *buf;
	int rt, len;
	qpol_fbuf_t *fb;

	if (fp == NULL)
		return -1;

	if (qpol_init_fbuf(&fb) != 0)
		return -1;

	/* magic # and sz of policy string */
	buf = qpol_read_fbuf(fb, sizeof(__u32) * 2, fp);
	if (buf == NULL) {
		rt = fb->err;
		goto err_return;
	}
	buf[0] = le32_to_cpu(buf[0]);
	if (buf[0] != SELINUX_MAGIC) {
		rt = -2;
		goto err_return;
	}

	len = le32_to_cpu(buf[1]);
	if (len < 0) {
		rt = -3;
		goto err_return;
	}
	/* skip over the policy string */
	if (fseek(fp, sizeof(char) * len, SEEK_CUR) != 0) {
		rt = -3;
		goto err_return;
	}

	/* Read the version, config, and table sizes. */
	buf = qpol_read_fbuf(fb, sizeof(__u32) * 1, fp);
	if (buf == NULL) {
		rt = fb->err;
		goto err_return;
	}
	buf[0] = le32_to_cpu(buf[0]);

	rt = buf[0];
      err_return:
	rewind(fp);
	qpol_free_fbuf(&fb);
	return rt;
}

int qpol_is_file_binpol(FILE * fp)
{
	int rt;
	size_t sz;
	__u32 ubuf;

	sz = fread(&ubuf, sizeof(__u32), 1, fp);
	if (sz != 1)
		rt = 0;

	ubuf = le32_to_cpu(ubuf);
	if (ubuf == SELINUX_MAGIC)
		rt = 1;
	else
		rt = 0;
	rewind(fp);
	return rt;
}

/**
 * @brief Internal version of qpol_policy_open_from_file() version 1.3
 *
 * Implementation of the exported function qpol_policy_open_from_file()
 * for version 1.3; this symbol name is not exported.
 * @see qpol_policy_open_from_file()
 */
int qpol_policy_open_from_file(const char *path, qpol_policy_t ** policy, qpol_callback_fn_t fn, void *varg, const int options)
{
	int error = 0, retv = -1;
	FILE *infile = NULL;
	sepol_policy_file_t *pfile = NULL;
	int fd = 0;
	struct stat sb;

	if (policy != NULL)
		*policy = NULL;

	if (path == NULL || policy == NULL || fn == NULL) {
		/* handle passed as NULL here as it has yet to be created */
		ERR(NULL, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

    errno = 0;
	if (!(*policy = calloc(1, sizeof(qpol_policy_t)))) {
		error = errno;
		ERR(NULL, "%s", strerror(error));
		goto err;
	}
	(*policy)->options = options;

	/* QPOL_POLICY_OPTION_NO_RULES implies QPOL_POLICY_OPTION_NO_NEVERALLOWS */
	if ((*policy)->options & QPOL_POLICY_OPTION_NO_RULES)
		(*policy)->options |= QPOL_POLICY_OPTION_NO_NEVERALLOWS;

	(*policy)->sh = sepol_handle_create();
	if ((*policy)->sh == NULL) {
		error = errno;
		ERR(*policy, "%s", strerror(error));
		errno = error;
		return -1;
	}

	(*policy)->fn = fn;
	(*policy)->varg = varg;

	sepol_msg_set_callback((*policy)->sh, sepol_handle_route_to_callback, (*policy));

	if (sepol_policydb_create(&((*policy)->p))) {
		error = errno;
		goto err;
	}

	if (sepol_policy_file_create(&pfile)) {
		error = errno;
		goto err;
	}

	infile = fopen(path, "rb");
	if (infile == NULL) {
		error = errno;
		goto err;
	}

	sepol_policy_file_set_handle(pfile, (*policy)->sh);

    errno=0;
	if (qpol_is_file_binpol(infile)) {
		(*policy)->type = retv = QPOL_POLICY_KERNEL_BINARY;
		sepol_policy_file_set_fp(pfile, infile);
		if (sepol_policydb_read((*policy)->p, pfile)) {
//			error = EIO;
			goto err;
		}
		/* By definition, binary policy cannot have neverallow rules and all other rules are always loaded. */
		(*policy)->options |= QPOL_POLICY_OPTION_NO_NEVERALLOWS;
		(*policy)->options &= ~(QPOL_POLICY_OPTION_NO_RULES);
		if (policy_extend(*policy)) {
			error = errno;
			goto err;
		}
	} else {
        error = EINVAL;
        goto err;
	}

	fclose(infile);
	sepol_policy_file_free(pfile);
	return retv;

      err:
	qpol_policy_destroy(policy);
	sepol_policy_file_free(pfile);
	if (infile)
		fclose(infile);
	errno = error;
	return -1;
}


void qpol_policy_destroy(qpol_policy_t ** policy)
{
	if (policy != NULL && *policy != NULL) {
		sepol_policydb_free((*policy)->p);
		sepol_handle_destroy((*policy)->sh);
		if ((*policy)->file_data_type == QPOL_POLICY_FILE_DATA_TYPE_MEM) {
			free((*policy)->file_data);
		} else if ((*policy)->file_data_type == QPOL_POLICY_FILE_DATA_TYPE_MMAP) {
			munmap((*policy)->file_data, (*policy)->file_data_sz);
		}
		free(*policy);
		*policy = NULL;
	}
}

static int is_mls_policy(const qpol_policy_t * policy)
{
	policydb_t *db = NULL;

	if (policy == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	if (db->mls != 0)
		return 1;
	else
		return 0;
}

int qpol_policy_is_mls_enabled(qpol_policy_t * policy)
{
	return is_mls_policy(policy);
}

int qpol_policy_get_policy_version(const qpol_policy_t * policy, unsigned int *version)
{
	policydb_t *db;

	if (version != NULL)
		*version = 0;

	if (policy == NULL || version == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	*version = db->policyvers;

	return STATUS_SUCCESS;
}

int qpol_policy_get_policy_handle_unknown(const qpol_policy_t * policy, unsigned int *handle_unknown)
{
	policydb_t *db;

	if (handle_unknown != NULL)
		*handle_unknown = 0;

	if (policy == NULL || handle_unknown == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	*handle_unknown = db->handle_unknown;

	return STATUS_SUCCESS;
}

int qpol_policy_get_target_platform(const qpol_policy_t *policy,
					    int *target_platform)
{
	policydb_t *db;

	if (target_platform != NULL)
		*target_platform = 0;

	if (policy == NULL || target_platform == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	*target_platform = db->target_platform;

	return STATUS_SUCCESS;
}

int qpol_policy_get_type(const qpol_policy_t * policy, int *type)
{
	if (!policy || !type) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	*type = policy->type;

	return STATUS_SUCCESS;
}

int qpol_policy_has_capability(const qpol_policy_t * policy, qpol_capability_e cap)
{
	unsigned int version = 0;

	if (!policy) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return 0;
	}

	qpol_policy_get_policy_version(policy, &version);

	switch (cap) {
	case QPOL_CAP_ATTRIB_NAMES:
	{
		if ((policy->type == QPOL_POLICY_KERNEL_SOURCE || policy->type == QPOL_POLICY_MODULE_BINARY) || (version >= 24))
			return 1;
		break;
	}
	case QPOL_CAP_SYN_RULES:
	{
		if (policy->type == QPOL_POLICY_KERNEL_SOURCE || policy->type == QPOL_POLICY_MODULE_BINARY)
			return 1;
		break;
	}
	case QPOL_CAP_LINE_NUMBERS:
	{
		if (policy->type == QPOL_POLICY_KERNEL_SOURCE)
			return 1;
		break;
	}
	case QPOL_CAP_CONDITIONALS:
	{
		if (version >= 16 || policy->type == QPOL_POLICY_MODULE_BINARY)
			return 1;
		break;
	}
	case QPOL_CAP_MLS:
	{
		return is_mls_policy(policy);
	}
	case QPOL_CAP_MODULES:
	{
		if (policy->type == QPOL_POLICY_MODULE_BINARY)
			return 1;
		break;
	}
	case QPOL_CAP_POLCAPS:
	{
		if (version >= 22 && policy->type != QPOL_POLICY_MODULE_BINARY)
			return 1;
		if (version >= 7 && policy->type == QPOL_POLICY_MODULE_BINARY)
			return 1;
		break;
	}
	case QPOL_CAP_BOUNDS:
	{
		if (version >= 24 && policy->type != QPOL_POLICY_MODULE_BINARY)
			return 1;
		if (version >= 9 && policy->type == QPOL_POLICY_MODULE_BINARY)
			return 1;
		break;
	}
	case QPOL_CAP_PERMISSIVE:
	{
		if (version >= 23 && policy->type != QPOL_POLICY_MODULE_BINARY)
			return 1;
		if (version >= 8 && policy->type == QPOL_POLICY_MODULE_BINARY)
			return 1;
		break;
	}
	case QPOL_CAP_FILENAME_TRANS:
	{
		if (version >= 25 && policy->type != QPOL_POLICY_MODULE_BINARY)
			return 1;
		if (version >= 11 && policy->type == QPOL_POLICY_MODULE_BINARY)
			return 1;
		break;
	}
	case QPOL_CAP_ROLETRANS:
	{
		if (version >= 26 && policy->type != QPOL_POLICY_MODULE_BINARY)
			return 1;
		if (version >= 12 && policy->type == QPOL_POLICY_MODULE_BINARY)
			return 1;
		break;
	}
	/* This indicates the user, role and range - types were ate 28/16 */
	case QPOL_CAP_DEFAULT_OBJECTS:
	{
		if (version >= 27 && policy->type != QPOL_POLICY_MODULE_BINARY)
			return 1;
		if (version >= 15 && policy->type == QPOL_POLICY_MODULE_BINARY)
			return 1;
		break;
	}
	case QPOL_CAP_DEFAULT_TYPE:
	{
		if (version >= 28 && policy->type != QPOL_POLICY_MODULE_BINARY)
			return 1;
		if (version >= 16 && policy->type == QPOL_POLICY_MODULE_BINARY)
			return 1;
		break;
	}
	case QPOL_CAP_XPERM_IOCTL:
	{
		if (version >= 30 && policy->type != QPOL_POLICY_MODULE_BINARY)
			return 1;
		if (version >= 17 && policy->type == QPOL_POLICY_MODULE_BINARY)
			return 1;
		break;
	}
	case QPOL_CAP_RULES_LOADED:
	{
		if (!(policy->options & QPOL_POLICY_OPTION_NO_RULES))
			return 1;
		break;
	}
	case QPOL_CAP_SOURCE:
	{
		if (policy->type == QPOL_POLICY_KERNEL_SOURCE)
			return 1;
		break;
	}
	case QPOL_CAP_NEVERALLOW:
	{
		if (!(policy->options & QPOL_POLICY_OPTION_NO_NEVERALLOWS) && policy->type != QPOL_POLICY_KERNEL_BINARY)
			return 1;
		break;
	}
	default:
	{
		ERR(policy, "%s", "Unknown capability");
		errno = EDOM;
		break;
	}
	}
	return 0;
}
