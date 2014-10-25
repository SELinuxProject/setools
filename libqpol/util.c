/**
 * @file
 *
 * Implementation of utility functions.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006-2008 Tresys Technology, LLC
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

#include <qpol/util.h>

#include <glob.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <selinux/selinux.h>

const char *libqpol_get_version(void)
{
	return LIBQPOL_VERSION_STRING;
}

static int search_policy_source_file(char **path)
{
	int error;
	char *source_path;
	if (asprintf(&source_path, "%s/src/policy/policy.conf", selinux_policy_root()) < 0) {
		return -1;
	}
	if (access(source_path, R_OK) < 0) {
		error = errno;
		free(source_path);
		errno = error;
		return 1;
	}
	*path = source_path;
	return 0;
}

static int get_binpol_version(const char *policy_fname)
{
	FILE *policy_fp = NULL;
	int ret_version, error;

	policy_fp = fopen(policy_fname, "r");
	if (policy_fp == NULL) {
		return -1;
	}
	if (!qpol_is_file_binpol(policy_fp)) {
		error = errno;
		fclose(policy_fp);
		errno = error;
		return -1;
	}
	ret_version = qpol_binpol_version(policy_fp);
	fclose(policy_fp);
	return ret_version;
}

static int search_policy_binary_file(char **path)
{
	const char *binary_path;
	if ((binary_path = selinux_binary_policy_path()) == NULL) {
		return -1;
	}

	int expected_version = -1, latest_version = -1;
#ifdef LIBSELINUX
	/* if the system has SELinux enabled, prefer the policy whose
	   name matches the current policy version */
	if ((expected_version = security_policyvers()) < 0) {
		return -1;
	}
#endif

	glob_t glob_buf;
	struct stat fs;
	int rt, error = 0, retval = -1;
	size_t i;
	char *pattern = NULL;
	if (asprintf(&pattern, "%s.*", binary_path) < 0) {
		return -1;
	}
	glob_buf.gl_offs = 1;
	glob_buf.gl_pathc = 0;
	rt = glob(pattern, GLOB_DOOFFS, NULL, &glob_buf);
	if (rt != 0 && rt != GLOB_NOMATCH) {
		errno = EIO;
		return -1;
	}

	for (i = 0; i < glob_buf.gl_pathc; i++) {
		char *p = glob_buf.gl_pathv[i + glob_buf.gl_offs];
		if (stat(p, &fs) != 0) {
			error = errno;
			goto cleanup;
		}
		if (S_ISDIR(fs.st_mode))
			continue;

		if ((rt = get_binpol_version(p)) < 0) {
			error = errno;
			goto cleanup;
		}

		if (rt > latest_version || rt == expected_version) {
			free(*path);
			if ((*path = strdup(p)) == NULL) {
				error = errno;
				goto cleanup;
			}
			if (rt == expected_version) {
				break;
			}
			latest_version = rt;
		}
	}

	if (*path == NULL) {
		retval = 1;
	} else {
		retval = 0;
	}
      cleanup:
	free(pattern);
	globfree(&glob_buf);
	if (retval == -1) {
		errno = error;
	}
	return retval;
}

int qpol_default_policy_find(char **path)
{
	int rt;
	if (path == NULL) {
		errno = EINVAL;
		return -1;
	}
	*path = NULL;
	/* Try default source policy first as a source policy contains
	 * more useful information. */
	if ((rt = search_policy_source_file(path)) <= 0) {
		return rt;
	}
	/* Try a binary policy */
	return search_policy_binary_file(path);
}

#include <stdlib.h>
#include <bzlib.h>
#include <string.h>
#include <sys/sendfile.h>

#define BZ2_MAGICSTR "BZh"
#define BZ2_MAGICLEN (sizeof(BZ2_MAGICSTR)-1)

/* qpol_bunzip() uncompresses a file to '*data', returning the total number of
 * uncompressed bytes in the file.
 * Returns -1 if file could not be decompressed.
 * Originally from libsemanage/src/direct_api.c, with slight mods */
ssize_t qpol_bunzip(FILE *f, char **data)
{
	BZFILE* b;
	size_t  nBuf;
	char    buf[1<<18];
	size_t  size = sizeof(buf);
	int     bzerror;
	size_t  total=0;
	int		small=0;	// Set to 1 to use less memory decompressing (about 2x slower)

	bzerror = fread(buf, 1, BZ2_MAGICLEN, f);
	rewind(f);
	if ((bzerror != BZ2_MAGICLEN) || memcmp(buf, BZ2_MAGICSTR, BZ2_MAGICLEN))
		return -1;
	
	b = BZ2_bzReadOpen ( &bzerror, f, 0, small, NULL, 0 );
	if ( bzerror != BZ_OK ) {
		BZ2_bzReadClose ( &bzerror, b );
		return -1;
	}
	
	char *uncompress = realloc(NULL, size);
	
	while ( bzerror == BZ_OK) {
		nBuf = BZ2_bzRead ( &bzerror, b, buf, sizeof(buf));
		if (( bzerror == BZ_OK ) || ( bzerror == BZ_STREAM_END )) {
			if (total + nBuf > size) {
				size *= 2;
				uncompress = realloc(uncompress, size);
			}
			memcpy(&uncompress[total], buf, nBuf);
			total += nBuf;
		}
	}
	if ( bzerror != BZ_STREAM_END ) {
		BZ2_bzReadClose ( &bzerror, b );
		free(uncompress);
		return -1;
	}
	BZ2_bzReadClose ( &bzerror, b );

	*data = uncompress;
	return  total;
}

