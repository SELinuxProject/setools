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

const char *libqpol_get_version(void)
{
	return LIBQPOL_VERSION_STRING;
}

#include <stdlib.h>
#include <bzlib.h>
#include <string.h>

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

