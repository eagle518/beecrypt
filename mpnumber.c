/*
 * Copyright (c) 2003 Bob Deblier
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

/*!\file mpnumber.c
 * \brief Multi-precision numbers.
 * \author Bob Deblier <bob.deblier@pandora.be>
 * \ingroup MP_m
 */

#define BEECRYPT_DLL_EXPORT

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "mpnumber.h"

void mpnzero(mpnumber* n)
{
	n->size = 0;
	n->data = (mpw*) 0;
}

void mpnsize(mpnumber* n, size_t size)
{
	if (size)
	{
		if (n->data)
		{
			if (n->size != size)
				n->data = (mpw*) realloc(n->data, size * sizeof(mpw));
		}
		else
			n->data = (mpw*) malloc(size * sizeof(mpw));

		if (n->data == (mpw*) 0)
			n->size = 0;
		else
			n->size = size;

	}
	else if (n->data)
	{
		free(n->data);
		n->data = (mpw*) 0;
		n->size = 0;
	}
}

void mpninit(mpnumber* n, size_t size, const mpw* data)
{
	n->size = size;
	n->data = (mpw*) malloc(size * sizeof(mpw));

	if (n->data)
		mpcopy(size, n->data, data);
}

void mpnfree(mpnumber* n)
{
	if (n->data)
	{
		free(n->data);
		n->data = (mpw*) 0;
	}
	n->size = 0;
}

void mpncopy(mpnumber* n, const mpnumber* copy)
{
	mpnset(n, copy->size, copy->data);
}

void mpnwipe(mpnumber* n)
{
	if (n->data != (mpw*) 0)
		mpzero(n->size, n->data);
}

void mpnset(mpnumber* n, size_t size, const mpw* data)
{
	if (size)
	{
		if (n->data)
		{
			if (n->size != size)
				n->data = (mpw*) realloc(n->data, size * sizeof(mpw));
		}
		else
			n->data = (mpw*) malloc(size * sizeof(mpw));

		if (n->data)
			mpcopy(n->size = size, n->data, data);
		else
			n->size = 0;
	}
	else if (n->data)
	{
		free(n->data);
		n->data = (mpw*) 0;
		n->size = 0;
	}
}

void mpnsetw(mpnumber* n, mpw val)
{
	if (n->data)
	{
		if (n->size != 1)
			n->data = (mpw*) realloc(n->data, sizeof(mpw));
	}
	else
		n->data = (mpw*) malloc(sizeof(mpw));

	if (n->data)
	{
		n->size = 1;
		n->data[0] = val;
	}
	else
		n->size = 0;
}

void mpnsethex(mpnumber* n, const char* hex)
{
	register size_t len = strlen(hex);
	register size_t size = MP_NIBBLES_TO_WORDS(len + MP_WNIBBLES - 1);

	if (n->data)
	{
		if (n->size != size)
			n->data = (mpw*) realloc(n->data, size * sizeof(mpw));
	}
	else
		n->data = (mpw*) malloc(size * sizeof(mpw));

	if (n->data)
	{
		n->size = size;

		hs2ip(n->data, size, hex, len);
	}
	else
		n->size = 0;
}

int mpninv(mpnumber* inv, const mpnumber* k, const mpnumber* mod)
{
	int rc = 0;
	size_t size = mod->size;
	mpw* wksp = (mpw*) malloc((7*size+6) * sizeof(mpw));

	if (wksp)
	{
		mpnsize(inv, size);
		mpsetx(size, wksp, k->size, k->data);
		rc = mpextgcd_w(size, wksp, mod->data, inv->data, wksp+size);
		free(wksp);
	}

	return rc;
}
