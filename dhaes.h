/*
 * dhaes.h
 *
 * DHAES, header
 *
 * Copyright (c) 2000, 2001 Virtual Unlimited, B.V.
 *
 * Author: Bob Deblier <bob@virtualunlimited.com>
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
 
#ifndef _DHAES_H
#define _DHAES_H
 
#include "beecrypt.h"
#include "dldp.h"

typedef struct
{
	const dldp_p*				param;
	const hashFunction*			hash;
	const blockCipher*			cipher;
	const keyedHashFunction*	mac;
	int							cipherkeybits;
	int							mackeybits;
} dhaes_pParameters;

typedef struct
{
	dldp_p						param;
	mp32number					pub;
	mp32number					pri;
	hashFunctionContext			hash;
	blockCipherContext			cipher;
	keyedHashFunctionContext	mac;
	int							cipherkeybits;
	int							mackeybits;
} dhaes_pContext;

BEEDLLAPI
int dhaes_pUsable(const dhaes_pParameters*);

BEEDLLAPI
int dhaes_pContextInit       (dhaes_pContext*, const dhaes_pParameters*);
BEEDLLAPI
int dhaes_pContextInitDecrypt(dhaes_pContext*, const dhaes_pParameters*, const mp32number*);
BEEDLLAPI
int dhaes_pContextInitEncrypt(dhaes_pContext*, const dhaes_pParameters*, const mp32number*);
BEEDLLAPI
int dhaes_pContextFree       (dhaes_pContext*);

BEEDLLAPI
memchunk* dhaes_pContextEncrypt(dhaes_pContext*,       mp32number*,       mp32number*, const memchunk*, randomGeneratorContext*);
BEEDLLAPI
memchunk* dhaes_pContextDecrypt(dhaes_pContext*, const mp32number*, const mp32number*, const memchunk*);

#endif
