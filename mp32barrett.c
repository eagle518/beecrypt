/*
 * mp32barrett.c
 *
 * Barrett modular reduction, code
 *
 * For more information on this algorithm, see:
 * "Handbook of Applied Cryptography", Chapter 14.3.3
 *  Menezes, van Oorschot, Vanstone
 *  CRC Press
 *
 * Copyright (c) 1997, 1998, 1999, 2000 Virtual Unlimited B.V.
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

#define BEECRYPT_DLL_EXPORT

#include "mp32.h"
#include "mp32prime.h"
#include "mp32barrett.h"

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_ALLOCA_H
#include <alloca.h>
#endif

#include <stdio.h>

void mp32bmu(mp32barrett* b)
{
	/* workspace needs to acommodate the dividend (size*2+1), and the divmod result (size*2+1) */
	register uint32  size = b->size;
	register uint32* divmod = b->mu-1; /* uses the last word of b->modl, which we made large enough */
	register uint32* dividend = divmod+(size*2+2);
	register uint32* workspace = dividend+(size*2+1);
	register uint32  shift;

	/* normalize modulus before division */
	shift = mp32norm(size, b->modl);
	/* make the dividend, initialize first word to 1 (shifted); the rest is zero */
	*dividend = (1 << shift);
	mp32zero(size*2, dividend+1);
	mp32ndivmod(divmod, size*2+1, dividend, size, b->modl, workspace);
	/* de-normalize */
	mp32rshift(size, b->modl, shift);
}

void mp32brndres(const mp32barrett* b, uint32* result, randomGeneratorContext* rc)
{
	uint32 msz = mp32mszcnt(b->size, b->modl);

	mp32copy(b->size, b->wksp, b->modl);
	mp32subw(b->size, b->wksp, 1);

	do
	{
		rc->rng->next(rc->param, result, b->size);

		result[0] &= (0xffffffff >> msz);

		while (mp32ge(b->size, result, b->wksp))
			mp32sub(b->size, result, b->wksp);
	} while (mp32leone(b->size, result));
}

void mp32brndoddres(const mp32barrett* b, uint32* result, randomGeneratorContext* rc)
{
	uint32 msz = mp32mszcnt(b->size, b->modl);

	mp32copy(b->size, b->wksp, b->modl);
	mp32subw(b->size, b->wksp, 1);

	do
	{
		rc->rng->next(rc->param, result, b->size);

		result[0] &= (0xffffffff >> msz);
		mp32setlsb(b->size, result);

		while (mp32ge(b->size, result, b->wksp))
		{
			mp32sub(b->size, result, b->wksp);
			mp32setlsb(b->size, result);
		}
	} while (mp32leone(b->size, result));
}

void mp32brndinvres(const mp32barrett* b, uint32* result, randomGeneratorContext* rc)
{
	do
	{
		if (mp32even(b->size, b->modl))
			mp32brndoddres(b, result, rc);
		else
			mp32brndres(b, result, rc);

	} while (mp32binv(b, b->size, result) == 0);
}

void mp32bmodres(const mp32barrett* b, uint32* result, const uint32* xdata)
{
	register uint32 rc;
	register uint32 sp = 2;
	register const uint32* src = xdata+b->size+1;
	register       uint32* dst = b->wksp+b->size+1;

	rc = mp32setmul(sp, dst, b->mu, *(--src));
	*(--dst) = rc;

	while (sp <= b->size)
	{
		sp++;
		if ((rc = *(--src)))
		{
			rc = mp32addmul(sp, dst, b->mu, rc);
			*(--dst) = rc;
		}
		else
			*(--dst) = 0;
	}
	if ((rc = *(--src)))
	{
		rc = mp32addmul(sp, dst, b->mu, rc);
		*(--dst) = rc;
	}
	else
		*(--dst) = 0;

	/* q3 is one word larger than b->modl */
	/* r2 is (2*size+1) words, of which we only needs the (size+1) lsw's */

	sp = b->size;
	rc = 0;

	dst = b->wksp+b->size+1;
	src = dst;

	*dst = mp32setmul(sp, dst+1, b->modl, *(--src));

	while (sp > 0)
	{
		mp32addmul(sp--, dst, b->modl+(rc++), *(--src));
	}

	mp32setx(b->size+1, b->wksp, b->size*2, xdata);
	mp32sub(b->size+1, b->wksp, b->wksp+b->size+1);
	while (mp32gex(b->size+1, b->wksp, b->size, b->modl))
	{
		mp32subx(b->size+1, b->wksp, b->size, b->modl);
	}
	mp32copy(b->size, result, b->wksp+1);
}

void mp32binit(mp32barrett* b, uint32 size)
{
	/*
	 * NOTE: consider having the mp32prime routines allocate their own memory when necessary;
	 *       this would limit the size to 3*size+2 + 4*size+2 = 7*size+4
	 * NOTE: sliding window exponentiation will also use its own storage
	 * NOTE: this memory can be allocated with either alloca (if available) or malloc.
	 */

	/* data, modulus and mu take 3*size+2 words, wksp needed = 7*size+2; total = 10*size+4 */
	b->size	= size;
	b->data	= (uint32*) calloc(size*10+4, sizeof(uint32));

	if (b->data)
	{
		b->modl = b->data+size+0;
		b->mu   = b->modl+size+1;
		b->wksp	= b->mu  +size+1;
	}
	else
	{
		b->modl = b->mu = b->wksp = (uint32*) 0;
	}
}

void mp32bzero(mp32barrett* b)
{
	b->size = 0;
	b->data = b->modl = b->mu = b->wksp = (uint32*) 0;
}

void mp32bfree(mp32barrett* b)
{
	if (b->data)
	{
		free(b->data);
		b->data = b->modl = b->mu = b->wksp = (uint32*) 0;
	}
	b->size = 0;
}

void mp32bset(mp32barrett* b, uint32 size, const uint32 *data)
{
	/* assumes that the msw of data is not zero */
	if (b->data)
		mp32bfree(b);

	if (size)
	{
		mp32binit(b, size);

		if (b->data)
		{
			mp32copy(size, b->modl, data);
			mp32bmu(b);
		}
	}
}

/* function mp32bsethex would be very useful! */

void mp32bmod(const mp32barrett* b, uint32 xsize, const uint32* xdata)
{
	register uint32  size = b->size;
	register uint32* opnd = b->wksp + size*2+2;

	mp32setx(size*2, opnd, xsize, xdata);
	mp32bmodres(b, b->data, opnd);
}

void mp32bmodsubone(const mp32barrett* b)
{
	register uint32 size = b->size;

	mp32copy(size, b->data, b->modl);
	mp32subw(size, b->data, 1);
}

void mp32bneg(const mp32barrett* b)
{
	register uint32  size = b->size;

	mp32neg(size, b->data);
	mp32add(size, b->data, b->modl);
}

void mp32baddmod(const mp32barrett* b, uint32 xsize, const uint32* xdata, uint32 ysize, const uint32* ydata)
{
	/* xsize and ysize must be less than or equal to b->size */
	register uint32  size = b->size;
	register uint32* opnd = b->wksp+size*2+2;

	mp32setx(2*size, opnd, xsize, xdata);
	mp32addx(2*size, opnd, ysize, ydata);

	mp32bmodres(b, b->data, opnd);
}

void mp32bsubmod(const mp32barrett* b, uint32 xsize, const uint32* xdata, uint32 ysize, const uint32* ydata)
{
	/* xsize and ysize must be less than or equal to b->size */
	register uint32  size = b->size;
	register uint32* opnd = b->wksp+size*2+2;
	
	mp32setx(2*size, opnd, xsize, xdata);
	if (mp32subx(2*size, opnd, ysize, ydata)) /* if there's carry, i.e. the result would be negative, add the modulus */
		mp32addx(2*size, opnd, size, b->modl);

	mp32bmodres(b, b->data, opnd);
}

void mp32bmulmodres(const mp32barrett* b, uint32* result, uint32 xsize, const uint32* xdata, uint32 ysize, const uint32* ydata)
{
	/* needs workspace of (size*2) in addition to what is needed by mp32bmodres (size*2+2) */
	/* xsize and ysize must be <= b->size */
	/* stores result in b->data */
	register uint32  size = b->size;
	register uint32  fill = 2*size-xsize-ysize;
	register uint32* opnd = b->wksp+size*2+2;

	if (fill)
		mp32zero(fill, opnd);

	mp32mul(opnd+fill, xsize, xdata, ysize, ydata);
	mp32bmodres(b, result, opnd);
}

void mp32bsqrmodres(const mp32barrett* b, uint32* result, uint32 xsize, const uint32* xdata)
{
	/* needs workspace of (size*2) in addition to what is needed by mp32bmodres (size*2+2) */
	/* xsize must be <= b->size */
	register uint32  size = b->size;
	register uint32  fill = 2*(size-xsize);
	register uint32* opnd = b->wksp + size*2+2;

	if (fill)
		mp32zero(fill, opnd);

	mp32sqr(opnd+fill, xsize, xdata);
	mp32bmodres(b, result, opnd);
}

void mp32bmulmod(const mp32barrett* b, uint32 xsize, const uint32* xdata, uint32 ysize, const uint32* ydata)
{
	mp32bmulmodres(b, b->data, xsize, xdata, ysize, ydata);
}

void mp32bsqrmod(const mp32barrett* b, uint32 xsize, const uint32* xdata)
{
	mp32bsqrmodres(b, b->data, xsize, xdata);
}

#if 0
/*
 * This algorithm will be phased out in favor of the sliding window method,
 * which is about 25% more efficient
 */

void mp32bpowmod(const mp32barrett* b, uint32 xsize, const uint32* xdata, uint32 psize, const uint32* pdata)
{
	/*
	 * Modular exponention
	 *
	 * Uses left-to-right exponentiation; needs no extra storage
	 *
	 */
	
	/* this routine calls mp32bmod, which needs (size*2+2), this routine needs (size*2) for sdata */

	register uint32  temp;

	mp32setw(b->size, b->data, 1);

	while (psize)
	{
		if ((temp = *(pdata++))) /* break when first non-zero word found */
			break;
		psize--;
	}

	/* if temp is still zero, then we're trying to raise x to power zero, and result stays one */
	if (temp)
	{
		register int count = 32;

		/* first skip bits until we reach a one */
		while (count)
		{
			if (temp & 0x80000000)
				break;
			temp <<= 1;
			count--;
		}

		while (psize)
		{
			while (count)
			{
				/* always square */
				mp32bnsqrmodres(b, b->data, (mp32number*) b);
				
				/* multiply by x if bit is 1 */
				if (temp & 0x80000000)
					mp32bmulmod(b, xsize, xdata, b->size, b->data);

				temp <<= 1;
				count--;
			}
			if (--psize)
			{
				count = 32;
				temp = *(pdata++);
			}
		}
	}
}
#endif

/*
 * Sliding Window Exponentiation technique, slightly altered from the method Applied Cryptography:
 *
 * First of all, the table with the powers of g can be reduced by about half; the even powers don't
 * need to be accessed or stored.
 *
 * Get up to K bits starting with a one, if we have that many still available
 *
 * Do the number of squarings of A in the first column, the multiply by the value in column two,
 * and finally do the number of squarings in column three.
 *
 * This table can be used for K=2,3,4 and can be extended
 *  
 *     0 : - | -       | -
 *     1 : 1 |  g1 @ 0 | 0
 *    10 : 1 |  g1 @ 0 | 1
 *    11 : 2 |  g3 @ 1 | 0
 *   100 : 1 |  g1 @ 0 | 2
 *   101 : 3 |  g5 @ 2 | 0
 *   110 : 2 |  g3 @ 1 | 1
 *   111 : 3 |  g7 @ 3 | 0
 *  1000 : 1 |  g1 @ 0 | 3
 *  1001 : 4 |  g9 @ 4 | 0
 *  1010 : 3 |  g5 @ 2 | 1
 *  1011 : 4 | g11 @ 5 | 0
 *  1100 : 2 |  g3 @ 1 | 2
 *  1101 : 4 | g13 @ 6 | 0
 *  1110 : 3 |  g7 @ 3 | 1
 *  1111 : 4 | g15 @ 7 | 0
 *
 */

static byte mp32bslide_presq[16] = 
{ 0, 1, 1, 2, 1, 3, 2, 3, 1, 4, 3, 4, 2, 4, 3, 4 };

static byte mp32bslide_mulg[16] =
{ 0, 0, 0, 1, 0, 2, 1, 3, 0, 4, 2, 5, 1, 6, 3, 7 };

static byte mp32bslide_postsq[16] =
{ 0, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0 };

void mp32bpowmod(const mp32barrett* b, uint32 xsize, const uint32* xdata, uint32 psize, const uint32* pdata)
{
	/*
	 * Modular exponention
	 *
	 * Uses sliding window exponentiation; needs extra storage: if K=3, needs 8*size, if K=4, needs 16*size
	 *
	 */

	/* K == 4 for the first try */
	
	uint32  size = b->size;
	uint32* data = b->data;
	uint32  temp;

	mp32setw(size, data, 1);

	while (psize)
	{
		if ((temp = *(pdata++))) /* break when first non-zero word found */
			break;
		psize--;
	}

	if (temp)
	{
		#if HAVE_ALLOCA
		uint32* xpow = (uint32*) alloca(size*8*sizeof(uint32));
		#else
		uint32* xpow = (uint32*) malloc(size*8*sizeof(uint32));
		#endif
		uint8 l = 0, n = 0, count = 32;
	
		mp32bsqrmodres(b, xpow       , xsize, xdata);                    /* x^2 mod b, temp */
		mp32bmulmodres(b, xpow+size  , xsize, xdata, size, xpow);        /* x^3 mod b */
		mp32bmulmodres(b, xpow+2*size,  size,  xpow, size, xpow+size);   /* x^5 mod b */
		mp32bmulmodres(b, xpow+3*size,  size,  xpow, size, xpow+2*size); /* x^7 mod b */
		mp32bmulmodres(b, xpow+4*size,  size,  xpow, size, xpow+3*size); /* x^9 mod b */
		mp32bmulmodres(b, xpow+5*size,  size,  xpow, size, xpow+4*size); /* x^11 mod b */
		mp32bmulmodres(b, xpow+6*size,  size,  xpow, size, xpow+5*size); /* x^13 mod b */
		mp32bmulmodres(b, xpow+7*size,  size,  xpow, size, xpow+6*size); /* x^15 mod b */
		mp32setx(size, xpow, xsize, xdata);                              /* x^1 mod b */

		/* first skip bits until we reach a one */
		while (count)
		{
			if (temp & 0x80000000)
				break;
			temp <<= 1;
			count--;
		}

		while (psize)
		{
			while (count)
			{
				uint8 bit = (temp & 0x80000000) != 0;

				n <<= 1;
				n += bit;
				
				if (n)
				{
					if (l)
						l++;
					else if (bit)
						l = 1;

					if (l == 4)
					{
						uint8 s = mp32bslide_presq[n];
						
						while (s--)
							mp32bnsqrmodres(b, data, (mp32number*) b);
						
						mp32bmulmod(b, size, xpow+mp32bslide_mulg[n]*size, b->size, b->data);
						
						s = mp32bslide_postsq[n];
						
						while (s--)
							mp32bnsqrmodres(b, data, (mp32number*) b);

						l = n = 0;
					}
				}
				else
					mp32bnsqrmodres(b, data, (mp32number*) b);

				temp <<= 1;
				count--;
			}
			if (--psize)
			{
				count = 32;
				temp = *(pdata++);
			}
		}

		if (n)
		{
			uint8 s = mp32bslide_presq[n];
			while (s--)
				mp32bnsqrmodres(b, data, (mp32number*) b);
				
			mp32bmulmod(b, size, xpow+mp32bslide_mulg[n]*size, b->size, b->data);
			
			s = mp32bslide_postsq[n];
			
			while (s--)
				mp32bnsqrmodres(b, data, (mp32number*) b);
		}
		#if !HAVE_ALLOCA
		free(xpow);
		#endif
	}
}

void mp32btwopowmod(const mp32barrett* b, uint32 psize, const uint32* pdata)
{
	/*
	 * Modular exponention, 2^p mod modulus, special optimization
	 *
	 * Uses left-to-right exponentiation; needs no extra storage
	 *
	 */

	/* this routine calls mp32bmod, which needs (size*2+2), this routine needs (size*2) for sdata */

	register uint32  temp;

	mp32setw(b->size, b->data, 1);

	while (psize)
	{
		if ((temp = *(pdata++))) /* break when first non-zero word found */
			break;
		psize--;
	}

	/* if temp is still zero, then we're trying to raise x to power zero, and result stays one */
	if (temp)
	{
		register int count = 32;

		/* first skip bits until we reach a one */
		while (count)
		{
			if (temp & 0x80000000)
				break;
			temp <<= 1;
			count--;
		}

		while (psize)
		{
			while (count)
			{
				/* always square */
				mp32bnsqrmodres(b, b->data, (mp32number*) b);
				
				/* multiply by two if bit is 1 */
				if (temp & 0x80000000)
				{
					if (mp32add(b->size, b->data, b->data) || mp32ge(b->size, b->data, b->modl))
					{
						/* there was carry, or the result is greater than the modulus, so we need to adjust */
						mp32sub(b->size, b->data, b->modl);
					}
				}

				temp <<= 1;
				count--;
			}
			if (psize--)
			{
				count = 32;
				temp = *(pdata++);
			}
		}
	}
}

int mp32binv(const mp32barrett* b, uint32 xsize, const uint32* xdata)
{
	/*
	 * Fact: if a element of Zn, then a is invertible if and only if gcd(a,n) = 1
	 * 
	 */

	/* where x or modl is odd, that algorithm will need (4*size+4) */

	if (mp32odd(b->size, b->modl))
	{
		/* use simplified binary extended gcd algorithm */

		register uint32  size = b->size;

		uint32* udata = b->wksp;
		uint32* vdata = udata+size+1;
		uint32* bdata = vdata+size+1;
		uint32* ddata = bdata+size+1;

		mp32setx(size+1, udata, size, b->modl);
		mp32setx(size+1, vdata, xsize, xdata);
		mp32zero(size+1, bdata);
		mp32setw(size+1, ddata, 1);

		while (1)
		{
			while (mp32even(size+1, udata))
			{
				mp32divtwo(size+1, udata);

				if (mp32odd(size+1, bdata))
					mp32subx(size+1, bdata, size, b->modl);

				mp32sdivtwo(size+1, bdata);
			}
			while (mp32even(size+1, vdata))
			{
				mp32divtwo(size+1, vdata);

				if (mp32odd(size+1, ddata))
					mp32subx(size+1, ddata, size, b->modl);

				mp32sdivtwo(size+1, ddata);
			}
			if (mp32ge(size+1, udata, vdata))
			{
				mp32sub(size+1, udata, vdata);
				mp32sub(size+1, bdata, ddata);
			}
			else
			{
				mp32sub(size+1, vdata, udata);
				mp32sub(size+1, ddata, bdata);
			}

			if (mp32z(size+1, udata))
			{
				if (mp32isone(size+1, vdata))
				{
					mp32setx(size, b->data, size+1, ddata);
					if (*ddata & 0x80000000)
						mp32add(size, b->data, b->modl);

					return 1;
				}
				return 0;
			}
		}
	}
	else if (mp32odd(xsize, xdata))
	{
		/* use simplified binary extended gcd algorithm */

		register uint32  size = b->size;

		uint32* udata = b->wksp;
		uint32* vdata = udata+size+1;
		uint32* bdata = vdata+size+1;
		uint32* ddata = bdata+size+1;

		mp32setx(size+1, udata, xsize, xdata);
		mp32setx(size+1, vdata, size, b->modl);
		mp32zero(size+1, bdata);
		mp32setw(size+1, ddata, 1);

		while (1)
		{
			while (mp32even(size+1, udata))
			{
				mp32divtwo(size+1, udata);

				if (mp32odd(size+1, bdata))
					mp32subx(size+1, bdata, xsize, xdata);

				mp32sdivtwo(size+1, bdata);
			}
			while (mp32even(size+1, vdata))
			{
				mp32divtwo(size+1, vdata);

				if (mp32odd(size+1, ddata))
					mp32subx(size+1, ddata, xsize, xdata);

				mp32sdivtwo(size+1, ddata);
			}
			if (mp32ge(size+1, udata, vdata))
			{
				mp32sub(size+1, udata, vdata);
				mp32sub(size+1, bdata, ddata);
			}
			else
			{
				mp32sub(size+1, vdata, udata);
				mp32sub(size+1, ddata, bdata);
			}

			if (mp32z(size+1, udata))
			{
				if (mp32isone(size+1, vdata))
				{
					mp32setx(size, b->data, size+1, ddata);
					if (*ddata & 0x80000000)
						mp32addx(size, b->data, xsize, xdata);

					return 1;
				}
				return 0;
			}
		}
	}

	return 0;
}

int mp32bpprime(const mp32barrett* b, randomGeneratorContext* r, int t)
{
	/*
	 * This test works for candidate probable primes >= 3, which are also not small primes 
	 *
	 * It assumes that b->modl contains the candidate prime
	 *
	 */

	/* first test if modl is odd */

	if (mp32odd(b->size, b->modl))
	{
		/*
		 * Small prime factor test:
		 * 
		 * Tables in mp32spprod contain multi-precision integers with products of small primes
		 * If the greatest common divisor of this product and the candidate is not one, then
		 * the candidate has small prime factors, or is a small prime. Neither is acceptable when
		 * we are looking for large probable primes =)
		 *
		 */
		
		if (b->size > SMALL_PRIMES_PRODUCT_MAX)
		{
			mp32setx(b->size, b->wksp+b->size, SMALL_PRIMES_PRODUCT_MAX, mp32spprod[SMALL_PRIMES_PRODUCT_MAX-1]);
			mp32gcd(b->data, b->size, b->modl, b->wksp+b->size, b->wksp);
		}
		else
		{
			mp32gcd(b->data, b->size, b->modl, mp32spprod[b->size-1], b->wksp);
		}

		if (mp32isone(b->size, b->data))
		{
			return mp32pmilrab(b, r, t);
		}
	}

	return 0;
}

void mp32brnd(const mp32barrett* b, randomGeneratorContext* rc)
{
	mp32brndres(b, b->data, rc);
}

void mp32bnmulmodres(const mp32barrett* b, uint32* result, const mp32number* x, const mp32number* y)
{
	/* needs workspace of (size*2) in addition to what is needed by mp32bmodres (size*2+2) */
	/* xsize and ysize must be <= b->size */
	/* stores result in b->data */
	register uint32  size = b->size;
	register uint32  fill = 2*size-x->size-y->size;
	register uint32* opnd = b->wksp+size*2+2;

	if (fill)
		mp32zero(fill, opnd);

	mp32mul(opnd+fill, x->size, x->data, y->size, y->data);
	mp32bmodres(b, result, opnd);
}

void mp32bnsqrmodres(const mp32barrett* b, uint32* result, const mp32number* x)
{
	/* needs workspace of (size*2) in addition to what is needed by mp32bmodres (size*2+2) */
	/* xsize must be <= b->size */
	register uint32  size = b->size;
	register uint32  fill = 2*(size-x->size);
	register uint32* opnd = b->wksp + size*2+2;

	if (fill)
		mp32zero(fill, opnd);

	mp32sqr(opnd+fill, x->size, x->data);
	mp32bmodres(b, result, opnd);
}

void mp32bnmulmod(const mp32barrett* b, const mp32number* x, const mp32number* y)
{
	mp32bnmulmodres(b, b->data, x, y);
}

void mp32bnpowmod(const mp32barrett* b, const mp32number* x, const mp32number* y)
{
	mp32bpowmod(b, x->size, x->data, y->size, y->data);
}

void mp32bnsqrmod(const mp32barrett* b, const mp32number* x)
{
	mp32bnsqrmodres(b, b->data, x);
}

void mp32bspowmod3(const mp32number* b, const uint32* x0, const uint32* p0, const uint32* x1, const uint32* p1, const uint32* x2, const uint32* p2)
{
	/* this algorithm needs (size*8) storage, which won't fit in the normal buffer */
}
