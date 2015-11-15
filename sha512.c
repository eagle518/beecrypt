/*
 * Copyright (c) 2004 Beeyond Software Holding BV
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

/*!\file sha512.c
 * \brief SHA-512 hash function, as specified by NIST FIPS 180-2.
 * \author Bob Deblier <bob.deblier@telenet.be>
 * \ingroup HASH_m HASH_sha512_m
 */
 
#define BEECRYPT_DLL_EXPORT

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "beecrypt/sha512.h"
#include "beecrypt/endianness.h"

#ifdef OPTIMIZE_SSE2
# include <xmmintrin.h>
#endif

/*!\addtogroup HASH_sha512_m
 * \{
 */

static const uint64_t k[80] = {
	#if (SIZEOF_UNSIGNED_LONG == 8) || !HAVE_UNSIGNED_LONG_LONG
	0x428a2f98d728ae22UL, 0x7137449123ef65cdUL,
	0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
	0x3956c25bf348b538UL, 0x59f111f1b605d019UL,
	0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
	0xd807aa98a3030242UL, 0x12835b0145706fbeUL,
	0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
	0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL,
	0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
	0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL,
	0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
	0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL,
	0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
	0x983e5152ee66dfabUL, 0xa831c66d2db43210UL,
	0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
	0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL,
	0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
	0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL,
	0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
	0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL,
	0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
	0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL,
	0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
	0xd192e819d6ef5218UL, 0xd69906245565a910UL,
	0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
	0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL,
	0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
	0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL,
	0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
	0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL,
	0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
	0x90befffa23631e28UL, 0xa4506cebde82bde9UL,
	0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
	0xca273eceea26619cUL, 0xd186b8c721c0c207UL,
	0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
	0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL,
	0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
	0x28db77f523047d84UL, 0x32caab7b40c72493UL,
	0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
	0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL,
	0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
	#else
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
	0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
	0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
	0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
	0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
	0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
	0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
	0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
	0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
	0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
	0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
	0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
	0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
	0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
	#endif
};

static const uint64_t hinit[8] = {
	#if (SIZEOF_UNSIGNED_LONG == 8) || !HAVE_UNSIGNED_LONG_LONG
	0x6a09e667f3bcc908UL,
	0xbb67ae8584caa73bUL,
	0x3c6ef372fe94f82bUL,
	0xa54ff53a5f1d36f1UL,
	0x510e527fade682d1UL,
	0x9b05688c2b3e6c1fUL,
	0x1f83d9abfb41bd6bUL,
	0x5be0cd19137e2179UL
	#else
	0x6a09e667f3bcc908ULL,
	0xbb67ae8584caa73bULL,
	0x3c6ef372fe94f82bULL,
	0xa54ff53a5f1d36f1ULL,
	0x510e527fade682d1ULL,
	0x9b05688c2b3e6c1fULL,
	0x1f83d9abfb41bd6bULL,
	0x5be0cd19137e2179ULL
	#endif
};

const hashFunction sha512 = { "SHA-512", sizeof(sha512Param), 128, 64, (hashFunctionReset) sha512Reset, (hashFunctionUpdate) sha512Update, (hashFunctionDigest) sha512Digest };

int sha512Reset(register sha512Param* sp)
{
	memcpy(sp->h, hinit, 8 * sizeof(uint64_t));
	memset(sp->data, 0, 80 * sizeof(uint64_t));
	#if (MP_WBITS == 64)
	mpzero(2, sp->length);
	#elif (MP_WBITS == 32)
	mpzero(4, sp->length);
	#else
	# error
	#endif
	sp->offset = 0;
	return 0;
}

#ifdef OPTIMIZE_SSE2

# define R(x,s) _mm_srli_si64(x,s)
# define S(x,s) _m_pxor(_mm_srli_si64(x,s),_mm_slli_si64(x,64-(s)))
# define CH(x,y,z) _m_pxor(_m_pand(x,_m_pxor(y,z)),z)
# define MAJ(x,y,z) _m_por(_m_pand(_m_por(x,y),z),_m_pand(x,y))
# define SIG0(x) _m_pxor(_m_pxor(S(x,28),S(x,34)),S(x,39))
# define SIG1(x) _m_pxor(_m_pxor(S(x,14),S(x,18)),S(x,41))
# define sig0(x) _m_pxor(_m_pxor(S(x,1),S(x,8)),R(x,7))
# define sig1(x) _m_pxor(_m_pxor(S(x,19),S(x,61)),R(x,6))

# define ROUND(a,b,c,d,e,f,g,h,w,k) \
	temp = _mm_add_si64(h, _mm_add_si64(_mm_add_si64(SIG1(e), CH(e,f,g)), _mm_add_si64((__m64) k, (__m64) w))); \
	h = _mm_add_si64(temp, _mm_add_si64(SIG0(a), MAJ(a,b,c))); \
	d = _mm_add_si64(d, temp)

#else

# define R(x,s) ((x) >> (s))
# define S(x,s) ROTR64(x, s)

# define CH(x,y,z) ((x&(y^z))^z)
# define MAJ(x,y,z) (((x|y)&z)|(x&y))
# define SIG0(x) (S(x,28) ^ S(x,34) ^ S(x,39))
# define SIG1(x) (S(x,14) ^ S(x,18) ^ S(x,41))
# define sig0(x) (S(x,1) ^ S(x,8) ^ R(x,7))
# define sig1(x) (S(x,19) ^ S(x,61) ^ R(x,6))

# define ROUND(a,b,c,d,e,f,g,h,w,k)	\
	temp = h + SIG1(e) + CH(e,f,g) + k + w;	\
	h = temp + SIG0(a) + MAJ(a,b,c);	\
	d += temp

#endif

#ifndef ASM_SHA512PROCESS
void sha512Process(register sha512Param* sp)
{
	#ifdef OPTIMIZE_SSE2
	# if HAVE_UNSIGNED_LONG_LONG
	static const uint64_t MASK = 0x00FF00FF00FF00FFULL;
	# else
	static const uint64_t MASK = 0x00FF00FF00FF00FFUL;
	# endif

	__m64 a, b, c, d, e, f, g, h, temp;
	register __m64* w;
	register byte t;

	w = (__m64*) sp->data;
	t = 16;
	while (t--)
	{
		temp = *w;
		*(w++) = _m_pxor(
				_mm_slli_si64(_m_pshufw(_m_pand(temp, (__m64) MASK), 27), 8),
				_m_pshufw(_m_pand(_mm_srli_si64(temp, 8), (__m64) MASK), 27)
			);
	}

	t = 64;
	while (t--)
	{
		temp = _mm_add_si64(_mm_add_si64(sig1(w[-2]), w[-7]), _mm_add_si64(sig0(w[-15]), w[-16]));
		*(w++) = temp;
	}

	w = (__m64*) sp->data;

	a = (__m64) sp->h[0]; b = (__m64) sp->h[1]; c = (__m64) sp->h[2]; d = (__m64) sp->h[3];
	e = (__m64) sp->h[4]; f = (__m64) sp->h[5]; g = (__m64) sp->h[6]; h = (__m64) sp->h[7];

	#else

	register uint64_t a, b, c, d, e, f, g, h, temp;
	register uint64_t *w;
	register byte t;

	# if WORDS_BIGENDIAN
	w = sp->data + 16;
	# else
	w = sp->data;
	t = 16;
	while (t--)
	{
		temp = swapu64(*w);
		*(w++) = temp;
	}
	# endif

	t = 64;
	while (t--)
	{
		temp = sig1(w[-2]) + w[-7] + sig0(w[-15]) + w[-16];
		*(w++) = temp;
	}

	w = sp->data;

	a = sp->h[0]; b = sp->h[1]; c = sp->h[2]; d = sp->h[3];
	e = sp->h[4]; f = sp->h[5]; g = sp->h[6]; h = sp->h[7];
	#endif

	ROUND(a,b,c,d,e,f,g,h,w[ 0],k[ 0]);
	ROUND(h,a,b,c,d,e,f,g,w[ 1],k[ 1]);
	ROUND(g,h,a,b,c,d,e,f,w[ 2],k[ 2]);
	ROUND(f,g,h,a,b,c,d,e,w[ 3],k[ 3]);
	ROUND(e,f,g,h,a,b,c,d,w[ 4],k[ 4]);
	ROUND(d,e,f,g,h,a,b,c,w[ 5],k[ 5]);
	ROUND(c,d,e,f,g,h,a,b,w[ 6],k[ 6]);
	ROUND(b,c,d,e,f,g,h,a,w[ 7],k[ 7]);
	ROUND(a,b,c,d,e,f,g,h,w[ 8],k[ 8]);
	ROUND(h,a,b,c,d,e,f,g,w[ 9],k[ 9]);
	ROUND(g,h,a,b,c,d,e,f,w[10],k[10]);
	ROUND(f,g,h,a,b,c,d,e,w[11],k[11]);
	ROUND(e,f,g,h,a,b,c,d,w[12],k[12]);
	ROUND(d,e,f,g,h,a,b,c,w[13],k[13]);
	ROUND(c,d,e,f,g,h,a,b,w[14],k[14]);
	ROUND(b,c,d,e,f,g,h,a,w[15],k[15]);
	ROUND(a,b,c,d,e,f,g,h,w[16],k[16]);
	ROUND(h,a,b,c,d,e,f,g,w[17],k[17]);
	ROUND(g,h,a,b,c,d,e,f,w[18],k[18]);
	ROUND(f,g,h,a,b,c,d,e,w[19],k[19]);
	ROUND(e,f,g,h,a,b,c,d,w[20],k[20]);
	ROUND(d,e,f,g,h,a,b,c,w[21],k[21]);
	ROUND(c,d,e,f,g,h,a,b,w[22],k[22]);
	ROUND(b,c,d,e,f,g,h,a,w[23],k[23]);
	ROUND(a,b,c,d,e,f,g,h,w[24],k[24]);
	ROUND(h,a,b,c,d,e,f,g,w[25],k[25]);
	ROUND(g,h,a,b,c,d,e,f,w[26],k[26]);
	ROUND(f,g,h,a,b,c,d,e,w[27],k[27]);
	ROUND(e,f,g,h,a,b,c,d,w[28],k[28]);
	ROUND(d,e,f,g,h,a,b,c,w[29],k[29]);
	ROUND(c,d,e,f,g,h,a,b,w[30],k[30]);
	ROUND(b,c,d,e,f,g,h,a,w[31],k[31]);
	ROUND(a,b,c,d,e,f,g,h,w[32],k[32]);
	ROUND(h,a,b,c,d,e,f,g,w[33],k[33]);
	ROUND(g,h,a,b,c,d,e,f,w[34],k[34]);
	ROUND(f,g,h,a,b,c,d,e,w[35],k[35]);
	ROUND(e,f,g,h,a,b,c,d,w[36],k[36]);
	ROUND(d,e,f,g,h,a,b,c,w[37],k[37]);
	ROUND(c,d,e,f,g,h,a,b,w[38],k[38]);
	ROUND(b,c,d,e,f,g,h,a,w[39],k[39]);
	ROUND(a,b,c,d,e,f,g,h,w[40],k[40]);
	ROUND(h,a,b,c,d,e,f,g,w[41],k[41]);
	ROUND(g,h,a,b,c,d,e,f,w[42],k[42]);
	ROUND(f,g,h,a,b,c,d,e,w[43],k[43]);
	ROUND(e,f,g,h,a,b,c,d,w[44],k[44]);
	ROUND(d,e,f,g,h,a,b,c,w[45],k[45]);
	ROUND(c,d,e,f,g,h,a,b,w[46],k[46]);
	ROUND(b,c,d,e,f,g,h,a,w[47],k[47]);
	ROUND(a,b,c,d,e,f,g,h,w[48],k[48]);
	ROUND(h,a,b,c,d,e,f,g,w[49],k[49]);
	ROUND(g,h,a,b,c,d,e,f,w[50],k[50]);
	ROUND(f,g,h,a,b,c,d,e,w[51],k[51]);
	ROUND(e,f,g,h,a,b,c,d,w[52],k[52]);
	ROUND(d,e,f,g,h,a,b,c,w[53],k[53]);
	ROUND(c,d,e,f,g,h,a,b,w[54],k[54]);
	ROUND(b,c,d,e,f,g,h,a,w[55],k[55]);
	ROUND(a,b,c,d,e,f,g,h,w[56],k[56]);
	ROUND(h,a,b,c,d,e,f,g,w[57],k[57]);
	ROUND(g,h,a,b,c,d,e,f,w[58],k[58]);
	ROUND(f,g,h,a,b,c,d,e,w[59],k[59]);
	ROUND(e,f,g,h,a,b,c,d,w[60],k[60]);
	ROUND(d,e,f,g,h,a,b,c,w[61],k[61]);
	ROUND(c,d,e,f,g,h,a,b,w[62],k[62]);
	ROUND(b,c,d,e,f,g,h,a,w[63],k[63]);
	ROUND(a,b,c,d,e,f,g,h,w[64],k[64]);
	ROUND(h,a,b,c,d,e,f,g,w[65],k[65]);
	ROUND(g,h,a,b,c,d,e,f,w[66],k[66]);
	ROUND(f,g,h,a,b,c,d,e,w[67],k[67]);
	ROUND(e,f,g,h,a,b,c,d,w[68],k[68]);
	ROUND(d,e,f,g,h,a,b,c,w[69],k[69]);
	ROUND(c,d,e,f,g,h,a,b,w[70],k[70]);
	ROUND(b,c,d,e,f,g,h,a,w[71],k[71]);
	ROUND(a,b,c,d,e,f,g,h,w[72],k[72]);
	ROUND(h,a,b,c,d,e,f,g,w[73],k[73]);
	ROUND(g,h,a,b,c,d,e,f,w[74],k[74]);
	ROUND(f,g,h,a,b,c,d,e,w[75],k[75]);
	ROUND(e,f,g,h,a,b,c,d,w[76],k[76]);
	ROUND(d,e,f,g,h,a,b,c,w[77],k[77]);
	ROUND(c,d,e,f,g,h,a,b,w[78],k[78]);
	ROUND(b,c,d,e,f,g,h,a,w[79],k[79]);

	#ifdef OPTIMIZE_SSE2
	sp->h[0] = (uint64_t) _mm_add_si64((__m64) sp->h[0], a);
	sp->h[1] = (uint64_t) _mm_add_si64((__m64) sp->h[1], b);
	sp->h[2] = (uint64_t) _mm_add_si64((__m64) sp->h[2], c);
	sp->h[3] = (uint64_t) _mm_add_si64((__m64) sp->h[3], d);
	sp->h[4] = (uint64_t) _mm_add_si64((__m64) sp->h[4], e);
	sp->h[5] = (uint64_t) _mm_add_si64((__m64) sp->h[5], f);
	sp->h[6] = (uint64_t) _mm_add_si64((__m64) sp->h[6], g);
	sp->h[7] = (uint64_t) _mm_add_si64((__m64) sp->h[7], h);
	_mm_empty();
	#else
	sp->h[0] += a;
	sp->h[1] += b;
	sp->h[2] += c;
	sp->h[3] += d;
	sp->h[4] += e;
	sp->h[5] += f;
	sp->h[6] += g;
	sp->h[7] += h;
	#endif
}
#endif

int sha512Update(register sha512Param* sp, const byte* data, size_t size)
{
	register uint64_t proclength;

	#if (MP_WBITS == 64)
	mpw add[2];
	mpsetw(2, add, size);
	mplshift(2, add, 3);
	mpadd(2, sp->length, add);
	#elif (MP_WBITS == 32)
	mpw add[4];
	mpsetw(4, add, size);
	mplshift(4, add, 3);
	mpadd(4, sp->length, add);
	#else
	# error
	#endif

	while (size > 0)
	{
		proclength = ((sp->offset + size) > 128U) ? (128U - sp->offset) : size;
		memcpy(((byte *) sp->data) + sp->offset, data, proclength);
		size -= proclength;
		data += proclength;
		sp->offset += proclength;

		if (sp->offset == 128U)
		{
			sha512Process(sp);
			sp->offset = 0;
		}
	}
	return 0;
}

static void sha512Finish(register sha512Param* sp)
{
	register byte *ptr = ((byte *) sp->data) + sp->offset++;

	*(ptr++) = 0x80;

	if (sp->offset > 112)
	{
		while (sp->offset++ < 128)
			*(ptr++) = 0;

		sha512Process(sp);
		sp->offset = 0;
	}

	ptr = ((byte *) sp->data) + sp->offset;
	while (sp->offset++ < 112)
		*(ptr++) = 0;

	#if (MP_WBITS == 64)
	ptr[ 0] = (byte)(sp->length[0] >> 56);
	ptr[ 1] = (byte)(sp->length[0] >> 48);
	ptr[ 2] = (byte)(sp->length[0] >> 40);
	ptr[ 3] = (byte)(sp->length[0] >> 32);
	ptr[ 4] = (byte)(sp->length[0] >> 24);
	ptr[ 5] = (byte)(sp->length[0] >> 16);
	ptr[ 6] = (byte)(sp->length[0] >>  8);
	ptr[ 7] = (byte)(sp->length[0]      );
	ptr[ 8] = (byte)(sp->length[1] >> 56);
	ptr[ 9] = (byte)(sp->length[1] >> 48);
	ptr[10] = (byte)(sp->length[1] >> 40);
	ptr[11] = (byte)(sp->length[1] >> 32);
	ptr[12] = (byte)(sp->length[1] >> 24);
	ptr[13] = (byte)(sp->length[1] >> 16);
	ptr[14] = (byte)(sp->length[1] >>  8);
	ptr[15] = (byte)(sp->length[1]      );
	#elif (MP_WBITS == 32)
	ptr[ 0] = (byte)(sp->length[0] >> 24);
	ptr[ 1] = (byte)(sp->length[0] >> 16);
	ptr[ 2] = (byte)(sp->length[0] >>  8);
	ptr[ 3] = (byte)(sp->length[0]      );
	ptr[ 4] = (byte)(sp->length[1] >> 24);
	ptr[ 5] = (byte)(sp->length[1] >> 16);
	ptr[ 6] = (byte)(sp->length[1] >>  8);
	ptr[ 7] = (byte)(sp->length[1]      );
	ptr[ 8] = (byte)(sp->length[2] >> 24);
	ptr[ 9] = (byte)(sp->length[2] >> 16);
	ptr[10] = (byte)(sp->length[2] >>  8);
	ptr[11] = (byte)(sp->length[2]      );
	ptr[12] = (byte)(sp->length[3] >> 24);
	ptr[13] = (byte)(sp->length[3] >> 16);
	ptr[14] = (byte)(sp->length[3] >>  8);
	ptr[15] = (byte)(sp->length[3]      );
	#else
	# error
	#endif

	sha512Process(sp);
	sp->offset = 0;
}

int sha512Digest(register sha512Param* sp, byte* data)
{
	sha512Finish(sp);

	/* encode 8 integers big-endian style */
	data[ 0] = (byte)(sp->h[0] >> 56);
	data[ 1] = (byte)(sp->h[0] >> 48);
	data[ 2] = (byte)(sp->h[0] >> 40);
	data[ 3] = (byte)(sp->h[0] >> 32);
	data[ 4] = (byte)(sp->h[0] >> 24);
	data[ 5] = (byte)(sp->h[0] >> 16);
	data[ 6] = (byte)(sp->h[0] >>  8);
	data[ 7] = (byte)(sp->h[0] >>  0);

	data[ 8] = (byte)(sp->h[1] >> 56);
	data[ 9] = (byte)(sp->h[1] >> 48);
	data[10] = (byte)(sp->h[1] >> 40);
	data[11] = (byte)(sp->h[1] >> 32);
	data[12] = (byte)(sp->h[1] >> 24);
	data[13] = (byte)(sp->h[1] >> 16);
	data[14] = (byte)(sp->h[1] >>  8);
	data[15] = (byte)(sp->h[1] >>  0);

	data[16] = (byte)(sp->h[2] >> 56);
	data[17] = (byte)(sp->h[2] >> 48);
	data[18] = (byte)(sp->h[2] >> 40);
	data[19] = (byte)(sp->h[2] >> 32);
	data[20] = (byte)(sp->h[2] >> 24);
	data[21] = (byte)(sp->h[2] >> 16);
	data[22] = (byte)(sp->h[2] >>  8);
	data[23] = (byte)(sp->h[2] >>  0);

	data[24] = (byte)(sp->h[3] >> 56);
	data[25] = (byte)(sp->h[3] >> 48);
	data[26] = (byte)(sp->h[3] >> 40);
	data[27] = (byte)(sp->h[3] >> 32);
	data[28] = (byte)(sp->h[3] >> 24);
	data[29] = (byte)(sp->h[3] >> 16);
	data[30] = (byte)(sp->h[3] >>  8);
	data[31] = (byte)(sp->h[3] >>  0);

	data[32] = (byte)(sp->h[4] >> 56);
	data[33] = (byte)(sp->h[4] >> 48);
	data[34] = (byte)(sp->h[4] >> 40);
	data[35] = (byte)(sp->h[4] >> 32);
	data[36] = (byte)(sp->h[4] >> 24);
	data[37] = (byte)(sp->h[4] >> 16);
	data[38] = (byte)(sp->h[4] >>  8);
	data[39] = (byte)(sp->h[4] >>  0);

	data[40] = (byte)(sp->h[5] >> 56);
	data[41] = (byte)(sp->h[5] >> 48);
	data[42] = (byte)(sp->h[5] >> 40);
	data[43] = (byte)(sp->h[5] >> 32);
	data[44] = (byte)(sp->h[5] >> 24);
	data[45] = (byte)(sp->h[5] >> 16);
	data[46] = (byte)(sp->h[5] >>  8);
	data[47] = (byte)(sp->h[5] >>  0);

	data[48] = (byte)(sp->h[6] >> 56);
	data[49] = (byte)(sp->h[6] >> 48);
	data[50] = (byte)(sp->h[6] >> 40);
	data[51] = (byte)(sp->h[6] >> 32);
	data[52] = (byte)(sp->h[6] >> 24);
	data[53] = (byte)(sp->h[6] >> 16);
	data[54] = (byte)(sp->h[6] >>  8);
	data[55] = (byte)(sp->h[6] >>  0);

	data[56] = (byte)(sp->h[7] >> 56);
	data[57] = (byte)(sp->h[7] >> 48);
	data[58] = (byte)(sp->h[7] >> 40);
	data[59] = (byte)(sp->h[7] >> 32);
	data[60] = (byte)(sp->h[7] >> 24);
	data[61] = (byte)(sp->h[7] >> 16);
	data[62] = (byte)(sp->h[7] >>  8);
	data[63] = (byte)(sp->h[7] >>  0);

	sha512Reset(sp);
	return 0;
}

/*!\}
 */
