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
 */

/*!\file SecretKeyFactory.h
 * \ingroup CXX_CRYPTO_m
 */

#ifndef _CLASS_SECRETKEYFACTORY_H
#define _CLASS_SECRETKEYFACTORY_H

// #include "beecrypt/beecrypt.api.h"

#ifdef __cplusplus

#include "beecrypt/c++/crypto/SecretKeyFactorySpi.h"
using beecrypt::crypto::SecretKeyFactorySpi;
#include "beecrypt/c++/security/Provider.h"
using beecrypt::security::Provider;
#include "beecrypt/c++/security/NoSuchAlgorithmException.h"
using beecrypt::security::NoSuchAlgorithmException;
#include "beecrypt/c++/security/NoSuchProviderException.h"
using beecrypt::security::NoSuchProviderException;

#include <typeinfo>
using std::type_info;

namespace beecrypt {
	namespace crypto {
		class BEECRYPTCXXAPI SecretKeyFactory
		{
			public:
				static SecretKeyFactory* getInstance(const String&) throw (NoSuchAlgorithmException);
				static SecretKeyFactory* getInstance(const String&, const String&) throw (NoSuchAlgorithmException, NoSuchProviderException);
				static SecretKeyFactory* getInstance(const String&, const Provider&) throw (NoSuchAlgorithmException);

			private:
				SecretKeyFactorySpi* _kspi;
				String               _algo;
				const Provider*      _prov;

			protected:
				SecretKeyFactory(SecretKeyFactorySpi*, const String&, const Provider&);

			public:
				~SecretKeyFactory();

				SecretKey* generateSecret(const KeySpec&) throw (InvalidKeySpecException);

				KeySpec* getKeySpec(const SecretKey& key, const type_info&) throw (InvalidKeySpecException);

				SecretKey* translateKey(const SecretKey&) throw (InvalidKeyException);

				const String& getAlgorithm() const throw ();
				const Provider& getProvider() const throw ();
		};
	}
}

#endif

#endif
