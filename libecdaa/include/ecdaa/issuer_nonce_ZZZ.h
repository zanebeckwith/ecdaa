/******************************************************************************
 *
 * Copyright 2019 Xaptum, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License
 *
 *****************************************************************************/

#ifndef ECDAA_ISSUER_NONCE_ZZZ_H
#define ECDAA_ISSUER_NONCE_ZZZ_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ecdaa/rand.h>

#include <amcl/big_XXX.h>
#include <amcl/ecp_ZZZ.h>

/*
 * Issuer nonce.
 */
struct ecdaa_issuer_nonce_ZZZ {
    uint8_t m[MODBYTES_XXX];
    ECP_ZZZ B;
};

#define ECDAA_ISSUER_NONCE_ZZZ_LENGTH (MODBYTES_XXX + (2*MODBYTES_XXX + 1))
size_t ecdaa_issuer_nonce_ZZZ_length(void);

/*
 * Generate a fresh `ecdaa_issuer_nonce_ZZZ`.
 *
 * Returns:
 * 0 on success
 * -1 on error
 */
int ecdaa_issuer_nonce_ZZZ_generate(struct ecdaa_issuer_nonce_ZZZ *nonce_out,
                                    ecdaa_rand_func get_random);

// /*
//  * Serialize an `ecdaa_issuer_public_key_ZZZ`
//  *
//  * The serialized format is:
//  *  ( gpk | c | sx | sy )
//  *  where c, sx, and sy are zero-padded and in big-endian byte-order.
//  *  Cf. `group_public_key_ZZZ.h` for the serialization of `gpk`.
//  *
//  * The provided buffer is assumed to be large enough.
//  */
// void ecdaa_issuer_public_key_ZZZ_serialize(uint8_t *buffer_out,
//                                             struct ecdaa_issuer_public_key_ZZZ *ipk);
// 
// int ecdaa_issuer_public_key_ZZZ_serialize_fp(FILE *p,
//                                             struct ecdaa_issuer_public_key_ZZZ *ipk);
// 
// int ecdaa_issuer_public_key_ZZZ_serialize_file(const char* file,
//                                            struct ecdaa_issuer_public_key_ZZZ *ipk);
// 
// 
// 
// /*
//  * De-serialize an `ecdaa_issuer_public_key_ZZZ` and check its validity and signature.
//  *
//  * The expected serialized format is:
//  *  ( gpk | c | sx | sy )
//  *  where c, sx, and sy are zero-padded and in big-endian byte-order.
//  *  Cf. `group_public_key_ZZZ.h` for the serialization of `gpk`.
//  *
//  *  Returns:
//  *  0 on success
//  *  -1 if gpk is invalid
//  *  -1 if format of c, sx, or sy is invalid
//  *  -2 if (c, sx, sy) don't verify
//  */
// int ecdaa_issuer_public_key_ZZZ_deserialize(struct ecdaa_issuer_public_key_ZZZ *ipk_out,
//                                              uint8_t *buffer_in);
// 
// int ecdaa_issuer_public_key_ZZZ_deserialize_file(struct ecdaa_issuer_public_key_ZZZ *ipk_out,
//                                             const char* file);
// 
// int ecdaa_issuer_public_key_ZZZ_deserialize_fp(struct ecdaa_issuer_public_key_ZZZ *ipk_out,
//                                             FILE* fp);

#ifdef __cplusplus
}
#endif

#endif

