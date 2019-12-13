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

#include <ecdaa/issuer_nonce_ZZZ.h>
#include <ecdaa/util/file_io.h>
#include <ecdaa/util/errors.h>

#include "amcl-extensions/ecp_ZZZ.h"

#include <ecdaa/group_public_key_ZZZ.h>

static
int ecdaa_issuer_nonce_ZZZ_compute_B(struct ecdaa_issuer_nonce_ZZZ *nonce);


size_t ecdaa_issuer_nonce_ZZZ_length(void) {
    return ECDAA_ISSUER_NONCE_ZZZ_LENGTH;
}

size_t ecdaa_issuer_nonce_ZZZ_m_length(void) {
    return ECDAA_ISSUER_NONCE_ZZZ_M_LENGTH;
}

void ecdaa_issuer_nonce_ZZZ_access_m(const uint8_t **m_out,
                                     const struct ecdaa_issuer_nonce_ZZZ *nonce)
{
    *m_out = nonce->sc + 4;
}

int ecdaa_issuer_nonce_ZZZ_generate(struct ecdaa_issuer_nonce_ZZZ *nonce_out,
                                    ecdaa_rand_func get_random)
{
    BIG_XXX curve_order;
    BIG_XXX_rcopy(curve_order, CURVE_Order_ZZZ);

    // 1) Choose random m <- Z_p
    BIG_XXX m;
    ecp_ZZZ_random_mod_order(&m, get_random);

    // 2) Copy m into sc
    BIG_XXX_toBytes((char*)(nonce_out->sc + 4), m);

    // 3) Find (sc, yc)
    //      (this also sets B = ecp_fromhash(m))
    uint16_t sc_length_ignore;
    int hash_ret = ecp_ZZZ_fromhash_pre(&nonce_out->B,
                                        nonce_out->sc,
                                        &sc_length_ignore,
                                        nonce_out->sc + 4,  // TODO: Don't double-copy
                                        MODBYTES_XXX);
    if (0 != hash_ret)
        return hash_ret;

    // 3i) Extract yc from the generated_point
    BIG_XXX x_ignore;
    ECP_ZZZ_get(x_ignore, nonce_out->yc, &nonce_out->B);  // TODO: Don't double-copy

    return 0;
}

// void ecdaa_issuer_public_key_ZZZ_serialize(uint8_t *buffer_out,
//                                            struct ecdaa_issuer_public_key_ZZZ *ipk)
// {
//     ecdaa_group_public_key_ZZZ_serialize(buffer_out, &ipk->gpk);
// 
//     BIG_XXX_toBytes((char*)(buffer_out + ecdaa_group_public_key_ZZZ_length()), ipk->c);
//     BIG_XXX_toBytes((char*)(buffer_out + ecdaa_group_public_key_ZZZ_length() + MODBYTES_XXX), ipk->sx);
//     BIG_XXX_toBytes((char*)(buffer_out + ecdaa_group_public_key_ZZZ_length() + 2*MODBYTES_XXX), ipk->sy);
// }
// 
// int ecdaa_issuer_public_key_ZZZ_serialize_file(const char* file,
//                                            struct ecdaa_issuer_public_key_ZZZ *ipk)
// {
//     uint8_t buffer[ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH] = {0};
//     ecdaa_issuer_public_key_ZZZ_serialize(buffer, ipk);
// 
//     int write_ret = ecdaa_write_buffer_to_file(file, buffer, ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH);
//     if (ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH != write_ret) {
//         return write_ret;
//     }
// 
//     return SUCCESS;
// }
// 
// int ecdaa_issuer_public_key_ZZZ_serialize_fp(FILE* fp,
//                                            struct ecdaa_issuer_public_key_ZZZ *ipk)
// {
//     uint8_t buffer[ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH] = {0};
//     ecdaa_issuer_public_key_ZZZ_serialize(buffer, ipk);
// 
//     int write_ret = ecdaa_write_buffer_to_fp(fp, buffer, ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH);
//     if (ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH != write_ret) {
//         return write_ret;
//     }
// 
//     return SUCCESS;
// }
// 
// int ecdaa_issuer_public_key_ZZZ_deserialize(struct ecdaa_issuer_public_key_ZZZ *ipk_out,
//                                             uint8_t *buffer_in)
// {
//     int ret = 0;
// 
//     // 1) Deserialize the gpk
//     //  (This also checks gpk.X and gpk.Y for membership in G2)
//     int deserial_ret = ecdaa_group_public_key_ZZZ_deserialize(&ipk_out->gpk, buffer_in);
//     if (0 != deserial_ret)
//         ret = -1;
// 
//     // 2) Deserialize the issuer_schnorr signature
//     BIG_XXX_fromBytes(ipk_out->c, (char*)(buffer_in + ecdaa_group_public_key_ZZZ_length()));
//     BIG_XXX_fromBytes(ipk_out->sx, (char*)(buffer_in + ecdaa_group_public_key_ZZZ_length() + MODBYTES_XXX));
//     BIG_XXX_fromBytes(ipk_out->sy, (char*)(buffer_in + ecdaa_group_public_key_ZZZ_length() + 2*MODBYTES_XXX));
// 
//     // 3) Check the signature
//     int sign_ret = ecdaa_issuer_public_key_ZZZ_validate(ipk_out);
//     if (0 != sign_ret)
//         ret = -2;
// 
//     return ret;
// }
// 
// int ecdaa_issuer_public_key_ZZZ_deserialize_file(struct ecdaa_issuer_public_key_ZZZ *ipk_out,
//                                             const char* file)
// {
//     uint8_t buffer[ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH] = {0};
// 
//     int read_ret = ecdaa_read_from_file(buffer, ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH, file);
//     if (ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH != read_ret) {
//         return read_ret;
//     }
//     int deserialize_ret = ecdaa_issuer_public_key_ZZZ_deserialize(ipk_out, buffer);
//     if (0 != deserialize_ret)
//         return DESERIALIZE_KEY_ERROR;
// 
//     return SUCCESS;
// }
// 
// int ecdaa_issuer_public_key_ZZZ_deserialize_fp(struct ecdaa_issuer_public_key_ZZZ *ipk_out,
//                                             FILE* fp)
// {
//     uint8_t buffer[ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH] = {0};
// 
//     int read_ret = ecdaa_read_from_fp(buffer, ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH, fp);
//     if (ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH != read_ret) {
//         return read_ret;
//     }
//     int deserialize_ret = ecdaa_issuer_public_key_ZZZ_deserialize(ipk_out, buffer);
//     if (0 != deserialize_ret)
//         return DESERIALIZE_KEY_ERROR;
// 
//     return SUCCESS;
// }

int ecdaa_issuer_nonce_ZZZ_compute_B(struct ecdaa_issuer_nonce_ZZZ *nonce)
{
    // B = (Hash(sc), yc) from an `ecdaa_issuer_nonce`

    // 1) Compute xc = Hash(sc)
    BIG_XXX x;
    big_XXX_from_hash(&x, nonce->sc, 4 + MODBYTES_XXX);

    // 2) Compute B as (xc, yc)
    if (!ECP_ZZZ_set(&nonce->B, x, nonce->yc)) {
        return -1;
    }

    return 0;
}
