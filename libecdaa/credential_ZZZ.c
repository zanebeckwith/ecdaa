/******************************************************************************
 *
 * Copyright 2017 Xaptum, Inc.
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

#include <ecdaa/credential_ZZZ.h>
#include <ecdaa/util/file_io.h>
#include <ecdaa/util/errors.h>

#include "schnorr/schnorr_ZZZ.h"
#include "internal-utilities/explicit_bzero.h"
#include "amcl-extensions/ecp_ZZZ.h"
#include "amcl-extensions/ecp2_ZZZ.h"
#include "amcl-extensions/pairing_ZZZ.h"

#include <ecdaa/member_keypair_ZZZ.h>
#include <ecdaa/issuer_keypair_ZZZ.h>
#include <ecdaa/group_public_key_ZZZ.h>

size_t ecdaa_credential_ZZZ_length(void)
{
    return ECDAA_CREDENTIAL_ZZZ_LENGTH;
}

int ecdaa_credential_ZZZ_generate(struct ecdaa_credential_ZZZ *cred,
                                  struct ecdaa_issuer_secret_key_ZZZ *isk,
                                  struct ecdaa_member_public_key_ZZZ *member_pk,
                                  struct ecdaa_issuer_nonce_ZZZ *nonce)
{
    int ret = 0;

    BIG_XXX curve_order;
    BIG_XXX_rcopy(curve_order, CURVE_Order_ZZZ);

    // cred->A = (1/y)*nonce->B
    // 1) Calculate 1/y
    BIG_XXX y_inv;
    BIG_XXX_invmodp(y_inv, isk->y, curve_order);

    // 2) cred->A = (1/y)*nonce->B
    ECP_ZZZ_copy(&cred->A, &nonce->B);
    ECP_ZZZ_mul(&cred->A, y_inv);

    // cred->B = nonce->B
    // 3) Copy nonce->B to cred->B
    ECP_ZZZ_copy(&cred->B, &nonce->B);

    // cred->C = x*(cred->A + member_pk->Q)
    // 4) Add A and Q and save to cred->C (store in cred->C temporarily)
    //      Nb. Add doesn't convert to affine, so do that explicitly (TODO: Maybe don't need this. _mul will convert to affine)
    ECP_ZZZ_copy(&cred->C, &cred->A);
    ECP_ZZZ_add(&cred->C, &member_pk->Q);
    // ECP_ZZZ_affine(&cred->C);

    // 5) Multiply (A+Q) by my secret x (A+Q already in cred->C)
    ECP_ZZZ_mul(&cred->C, isk->x);

    // cred->D = member_pk->Q
    // 6) Save member's public_key to cred->D
    ECP_ZZZ_copy(&cred->D, &member_pk->Q);

    // Clear sensitive intermediate memory
    explicit_bzero(&y_inv, sizeof(BIG_XXX));

    return ret;
}

// int ecdaa_credential_ZZZ_validate(struct ecdaa_credential_ZZZ *credential,
//                                   struct ecdaa_member_public_key_ZZZ *member_pk,
//                                   struct ecdaa_group_public_key_ZZZ *gpk,
//                                   struct ecdaa_issuer_nonce_ZZZ *nonce)
// {
//     int ret = 0;
// 
//     // 1) Check A,B,C,D for membership in group, and A for !=inf
//     // NOTE: We assume the credential was obtained from a call to `deserialize`,
//     //  which already checked the validity of the points A,B,C,D
// 
//     // 2) Check e(A, Y) == e(B, P_2)
//     FP12_YYY pairing_one;
//     FP12_YYY pairing_one_prime;
//     compute_pairing_ZZZ(&pairing_one, &credential->A, &gpk->Y);
//     compute_pairing_ZZZ(&pairing_one_prime, &credential->B, &basepoint2);
//     if (!FP12_YYY_equals(&pairing_one, &pairing_one_prime))
//         ret = -1;
// 
//     // e(C, P_2) == e(A+D, X)
//     // 3) Compute A+D
//     //      Nb. Add doesn't convert to affine, so do that explicitly
//     ECP_ZZZ AD;
//     ECP_ZZZ_copy(&AD, &credential->A);
//     ECP_ZZZ_add(&AD, &credential->D);
//     ECP_ZZZ_affine(&AD);
// 
//     // 4) Check e(C, P_2) == e(A+D, X)
//     FP12_YYY pairing_two;
//     FP12_YYY pairing_two_prime;
//     compute_pairing_ZZZ(&pairing_two, &credential->C, &basepoint2);
//     compute_pairing_ZZZ(&pairing_two_prime, &AD, &gpk->X);
//     if (!FP12_YYY_equals(&pairing_two, &pairing_two_prime))
//         ret = -1;
// 
//     return ret;
// }
// 
// void ecdaa_credential_ZZZ_serialize(uint8_t *buffer_out,
//                                     struct ecdaa_credential_ZZZ *credential)
// {
//     ecp_ZZZ_serialize(buffer_out, &credential->A);
//     ecp_ZZZ_serialize(buffer_out + ECP_ZZZ_LENGTH, &credential->B);
//     ecp_ZZZ_serialize(buffer_out + 2*ECP_ZZZ_LENGTH, &credential->C);
//     ecp_ZZZ_serialize(buffer_out + 3*ECP_ZZZ_LENGTH, &credential->D);
// }
// 
// int ecdaa_credential_ZZZ_serialize_file(const char* file,
//                                     struct ecdaa_credential_ZZZ *credential)
// {
//     uint8_t buffer[ECDAA_CREDENTIAL_ZZZ_LENGTH] = {0};
//     ecdaa_credential_ZZZ_serialize(buffer, credential);
//     int write_ret = ecdaa_write_buffer_to_file(file, buffer, ECDAA_CREDENTIAL_ZZZ_LENGTH);
//     if (ECDAA_CREDENTIAL_ZZZ_LENGTH != write_ret) {
//         return write_ret;
//     }
//     return SUCCESS;
// }
// 
// int ecdaa_credential_ZZZ_serialize_fp(FILE* fp,
//                                     struct ecdaa_credential_ZZZ *credential)
// {
//     uint8_t buffer[ECDAA_CREDENTIAL_ZZZ_LENGTH] = {0};
//     ecdaa_credential_ZZZ_serialize(buffer, credential);
//     int write_ret = ecdaa_write_buffer_to_fp(fp, buffer, ECDAA_CREDENTIAL_ZZZ_LENGTH);
//     if (ECDAA_CREDENTIAL_ZZZ_LENGTH != write_ret) {
//         return write_ret;
//     }
//     return SUCCESS;
// }
// 
// int ecdaa_credential_ZZZ_deserialize(struct ecdaa_credential_ZZZ *credential_out,
//                                      uint8_t *buffer_in)
// {
//     int ret = 0;
// 
//     if (0 != ecp_ZZZ_deserialize(&credential_out->A, buffer_in))
//         ret = -1;
// 
//     if (0 != ecp_ZZZ_deserialize(&credential_out->B, buffer_in + ECP_ZZZ_LENGTH))
//         ret = -1;
// 
//     if (0 != ecp_ZZZ_deserialize(&credential_out->C, buffer_in + 2*ECP_ZZZ_LENGTH))
//         ret = -1;
// 
//     if (0 != ecp_ZZZ_deserialize(&credential_out->D, buffer_in + 3*ECP_ZZZ_LENGTH))
//         ret = -1;
// 
//     if (0 == ret) {
//         int valid_ret = ecdaa_credential_ZZZ_validate(credential_out, &cred_sig, member_pk, gpk);
//         if (0 != valid_ret)
//             ret = -2;
//     }
// 
//     return ret;
// }
// 
// int ecdaa_credential_ZZZ_deserialize_file(struct ecdaa_credential_ZZZ *credential_out,
//                                      const char* file)
// {
//     uint8_t buffer[ECDAA_CREDENTIAL_ZZZ_LENGTH] = {0};
//     int read_ret = ecdaa_read_from_file(buffer, ECDAA_CREDENTIAL_ZZZ_LENGTH, file);
//     if (ECDAA_CREDENTIAL_ZZZ_LENGTH != read_ret) {
//         return read_ret;
//     }
//     int ret = ecdaa_credential_ZZZ_deserialize(credential_out, buffer);
//     if (0 != ret) {
//         return DESERIALIZE_KEY_ERROR;
//     }
//     return SUCCESS;
// }
// 
// int ecdaa_credential_ZZZ_deserialize_fp(struct ecdaa_credential_ZZZ *credential_out,
//                                      FILE* fp)
// {
//     uint8_t buffer[ECDAA_CREDENTIAL_ZZZ_LENGTH] = {0};
//     int read_ret = ecdaa_read_from_fp(buffer, ECDAA_CREDENTIAL_ZZZ_LENGTH, fp);
//     if (ECDAA_CREDENTIAL_ZZZ_LENGTH != read_ret) {
//         return read_ret;
//     }
//     int ret = ecdaa_credential_ZZZ_deserialize(credential_out, buffer);
//     if (0 != ret) {
//         return DESERIALIZE_KEY_ERROR;
//     }
//     return SUCCESS;
// }
