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

#ifndef ECDAA_SIGNATURE_ZZZ_H
#define ECDAA_SIGNATURE_ZZZ_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <amcl/big_XXX.h>
#include <amcl/ecp_ZZZ.h>

struct ecdaa_credential_ZZZ;
struct ecdaa_member_secret_key_ZZZ;
struct ecdaa_revocation_list_ZZZ;
struct ecdaa_group_public_key_ZZZ;
struct ecdaa_prng;

/*
 * ECDAA signature.
 */
struct ecdaa_signature_ZZZ {
    BIG_XXX c;
    BIG_XXX s;
    ECP_ZZZ R;
    ECP_ZZZ S;
    ECP_ZZZ T;
    ECP_ZZZ W;
};

#define ECDAA_SIGNATURE_ZZZ_LENGTH (2*MODBYTES_XXX + 4*(2*MODBYTES_XXX + 1))
size_t ecdaa_signature_ZZZ_length(void);
/*
 * Create an ECDAA signature.
 *
 * Returns:
 * 0 on success
 * -1 if unable to create signature
 */
int ecdaa_signature_ZZZ_sign(struct ecdaa_signature_ZZZ *signature_out,
                             const uint8_t* message,
                             uint32_t message_len,
                             struct ecdaa_member_secret_key_ZZZ *sk,
                             struct ecdaa_credential_ZZZ *cred,
                             struct ecdaa_prng *prng);

/*
 * Verify an ECDAA signature.
 *
 * Returns:
 * 0 on success
 * -1 if signature is invalid
 */
int ecdaa_signature_ZZZ_verify(struct ecdaa_signature_ZZZ *signature,
                               struct ecdaa_group_public_key_ZZZ *gpk,
                               struct ecdaa_revocation_list_ZZZ *sk_rev_list,
                               uint8_t* message,
                               uint32_t message_len);


/*
 * Serialize an `ecdaa_signature_ZZZ`
 *
 * The serialized format is:
 *  ( c | s |
 *    0x04 | R.x-coord | R.y-coord |
 *    0x04 | S.x-coord | S.y-coord |
 *    0x04 | T.x-coord | T.y-coord |
 *    0x04 | W.x-coord | W.y-coord )
 *
 * The provided buffer is assumed to be large enough.
 */
void ecdaa_signature_ZZZ_serialize(uint8_t *buffer_out,
                                   struct ecdaa_signature_ZZZ *signature);

/*
 * De-serialize an `ecdaa_signature_ZZZ`, but _don't_ verify it.
 *
 * The serialized format is expected to be:
 *  ( c | s |
 *    0x04 | R.x-coord | R.y-coord |
 *    0x04 | S.x-coord | S.y-coord |
 *    0x04 | T.x-coord | T.y-coord |
 *    0x04 | W.x-coord | W.y-coord )
 *
 *  NOTE: The four G1 points are checked as being on the curve,
 *      but not for membership in the group.
 *
 * Returns:
 * 0 on success
 * -1 if signature is mal-formed
 */
int ecdaa_signature_ZZZ_deserialize(struct ecdaa_signature_ZZZ *signature_out,
                                    uint8_t *buffer_in);

/*
 * De-serialize an `ecdaa_signature_ZZZ`, and the message it's over, and verify the signature.
 *
 * The serialized format is expected to be:
 *  ( c | s |
 *    0x04 | R.x-coord | R.y-coord |
 *    0x04 | S.x-coord | S.y-coord |
 *    0x04 | T.x-coord | T.y-coord |
 *    0x04 | W.x-coord | W.y-coord )
 *
 * Returns:
 * 0 on success
 * -1 if signature is mal-formed
 *  -2 if signature is not valid
 */
int ecdaa_signature_ZZZ_deserialize_and_verify(struct ecdaa_signature_ZZZ *signature_out,
                                               struct ecdaa_group_public_key_ZZZ *gpk,
                                               struct ecdaa_revocation_list_ZZZ *sk_rev_list,
                                               uint8_t *signature_buffer,
                                               uint8_t* message_buffer,
                                               uint32_t message_len);

#ifdef __cplusplus
}
#endif

#endif