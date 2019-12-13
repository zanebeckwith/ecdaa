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

#include <ecdaa/member_keypair_ZZZ.h>
#include <ecdaa/util/errors.h>
#include <ecdaa/util/file_io.h>
#include "amcl-extensions/ecp_ZZZ.h"
#include "schnorr/schnorr_ZZZ.h"

#include <assert.h>

size_t ecdaa_member_public_key_ZZZ_length(void)
{
   return ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH;
}

size_t ecdaa_member_secret_key_ZZZ_length(void)
{
    return ECDAA_MEMBER_SECRET_KEY_ZZZ_LENGTH;
}

int ecdaa_member_key_pair_ZZZ_generate(struct ecdaa_member_public_key_ZZZ *pk,
                                       struct ecdaa_member_secret_key_ZZZ *sk,
                                       struct ecdaa_issuer_nonce_ZZZ *nonce,
                                       ecdaa_rand_func get_random)
{
    // 1) Generate Schnorr-type keypair,
    //      Q = sk * B, where B is the B-value of the nonce.
    schnorr_keygen_from_basepoint_ZZZ(&pk->Q, &sk->sk, &nonce->B, get_random);

    // 2) and a Schnorr-type signature on the Schnorr-type public_key itself concatenated with the `m`-value of the nonce.
    const uint8_t *m;
    ecdaa_issuer_nonce_ZZZ_access_m(&m, nonce);
    ECP_ZZZ generator;
    ecp_ZZZ_set_to_generator(&generator);
    int sign_ret = schnorr_sign_ZZZ(&pk->c,
                                    &pk->s,
                                    &pk->n,
                                    NULL,
                                    m,
                                    ECDAA_ISSUER_NONCE_ZZZ_M_LENGTH,
                                    &generator,
                                    &nonce->B,
                                    &pk->Q,
                                    sk->sk,
                                    NULL,
                                    0,
                                    get_random);

    return sign_ret;
}

int ecdaa_member_public_key_ZZZ_validate(struct ecdaa_member_public_key_ZZZ *pk,
                                         struct ecdaa_issuer_nonce_ZZZ *nonce)
{
    int ret = 0;

    ECP_ZZZ generator;
    ecp_ZZZ_set_to_generator(&generator);
    const uint8_t *m;
    ecdaa_issuer_nonce_ZZZ_access_m(&m, nonce);
    int sign_ret = schnorr_verify_ZZZ(pk->c,
                                      pk->s,
                                      pk->n,
                                      NULL,
                                      m,
                                      ECDAA_ISSUER_NONCE_ZZZ_M_LENGTH,
                                      &generator,
                                      &nonce->B,
                                      &pk->Q,
                                      NULL,
                                      0);
    if (0 != sign_ret)
        ret = -1;

    return ret;
}

void ecdaa_member_public_key_ZZZ_serialize(uint8_t *buffer_out,
                                           struct ecdaa_member_public_key_ZZZ *pk)
{
    ecp_ZZZ_serialize(buffer_out, &pk->Q);
    BIG_XXX_toBytes((char*)(buffer_out + ecp_ZZZ_length()), pk->c);
    BIG_XXX_toBytes((char*)(buffer_out + ecp_ZZZ_length() + MODBYTES_XXX), pk->s);
    BIG_XXX_toBytes((char*)(buffer_out + ecp_ZZZ_length() + MODBYTES_XXX + MODBYTES_XXX), pk->n);
}

int ecdaa_member_public_key_ZZZ_serialize_file(const char* file,
                                           struct ecdaa_member_public_key_ZZZ *pk)
{
    uint8_t buffer[ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH] = {0};
    ecdaa_member_public_key_ZZZ_serialize(buffer, pk);
    int write_ret = ecdaa_write_buffer_to_file(file, buffer, ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH);
    if (ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH != write_ret) {
        return write_ret;
    }
    return SUCCESS;
}

int ecdaa_member_public_key_ZZZ_serialize_fp(FILE* fp,
                                           struct ecdaa_member_public_key_ZZZ *pk)
{
    uint8_t buffer[ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH] = {0};
    ecdaa_member_public_key_ZZZ_serialize(buffer, pk);
    int write_ret = ecdaa_write_buffer_to_fp(fp, buffer, ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH);
    if (ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH != write_ret) {
        return write_ret;
    }
    return SUCCESS;
}

int ecdaa_member_public_key_ZZZ_deserialize(struct ecdaa_member_public_key_ZZZ *pk_out,
                                            uint8_t *buffer_in,
                                            struct ecdaa_issuer_nonce_ZZZ *nonce)
{
    int ret = 0;

    // 1) Deserialize public key and its signature.
    int deserial_ret = ecdaa_member_public_key_ZZZ_deserialize_no_check(pk_out, buffer_in);
    if (0 != deserial_ret)
        ret = -1;

    if (0 == deserial_ret) {
        // 3) Verify the schnorr signature.
        //  (This also verifies that the public key is valid).
        int schnorr_ret = ecdaa_member_public_key_ZZZ_validate(pk_out, nonce);
        if (0 != schnorr_ret)
            ret = -2;
    }

    return ret;
}

int ecdaa_member_public_key_ZZZ_deserialize_file(struct ecdaa_member_public_key_ZZZ *pk_out,
                                            const char* file,
                                            struct ecdaa_issuer_nonce_ZZZ *nonce)
{
    uint8_t buffer[ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH] = {0};
    int read_ret = ecdaa_read_from_file(buffer, ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH, file);
    if (ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH != read_ret) {
        return read_ret;
    }
    int deserialize_ret = ecdaa_member_public_key_ZZZ_deserialize(pk_out, buffer, nonce);
    if (0 != deserialize_ret) {
        return DESERIALIZE_KEY_ERROR;
    }
    return SUCCESS;
}

int ecdaa_member_public_key_ZZZ_deserialize_fp(struct ecdaa_member_public_key_ZZZ *pk_out,
                                            FILE* file,
                                            struct ecdaa_issuer_nonce_ZZZ *nonce)
{
    uint8_t buffer[ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH] = {0};
    int read_ret = ecdaa_read_from_fp(buffer, ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH, file);
    if (ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH != read_ret) {
        return read_ret;
    }
    int deserialize_ret = ecdaa_member_public_key_ZZZ_deserialize(pk_out, buffer, nonce);
    if (0 != deserialize_ret) {
        return DESERIALIZE_KEY_ERROR;
    }
    return SUCCESS;
}

int ecdaa_member_public_key_ZZZ_deserialize_no_check(struct ecdaa_member_public_key_ZZZ *pk_out,
                                                     uint8_t *buffer_in)
{
    int ret = 0;

    // 1) Deserialize schnorr public key Q.
    int deserial_ret = ecp_ZZZ_deserialize(&pk_out->Q, buffer_in);
    if (0 != deserial_ret)
        ret = -1;

    // 2) Deserialize the schnorr signature
    BIG_XXX_fromBytes(pk_out->c, (char*)(buffer_in + ecp_ZZZ_length()));
    BIG_XXX_fromBytes(pk_out->s, (char*)(buffer_in + ecp_ZZZ_length() + MODBYTES_XXX));
    BIG_XXX_fromBytes(pk_out->n, (char*)(buffer_in + ecp_ZZZ_length() + MODBYTES_XXX + MODBYTES_XXX));

    return ret;
}

int ecdaa_member_public_key_ZZZ_deserialize_no_check_file(struct ecdaa_member_public_key_ZZZ *pk_out,
                                                     const char *file)
{
    uint8_t buffer[ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH] = {0};
    int read_ret = ecdaa_read_from_file(buffer, ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH, file);
    if (ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH != read_ret) {
        return read_ret;
    }

    int ret = ecdaa_member_public_key_ZZZ_deserialize_no_check(pk_out, buffer);
    if (0 != ret) {
        return DESERIALIZE_KEY_ERROR;
    }

    return SUCCESS;
}

int ecdaa_member_public_key_ZZZ_deserialize_no_check_fp(struct ecdaa_member_public_key_ZZZ *pk_out,
                                                     FILE *file)
{
    uint8_t buffer[ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH] = {0};
    int read_ret = ecdaa_read_from_fp(buffer, ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH, file);
    if (ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH != read_ret) {
        return read_ret;
    }

    int ret = ecdaa_member_public_key_ZZZ_deserialize_no_check(pk_out, buffer);
    if (0 != ret) {
        return DESERIALIZE_KEY_ERROR;
    }

    return SUCCESS;
}

void ecdaa_member_secret_key_ZZZ_serialize(uint8_t *buffer_out,
                                           struct ecdaa_member_secret_key_ZZZ *sk)
{
    BIG_XXX_toBytes((char*)buffer_out, sk->sk);
}

int ecdaa_member_secret_key_ZZZ_serialize_file(const char* file,
                                           struct ecdaa_member_secret_key_ZZZ *sk)
{
    uint8_t buffer[ECDAA_MEMBER_SECRET_KEY_ZZZ_LENGTH] = {0};
    ecdaa_member_secret_key_ZZZ_serialize(buffer, sk);
    int write_ret = ecdaa_write_buffer_to_file(file, buffer, ECDAA_MEMBER_SECRET_KEY_ZZZ_LENGTH);
    if (ECDAA_MEMBER_SECRET_KEY_ZZZ_LENGTH != write_ret) {
        return write_ret;
    }
    return SUCCESS;
}

int ecdaa_member_secret_key_ZZZ_serialize_fp(FILE* fp,
                                           struct ecdaa_member_secret_key_ZZZ *sk)
{
    uint8_t buffer[ECDAA_MEMBER_SECRET_KEY_ZZZ_LENGTH] = {0};
    ecdaa_member_secret_key_ZZZ_serialize(buffer, sk);
    int write_ret = ecdaa_write_buffer_to_fp(fp, buffer, ECDAA_MEMBER_SECRET_KEY_ZZZ_LENGTH);
    if (ECDAA_MEMBER_SECRET_KEY_ZZZ_LENGTH != write_ret) {
        return write_ret;
    }
    return SUCCESS;
}

int ecdaa_member_secret_key_ZZZ_deserialize(struct ecdaa_member_secret_key_ZZZ *sk_out,
                                            uint8_t *buffer_in)
{
    BIG_XXX_fromBytes(sk_out->sk, (char*)buffer_in);

    return 0;
}

int ecdaa_member_secret_key_ZZZ_deserialize_file(struct ecdaa_member_secret_key_ZZZ *sk_out,
                                            const char* file)
{
    uint8_t buffer[ECDAA_MEMBER_SECRET_KEY_ZZZ_LENGTH] = {0};
    int read_ret = ecdaa_read_from_file(buffer, ECDAA_MEMBER_SECRET_KEY_ZZZ_LENGTH, file);
    if (ECDAA_MEMBER_SECRET_KEY_ZZZ_LENGTH != read_ret) {
        return read_ret;
    }
    int ret = ecdaa_member_secret_key_ZZZ_deserialize(sk_out, buffer);
    if (0 != ret) {
        return DESERIALIZE_KEY_ERROR;
    }
    return SUCCESS;
}

int ecdaa_member_secret_key_ZZZ_deserialize_fp(struct ecdaa_member_secret_key_ZZZ *sk_out,
                                            FILE* fp)
{
    uint8_t buffer[ECDAA_MEMBER_SECRET_KEY_ZZZ_LENGTH] = {0};
    int read_ret = ecdaa_read_from_fp(buffer, ECDAA_MEMBER_SECRET_KEY_ZZZ_LENGTH, fp);
    if (ECDAA_MEMBER_SECRET_KEY_ZZZ_LENGTH != read_ret) {
        return read_ret;
    }
    int ret = ecdaa_member_secret_key_ZZZ_deserialize(sk_out, buffer);
    if (0 != ret) {
        return DESERIALIZE_KEY_ERROR;
    }
    return SUCCESS;
}
