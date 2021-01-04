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

#include "../ecdaa-test-utils.h"
#include "tpm_ZZZ-test-utils.h"

#include "schnorr-tpm/schnorr_TPM_ZZZ.h"
#include "schnorr/schnorr_FP256BN.h"
#include "amcl-extensions/ecp_FP256BN.h"

#include <ecdaa-tpm/tpm_context.h>

#include <string.h>

#define MAX_REPS 10000

static void schnorr_TPM_repeated(int schnorr_repetitions);

int main(int argc, char *argv[])
{
    int schnorr_repetitions = 5;
    if (argc == 2) {
        schnorr_repetitions = atoi(argv[1]);
        if (schnorr_repetitions < 1 || schnorr_repetitions > MAX_REPS) {
            fprintf(stderr, "Invalid value '%s' pass to 'repetitions' argument\n", argv[1]);
            return 1;
        }
    }

    schnorr_TPM_repeated(schnorr_repetitions);
}

void schnorr_TPM_repeated(int schnorr_repetitions)
{
    // The basic Schnorr primitive includes randomness in two places:
    // - in the "commit" stage, and
    // - for the "n" nonce during the "sign" stage

    printf("Starting schnorr_TPM::schnorr_TPM_repeated...\n");

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    uint8_t *basename = (uint8_t*) "BASENAME";
    uint32_t basename_len = strlen((char*)basename);

    BIG_XXX c, s, n;
    ECP_ZZZ K;

    ECP_ZZZ basepoint;
    ecp_ZZZ_set_to_generator(&basepoint);
    // BIG_XXX rand;

    struct tpm_test_context ctx;

    for (int i=0; i<schnorr_repetitions; ++i) {
        TEST_ASSERT(0 == tpm_initialize(&ctx));

        // ecp_ZZZ_random_mod_order(&rand, test_randomness);
        // ECP_ZZZ_mul(&basepoint, rand);

        int ret = schnorr_sign_TPM_ZZZ(&c, &s, &n, &K, msg, msg_len, &basepoint, &ctx.public_key, basename, basename_len, &ctx.tpm_ctx);
        if (0 != ret) {
            printf("Error in schnorr_sign_TPM_ZZZ, ret=%d, tpm_rc=0x%x\n", ret, ctx.tpm_ctx.last_return_code);
            TEST_ASSERT(0==1);
        }

        ret = schnorr_verify_ZZZ(c, s, n, &K, msg, msg_len, &basepoint, &ctx.public_key, basename, basename_len);
        if (0 != ret) {
            printf("Error in schnorr_verify_TPM_ZZZ, ret=%d, tpm_rc=0x%x\n", ret, ctx.tpm_ctx.last_return_code);
            TEST_ASSERT(0==1);
        }

        tpm_cleanup(&ctx);
    }

    printf("\tsuccess\n");
}

