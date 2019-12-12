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

#include "ecdaa-test-utils.h"

#include "schnorr/schnorr_ZZZ.h"

#include "amcl-extensions/big_XXX.h"
#include "amcl-extensions/ecp_ZZZ.h"
#include "amcl-extensions/ecp2_ZZZ.h"

#include <ecdaa/credential_ZZZ.h>

#include <amcl/big_XXX.h>
#include <amcl/ecp_ZZZ.h>

#include <string.h>
#include <stdio.h>

#define MAX_REPS 10000

static void schnorr_repeated(int schnorr_repetitions);

int main(int argc, char *argv[])
{
    int schnorr_repetitions = 20;
    if (argc == 2) {
        schnorr_repetitions = atoi(argv[1]);
        if (schnorr_repetitions < 1 || schnorr_repetitions > MAX_REPS) {
            fprintf(stderr, "Invalid value '%s' pass to 'repetitions' argument\n", argv[1]);
            return 1;
        }
    }

    schnorr_repeated(schnorr_repetitions);
}

void schnorr_repeated(int schnorr_repetitions)
{
    // The basic Schnorr primitive includes randomness in two places:
    // - in the "commit" stage, and
    // - for the "n" nonce during the "sign" stage

    printf("Starting schnorr::schnorr_repeated...\n");

    uint8_t raw_len = 0;

    uint32_t msg_len = 0;
    uint8_t msg[UINT8_MAX];

    uint32_t basename_len = 0;
    uint8_t basename[UINT8_MAX];

    BIG_XXX c, s, n;
    ECP_ZZZ K;

    ECP_ZZZ basepoint;
    ecp_ZZZ_set_to_generator(&basepoint);
    BIG_XXX rand;

    ECP_ZZZ public;
    BIG_XXX private;

    for (int i=0; i<schnorr_repetitions; ++i) {
        do {
            test_randomness(&raw_len, sizeof(raw_len)); // generate random number between 0 and 255
        } while(raw_len == 0);
        msg_len = raw_len;
        test_randomness(msg, msg_len);

        do {
            test_randomness(&raw_len, sizeof(raw_len)); // generate random number between 0 and 255
        } while(raw_len == 0);
        basename_len = raw_len;
        test_randomness(basename, basename_len);

        ecp_ZZZ_random_mod_order(&rand, test_randomness);
        ECP_ZZZ_mul(&basepoint, rand);

        ecp_ZZZ_random_mod_order(&private, test_randomness);
        ECP_ZZZ_copy(&public, &basepoint);
        ECP_ZZZ_mul(&public, private);

        TEST_ASSERT(0 == schnorr_sign_ZZZ(&c, &s, &n, &K, msg, msg_len, &basepoint, &public, private, basename, basename_len, test_randomness));

        TEST_ASSERT(0 == schnorr_verify_ZZZ(c, s, n, &K, msg, msg_len, &basepoint, &public, basename, basename_len));
    }

    printf("\tsuccess\n");
}
