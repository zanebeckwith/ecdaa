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
#include "ecdaa_extract_group_public_key.h"
#include <ecdaa.h>

#include <string.h>
#include <stdio.h>
#include <stdint.h>

int ecdaa_extract_gpk(const char* issuer_public_key_file, const char* group_public_key_file)
{
    // Read issuer public key from disk.
    struct ecdaa_issuer_public_key_FP256BN ipk;
    int ret = ecdaa_issuer_public_key_FP256BN_deserialize_file(&ipk, issuer_public_key_file);
    if(0 != ret)
        return ret;

    // Write group-public-key to file
    ret = ecdaa_group_public_key_FP256BN_serialize_file(group_public_key_file, &ipk.gpk);

    return ret;
}
