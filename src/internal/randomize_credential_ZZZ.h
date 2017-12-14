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

#ifndef ECDAA_RANDOMIZE_CREDENTIAL_H
#define ECDAA_RANDOMIZE_CREDENTIAL_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ecdaa/credential_ZZZ.h>
#include <ecdaa/prng.h>
#include <ecdaa/signature_ZZZ.h>

void randomize_credential_ZZZ(struct ecdaa_credential_ZZZ *cred,
                              struct ecdaa_prng *prng,
                              struct ecdaa_signature_ZZZ *signature_out);

#ifdef __cplusplus
}
#endif

#endif

