//
//  blake2b-common.h
//  libsse_crypto
//
//  Created by Raphael Bost on 24/05/2017.
//  Copyright © 2017 VSSE project. All rights reserved.
//

#pragma once

#ifdef __cplusplus
extern "C" {
#endif


#include <stddef.h>

void blake2b_hash(const unsigned char *in, size_t inlen, unsigned char *out);

#ifdef __cplusplus
}
#endif
