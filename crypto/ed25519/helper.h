/*
 * person.h
 * Copyright (C) 2019 Tim Hughes
 *
 * Distributed under terms of the MIT license.
 */

#ifndef HELPER_H
#define HELPER_H



size_t crypto_core_ed25519_uniformbytes(void);
const char * sodium_version_string(void);
int crypto_core_ed25519_is_valid_point(const unsigned char *p);
int crypto_core_ed25519_from_uniform(unsigned char *p, const unsigned char *r);
size_t crypto_sign_seedbytes(void);
void *sodium_malloc(size_t size);
void sodium_free(void *ptr);
int crypto_core_ed25519_add(unsigned char *r,const unsigned char *p, const unsigned char *q);
int crypto_core_ed25519_sub(unsigned char *r, const unsigned char *p, const unsigned char *q);
void crypto_core_ed25519_scalar_mul(unsigned char *z,const unsigned char *x, const unsigned char *y);
int crypto_scalarmult_ed25519_base_noclamp(unsigned char *q, const unsigned char *n);
int crypto_scalarmult_ed25519_noclamp(unsigned char *q, const unsigned char *n,
                                      const unsigned char *p);
int sodium_memcmp(const void * const b1_, const void * const b2_, size_t len);

#endif /* !HELPER_H */
