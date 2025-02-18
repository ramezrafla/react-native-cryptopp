#ifndef ED25519_H
#define ED25519_H
#include "ed_fe.h"
#include "ed_fixedint.h"
#include "ed_ge.h"
#include "ed_key_exchange.h"
#include "ed_keypair.h"
#include "ed_precomp_data.h"
#include "ed_sc.h"
#include "ed_seed.h"
#include "ed_sha512.h"
#include "ed_sign.h"
#include "ed_verify.h"
#include <stddef.h>

extern "C" {

    int ed25519_create_seed(unsigned char *seed);
    void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed);
    void ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key);
    int ed25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key);
    void ed25519_add_scalar(unsigned char *public_key, unsigned char *private_key, const unsigned char *scalar);
    void ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key);

}

#endif