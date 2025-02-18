#include "ed_sha512.h"
#include "ed_ge.h"
#include "ed_sc.h"

void ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key);