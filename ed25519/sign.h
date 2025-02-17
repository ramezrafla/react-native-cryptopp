#include "ed25519.h"
#include "sha512.h"
#include "ge.h"
#include "sc.h"

void ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key);