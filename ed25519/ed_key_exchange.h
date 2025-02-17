#include "ed25519.h"
#include "ed_fe.h"

void ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key);