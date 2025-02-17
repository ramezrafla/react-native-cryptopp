#include "ed25519.h"
#include "ed_ge.h"
#include "ed_sc.h"
#include "ed_sha512.h"

void ed25519_add_scalar(unsigned char *public_key, unsigned char *private_key, const unsigned char *scalar);