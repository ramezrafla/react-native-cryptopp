#include "ed_sha512.h"
#include "ed_ge.h"

extern "C" {
  void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed);
}