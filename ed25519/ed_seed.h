#include <stdio.h>

extern "C" {
  int ed25519_create_seed(unsigned char *seed);
}