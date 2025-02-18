#include "ed_sha512.h"
#include "ed_ge.h"
#include "ed_sc.h"

static int consttime_equal(const unsigned char *x, const unsigned char *y);

extern "C" {
  int ed25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key);
}
