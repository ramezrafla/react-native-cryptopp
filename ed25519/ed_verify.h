#include "ed_sha512.h"
#include "ed_ge.h"
#include "ed_sc.h"

static int consttime_equal(const unsigned char *x, const unsigned char *y);