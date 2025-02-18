#include "ed_seed.h"

int ed25519_create_seed(unsigned char *seed) {
    FILE *f = fopen("/dev/urandom", "rb");

    if (f == NULL) {
        return 1;
    }

    fread(seed, 1, 32, f);
    fclose(f);

    return 0;
}
