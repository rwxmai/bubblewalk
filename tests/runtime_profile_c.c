#include "../include/ioctl_runtime_26100_1.h"

int nuRuntimeProfileMatchesC(const NU_CODE_CHECK* check, const unsigned char* bytes) {
    return NuIoctlRuntimeCodeMatches(check, bytes);
}
