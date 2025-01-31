#include "pe_image.h"
#include <cstring>
namespace nu {
namespace {
bool fits(uint64_t start, uint64_t count, uint64_t length) {
    return start <= length && count <= length - start;
}
}
bool readRegion(uint64_t base, const uint8_t* bytes, size_t available,
                uint64_t address, void* output, size_t wanted) {
    if (address < base || !fits(address - base, wanted, available)) return false;
    std::memcpy(output, bytes + size_t(address - base), wanted);
    return true;
}
}
