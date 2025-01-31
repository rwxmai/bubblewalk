#pragma once
#include <cstdint>
#include <cstddef>
namespace nu {
bool readRegion(uint64_t base, const uint8_t* bytes, size_t available,
                uint64_t address, void* output, size_t wanted);
}
