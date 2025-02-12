#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <filesystem>

namespace nu {
struct RuntimeFunction { uint32_t Begin, End, Unwind; };
static_assert(sizeof(RuntimeFunction) == 12);
struct Section { uint32_t Begin, Size, Characteristics; };

class PeImage {
public:
    static PeImage load(const std::filesystem::path& path);
    static PeImage parse(const std::vector<uint8_t>& file);
    bool read(uint64_t rva, void* out, size_t size) const;
    bool executable(uint64_t rva) const;
    const RuntimeFunction* function(uint64_t rva) const;
    uint32_t size() const { return size_; }
    uint32_t timestamp() const { return timestamp_; }
    uint32_t checksum() const { return checksum_; }
private:
    uint32_t size_ = 0, headers_ = 0, timestamp_ = 0, checksum_ = 0;
    std::vector<uint8_t> image_;
    std::vector<Section> sections_;
    std::vector<RuntimeFunction> functions_;
};

bool readRegion(uint64_t base, const uint8_t* bytes, size_t available,
                uint64_t address, void* output, size_t wanted);
}
