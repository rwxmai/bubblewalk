#include "pe_image.h"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <stdexcept>

namespace nu {
namespace {
bool fits(uint64_t start, uint64_t count, uint64_t length) {
    return start <= length && count <= length - start;
}
uint16_t u16(const std::vector<uint8_t>& b, uint64_t at) {
    if (!fits(at, 2, b.size())) throw std::runtime_error("truncated PE integer");
    return uint16_t(b[size_t(at)]) | uint16_t(b[size_t(at + 1)]) << 8;
}
uint32_t u32(const std::vector<uint8_t>& b, uint64_t at) {
    return uint32_t(u16(b, at)) | uint32_t(u16(b, at + 2)) << 16;
}
}

PeImage PeImage::load(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) throw std::runtime_error("cannot open PE image");
    auto length = input.tellg();
    if (length < 0 || length > 256 * 1024 * 1024)
        throw std::runtime_error("PE file exceeds research reader limit");
    std::vector<uint8_t> raw(static_cast<size_t>(length));
    input.seekg(0);
    if (!input.read(reinterpret_cast<char*>(raw.data()), length))
        throw std::runtime_error("cannot read PE image");
    return parse(raw);
}

PeImage PeImage::parse(const std::vector<uint8_t>& raw) {
    PeImage p;
    if (u16(raw, 0) != 0x5a4d) throw std::runtime_error("not MZ");
    uint64_t nt = u32(raw, 0x3c), opt = nt + 24;
    if (u32(raw, nt) != 0x4550 || u16(raw, nt + 4) != 0x8664)
        throw std::runtime_error("not AMD64 PE");
    uint32_t count = u16(raw, nt + 6), optionalSize = u16(raw, nt + 20);
    if (!count || count > 96 || optionalSize < 144 ||
        !fits(opt, optionalSize + uint64_t(count) * 40, raw.size()) ||
        u16(raw, opt) != 0x20b) throw std::runtime_error("invalid PE32+ headers");
    p.size_ = u32(raw, opt + 56);
    p.headers_ = u32(raw, opt + 60);
    p.timestamp_ = u32(raw, nt + 8);
    p.checksum_ = u32(raw, opt + 64);
    if (!p.size_ || p.size_ > 256 * 1024 * 1024 || p.headers_ > p.size_ ||
        !fits(0, p.headers_, raw.size()) ||
        opt + optionalSize + uint64_t(count) * 40 > p.headers_)
        throw std::runtime_error("invalid PE image/header size");
    p.image_.resize(p.size_);
    std::copy_n(raw.begin(), p.headers_, p.image_.begin());
    for (uint32_t i = 0; i < count; ++i) {
        uint64_t at = opt + optionalSize + uint64_t(i) * 40;
        uint32_t va = u32(raw, at + 12), rawSize = u32(raw, at + 16);
        uint32_t offset = u32(raw, at + 20), virtualSize = u32(raw, at + 8);
        uint32_t span = std::max(rawSize, virtualSize);
        if (va < p.headers_ || !fits(va, span, p.size_) ||
            !fits(offset, rawSize, raw.size())) throw std::runtime_error("invalid PE section");
        for (const auto& s : p.sections_)
            if (uint64_t(va) < uint64_t(s.Begin) + s.Size && uint64_t(s.Begin) < uint64_t(va) + span)
                throw std::runtime_error("overlapping PE sections");
        p.sections_.push_back({va, span, u32(raw, at + 36)});
        if (rawSize) std::copy_n(raw.begin() + offset, rawSize, p.image_.begin() + va);
    }
    if (u32(raw, opt + 108) > 3) {
        uint32_t table = u32(raw, opt + 136), bytes = u32(raw, opt + 140);
        if ((bytes % 12) || !fits(table, bytes, p.size_))
            throw std::runtime_error("invalid exception directory");
        uint32_t previous = 0;
        for (uint32_t i = 0; i < bytes / 12; ++i) {
            uint64_t at = uint64_t(table) + uint64_t(i) * 12;
            RuntimeFunction entry{u32(p.image_, at), u32(p.image_, at + 4), u32(p.image_, at + 8)};
            const bool mapped = entry.Begin == entry.End ||
                std::any_of(p.sections_.begin(), p.sections_.end(), [&](const Section& section) {
                    return entry.Begin >= section.Begin && entry.End >= entry.Begin &&
                        fits(entry.Begin - section.Begin, entry.End - entry.Begin, section.Size);
                });
            if (entry.Begin > entry.End || entry.End > p.size_ ||
                (i && entry.Begin < previous) || !mapped ||
                !fits(entry.Unwind & ~1u, 4, p.size_))
                throw std::runtime_error("invalid runtime function");
            previous = entry.Begin;
            /* pe: Omit zero-length .pdata markers from function lookup
             * The 26100.1 kernel includes an empty range near its table end.
             */
            if (entry.Begin != entry.End) p.functions_.push_back(entry);
        }
    }
    return p;
}

bool PeImage::read(uint64_t rva, void* output, size_t size) const {
    if (!fits(rva, size, image_.size())) return false;
    bool covered = fits(rva, size, headers_);
    for (const auto& s : sections_) {
        if (rva >= s.Begin && fits(rva - s.Begin, size, s.Size)) {
            /* pe: Refuse IMAGE_SCN_MEM_WRITE bytes from disk
             * The archived PE omits loader fixups and subsequent writes.
             */
            if (s.Characteristics & 0x80000000u) return false;
            covered = true;
            break;
        }
    }
    if (!covered) return false;
    std::memcpy(output, image_.data() + size_t(rva), size);
    return true;
}

bool PeImage::executable(uint64_t rva) const {
    for (const auto& s : sections_)
        if (rva >= s.Begin && rva - s.Begin < s.Size)
            return (s.Characteristics & 0x20000000u) != 0;
    return false;
}

const RuntimeFunction* PeImage::function(uint64_t rva) const {
    auto it = std::upper_bound(functions_.begin(), functions_.end(), rva,
        [](uint64_t pc, const RuntimeFunction& f) { return pc < f.Begin; });
    if (it == functions_.begin()) return nullptr;
    --it;
    return rva < it->End ? &*it : nullptr;
}

bool readRegion(uint64_t base, const uint8_t* bytes, size_t available,
                uint64_t address, void* output, size_t wanted) {
    if (address < base || !fits(address - base, wanted, available)) return false;
    std::memcpy(output, bytes + size_t(address - base), wanted);
    return true;
}
}
