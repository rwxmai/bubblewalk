#include "ioctl_observer.h"
#include "../include/ioctl_runtime_26100_1.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

extern "C" int nuRuntimeProfileMatchesC(const NU_CODE_CHECK* check, const unsigned char* bytes);

namespace {
void require(bool value, const char* what) {
    if (!value) throw std::runtime_error(what);
}

constexpr uint32_t targets[] = {0x664660u, 0xb57780u, 0xb577e0u};
struct CallSite { uint32_t Rva, Size, Return; };
constexpr CallSite sites[] = {
    {0x32bf0cu, 17u, 0x32bf1du},
    {0x86ffc2u, 66u, 0x870004u},
};
using CodeBytes = std::array<unsigned char, sizeof(NU_CODE_CHECK::Bytes)>;

bool matches(const NU_CODE_CHECK* check, const unsigned char* bytes) {
    const bool cpp = NuIoctlRuntimeCodeMatches(check, bytes) != 0;
    const bool c = nuRuntimeProfileMatchesC(check, bytes) != 0;
    require(cpp == c, "C11 and C++ runtime matcher agreement");
    return cpp;
}

const NU_CODE_CHECK& checkFor(uint32_t rva) {
    for (const auto& check : NuIoctlCode)
        if (check.Rva == rva) return check;
    throw std::runtime_error("missing runtime call-site fixture");
}

CodeBytes copy(const NU_CODE_CHECK& check) {
    CodeBytes bytes{};
    std::copy_n(check.Bytes, check.Size, bytes.begin());
    return bytes;
}

void setTarget(CodeBytes& bytes, const CallSite& site, uint32_t target) {
    const auto call = site.Return - site.Rva - 5;
    require(call + 5 == site.Size && bytes[call] == 0xe8, "pinned E8 return position");
    // Encode the two's-complement displacement without host-endian assumptions.
    const auto displacement = uint32_t(uint64_t(target) - site.Return);
    for (unsigned int i = 0; i < 4; ++i)
        bytes[call + 1 + i] = static_cast<unsigned char>(displacement >> (i * 8));
}

void callSiteTests(const CallSite& site) {
    const auto& check = checkFor(site.Rva);
    require(check.Size == site.Size, "pinned call-site extent");
    const auto call = site.Return - site.Rva - 5;
    auto original = copy(check);
    auto encoded = original;
    setTarget(encoded, site, targets[0]);
    require(encoded == original, "original target displacement matches pinned bytes");
    if (site.Return == NU_IOCTL_FAST_RETURN)
        require((original[call + 4] & 0x80) != 0, "Fast I/O original rel32 is negative");

    for (const auto target : targets) {
        auto bytes = original;
        setTarget(bytes, site, target);
        require(matches(&check, bytes.data()), "approved runtime destination");
        for (unsigned int i = 0; i < check.Size; ++i) {
            if (i > call && i < call + 5) continue;
            auto changed = bytes;
            changed[i] ^= 1;
            require(!matches(&check, changed.data()),
                    "runtime override must preserve opcode and every surrounding byte");
        }
        for (const auto neighbor : {target - 1, target + 1}) {
            auto changed = original;
            setTarget(changed, site, neighbor);
            require(!matches(&check, changed.data()),
                    "off-by-one override destination rejected");
        }
    }
    for (const auto target : {0u, site.Return, 0x32bf18u, 0x664600u, 0xb57800u, 0xffffffffu}) {
        auto changed = original;
        setTarget(changed, site, target);
        require(!matches(&check, changed.data()), "arbitrary destination rejected");
    }
}

void unchangedSignatureTests() {
    for (const auto& check : NuIoctlCode) {
        if (check.Rva == sites[0].Rva || check.Rva == sites[1].Rva) continue;
        auto bytes = copy(check);
        require(matches(&check, bytes.data()), "unaffected pinned signature accepted");
        for (unsigned int i = 0; i < check.Size; ++i) {
            bytes[i] ^= 1;
            require(!matches(&check, bytes.data()), "unaffected signature remains exact");
            bytes[i] ^= 1;
        }
    }
}

void malformedAndUnrecognizedTests() {
    const auto& original = checkFor(sites[0].Rva);
    auto bytes = copy(original);
    require(!matches(nullptr, bytes.data()), "missing signature rejected");
    require(!matches(&original, nullptr), "missing runtime bytes rejected");
    auto invalid = original;
    invalid.Size = 0;
    require(!matches(&invalid, bytes.data()), "empty signature rejected");
    invalid.Size = sizeof(invalid.Bytes) + 1;
    require(!matches(&invalid, bytes.data()), "oversized signature rejected");

    for (const auto& site : sites) {
        auto check = checkFor(site.Rva);
        auto changed = copy(check);
        setTarget(changed, site, targets[1]);
        check.Size--;
        require(!matches(&check, changed.data()), "wrong-sized known signature cannot allow overrides");
        check = checkFor(site.Rva);
        check.Rva++;
        require(!matches(&check, changed.data()), "neighboring signature RVA cannot allow overrides");
    }
    NU_CODE_CHECK arbitrary{0x123456u, 5u, {0xe8, 0x00, 0x00, 0x00, 0x00}};
    require(matches(&arbitrary, arbitrary.Bytes), "unrecognized signature still permits exact bytes");
    CodeBytes altered{};
    std::copy_n(arbitrary.Bytes, arbitrary.Size, altered.begin());
    altered[1] = 1;
    require(!matches(&arbitrary, altered.data()), "unrecognized signature cannot allow changed calls");
}

// A compact PE fixture holds all pinned signatures in separate executable sections.
// Its disk signature policy must remain exact even when live runtime variants pass.
std::vector<uint8_t> diskImage() {
    constexpr size_t count = sizeof(NuIoctlCode) / sizeof(NuIoctlCode[0]);
    std::vector<uint8_t> raw(0x400 + count * 96);
    const auto w16 = [&](size_t at, uint16_t value) {
        raw[at] = uint8_t(value); raw[at + 1] = uint8_t(value >> 8);
    };
    const auto w32 = [&](size_t at, uint32_t value) {
        w16(at, uint16_t(value)); w16(at + 2, uint16_t(value >> 16));
    };
    w16(0, 0x5a4d); w32(0x3c, 0x80); w32(0x80, 0x4550);
    w16(0x84, 0x8664); w16(0x86, uint16_t(count));
    w32(0x88, NU_TARGET_TIMESTAMP); w16(0x94, 0xf0); w16(0x98, 0x20b);
    w32(0x98 + 56, NU_TARGET_SIZE); w32(0x98 + 60, 0x400);
    w32(0x98 + 64, NU_TARGET_CHECKSUM);
    for (size_t i = 0; i < count; ++i) {
        const auto& check = NuIoctlCode[i];
        const auto header = 0x188 + i * 40;
        w32(header + 8, check.Size); w32(header + 12, check.Rva);
        w32(header + 16, check.Size); w32(header + 20, uint32_t(0x400 + i * 96));
        w32(header + 36, 0x60000020);
        std::copy_n(check.Bytes, check.Size, raw.begin() + 0x400 + i * 96);
    }
    return raw;
}

void combinedAndDiskTests() {
    auto raw = diskImage();
    require(nu::ioctlTarget(nu::PeImage::parse(raw)), "disk profile accepts original pinned bytes");
    for (const auto driverTarget : targets) {
        for (const auto fastTarget : targets) {
            auto changed = raw;
            const uint32_t combination[] = {driverTarget, fastTarget};
            for (unsigned int siteIndex = 0; siteIndex < 2; ++siteIndex) {
                const auto& site = sites[siteIndex];
                const auto& check = checkFor(site.Rva);
                auto bytes = copy(check);
                setTarget(bytes, site, combination[siteIndex]);
                require(matches(&check, bytes.data()), "independent runtime call-site combinations");
                const auto index = size_t(&check - NuIoctlCode);
                std::copy_n(bytes.begin(), check.Size, changed.begin() + 0x400 + index * 96);
            }
            require(nu::ioctlTarget(nu::PeImage::parse(changed)) ==
                    (driverTarget == targets[0] && fastTarget == targets[0]),
                    "disk profile rejects runtime-only override variants");
        }
    }
}

void realImageTests(const char* path) {
    const auto image = nu::PeImage::load(path);
    require(nu::ioctlTarget(image), "real pinned kernel disk profile");
    for (const auto& check : NuIoctlCode) {
        CodeBytes bytes{};
        require(image.read(check.Rva, bytes.data(), check.Size), "read pinned kernel instruction range");
        require(!std::memcmp(bytes.data(), check.Bytes, check.Size), "real kernel bytes match pinned signature");
        require(matches(&check, bytes.data()), "runtime matcher accepts real original kernel");
    }
}
}

int main(int argc, char** argv) {
    try {
        require(argc <= 2, "usage: bubble-runtime-profile-tests [ntoskrnl.exe]");
        for (const auto& site : sites) callSiteTests(site);
        unchangedSignatureTests();
        malformedAndUnrecognizedTests();
        combinedAndDiskTests();
        if (argc == 2) realImageTests(argv[1]);
        std::cout << "RUNTIME_PROFILE_PASSED\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
