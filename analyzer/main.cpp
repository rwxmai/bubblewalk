#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <dbghelp.h>
#include "../include/protocol.h"
#include "pe_image.h"
#include "interrupted_context.h"
#include "provenance.h"
#include "demo.h"
#include <atomic>
#include <thread>
#include "../include/target_26100_1.h"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include "../tests/fixture.h"

namespace fs = std::filesystem;
namespace {
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
struct Capture {
    NU_FILE_HEADER Header{};
    std::vector<NU_MODULE> Modules;
    std::vector<NU_SAMPLE> Samples;
};
struct Image {
    NU_MODULE Module{};
    fs::path File;
    std::unique_ptr<nu::PeImage> Pe;
    std::string Error;
};
struct Walker {
    const NU_SAMPLE* Sample = nullptr;
    std::vector<Image> Images;
    bool ReadFailed = false;
    nu::StackEvidence Evidence;
    Image* find(uint64_t pc) {
        for (auto& i : Images)
            if (pc >= i.Module.Base && pc - i.Module.Base < i.Module.Size) return &i;
        return nullptr;
    }
};
/* dbghelp: Bind callbacks to the serialized walker */
Walker* active = nullptr;

void failWin(const char* message) {
    throw std::runtime_error(std::string(message) + ": Win32=" + std::to_string(GetLastError()));
}
bool ioctl(HANDLE h, DWORD code, void* in, DWORD ins, void* out, DWORD outs, DWORD& count) {
    return DeviceIoControl(h, code, in, ins, out, outs, &count, nullptr) != FALSE;
}
std::vector<NU_MODULE> modules(HANDLE h) {
    std::vector<uint8_t> buffer(4 * 1024 * 1024);
    DWORD count = 0;
    if (!ioctl(h, NU_MODULES, nullptr, 0, buffer.data(), DWORD(buffer.size()), count))
        failWin("module inventory");
    if (count < sizeof(NU_MODULE_HEADER)) throw std::runtime_error("short module response");
    NU_MODULE_HEADER header{};
    std::memcpy(&header, buffer.data(), sizeof(header));
    if (header.Count > 8192 || count != sizeof(header) + size_t(header.Count) * sizeof(NU_MODULE))
        throw std::runtime_error("invalid module response");
    std::vector<NU_MODULE> result(header.Count);
    std::memcpy(result.data(), buffer.data() + sizeof(header), result.size() * sizeof(NU_MODULE));
    for (auto& m : result) m.Path[sizeof(m.Path) - 1] = 0;
    std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) { return a.Base < b.Base; });
    return result;
}

std::wstring widen(const char* p) {
    int count = MultiByteToWideChar(CP_ACP, 0, p, -1, nullptr, 0);
    if (!count) failWin("path conversion");
    std::wstring result(size_t(count), L'\0');
    MultiByteToWideChar(CP_ACP, 0, p, -1, result.data(), count);
    result.pop_back();
    return result;
}
fs::path sourcePath(const NU_MODULE& m) {
    std::wstring path = widen(m.Path);
    wchar_t windows[MAX_PATH]{};
    if (!GetWindowsDirectoryW(windows, MAX_PATH)) failWin("Windows directory");
    if (path.rfind(L"\\SystemRoot\\", 0) == 0)
        path = std::wstring(windows) + path.substr(11);
    else if (path.rfind(L"\\??\\", 0) == 0) path = path.substr(4);
    else if (path.rfind(L"\\Windows\\", 0) == 0)
        path = std::wstring(windows).substr(0, 2) + path;
    return fs::path(path);
}
fs::path imagePath(const fs::path& capture, uint64_t base) {
    std::wostringstream name;
    name << std::hex << base << L".pe";
    return fs::path(capture.wstring() + L".images") / name.str();
}
void checkIdentity(const NU_MODULE& m, const nu::PeImage& pe) {
    if (!(m.Flags & NU_M_IDENTITY_VALID) || pe.size() != m.Size ||
        pe.timestamp() != m.Timestamp || pe.checksum() != m.Checksum)
        throw std::runtime_error("PE identity mismatch or missing runtime identity");
}

Capture takeCapture(const fs::path& output) {
    Handle device;
    device.value = CreateFileW(NU_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
                               0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (device.value == INVALID_HANDLE_VALUE) failWin("open Bubble (administrator required)");
    Capture c;
    NU_INFO_DATA info{};
    DWORD count = 0;
    if (!ioctl(device.value, NU_INFO, nullptr, 0, &info, sizeof(info), count)) failWin("info");
    if (count != sizeof(info) || info.Version != NU_VERSION || info.SampleSize != sizeof(NU_SAMPLE))
        throw std::runtime_error("driver/client protocol mismatch");
    if (!info.CpuCount || info.CpuCount > 4096) throw std::runtime_error("invalid processor count");
    c.Modules = modules(device.value);
    std::cout << "Build " << info.Build << ", " << info.CpuCount
              << " possible CPUs, thread snapshot cap=" << info.CaptureBytes << " bytes.\n"
              << "Press Enter to arm for 10 seconds; inject ONE NMI from the VM host during that window.\n";
    std::cin.get();
    if (!ioctl(device.value, NU_ARM, nullptr, 0, nullptr, 0, count)) failWin("arm");
    struct Disarm {
        HANDLE h;
        ~Disarm() { DWORD n; DeviceIoControl(h, NU_DISARM, nullptr, 0, nullptr, 0, &n, nullptr); }
    } disarm{device.value};
    std::cout << "ARMED: inject now.\n" << std::flush;
    ULONGLONG start = GetTickCount64();
    while (GetTickCount64() - start < 10200) {
        for (uint32_t cpu = 0; cpu < info.CpuCount; ++cpu) {
            auto s = std::make_unique<NU_SAMPLE>();
            if (ioctl(device.value, NU_READ, &cpu, sizeof(cpu), s.get(), sizeof(*s), count)) {
                if (count != sizeof(*s) || s->Version != NU_VERSION)
                    throw std::runtime_error("invalid sample response");
                c.Samples.push_back(*s);
            } else if (GetLastError() != ERROR_NO_MORE_ITEMS && GetLastError() != ERROR_NO_MORE_FILES) {
                failWin("read sample");
            }
        }
        if (!c.Samples.empty()) break;
        Sleep(20);
    }
    /* capture: Drain only after the driver completes callback rundown */
    if (!ioctl(device.value, NU_DISARM, nullptr, 0, nullptr, 0, count)) failWin("disarm");
    for (uint32_t cpu = 0; cpu < info.CpuCount; ++cpu) {
        auto s = std::make_unique<NU_SAMPLE>();
        if (ioctl(device.value, NU_READ, &cpu, sizeof(cpu), s.get(), sizeof(*s), count)) {
            if (count != sizeof(*s) || s->Version != NU_VERSION)
                throw std::runtime_error("invalid drained sample");
            c.Samples.push_back(*s);
        } else if (GetLastError() != ERROR_NO_MORE_ITEMS && GetLastError() != ERROR_NO_MORE_FILES) {
            failWin("drain sample");
        }
    }
    auto after = modules(device.value);
    c.Header = {NU_MAGIC, NU_VERSION, info.Build, uint32_t(c.Modules.size()),
                uint32_t(c.Samples.size()), sizeof(NU_SAMPLE), 0, 0};
    c.Header.InventoryStable = c.Modules.size() == after.size() &&
        std::equal(c.Modules.begin(), c.Modules.end(), after.begin(),
            [](const NU_MODULE& a, const NU_MODULE& b) { return std::memcmp(&a, &b, sizeof(a)) == 0; });
    if (!c.Header.InventoryStable)
        std::cerr << "Module inventory changed: attribution is incomplete.\n";
    fs::create_directories(fs::path(output.wstring() + L".images"));
    for (const auto& m : c.Modules) {
        try {
            auto source = sourcePath(m);
            checkIdentity(m, nu::PeImage::load(source));
            auto dest = imagePath(output, m.Base);
            fs::copy_file(source, dest, fs::copy_options::overwrite_existing);
            checkIdentity(m, nu::PeImage::load(dest));
        } catch (const std::exception& e) {
            std::cerr << "Image unavailable: " << m.Path << ": " << e.what() << "\n";
        }
    }
    std::ofstream file(output, std::ios::binary);
    file.write(reinterpret_cast<const char*>(&c.Header), sizeof(c.Header));
    file.write(reinterpret_cast<const char*>(c.Modules.data()),
               std::streamsize(c.Modules.size() * sizeof(NU_MODULE)));
    file.write(reinterpret_cast<const char*>(c.Samples.data()),
               std::streamsize(c.Samples.size() * sizeof(NU_SAMPLE)));
    if (!file) throw std::runtime_error("cannot write capture");
    return c;
}

Capture loadCapture(const fs::path& path) {
    Capture c;
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) throw std::runtime_error("cannot open capture");
    auto size = file.tellg();
    file.seekg(0);
    if (!file.read(reinterpret_cast<char*>(&c.Header), sizeof(c.Header)))
        throw std::runtime_error("short capture header");
    if (c.Header.Magic != NU_MAGIC || c.Header.Version != NU_VERSION ||
        c.Header.SampleSize != sizeof(NU_SAMPLE) || c.Header.ModuleCount > 8192 ||
        c.Header.SampleCount > 4096) throw std::runtime_error("invalid capture header");
    uint64_t expected = sizeof(c.Header) + uint64_t(c.Header.ModuleCount) * sizeof(NU_MODULE) +
                        uint64_t(c.Header.SampleCount) * sizeof(NU_SAMPLE);
    if (size < 0 || uint64_t(size) != expected) throw std::runtime_error("capture length mismatch");
    c.Modules.resize(c.Header.ModuleCount);
    c.Samples.resize(c.Header.SampleCount);
    file.read(reinterpret_cast<char*>(c.Modules.data()),
              std::streamsize(c.Modules.size() * sizeof(NU_MODULE)));
    file.read(reinterpret_cast<char*>(c.Samples.data()),
              std::streamsize(c.Samples.size() * sizeof(NU_SAMPLE)));
    if (!file) throw std::runtime_error("truncated capture");
    for (auto& m : c.Modules) {
        if (!m.Size || m.Base < 0xffff800000000000ull ||
            m.Size > UINT64_MAX - m.Base || !std::memchr(m.Path, 0, sizeof(m.Path)))
            throw std::runtime_error("invalid module record");
    }
    std::sort(c.Modules.begin(), c.Modules.end(), [](const auto& a, const auto& b) { return a.Base < b.Base; });
    for (size_t i = 1; i < c.Modules.size(); ++i)
        if (c.Modules[i - 1].Base + c.Modules[i - 1].Size > c.Modules[i].Base)
            throw std::runtime_error("overlapping module inventory");
    for (const auto& s : c.Samples)
        if (s.Version != NU_VERSION || s.Nmi.Size > NU_NMI_BYTES || s.Stack.Size > NU_THREAD_BYTES ||
            s.Nmi.Size > UINT64_MAX - s.Nmi.Base || s.Stack.Size > UINT64_MAX - s.Stack.Base)
            throw std::runtime_error("invalid stack record");
    return c;
}

BOOL CALLBACK readMemory(HANDLE, DWORD64 address, PVOID buffer, DWORD size, LPDWORD read) {
    *read = 0;
    if (!active || !active->Sample) return FALSE;
    const auto& s = *active->Sample;
    bool ok = nu::readRegion(s.Nmi.Base, s.NmiBytes, s.Nmi.Size, address, buffer, size) ||
              nu::readRegion(s.Stack.Base, s.StackBytes, s.Stack.Size, address, buffer, size);
    if (!ok) {
        auto image = active->find(address);
        ok = image && image->Pe && image->Pe->read(address - image->Module.Base, buffer, size);
    }
    if (ok) *read = size;
    else active->ReadFailed = true;
    return ok ? TRUE : FALSE;
}
BOOL CALLBACK symbolCallback(HANDLE process, ULONG action, ULONG64 data, ULONG64) {
    if (action != CBA_READ_MEMORY || !data) return FALSE;
    auto request=reinterpret_cast<PIMAGEHLP_CBA_READ_MEMORY>(data);
    DWORD localRead=0;
    return readMemory(process, request->addr, request->buf, request->bytes,
                      request->bytesread ? request->bytesread : &localRead);
}
PVOID CALLBACK functionTable(HANDLE, DWORD64 pc) {
    auto image = active->find(pc);
    return image && image->Pe
        ? const_cast<nu::RuntimeFunction*>(image->Pe->function(pc - image->Module.Base)) : nullptr;
}
DWORD64 CALLBACK moduleBase(HANDLE, DWORD64 pc) {
    auto image = active->find(pc);
    return image ? image->Module.Base : 0;
}
CONTEXT context(const NU_REGS& r) {
    CONTEXT c{};
    c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    c.Rax=r.Rax; c.Rcx=r.Rcx; c.Rdx=r.Rdx; c.Rbx=r.Rbx;
    c.Rsp=r.Rsp; c.Rbp=r.Rbp; c.Rsi=r.Rsi; c.Rdi=r.Rdi;
    c.R8=r.R8; c.R9=r.R9; c.R10=r.R10; c.R11=r.R11;
    c.R12=r.R12; c.R13=r.R13; c.R14=r.R14; c.R15=r.R15;
    c.Rip=r.Rip; c.EFlags=DWORD(r.Rflags);
    c.SegCs=WORD(r.Cs); c.SegSs=WORD(r.Ss);
    return c;
}


}

int wmain(int argc,wchar_t** argv) {
    try {
        if(argc==2&&std::wstring(argv[1])==L"demo"){nu::runNmiDemo(std::cout);return 0;}
        if(argc!=3||std::wstring(argv[1])!=L"capture") {
            std::cerr<<"Usage: bubble capture bubble.nwu | bubble demo\n";return 1;
        }
        takeCapture(fs::path(argv[2]));return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}
}
