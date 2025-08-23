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


}

int wmain(int argc,wchar_t** argv) {
    try {
        if(argc==2&&std::wstring(argv[1])==L"demo"){nu::runNmiDemo(std::cout);return 0;}
        std::cerr<<"Usage: bubble demo\n";return 1;
    }catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}
}
