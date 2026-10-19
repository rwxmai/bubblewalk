#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <dbghelp.h>
#include "../include/protocol.h"
#include "pe_image.h"
#include "interrupted_context.h"
#include "provenance.h"
#include "ioctl_observer.h"
#include "../include/ioctl_26100_1.h"
#include <random>
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
    Handle()=default;
    Handle(const Handle&)=delete;
    Handle& operator=(const Handle&)=delete;
    ~Handle() {
        const auto error=GetLastError();
        if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);
        SetLastError(error);
    }
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
    bool Verbose = true;
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
    Handle event;
    event.value=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    if(!event.value){event.value=INVALID_HANDLE_VALUE;return false;}
    OVERLAPPED pending{};pending.hEvent=event.value;
    const BOOL done=DeviceIoControl(h,code,in,ins,out,outs,&count,&pending);
    if(!done&&GetLastError()!=ERROR_IO_PENDING)return false;
    return GetOverlappedResult(h,&pending,&count,TRUE)!=FALSE;
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
                               0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
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
        ~Disarm() { DWORD n; ioctl(h, NU_DISARM, nullptr, 0, nullptr, 0, n); }
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

enum class WalkResult { Complete, Incomplete, OutsideModules, NonExecutable };
WalkResult walk(Walker& w, const NU_SAMPLE& sample, const NU_REGS& interrupted, bool stable,
                decltype(&StackWalk64) step = &StackWalk64) {
    w.Sample=&sample;
    w.Evidence={sample.Cpu,sample.Generation,sample.Tsc,true,stable,
                (sample.Flags&NU_F_THREAD_TRUNCATED)!=0,"unwind_failure",{}};
    std::vector<nu::ModuleView> views;
    for(const auto& i:w.Images)views.push_back({i.Module.Base,i.Module.Size,i.Module.Path,i.Pe.get()});
    const nu::ModuleMap map(std::move(views));
    auto finish=[&](WalkResult result,const char* stop){w.Evidence.Stop=stop;return result;};
    CONTEXT c=context(interrupted);
    STACKFRAME64 frame{};
    frame.AddrPC.Offset=c.Rip;frame.AddrPC.Mode=AddrModeFlat;
    frame.AddrStack.Offset=c.Rsp;frame.AddrStack.Mode=AddrModeFlat;
    frame.AddrFrame.Offset=c.Rbp;frame.AddrFrame.Mode=AddrModeFlat;
    bool initial=true;
    for(uint32_t depth=0;depth<NU_MAX_FRAMES;++depth) {
        const uint64_t pc=frame.AddrPC.Offset,sp=frame.AddrStack.Offset;
        if(!pc) {
            if(w.Evidence.StackTruncated||!stable)return finish(WalkResult::Incomplete,"terminal_incomplete");
            return finish(WalkResult::Complete,"terminal");
        }
        if(sp<sample.Stack.Base||sp-sample.Stack.Base>sample.Stack.Size)
            return finish(WalkResult::Incomplete,"stack_bounds");
        auto observed=map.classify(pc,sp,depth);
        if(observed.Kind==nu::FrameKind::Invalid)return finish(WalkResult::Incomplete,"invalid_frame");
        w.Evidence.Frames.push_back(observed);
        if(w.Verbose)std::cout<<"  "<<depth<<" pc=0x"<<std::hex<<pc<<" sp=0x"<<sp<<std::dec<<" "<<observed.Image<<"\n";
        if(observed.Kind==nu::FrameKind::OutsideModules)return finish(WalkResult::OutsideModules,"outside_modules");
        if(observed.Kind==nu::FrameKind::MissingImage)return finish(WalkResult::Incomplete,"missing_image");
        if(observed.Kind==nu::FrameKind::NonExecutableImage)return finish(WalkResult::NonExecutable,"nonexecutable_image");
        /* unwind: Retain the current frame before probing for its caller
         * A TRUE step can survive an optional read miss. A FALSE step
         * supplies no documented next-frame contract.
         */
        for(;;) {
            w.ReadFailed=false;
            const BOOL advanced=step(IMAGE_FILE_MACHINE_AMD64,GetCurrentProcess(),GetCurrentThread(),
                                     &frame,&c,readMemory,functionTable,moduleBase,nullptr);
            if(!advanced)return finish(WalkResult::Incomplete,w.ReadFailed?"read_failure":"unwind_failure");
            const bool same=frame.AddrPC.Offset==pc&&frame.AddrStack.Offset==sp;
            if(same&&initial){initial=false;continue;}
            initial=false;
            if(same)return finish(WalkResult::Incomplete,"no_progress");
            if(frame.AddrStack.Offset<sp)return finish(WalkResult::Incomplete,"stack_regression");
            break;
        }
    }
    return finish(WalkResult::Incomplete,"frame_limit");
}

enum class TestStep { ProbeMiss, Terminal, Repeated, Failed };
TestStep testStepMode=TestStep::Failed;
/* test: Inject DbgHelp results without coupling probes to frame validity */
BOOL WINAPI testStep(DWORD, HANDLE, HANDLE, LPSTACKFRAME64 frame, PVOID,
                      PREAD_PROCESS_MEMORY_ROUTINE64, PFUNCTION_TABLE_ACCESS_ROUTINE64,
                      PGET_MODULE_BASE_ROUTINE64, PTRANSLATE_ADDRESS_ROUTINE64) {
    if (testStepMode == TestStep::Failed) return FALSE;
    if (testStepMode == TestStep::ProbeMiss) {
        active->ReadFailed=true;
        frame->AddrPC.Offset=0xfffff80020000020ull;
        frame->AddrStack.Offset+=40;
    } else if (testStepMode == TestStep::Terminal) frame->AddrPC.Offset=0;
    return TRUE;
}

void selftest() {
    HANDLE process=GetCurrentProcess();
    if (!SymInitialize(process, nullptr, FALSE)) failWin("SymInitialize");
    struct Cleanup { HANDLE p; ~Cleanup() { SymCleanup(p); } } cleanup{process};
    if (!SymRegisterCallback64(process, symbolCallback, 0)) failWin("SymRegisterCallback64");
    Walker w;
    Image image;
    image.Module.Base=0xfffff80010000000ull;
    image.Module.Size=0x4000;
    std::memcpy(image.Module.Path, "synthetic-unwind-fixture", sizeof("synthetic-unwind-fixture"));
    image.Pe=std::make_unique<nu::PeImage>(nu::PeImage::parse(nu::testImage()));
    w.Images.push_back(std::move(image));
    auto sample=std::make_unique<NU_SAMPLE>();
    sample->Version=NU_VERSION;
    sample->Entry.Rip=w.Images[0].Module.Base + 0x1010;
    sample->Entry.Rsp=0xffffa00000008000ull;
    sample->Entry.Rflags=0x202;
    sample->Entry.Cs=0x10;
    sample->Entry.Ss=0x18;
    sample->Nmi.Base=sample->Entry.Rsp;
    sample->Nmi.Size=80;
    sample->Stack.Base=0xffffa00000108000ull;
    sample->Stack.Size=64;
    sample->InterruptedRip=w.Images[0].Module.Base + 0x1210;
    sample->InterruptedRsp=sample->Stack.Base;
    sample->InterruptedCs=0x10;
    auto put=[&](uint8_t* b, size_t at, uint64_t value) { std::memcpy(b + at, &value, 8); };
    put(sample->NmiBytes, 32, w.Images[0].Module.Base + 0x1110);
    put(sample->NmiBytes, 40, sample->InterruptedRip);
    put(sample->NmiBytes, 48, 0x10);
    put(sample->NmiBytes, 56, 0x202);
    put(sample->NmiBytes, 64, sample->InterruptedRsp);
    put(sample->NmiBytes, 72, 0x18);
    put(sample->StackBytes, 32, 0xfffff80020000020ull);
    NU_REGS seed{};
    seed.Rip=sample->InterruptedRip; seed.Rsp=sample->InterruptedRsp;
    seed.Cs=0x10; seed.Ss=0x18; seed.Rflags=0x202;
    active=&w;
    auto result=walk(w, *sample, seed, true);
    active=nullptr;
    if (result != WalkResult::OutsideModules)
        throw std::runtime_error("selftest failed: unbacked caller not recovered");
    const auto callerEvidence=nu::evaluate(w.Evidence);
    if(callerEvidence.Findings.size()!=1||callerEvidence.Findings[0].Code!="NMI_UNOWNED_CALLER")
        throw std::runtime_error("selftest failed: caller finding requires no reputation rule");
    /* test: Cross UWOP_PUSH_MACHFRAME using the captured IST bytes */
    CONTEXT handler{};
    handler.ContextFlags=CONTEXT_CONTROL|CONTEXT_INTEGER;
    handler.Rip=w.Images[0].Module.Base+0x1010;
    handler.Rsp=sample->Nmi.Base;
    handler.EFlags=0x202;handler.SegCs=0x10;handler.SegSs=0x18;
    STACKFRAME64 machine{};
    machine.AddrPC.Offset=handler.Rip;machine.AddrPC.Mode=AddrModeFlat;
    machine.AddrStack.Offset=handler.Rsp;machine.AddrStack.Mode=AddrModeFlat;
    machine.AddrFrame.Mode=AddrModeFlat;
    bool crossed=false;
    active=&w;
    for(unsigned attempt=0;attempt<8;++attempt) {
        if(!StackWalk64(IMAGE_FILE_MACHINE_AMD64,process,GetCurrentThread(),&machine,&handler,
                        readMemory,functionTable,moduleBase,nullptr))break;
        if(machine.AddrPC.Offset==sample->InterruptedRip&&machine.AddrStack.Offset==sample->Stack.Base) {
            crossed=true;break;
        }
    }
    active=nullptr;
    if(!crossed)throw std::runtime_error("selftest failed: PUSH_MACHFRAME did not restore RIP/RSP");
    /* test: Recover a pool return PC from a mapped leaf without .pdata */
    seed.Rip=w.Images[0].Module.Base+0x1350;
    put(sample->StackBytes,0,0xfffff80020000020ull);
    active=&w;
    result=walk(w,*sample,seed,true);
    active=nullptr;
    if(result!=WalkResult::OutsideModules||nu::evaluate(w.Evidence).Findings.empty())
        throw std::runtime_error("selftest failed: mapped leaf caller was not recovered");
    put(sample->StackBytes,0,0);
    seed.Rip=sample->InterruptedRip;
    /* test: Truncate before the return slot at RSP+0x20 */
    sample->Stack.Size=16;
    active=&w;
    result=walk(w, *sample, seed, true);
    active=nullptr;
    if (result != WalkResult::Incomplete)
        throw std::runtime_error("selftest failed: truncated stack produced a detection");
    sample->Stack.Size=64;
    /* test: Classify an unknown sampled RIP before any unwind probe */
    seed.Rip=0xfffff80020000020ull;
    active=&w;
    result=walk(w, *sample, seed, true);
    active=nullptr;
    if (result != WalkResult::OutsideModules)
        throw std::runtime_error("selftest failed: sampled unbacked RIP was suppressed");
    const auto ripEvidence=nu::evaluate(w.Evidence);
    if(ripEvidence.Findings.size()!=1||ripEvidence.Findings[0].Code!="NMI_UNOWNED_RIP")
        throw std::runtime_error("selftest failed: standalone RIP finding");
    seed.Rip=sample->InterruptedRip;
    for (auto mode : {TestStep::ProbeMiss, TestStep::Terminal, TestStep::Repeated, TestStep::Failed}) {
        testStepMode=mode;
        active=&w;
        result=walk(w, *sample, seed, true, testStep);
        active=nullptr;
        const auto expected=mode == TestStep::ProbeMiss ? WalkResult::OutsideModules :
                            mode == TestStep::Terminal ? WalkResult::Complete : WalkResult::Incomplete;
        if (result != expected) throw std::runtime_error("selftest failed: step result classification");
    }
    sample->Flags|=NU_F_THREAD_TRUNCATED;
    testStepMode=TestStep::Terminal;
    active=&w;
    result=walk(w, *sample, seed, true, testStep);
    active=nullptr;
    if (result != WalkResult::Incomplete)
        throw std::runtime_error("selftest failed: truncated terminal context reported complete");
    std::cout << "SELFTEST_PASSED: caller attribution, read probes, terminal state, no progress, and truncation.\n";
}

void analyze(const fs::path& path,const Capture& c) {
    Walker w;
    HANDLE process=GetCurrentProcess();
    SymSetOptions(SYMOPT_FAIL_CRITICAL_ERRORS|SYMOPT_DEFERRED_LOADS|SYMOPT_UNDNAME);
    if(!SymInitialize(process,nullptr,FALSE))failWin("SymInitialize");
    struct Cleanup {HANDLE p;~Cleanup(){SymCleanup(p);}} cleanup{process};
    if(!SymRegisterCallback64(process,symbolCallback,0))failWin("SymRegisterCallback64");
    for(const auto& module:c.Modules) {
        Image i;
        i.Module=module;i.File=imagePath(path,module.Base);
        try {
            i.Pe=std::make_unique<nu::PeImage>(nu::PeImage::load(i.File));
            checkIdentity(module,*i.Pe);
            /* dbghelp: Resolve names separately from .pdata lookup */
            SymLoadModuleExW(process,nullptr,i.File.c_str(),nullptr,module.Base,module.Size,nullptr,0);
        }catch(const std::exception& e){i.Pe.reset();i.Error=e.what();}
        w.Images.push_back(std::move(i));
    }
    if(c.Samples.empty())std::cout<<"NO_SAMPLES: no NMI observation was captured.\n";
    active=&w;
    for(const auto& sample:c.Samples) {
        w.Evidence={sample.Cpu,sample.Generation,sample.Tsc,false,c.Header.InventoryStable!=0,
                    (sample.Flags&NU_F_THREAD_TRUNCATED)!=0,"context_unavailable",{}};
        auto kernel=w.find(sample.KernelBase);
        if(sample.Flags&NU_F_USER_INTERRUPTED)w.Evidence.Stop="user_context";
        else if(c.Header.Build!=NU_TARGET_BUILD||!kernel||!kernel->Pe||!nu::targetImage(*kernel->Pe))
            w.Evidence.Stop="target_mismatch";
        else {
            NU_REGS interrupted{};std::string error;
            if(!nu::interruptedContext(sample,kernel->Module,interrupted,error))w.Evidence.Stop="context_"+error;
            else walk(w,sample,interrupted,c.Header.InventoryStable!=0);
        }
        const auto result=nu::evaluate(w.Evidence);
        std::cout<<nu::reportJson(w.Evidence,result)<<"\n";
        const auto observation=nu::observeIoctl(sample,w.Evidence,
            kernel&&kernel->Pe&&nu::ioctlTarget(*kernel->Pe));
        if(observation.Observed)std::cout<<nu::ioctlJson(sample,observation)<<"\n";
    }
    active=nullptr;
}

std::atomic<HANDLE> monitorStop{nullptr};
BOOL WINAPI stopMonitor(DWORD signal) {
    if(signal!=CTRL_C_EVENT&&signal!=CTRL_BREAK_EVENT)return FALSE;
    if(const auto event=monitorStop.load())SetEvent(event);
    return TRUE;
}

bool sameModules(const std::vector<NU_MODULE>& a,const std::vector<NU_MODULE>& b) {
    return a.size()==b.size()&&std::equal(a.begin(),a.end(),b.begin(),
        [](const auto& x,const auto& y){return std::memcmp(&x,&y,sizeof(x))==0;});
}

/* monitor: Reuse PE metadata until the sampled module identity changes */
void refreshImages(Walker& w,const std::vector<NU_MODULE>& inventory) {
    std::vector<Image> next;
    for(const auto& module:inventory) {
        auto found=std::find_if(w.Images.begin(),w.Images.end(),[&](const Image& i) {
            return !std::memcmp(&i.Module,&module,sizeof(module));
        });
        if(found!=w.Images.end()) {next.push_back(std::move(*found));continue;}
        Image image;image.Module=module;
        try {
            image.File=sourcePath(module);
            image.Pe=std::make_unique<nu::PeImage>(nu::PeImage::load(image.File));
            checkIdentity(module,*image.Pe);
        } catch(const std::exception& e) {image.Pe.reset();image.Error=e.what();}
        next.push_back(std::move(image));
    }
    w.Images=std::move(next);
}

void monitor(uint32_t interval,uint32_t rounds,bool verbose) {
    Handle stop;
    stop.value=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    if(!stop.value){stop.value=INVALID_HANDLE_VALUE;failWin("stop event");}
    monitorStop=stop.value;
    if(!SetConsoleCtrlHandler(stopMonitor,TRUE)){monitorStop=nullptr;failWin("Ctrl+C handler");}
    struct ConsoleCleanup {~ConsoleCleanup(){SetConsoleCtrlHandler(stopMonitor,FALSE);monitorStop=nullptr;}} console;
    Handle device;
    device.value=CreateFileW(NU_DEVICE_PATH,GENERIC_READ|GENERIC_WRITE,0,nullptr,
                             OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr);
    if(device.value==INVALID_HANDLE_VALUE)failWin("open Bubble (administrator required)");
    DWORD count=0;NU_INFO_DATA info{};
    if(!ioctl(device.value,NU_INFO,nullptr,0,&info,sizeof(info),count))failWin("info");
    if(count!=sizeof(info)||info.Version!=NU_VERSION||info.SampleSize!=sizeof(NU_SAMPLE)||
       info.Build!=NU_TARGET_BUILD||!info.CpuCount||info.CpuCount>4096)
        throw std::runtime_error("driver/client profile mismatch");
    if(!(info.Features&NU_CAP_PULSE))throw std::runtime_error("driver lacks the pinned HalSendNMI sender");
    if(GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)<2)throw std::runtime_error("monitor requires at least two active processors");
    const HANDLE process=GetCurrentProcess();
    SymSetOptions(SYMOPT_FAIL_CRITICAL_ERRORS|SYMOPT_DEFERRED_LOADS|SYMOPT_UNDNAME);
    if(!SymInitialize(process,nullptr,FALSE))failWin("SymInitialize");
    struct Symbols {HANDLE p;~Symbols(){active=nullptr;SymCleanup(p);}} symbols{process};
    if(!SymRegisterCallback64(process,symbolCallback,0))failWin("SymRegisterCallback64");
    Walker walker;walker.Verbose=verbose;
    uint64_t round=0,total=0,observations=0;
    std::mt19937 jitter(std::random_device{}());
    std::uniform_int_distribution<uint32_t> extra(0,interval/4);
    std::cerr<<"MONITOR: periodic NMI capture; Ctrl+C stops. Run the driver workload separately.\n";
    std::cout<<"{\"event\":\"monitor_started\",\"interval_ms\":"<<interval
             <<",\"jitter_max_ms\":"<<interval/4<<",\"coverage\":\"sampled\"}\n"<<std::flush;
    while(WaitForSingleObject(stop.value,0)==WAIT_TIMEOUT&&(!rounds||round<rounds)) {
        const auto started=GetTickCount64();
        auto before=modules(device.value);
        refreshImages(walker,before);
        bool kernelReady=false;
        for(const auto& image:walker.Images)
            if(image.Pe&&nu::targetImage(*image.Pe)&&nu::ioctlTarget(*image.Pe))kernelReady=true;
        if(!kernelReady)throw std::runtime_error("matching kernel PE and IOCTL profile unavailable");
        if(!ioctl(device.value,NU_ARM,nullptr,0,nullptr,0,count))failWin("arm");
        struct RoundCleanup {
            HANDLE h;bool Armed=true;
            ~RoundCleanup(){if(Armed){DWORD n=0;ioctl(h,NU_DISARM,nullptr,0,nullptr,0,n);}}
        } cleanup{device.value};
        NU_PULSE_DATA pulse{};
        if(!ioctl(device.value,NU_PULSE,nullptr,0,&pulse,sizeof(pulse),count))failWin("send NMI");
        if(count!=sizeof(pulse)||!pulse.TargetCount||pulse.TargetCount>=info.CpuCount||
           pulse.SenderCpu>=info.CpuCount)throw std::runtime_error("invalid pulse response");
        std::vector<NU_SAMPLE> samples;
        std::vector<bool> seen(info.CpuCount,false);
        auto sample=std::make_unique<NU_SAMPLE>();
        uint32_t received=0;
        auto drain=[&] {
            for(uint32_t cpu=0;cpu<info.CpuCount;++cpu) {
                if(seen[cpu])continue;
                if(!ioctl(device.value,NU_READ,&cpu,sizeof(cpu),sample.get(),sizeof(*sample),count)) {
                    const auto error=GetLastError();
                    if(error==ERROR_NO_MORE_ITEMS||error==ERROR_NO_MORE_FILES)continue;
                    failWin("read sample");
                }
                if(count!=sizeof(*sample)||sample->Version!=NU_VERSION||sample->Cpu!=cpu||
                   sample->Generation!=pulse.Generation||sample->Stack.Size>NU_THREAD_BYTES||
                   sample->Nmi.Size>NU_NMI_BYTES)throw std::runtime_error("invalid monitor sample");
                seen[cpu]=true;samples.push_back(*sample);
                if(cpu!=pulse.SenderCpu)++received;
            }
        };
        const auto sent=GetTickCount64();
        do {
            drain();
            if(received>=pulse.TargetCount||GetTickCount64()-sent>=100)break;
            if(WaitForSingleObject(stop.value,1)!=WAIT_TIMEOUT)break;
        } while(true);
        if(!ioctl(device.value,NU_DISARM,nullptr,0,nullptr,0,count))failWin("disarm");
        cleanup.Armed=false;
        drain();
        const bool stable=sameModules(before,modules(device.value));
        uint32_t ioctlCount=0,incomplete=0;
        active=&walker;
        for(const auto& item:samples) {
            walker.Evidence={item.Cpu,item.Generation,item.Tsc,false,stable,
                (item.Flags&NU_F_THREAD_TRUNCATED)!=0,"context_unavailable",{}};
            auto kernel=walker.find(item.KernelBase);
            const bool target=kernel&&kernel->Pe&&nu::targetImage(*kernel->Pe)&&nu::ioctlTarget(*kernel->Pe);
            if(item.Flags&NU_F_USER_INTERRUPTED)walker.Evidence.Stop="user_context";
            else if(!target)walker.Evidence.Stop="target_mismatch";
            else {
                NU_REGS interrupted{};std::string error;
                if(!nu::interruptedContext(item,kernel->Module,interrupted,error))walker.Evidence.Stop="context_"+error;
                else walk(walker,item,interrupted,stable);
            }
            const auto observation=nu::observeIoctl(item,walker.Evidence,target);
            if(observation.Observed){++ioctlCount;std::cout<<nu::ioctlJson(item,observation)<<"\n";}
            const auto result=nu::evaluate(walker.Evidence);
            if(result.Status=="incomplete")++incomplete;
            if(verbose||!result.Findings.empty())std::cout<<nu::reportJson(walker.Evidence,result)<<"\n";
        }
        active=nullptr;
        ++round;total+=samples.size();observations+=ioctlCount;
        std::cout<<"{\"event\":\"nmi_round\",\"round\":"<<round<<",\"generation\":"<<pulse.Generation
                 <<",\"sender_cpu\":"<<pulse.SenderCpu<<",\"targeted\":"<<pulse.TargetCount
                 <<",\"captured\":"<<received<<",\"ioctl_observations\":"<<ioctlCount
                 <<",\"incomplete_samples\":"<<incomplete<<",\"inventory_stable\":"<<(stable?"true":"false")
                 <<",\"elapsed_ms\":"<<GetTickCount64()-started<<"}\n"<<std::flush;
        if(received<pulse.TargetCount&&WaitForSingleObject(stop.value,0)==WAIT_TIMEOUT)
            throw std::runtime_error("NMI delivery incomplete; stopping before another generation");
        const auto elapsed=GetTickCount64()-started;
        const uint64_t delay=interval+extra(jitter);
        if(elapsed<delay)WaitForSingleObject(stop.value,DWORD(delay-elapsed));
    }
    std::cout<<"{\"event\":\"monitor_stopped\",\"rounds\":"<<round<<",\"samples\":"<<total
             <<",\"ioctl_observations\":"<<observations<<"}\n"<<std::flush;
}

}

int wmain(int argc,wchar_t** argv) {
    try {
        if(argc==2&&std::wstring(argv[1])==L"replay"){nu::runNmiDemo(std::cout);return 0;}
        if(argc==2&&std::wstring(argv[1])==L"selftest"){selftest();return 0;}
        if(argc>=2&&(std::wstring(argv[1])==L"monitor"||std::wstring(argv[1])==L"demo")) {
            uint32_t interval=250,rounds=0;bool verbose=false;
            for(int i=2;i<argc;++i) {
                const std::wstring option=argv[i];
                if(option==L"--verbose"){verbose=true;continue;}
                if((option!=L"--interval-ms"&&option!=L"--rounds")||i+1>=argc)
                    throw std::runtime_error("expected --interval-ms N, --rounds N or --verbose");
                const std::wstring value=argv[++i];
                if(value.empty()||value.find_first_not_of(L"0123456789")!=std::wstring::npos)
                    throw std::runtime_error("expected an unsigned decimal integer");
                const auto number=std::stoull(value);
                if(number>UINT32_MAX)throw std::runtime_error("option exceeds uint32");
                if(option==L"--interval-ms")interval=uint32_t(number);else rounds=uint32_t(number);
            }
            if(interval<NU_PULSE_MIN_MS||interval>60000)throw std::runtime_error("interval must be 50..60000 ms");
            monitor(interval,rounds,verbose);return 0;
        }
        if(argc<3||argc>4) {
            std::cerr<<"Usage: bubble monitor [--interval-ms N] [--rounds N] [--verbose]\n"
                       "       bubble demo (live monitor)\n"
                       "       bubble capture|analyze bubble.nwu\n"
                       "       bubble replay | bubble selftest\n";return 1;
        }
        const std::wstring command=argv[1];
        if(argc!=3||(command!=L"capture"&&command!=L"analyze"))throw std::runtime_error("invalid command");
        const fs::path path=argv[2];
        if(command==L"capture")takeCapture(path);
        analyze(path,loadCapture(path));
        return 0;
    }catch(const std::exception& e){std::cerr<<"Error: "<<e.what()<<"\n";return 1;}
}
