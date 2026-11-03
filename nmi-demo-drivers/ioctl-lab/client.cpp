#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <limits>
#include "protocol.h"

namespace {
enum class Mode { Status, Evaluate };

struct Options {
    Mode mode = Mode::Evaluate;
    unsigned count = 20;
    unsigned spacingMs = 20;
    unsigned holdMs = 0;
    unsigned targetPid = GetCurrentProcessId();
    bool readOnly = false;
    bool badLength = false;
};

void usage() {
    std::fwprintf(stderr,
        L"Usage: nmi-ioctl-client [--mode status|evaluate] [--count 1..100000] "
        L"[--spacing-ms 0..60000] [--hold-ms 0..20] [--pid N] "
        L"[--read-only] [--bad-length]\n"
        L"  evaluate is a policy-denied simulation. It never touches the target PID.\n"
        L"  --hold-ms adds artificial active dispatch time for sampling experiments.\n"
        L"  --read-only tests access denial; --bad-length tests buffer validation.\n");
}

bool parseUnsigned(const wchar_t* value, unsigned minimum, unsigned maximum,
                   unsigned& result) {
    if (!value || !*value || *value == L'-') return false;
    errno = 0;
    wchar_t* end = nullptr;
    unsigned long long parsed = std::wcstoull(value, &end, 10);
    if (errno || !end || *end || parsed < minimum || parsed > maximum) return false;
    result = static_cast<unsigned>(parsed);
    return true;
}

bool parse(int argc, wchar_t** argv, Options& options) {
    for (int i = 1; i < argc; ++i) {
        const wchar_t* arg = argv[i];
        if (!std::wcscmp(arg, L"--help") || !std::wcscmp(arg, L"-h")) {
            usage();
            std::exit(0);
        }
        if (!std::wcscmp(arg, L"--read-only")) {
            options.readOnly = true;
            continue;
        }
        if (!std::wcscmp(arg, L"--bad-length")) {
            options.badLength = true;
            continue;
        }
        if (++i >= argc) return false;
        const wchar_t* value = argv[i];
        if (!std::wcscmp(arg, L"--mode")) {
            if (!std::wcscmp(value, L"status")) options.mode = Mode::Status;
            else if (!std::wcscmp(value, L"evaluate")) options.mode = Mode::Evaluate;
            else return false;
        } else if (!std::wcscmp(arg, L"--count")) {
            if (!parseUnsigned(value, 1, 100000, options.count)) return false;
        } else if (!std::wcscmp(arg, L"--spacing-ms")) {
            if (!parseUnsigned(value, 0, 60000, options.spacingMs)) return false;
        } else if (!std::wcscmp(arg, L"--hold-ms")) {
            if (!parseUnsigned(value, 0, LAB_MAX_HOLD_MS, options.holdMs)) return false;
        } else if (!std::wcscmp(arg, L"--pid")) {
            if (!parseUnsigned(value, 1, std::numeric_limits<unsigned>::max(),
                               options.targetPid)) return false;
        } else return false;
    }
    if (options.mode == Mode::Status &&
        (options.holdMs || options.badLength || options.readOnly)) return false;
    if (options.readOnly && options.badLength) return false;
    return true;
}

unsigned long long filetimeNow() {
    FILETIME filetime{};
    GetSystemTimePreciseAsFileTime(&filetime);
    ULARGE_INTEGER ticks{};
    ticks.LowPart = filetime.dwLowDateTime;
    ticks.HighPart = filetime.dwHighDateTime;
    return ticks.QuadPart;
}

const char* caseName(const Options& options) {
    if (options.readOnly) return "read_only_handle";
    if (options.badLength) return "bad_input_length";
    if (options.holdMs) return "artificial_active_hold";
    return "natural_dispatch";
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    Options options;
    if (!parse(argc, argv, options)) {
        usage();
        return 2;
    }
    const bool evaluate = options.mode == Mode::Evaluate;
    const DWORD access = evaluate && !options.readOnly
        ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_READ;
    HANDLE device = CreateFileW(L"\\\\.\\NmiIoctlLab", access,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        std::fprintf(stderr, "NmiIoctlLab open failed: Win32 error %lu\n", GetLastError());
        return 1;
    }

    LARGE_INTEGER frequency{};
    if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0) {
        std::fprintf(stderr, "QueryPerformanceFrequency failed\n");
        CloseHandle(device);
        return 1;
    }
    const DWORD code = evaluate ? LAB_IOCTL_EVALUATE : LAB_IOCTL_STATUS;
    const char* mode = evaluate ? "evaluate" : "status";
    unsigned succeeded = 0;
    unsigned failed = 0;
    unsigned invalidReplies = 0;

    for (unsigned i = 0; i < options.count; ++i) {
        LAB_REQUEST request{LAB_VERSION, i + 1, options.targetPid, options.holdMs};
        LAB_REPLY reply{};
        DWORD returned = 0;
        DWORD inputBytes = evaluate ? static_cast<DWORD>(sizeof(request)) : 0;
        if (evaluate && options.badLength) inputBytes -= sizeof(ULONG);
        LARGE_INTEGER before{}, after{};
        const unsigned long long startTicks = filetimeNow();
        QueryPerformanceCounter(&before);
        BOOL ok = DeviceIoControl(device, code, evaluate ? &request : nullptr,
                                  inputBytes, &reply, sizeof(reply), &returned, nullptr);
        const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        QueryPerformanceCounter(&after);
        const unsigned long long endTicks = filetimeNow();
        const double durationUs = (after.QuadPart - before.QuadPart) * 1000000.0 /
                                  static_cast<double>(frequency.QuadPart);
        if (ok) ++succeeded;
        else ++failed;
        const bool replyValid = ok && returned == sizeof(reply) &&
            reply.Version == LAB_VERSION &&
            reply.Decision == (evaluate ? LAB_DECISION_DENIED : 0u) &&
            (!evaluate || reply.RequestId == i + 1);
        if (ok && !replyValid) ++invalidReplies;

        std::printf("{\"event\":\"lab_ioctl_request\",\"request_id\":%u,"
            "\"mode\":\"%s\",\"case\":\"%s\",\"submitted_ioctl\":\"0x%08lX\","
            "\"input_length\":%lu,\"output_length\":%zu,\"returned_length\":%lu,"
            "\"target_pid_field\":%u,\"hold_ms\":%u,"
            "\"start_filetime_100ns\":%llu,\"end_filetime_100ns\":%llu,"
            "\"duration_us\":%.3f,\"device_io_control_ok\":%s,"
            "\"win32_error\":%lu,\"reply_valid\":%s,"
            "\"reply_version\":%lu,\"decision\":%lu,"
            "\"driver_elapsed_us\":%lu}\n",
            i + 1, mode, caseName(options), code, inputBytes, sizeof(reply), returned,
            options.targetPid, options.holdMs, startTicks, endTicks, durationUs,
            ok ? "true" : "false", error, replyValid ? "true" : "false",
            reply.Version, reply.Decision,
            reply.ElapsedUs);
        std::fflush(stdout);
        if (i + 1 < options.count && options.spacingMs) Sleep(options.spacingMs);
    }
    std::printf("{\"event\":\"lab_ioctl_summary\",\"mode\":\"%s\","
                "\"case\":\"%s\",\"sent\":%u,\"succeeded\":%u,"
                "\"failed\":%u,\"invalid_replies\":%u}\n",
                mode, caseName(options), options.count, succeeded, failed,
                invalidReplies);
    CloseHandle(device);
    if (options.readOnly || options.badLength) return succeeded == 0 ? 0 : 1;
    return failed == 0 && invalidReplies == 0 ? 0 : 1;
}
