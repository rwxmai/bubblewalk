#pragma once
#include <cstdint>
#include <limits>

namespace nu {
/* monitor: Space pulses from the previous send, excluding startup work. */
inline uint64_t monitorDelay100ns(uint64_t sentAt, uint64_t now,
                                  uint32_t intervalMs, uint32_t jitterMs) {
    const uint64_t period = (uint64_t(intervalMs) + jitterMs) * 10000u;
    const uint64_t elapsed = now - sentAt;
    if (elapsed >= period) return 0;
    return period - elapsed;
}

/* monitor: Bound measured round wall time, excluding idle, with additional rest.
 * This is a wall-time duty budget, not a CPU utilization guarantee. The caller
 * accepts 1..100 percent; zero defensively saturates and >=100 requires no rest.
 */
inline uint64_t monitorDutyDelay100ns(uint64_t roundWork100ns, uint32_t dutyPercent) {
    if (!dutyPercent) return std::numeric_limits<uint64_t>::max();
    if (dutyPercent >= 100) return 0;
    const uint64_t restPercent = 100u - dutyPercent;
    const uint64_t whole = roundWork100ns / dutyPercent;
    const uint64_t remainder = roundWork100ns % dutyPercent;
    const auto limit = std::numeric_limits<uint64_t>::max();
    if (whole > limit / restPercent) return limit;
    const uint64_t rest = whole * restPercent;
    const uint64_t extra = (remainder * restPercent + dutyPercent - 1u) / dutyPercent;
    return extra > limit - rest ? limit : rest + extra;
}
}
