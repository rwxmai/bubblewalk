#include "monitor_timing.h"
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>

namespace {
void require(bool value, const char* what) {
    if (!value) throw std::runtime_error(what);
}
constexpr uint64_t ms(uint64_t value) { return value * 10000u; }
}

int main() {
    try {
        // A 250 ms startup before sending must not consume the 50 ms pulse period.
        require(nu::monitorDelay100ns(ms(1250), ms(1255), 50, 0) == ms(45),
                "slow startup must not erase the wait after sending");
        require(nu::monitorDelay100ns(ms(1000), ms(1255), 50, 0) == 0,
                "round-start timing reproduces the old missing wait");
        require(nu::monitorDelay100ns(ms(1250), ms(1250), 50, 0) == ms(50),
                "full period remains at send time");
        require(nu::monitorDelay100ns(ms(1250), ms(1250) + 9999, 1, 0) == 1,
                "one 100 ns tick remains at the submillisecond deadline");
        require(nu::monitorDelay100ns(ms(1250), ms(1250) + 2500, 1, 0) == 7500,
                "one millisecond scheduling preserves a fractional millisecond wait");
        require(nu::monitorDelay100ns(ms(1250), ms(1251), 1, 0) == 0,
                "one millisecond scheduling has an exact deadline");
        require(nu::monitorDelay100ns(ms(1250), ms(1300), 50, 0) == 0,
                "no wait at the exact deadline");
        require(nu::monitorDelay100ns(ms(1250), ms(1450), 50, 0) == 0,
                "slow processing does not produce a negative wait");
        require(nu::monitorDelay100ns(ms(1250), ms(1255), 50, 12) == ms(57),
                "jitter extends the pulse period");
        require(nu::monitorDelay100ns(ms(1250), ms(1312), 50, 12) == 0,
                "jitter deadline has an exact boundary");
        require(nu::monitorDelay100ns(ms(1250), ms(1255), 60000, 15000) == ms(74995),
                "maximum configured interval and jitter");

        constexpr auto lastTick = std::numeric_limits<uint64_t>::max();
        require(nu::monitorDelay100ns(lastTick - 20, lastTick - 15, 1, 0) == 9995,
                "large clock values do not overflow a deadline addition");
        require(nu::monitorDelay100ns(lastTick - 20, 5, 1, 0) == 9974,
                "elapsed time remains correct across unsigned clock rollover");
        constexpr auto largestWait = std::numeric_limits<uint32_t>::max();
        require(nu::monitorDelay100ns(0, 0, largestWait, largestWait) ==
                uint64_t(largestWait) * 20000u,
                "wide interval and jitter addition remain exact");

        require(nu::monitorDutyDelay100ns(1000, 1) == 99000,
                "one percent duty adds ninety-nine work periods of rest");
        require(nu::monitorDutyDelay100ns(1000, 100) == 0,
                "one hundred percent duty adds no rest");
        require(nu::monitorDutyDelay100ns(0, 1) == 0,
                "zero measured work requires no duty rest");
        require(nu::monitorDutyDelay100ns(1, 3) == 33,
                "fractional duty rest rounds upward");
        require(nu::monitorDutyDelay100ns(2, 3) == 65,
                "duty rest retains fractions before rounding");
        require(nu::monitorDutyDelay100ns(1, 99) == 1,
                "small nonzero duty rest does not disappear");
        require(nu::monitorDutyDelay100ns(lastTick, 50) == lastTick,
                "representable duty rest avoids intermediate multiplication overflow");
        require(nu::monitorDutyDelay100ns(lastTick, 1) == lastTick,
                "unrepresentable duty rest saturates");
        require(nu::monitorDutyDelay100ns(lastTick / 99, 1) == (lastTick / 99) * 99,
                "largest representable one percent rest stays exact");
        require(nu::monitorDutyDelay100ns(lastTick / 99 + 1, 1) == lastTick,
                "one percent rest saturates at the first overflowing input");
        require(nu::monitorDutyDelay100ns(lastTick, 99) ==
                lastTick / 99 + (lastTick % 99 != 0),
                "large work at high duty preserves a representable result");
        require(nu::monitorDutyDelay100ns(1000, 0) == lastTick,
                "invalid zero duty defensively requests maximum rest");
        require(nu::monitorDutyDelay100ns(1000, 101) == 0,
                "duties above one hundred defensively add no rest");
        std::cout << "MONITOR_TIMING_PASSED\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
