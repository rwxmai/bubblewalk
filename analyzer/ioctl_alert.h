#pragma once
#include "ioctl_observer.h"

namespace nu {
// Human-readable companion to the nmi_ioctl JSON event. No threat verdict is implied.
std::string ioctlAlertText(const NU_SAMPLE& sample,const IoctlObservation& observation);
}
