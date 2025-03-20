#pragma once
#include "../include/protocol.h"
#include "pe_image.h"
#include <string>

namespace nu {
bool targetImage(const PeImage& image);
bool interruptedContext(const NU_SAMPLE& sample, const NU_MODULE& kernel,
                        NU_REGS& output, std::string& error);
}
