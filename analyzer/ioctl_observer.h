#pragma once
#include "provenance.h"
#include "../include/protocol.h"

namespace nu {
struct IoctlObservation {
    bool Observed=false;
    uint32_t Code=0, InputLength=0, OutputLength=0;
    uint32_t DispatchDepth=0;
    uint64_t DispatchPc=0, ArgumentAddress=0;
    std::string Path, Image;
};
bool ioctlTarget(const PeImage& image);
IoctlObservation observeIoctl(const NU_SAMPLE& sample,const StackEvidence& evidence,
                              bool targetValidated);
std::string ioctlJson(const NU_SAMPLE& sample,const IoctlObservation& observation);
}
