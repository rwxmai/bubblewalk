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
/* A candidate has the pinned NtDeviceIoControlFile return PC in its walk.
 * Rejection is null for an observed dispatch or an unrelated sample.
 * Rejections: target_profile, context_unavailable, inventory_unstable,
 * sample_bounds, invalid_frame_prefix, missing_dispatch_frame,
 * return_chain_mismatch, frame_extent_mismatch, argument_unavailable,
 * not_device_control, argument_mismatch.
 */
struct IoctlDiagnosis {
    IoctlObservation Observation;
    bool Candidate=false;
    uint32_t CandidateDepth=0;
    const char* Rejection=nullptr;
};
bool ioctlTarget(const PeImage& image);
IoctlDiagnosis diagnoseIoctl(const NU_SAMPLE& sample,const StackEvidence& evidence,
                             bool targetValidated);
IoctlObservation observeIoctl(const NU_SAMPLE& sample,const StackEvidence& evidence,
                              bool targetValidated);
std::string ioctlJson(const NU_SAMPLE& sample,const IoctlObservation& observation);
}
