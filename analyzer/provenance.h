#pragma once
#include "pe_image.h"
#include <cstdint>
#include <string>
#include <vector>

namespace nu {
struct ModuleView {
    uint64_t Base=0, Size=0;
    std::string Name;
    const PeImage* Image=nullptr;
};
enum class FrameKind { ImageCode, OutsideModules, NonExecutableImage, MissingImage, Invalid };
struct Frame {
    uint64_t Pc=0, LookupPc=0, Sp=0;
    uint32_t Depth=0;
    FrameKind Kind=FrameKind::Invalid;
    std::string Image;
};
class ModuleMap {
public:
    explicit ModuleMap(std::vector<ModuleView> modules);
    Frame classify(uint64_t pc,uint64_t sp,uint32_t depth) const;
private:
    std::vector<ModuleView> modules_;
    const ModuleView* owner(uint64_t pc) const;
};
struct StackEvidence {
    uint32_t Cpu=0, Generation=0;
    uint64_t Tsc=0;
    bool ContextRecovered=false, InventoryStable=false, StackTruncated=false;
    std::string Stop="context_unavailable";
    std::vector<Frame> Frames;
};
struct Finding { std::string Code; Frame Location; };
struct Evaluation {
    std::string Status="incomplete";
    bool Complete=false;
    std::vector<Finding> Findings;
};
Evaluation evaluate(const StackEvidence& evidence);
std::string reportJson(const StackEvidence& evidence,const Evaluation& result);
}
