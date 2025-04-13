#include "provenance.h"
#include <algorithm>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace nu {
namespace {
bool kernel(uint64_t address) {return address>=0xffff800000000000ull;}
}
/* modules: Reject wrapped or overlapping ranges before resolving PCs */
ModuleMap::ModuleMap(std::vector<ModuleView> modules):modules_(std::move(modules)) {
    if(modules_.empty())throw std::runtime_error("empty module inventory");
    std::sort(modules_.begin(),modules_.end(),[](const auto& a,const auto& b){return a.Base<b.Base;});
    uint64_t end=0;
    for(const auto& m:modules_) {
        if(!kernel(m.Base)||!m.Size||m.Size>std::numeric_limits<uint64_t>::max()-m.Base||m.Base<end)
            throw std::runtime_error("invalid module interval");
        if(m.Image&&m.Image->size()!=m.Size)throw std::runtime_error("module/image size mismatch");
        end=m.Base+m.Size;
    }
}
const ModuleView* ModuleMap::owner(uint64_t pc) const {
    auto it=std::upper_bound(modules_.begin(),modules_.end(),pc,
        [](uint64_t value,const ModuleView& m){return value<m.Base;});
    if(it==modules_.begin())return nullptr;
    --it;return pc-it->Base<it->Size?&*it:nullptr;
}
/* provenance: Preserve the sampled PC while adjusting caller membership
 * CALL may leave a return PC at an executable section's exclusive end.
 * Apply PC-1 only to callers whose exact PC lacks executable coverage.
 */
Frame ModuleMap::classify(uint64_t pc,uint64_t sp,uint32_t depth) const {
    Frame f{pc,pc,sp,depth,FrameKind::Invalid,{}};
    if(!kernel(pc)||!kernel(sp)||(sp&7))return f;
    auto m=owner(pc);
    if(depth&&(!m||(m->Image&&!m->Image->executable(pc-m->Base)))) {
        auto previous=owner(pc-1);
        if(previous&&previous->Image&&previous->Image->executable(pc-1-previous->Base)) {
            m=previous;f.LookupPc=pc-1;
        }
    }
    if(!m){f.Kind=FrameKind::OutsideModules;return f;}
    f.Image=m->Name;
    if(!m->Image){f.Kind=FrameKind::MissingImage;return f;}
    f.Kind=m->Image->executable(f.LookupPc-m->Base)?FrameKind::ImageCode:FrameKind::NonExecutableImage;
    return f;
}
}
