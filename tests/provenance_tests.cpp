#include "../analyzer/provenance.h"
#include "fixture.h"
#include <iostream>
#include <stdexcept>

namespace {
void check(bool ok,const char* why){if(!ok)throw std::runtime_error(why);}
template<class F> void rejects(F action) {
    bool caught=false;try{action();}catch(const std::exception&){caught=true;}
    check(caught,"invalid inventory accepted");
}
}
int main() {
    try {
        constexpr uint64_t base=0xfffff80010000000ull,sp=0xffffa00000100000ull;
        auto pe=nu::PeImage::parse(nu::testImage());
        nu::ModuleMap map({{base,pe.size(),"ordinary.sys",&pe}});
        using K=nu::FrameKind;
        check(map.classify(base+0x1010,sp,0).Kind==K::ImageCode,"ordinary code");
        check(map.classify(base+0x9000,sp,0).Kind==K::OutsideModules,"standalone unowned RIP");
        check(map.classify(base+0x2010,sp,0).Kind==K::NonExecutableImage,"RIP in data");
        check(map.classify(base+0x1400,sp,0).Kind==K::NonExecutableImage,"sampled RIP is never biased");
        check(map.classify(base+0x1401,sp+40,1).Kind==K::NonExecutableImage,"one-byte bias cannot span a gap");
        check(map.classify(base+pe.size(),sp,0).Kind==K::OutsideModules,"exclusive module end");
        check(map.classify(0x1000,sp,0).Kind==K::Invalid,"user PC excluded");
        check(map.classify(base+0x1010,sp+1,0).Kind==K::Invalid,"unaligned SP excluded");
        nu::ModuleMap missing({{base,pe.size(),"ordinary.sys",nullptr}});
        check(missing.classify(base+0x1010,sp,0).Kind==K::MissingImage,"missing PE is not unowned");
        nu::ModuleMap renamed({{base,pe.size(),"arbitrary-name.sys",&pe}});
        check(renamed.classify(base+0x9000,sp,0).Kind==map.classify(base+0x9000,sp,0).Kind,"names cannot select a finding");
        rejects([]{nu::ModuleMap invalid({});});
        rejects([&]{nu::ModuleMap invalid({{base,0,"",nullptr}});});
        rejects([&]{nu::ModuleMap invalid({{UINT64_MAX-15,32,"",nullptr}});});
        rejects([&]{nu::ModuleMap invalid({{base,pe.size(),"",&pe},{base+0x1000,pe.size(),"",&pe}});});
        rejects([&]{nu::ModuleMap invalid({{base,0x1000,"",&pe}});});
        std::cout<<"Frame provenance passed: module bounds, section permissions, caller bias and unavailable images.\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}
}
