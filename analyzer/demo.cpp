#include "demo.h"
#include "provenance.h"
#include "../tests/fixture.h"
#include <ostream>
#include <stdexcept>
namespace nu {
/* demo: Feed synthetic PCs through the production module classifier */
void runNmiDemo(std::ostream& out) {
    const auto pe=PeImage::parse(testImage());
    constexpr uint64_t base=0xfffff80010000000ull,sp=0xffffa00000100000ull;
    const ModuleMap map({{base,pe.size(),"ordinary.sys",&pe}});
    struct Case {const char* Name;uint64_t Rip,Caller;bool Recovered,Stable;const char* Stop;const char* Code;};
    const Case cases[]={
        {"unowned_rip",base+0x9000,0,true,true,"outside_modules","NMI_UNOWNED_RIP"},
        {"unowned_caller",base+0x1010,base+0x9000,true,true,"outside_modules","NMI_UNOWNED_CALLER"},
        {"nonexecutable_rip",base+0x2010,0,true,true,"nonexecutable_image","NMI_RIP_OUTSIDE_EXECUTABLE_SECTIONS"},
        {"nonexecutable_caller",base+0x1010,base+0x2010,true,true,"nonexecutable_image","NMI_CALLER_OUTSIDE_EXECUTABLE_SECTIONS"},
        {"ordinary_image_code",base+0x1010,0,true,true,"terminal",""},
        {"data_only_indistinguishable",base+0x1010,0,true,true,"terminal",""},
        {"missing_context",base+0x9000,0,false,true,"context_unavailable",""},
        {"inventory_changed",base+0x9000,0,true,false,"inventory_changed",""},
        {"unwind_failure",base+0x1010,0,true,true,"unwind_failure",""}};
    for(const auto& c:cases) {
        StackEvidence e;
        e.ContextRecovered=c.Recovered;e.InventoryStable=c.Stable;e.Stop=c.Stop;
        e.Frames.push_back(map.classify(c.Rip,sp,0));
        if(c.Caller)e.Frames.push_back(map.classify(c.Caller,sp+40,1));
        const auto result=evaluate(e);
        if(*c.Code?(result.Findings.size()!=1||result.Findings[0].Code!=c.Code):!result.Findings.empty())
            throw std::runtime_error("demo finding mismatch");
        const std::string expected=*c.Code?"anomaly":std::string(c.Stop)=="terminal"?
                                   "no_anomaly_in_observed_frames":"incomplete";
        if(result.Status!=expected)throw std::runtime_error("demo coverage mismatch");
        out<<"{\"source\":\"synthetic_demo\",\"scenario\":\""<<c.Name<<"\",\"result\":"<<reportJson(e,result)<<"}\n";
    }
}
}
