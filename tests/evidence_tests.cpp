#include "../analyzer/provenance.h"
#include "fixture.h"
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace {void check(bool ok,const char* why){if(!ok)throw std::runtime_error(why);}}
int main() {
    try {
        constexpr uint64_t base=0xfffff80010000000ull,sp=0xffffa00000100000ull;
        auto pe=nu::PeImage::parse(nu::testImage());
        nu::ModuleMap map({{base,pe.size(),"quote\"slash\\newline\n.sys",&pe}});
        nu::StackEvidence e;
        e.ContextRecovered=true;e.InventoryStable=true;e.Stop="outside_modules";
        e.Frames={map.classify(base+0x9000,sp,0)};
        auto r=nu::evaluate(e);
        check(r.Findings.size()==1&&r.Findings[0].Code=="NMI_UNOWNED_RIP","unowned RIP needs no known-driver frame");
        e.Frames={map.classify(base+0x1010,sp,0),map.classify(base+0x9000,sp+40,1)};
        r=nu::evaluate(e);
        check(r.Findings.size()==1&&r.Findings[0].Code=="NMI_UNOWNED_CALLER","caller after an ordinary image");
        e.StackTruncated=true;
        check(nu::evaluate(e).Status=="anomaly"&&!nu::evaluate(e).Complete,"truncated suffix preserves valid prefix evidence");
        e.StackTruncated=false;e.ContextRecovered=false;
        check(nu::evaluate(e).Findings.empty()&&nu::evaluate(e).Status=="incomplete","context gate");
        e.ContextRecovered=true;e.InventoryStable=false;
        check(nu::evaluate(e).Findings.empty(),"changed inventory gate");
        e.InventoryStable=true;e.Frames={map.classify(base+0x2010,sp,0)};e.Stop="nonexecutable_image";
        r=nu::evaluate(e);
        check(r.Findings[0].Code=="NMI_RIP_OUTSIDE_EXECUTABLE_SECTIONS","RIP section evidence");
        auto json=nu::reportJson(e,r);
        check(json.find("\\\"")!=std::string::npos&&json.find("\\\\")!=std::string::npos&&json.find("\\u000a")!=std::string::npos,"JSON path escaping");
        e.Frames={map.classify(base+0x1010,sp,0),map.classify(base+0x2010,sp+40,1)};
        check(nu::evaluate(e).Findings[0].Code=="NMI_CALLER_OUTSIDE_EXECUTABLE_SECTIONS","caller section evidence");
        e.Frames={map.classify(base+0x1010,sp,0)};e.Stop="terminal";
        check(nu::evaluate(e).Findings.empty()&&nu::evaluate(e).Complete,"ordinary image execution is not suspicious");
        for(const char* stop:{"read_failure","unwind_failure","no_progress","frame_limit","stack_bounds"}) {
            e.Stop=stop;check(nu::evaluate(e).Status=="incomplete","failed walk cannot report a clean chain");
        }
        e.Stop="terminal";e.StackTruncated=true;
        check(!nu::evaluate(e).Complete,"truncated terminal chain");
        e.StackTruncated=false;e.Frames.clear();
        check(nu::evaluate(e).Status=="incomplete","empty sample is not clean");
        e.Frames={map.classify(base+0x9000,sp,2)};
        check(nu::evaluate(e).Findings.empty(),"noncontiguous frame depths rejected");
        nu::ModuleMap missing({{base,pe.size(),"missing.sys",nullptr}});
        e.Frames={missing.classify(base+0x1010,sp,0)};
        check(nu::evaluate(e).Status=="incomplete","missing metadata is not execution outside an image");
        std::cout<<"NMI evidence passed: independent anomalies, coverage gates, JSON and replay controls.\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}
}
