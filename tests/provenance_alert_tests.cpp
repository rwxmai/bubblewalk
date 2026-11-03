#include "../analyzer/provenance_alert.h"
#include "fixture.h"
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
void check(bool ok,const char* why) {if(!ok)throw std::runtime_error(why);}
void contains(const std::string& value,const std::string& part,const char* why) {
    check(value.find(part)!=std::string::npos,why);
}
}

int main() {
    try {
        constexpr uint64_t base=0xfffff80010000000ull,sp=0xffffa00000100000ull;
        auto pe=nu::PeImage::parse(nu::testImage());
        nu::ModuleMap map({{base,pe.size(),"lab\n\x1b.sys",&pe}});
        nu::StackEvidence e;
        e.Cpu=3;e.Generation=42;e.Tsc=0x1234;
        e.ContextRecovered=true;e.InventoryStable=true;
        e.Stop="outside_modules";
        e.Frames={map.classify(base+0x9000,sp,0)};
        auto alert=nu::provenanceAlerts(e,nu::evaluate(e));
        contains(alert,"KERNEL EXECUTION ANOMALY\n","unowned RIP heading");
        contains(alert,"NMI_UNOWNED_RIP","unowned RIP code");
        contains(alert,"PC: 0xfffff80010009000","sampled PC");
        contains(alert,"Image: none in loaded-image inventory","no invented driver name");
        contains(alert,"CPU: 3  Generation: 42  TSC: 0x1234","sample identity");
        check(alert.find("unsigned")==std::string::npos&&alert.find("IOCTL")==std::string::npos,
              "unavailable attribution claimed");

        e.Frames={map.classify(base+0x1010,sp,0),map.classify(base+0x9000,sp+40,1)};
        alert=nu::provenanceAlerts(e,nu::evaluate(e));
        contains(alert,"KERNEL STACK ANOMALY\n","unowned caller heading");
        contains(alert,"NMI_UNOWNED_CALLER","unowned caller code");
        contains(alert,"Recovered return PC","caller wording");

        e.Stop="nonexecutable_image";
        e.Frames={map.classify(base+0x2010,sp,0)};
        alert=nu::provenanceAlerts(e,nu::evaluate(e));
        contains(alert,"NMI_RIP_OUTSIDE_EXECUTABLE_SECTIONS","nonexecuting RIP code");
        contains(alert,"Image: \"lab\\x0a\\x1b.sys\"","terminal-safe path");
        check(alert.find('\x1b')==std::string::npos,"raw terminal escape leaked");

        e.Frames={map.classify(base+0x1010,sp,0),map.classify(base+0x2010,sp+40,1)};
        alert=nu::provenanceAlerts(e,nu::evaluate(e));
        contains(alert,"NMI_CALLER_OUTSIDE_EXECUTABLE_SECTIONS","nonexecuting caller code");

        e.Frames={map.classify(base+0x1010,sp,0)};e.Stop="terminal";
        check(nu::provenanceAlerts(e,nu::evaluate(e)).empty(),"clean sample alerted");
        e.ContextRecovered=false;
        check(nu::provenanceAlerts(e,nu::evaluate(e)).empty(),"incomplete sample alerted");
        std::cout<<"Provenance alerts passed.\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
