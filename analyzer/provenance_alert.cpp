#include "provenance_alert.h"
#include <iomanip>
#include <sstream>

namespace nu {
namespace {
std::string hex(uint64_t value) {
    std::ostringstream out;
    out<<"0x"<<std::hex<<value;
    return out.str();
}

/* Module paths come from the capture. Keep control bytes out of the terminal. */
std::string printable(const std::string& value) {
    std::ostringstream out;
    out<<'"';
    for(unsigned char c:value) {
        if(c=='"'||c=='\\')out<<'\\'<<char(c);
        else if(c<0x20||c>=0x7f)
            out<<"\\x"<<std::hex<<std::setw(2)<<std::setfill('0')<<unsigned(c)<<std::dec;
        else out<<char(c);
    }
    out<<'"';
    return out.str();
}

const char* description(const std::string& code) {
    if(code=="NMI_UNOWNED_RIP")return "Interrupted RIP is outside the OS loaded-image inventory.";
    if(code=="NMI_UNOWNED_CALLER")return "Recovered return PC is outside the OS loaded-image inventory.";
    if(code=="NMI_RIP_OUTSIDE_EXECUTABLE_SECTIONS")
        return "Interrupted RIP is outside the recorded image's executable sections.";
    if(code=="NMI_CALLER_OUTSIDE_EXECUTABLE_SECTIONS")
        return "Recovered return PC is outside the recorded image's executable sections.";
    return "The recovered frame has a provenance finding.";
}
}

std::string provenanceAlerts(const StackEvidence& e,const Evaluation& r) {
    if(r.Status!="anomaly"||r.Findings.empty())return {};
    std::ostringstream out;
    for(const auto& finding:r.Findings) {
        const auto& location=finding.Location;
        out<<(location.Depth==0?"KERNEL EXECUTION ANOMALY":"KERNEL STACK ANOMALY")<<'\n'
           <<"  Finding: "<<finding.Code<<'\n'
           <<"  Evidence: "<<description(finding.Code)<<'\n'
           <<"  PC: "<<hex(location.Pc);
        if(location.LookupPc!=location.Pc)out<<"  Lookup PC: "<<hex(location.LookupPc);
        out<<"  SP: "<<hex(location.Sp)<<"  Depth: "<<location.Depth<<'\n'
           <<"  Image: "<<(location.Image.empty()?"none in loaded-image inventory":printable(location.Image))<<'\n'
           <<"  CPU: "<<e.Cpu<<"  Generation: "<<e.Generation<<"  TSC: "<<hex(e.Tsc)<<'\n';
    }
    return out.str();
}
}
