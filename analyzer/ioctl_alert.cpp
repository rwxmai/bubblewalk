#include "ioctl_alert.h"
#include <iomanip>
#include <sstream>
#include <string_view>

namespace nu {
namespace {
std::string safeText(std::string_view value) {
    std::string result;
    result.reserve(value.size());
    for(unsigned char c:value)result.push_back(c<0x20||c==0x7f?'?':char(c));
    return result;
}
}

std::string ioctlAlertText(const NU_SAMPLE& sample,const IoctlObservation& observation) {
    if(!observation.Observed)return {};
    std::ostringstream out;
    out<<"\n=== IOCTL Detected (sampled) ===\n"
       <<"Dispatch image: "<<safeText(observation.Image)<<'\n'
       <<"Submitted IOCTL: 0x"<<std::hex<<std::setw(8)<<std::setfill('0')
       <<observation.Code<<"  dispatch PC: 0x"<<observation.DispatchPc<<'\n'
       <<"Thread: 0x"<<sample.Thread<<std::dec<<"  CPU: "<<sample.Cpu
       <<"  generation: "<<sample.Generation<<'\n'
       <<"Input: "<<observation.InputLength<<" bytes  output: "
       <<observation.OutputLength<<" bytes  path: "<<safeText(observation.Path)<<'\n';
    return out.str();
}
}
