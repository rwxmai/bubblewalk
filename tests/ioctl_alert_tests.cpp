#include "ioctl_alert.h"
#include <iostream>
#include <memory>
#include <stdexcept>

namespace {
void check(bool value,const char* reason) {if(!value)throw std::runtime_error(reason);}
}

int main() {
    try {
        nu::IoctlObservation observation;
        auto sample=std::make_unique<NU_SAMPLE>();
        check(nu::ioctlAlertText(*sample,observation).empty(),
              "no human alert without a validated IOCTL observation");
        observation.Observed=true;
        observation.Code=0x8338a004;
        observation.InputLength=16;
        observation.OutputLength=8;
        observation.DispatchPc=0xfffff80112345678ull;
        observation.Image="\\SystemRoot\\System32\\drivers\\nmi-ioctl-lab.sys";
        observation.Path="irp_dispatch";
        sample->Cpu=2;sample->Generation=7;sample->Thread=0xffff900000001000ull;
        const auto alert=nu::ioctlAlertText(*sample,observation);
        check(alert.find("IOCTL Detected (sampled)")!=std::string::npos,
              "observation must be visible as a sampled IOCTL alert");
        check(alert.find(observation.Image)!=std::string::npos,
              "alert must name the dispatch image");
        check(alert.find("0x8338a004")!=std::string::npos&&
              alert.find("Input: 16 bytes  output: 8 bytes")!=std::string::npos,
              "alert must show code and lengths");
        check(alert.find("CPU: 2  generation: 7")!=std::string::npos&&
              alert.find("path: irp_dispatch")!=std::string::npos,
              "alert must show capture identity and dispatch path");
        observation.Image="driver\nname.sys";
        check(nu::ioctlAlertText(*sample,observation).find("driver?name.sys")!=std::string::npos,
              "untrusted image text must not inject new terminal lines");
        std::cout<<"IOCTL_ALERT_PASSED\n";
        return 0;
    } catch(const std::exception& e) {std::cerr<<e.what()<<"\n";return 1;}
}
