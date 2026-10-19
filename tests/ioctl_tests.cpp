#include "ioctl_observer.h"
#include "../include/ioctl_26100_1.h"
#include <cstring>
#include <iostream>
#include <memory>
#include <stdexcept>

namespace {
void require(bool value,const char* what) {if(!value)throw std::runtime_error(what);}
void put(NU_SAMPLE& s,uint64_t address,uint32_t value) {
    const auto at=address-s.Stack.Base;
    require(at+4<=s.Stack.Size,"fixture write bounds");
    std::memcpy(s.StackBytes+at,&value,4);
}
nu::StackEvidence fixture(NU_SAMPLE& s,bool fast=false) {
    s={};s.Version=NU_VERSION;s.KernelBase=0xfffff80000000000ull;
    s.Stack={0xffff900000010000ull,4096,0};
    nu::StackEvidence e;e.ContextRecovered=true;e.InventoryStable=true;
    auto frame=[&](uint64_t rva,uint64_t sp,const char* name) {
        auto pc=s.KernelBase+rva;
        e.Frames.push_back({pc,pc,sp,uint32_t(e.Frames.size()),nu::FrameKind::ImageCode,name});
    };
    const auto sp=s.Stack.Base;
    frame(0x2000000,sp,"ordinary.sys");
    if(!fast) {frame(NU_IOCTL_DRIVER_RETURN,sp+0x40,"ntoskrnl.exe");
              frame(NU_IOCTL_TAIL_RETURN,sp+0x80,"ntoskrnl.exe");}
    frame(fast?NU_IOCTL_FAST_RETURN:NU_IOCTL_IOP_RETURN,sp+0x130,"ntoskrnl.exe");
    frame(NU_IOCTL_NT_RETURN,sp+0x3a0,"ntoskrnl.exe");
    const auto nt=e.Frames.back().Sp;
    put(s,nt+0x28,0x8337e020);put(s,nt+0x98,0x8337e020);
    put(s,nt+0x38,4);put(s,nt+0xa8,4);
    put(s,nt+0x48,8);put(s,nt+0xb8,8);put(s,nt+0x50,1);
    return e;
}
}
int main() {
    try {
        auto s=std::make_unique<NU_SAMPLE>();
        auto e=fixture(*s);
        auto observe=[&]{return nu::observeIoctl(*s,e,true);};
        auto o=observe();
        require(o.Observed&&o.Code==0x8337e020&&o.Image=="ordinary.sys"&&
                o.Path=="irp_dispatch"&&o.InputLength==4&&o.OutputLength==8,"IRP dispatch");
        require(!nu::observeIoctl(*s,e,false).Observed,"profile mismatch");
        e.InventoryStable=false;require(!observe().Observed,"changed inventory");e.InventoryStable=true;
        e.ContextRecovered=false;require(!observe().Observed,"missing context");e.ContextRecovered=true;
        e.Frames.back().Pc-=0x800;require(!observe().Observed,"exclude NtFsControlFile");e=fixture(*s);
        e.Frames[2].Pc++;require(!observe().Observed,"exclude generic I/O calls");e=fixture(*s);
        e.Frames[1].Sp+=8;require(!observe().Observed,"reject wrong frame extent");e=fixture(*s);
        e.Frames[0].Kind=nu::FrameKind::MissingImage;require(!observe().Observed,"missing dispatch PE");e=fixture(*s);
        put(*s,e.Frames.back().Sp+0x98,42);require(!observe().Observed,"argument copies differ");e=fixture(*s);
        put(*s,e.Frames.back().Sp+0x50,0);require(!observe().Observed,"file-system selector");e=fixture(*s);
        s->Stack.Size=uint32_t(e.Frames.back().Sp-s->Stack.Base+0xba);
        require(!observe().Observed,"truncated argument");e=fixture(*s);
        e.StackTruncated=true;require(observe().Observed,"retain complete observed prefix");
        e.Frames.push_back({s->KernelBase+0x888888,s->KernelBase+0x888888,
            e.Frames.back().Sp+0x70,5,nu::FrameKind::MissingImage,"outer.sys"});
        require(observe().Observed,"retain prefix before unavailable outer frame");
        e=fixture(*s,true);o=observe();require(o.Observed&&o.Path=="fast_io_dispatch","fast I/O");
        e.Frames[0].Image="driver\"\\\n.sys";o=observe();
        require(nu::ioctlJson(*s,o).find("driver\\\"\\\\\\u000a.sys")!=std::string::npos,"JSON escape");
        e.Frames.erase(e.Frames.begin());require(!observe().Observed,"missing driver frame");
        std::cout<<"IOCTL_OBSERVER_PASSED\n";
        return 0;
    } catch(const std::exception& e) {std::cerr<<e.what()<<"\n";return 1;}
}
