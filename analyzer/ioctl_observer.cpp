#include "ioctl_observer.h"
#include "../include/ioctl_26100_1.h"
#include <cstring>
#include <iomanip>
#include <sstream>

namespace nu {
bool ioctlTarget(const PeImage& image) {
    if(image.size()!=NU_TARGET_SIZE||image.timestamp()!=NU_TARGET_TIMESTAMP||
       image.checksum()!=NU_TARGET_CHECKSUM)return false;
    for(const auto& check:NuIoctlCode) {
        unsigned char bytes[96]{};
        if(!image.read(check.Rva,bytes,check.Size)||
           std::memcmp(bytes,check.Bytes,check.Size))return false;
    }
    return true;
}

IoctlObservation observeIoctl(const NU_SAMPLE& sample,const StackEvidence& e,bool validated) {
    IoctlObservation result;
    if(!validated||!e.ContextRecovered||!e.InventoryStable||
       sample.Stack.Size>NU_THREAD_BYTES||sample.KernelBase<0xffff800000000000ull||
       sample.KernelBase>UINT64_MAX-NU_TARGET_SIZE)return result;
    const auto& frames=e.Frames;
    size_t valid=0;
    for(size_t i=0;i<frames.size();++i) {
        const auto& f=frames[i];
        if(f.Depth!=i||f.Kind!=FrameKind::ImageCode||f.Sp<sample.Stack.Base||
           f.Sp-sample.Stack.Base>sample.Stack.Size||
           (i&&f.Sp<frames[i-1].Sp))break;
        ++valid;
    }
    auto at=[&](size_t i,uint64_t rva) {
        return i<frames.size()&&frames[i].Pc==sample.KernelBase+rva;
    };
    for(size_t nt=2;nt<valid;++nt) {
        if(!at(nt,NU_IOCTL_NT_RETURN))continue;
        size_t dispatch=0;
        const char* path=nullptr;
        /* ioctl: Require adjacent return sites through the first dispatch
         * A generic IofCallDriver frame cannot distinguish IRP major codes.
         * NtDeviceIoControlFile excludes the shared FsControlFile path.
         */
        if(nt>=4&&at(nt-1,NU_IOCTL_IOP_RETURN)&&at(nt-2,NU_IOCTL_TAIL_RETURN)&&
           at(nt-3,NU_IOCTL_DRIVER_RETURN)) {
            dispatch=nt-4;path="irp_dispatch";
            if(frames[nt-2].Sp-frames[nt-3].Sp!=0x40||
               frames[nt-1].Sp-frames[nt-2].Sp!=0xb0)continue;
        } else if(at(nt-1,NU_IOCTL_FAST_RETURN)) {
            dispatch=nt-2;path="fast_io_dispatch";
        } else continue;
        if(frames[nt].Sp-frames[nt-1].Sp!=0x270)continue;
        const auto sp=frames[nt].Sp;
        if(sp>UINT64_MAX-0xbc)continue;
        auto read=[&](uint64_t offset,void* to,size_t size) {
            return readRegion(sample.Stack.Base,sample.StackBytes,sample.Stack.Size,sp+offset,to,size);
        };
        uint32_t code=0,input=0,output=0,originalCode=0,originalInput=0,originalOutput=0;
        uint8_t deviceControl=0;
        /* ioctl: Read copied arguments while the wrapper remains suspended
         * RSP+28/38/48 contain code and lengths; +98/A8/B8 retain the
         * incoming values. +50 selects device control in IopXxxControlFile.
         * Report the submitted code, not a downstream rewritten IRP.
         */
        if(!read(0x28,&code,4)||!read(0x38,&input,4)||!read(0x48,&output,4)||
           !read(0x98,&originalCode,4)||!read(0xa8,&originalInput,4)||
           !read(0xb8,&originalOutput,4)||!read(0x50,&deviceControl,1)||
           deviceControl!=1||code!=originalCode||input!=originalInput||output!=originalOutput)continue;
        const auto& driver=frames[dispatch];
        result={true,code,input,output,driver.Depth,driver.Pc,sp+0x28,path,driver.Image};
        return result;
    }
    return result;
}

std::string ioctlJson(const NU_SAMPLE& s,const IoctlObservation& o) {
    std::ostringstream out;
    out<<"{\"event\":\"nmi_ioctl\",\"cpu\":"<<s.Cpu<<",\"generation\":"<<s.Generation
       <<",\"tsc\":"<<s.Tsc<<",\"thread\":\"0x"<<std::hex<<s.Thread
       <<"\",\"submitted_ioctl\":\"0x"<<std::setw(8)<<std::setfill('0')<<o.Code
       <<"\",\"dispatch_pc\":\"0x"<<o.DispatchPc<<"\",\"argument_address\":\"0x"
       <<o.ArgumentAddress<<"\",\"dispatch_depth\":"<<std::dec<<o.DispatchDepth
       <<",\"input_length\":"<<o.InputLength<<",\"output_length\":"<<o.OutputLength
       <<",\"path\":\""<<o.Path<<"\",\"dispatch_image\":\"";
    for(unsigned char c:o.Image) {
        if(c=='"'||c=='\\')out<<'\\'<<char(c);
        else if(c<0x20)out<<"\\u00"<<std::hex<<std::setw(2)<<std::setfill('0')<<unsigned(c)<<std::dec;
        else out<<char(c);
    }
    out<<"\",\"coverage\":\"sampled\"}";
    return out.str();
}
}
