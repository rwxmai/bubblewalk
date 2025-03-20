#include "../analyzer/pe_image.h"
#include "../analyzer/interrupted_context.h"
#include "../include/protocol.h"
#include "fixture.h"
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <functional>

static void require(bool ok, const char* description) {
    if (!ok) throw std::runtime_error(description);
}
static void rejects(std::vector<uint8_t> b, const std::function<void(std::vector<uint8_t>&)>& mutate) {
    mutate(b);
    bool threw=false;
    try { (void)nu::PeImage::parse(b); } catch (const std::exception&) { threw=true; }
    require(threw,"malformed image was accepted");
}
int main() {
    try {
        auto bytes=nu::testImage();
        auto pe=nu::PeImage::parse(bytes);
        require(pe.size()==0x4000 && pe.timestamp()==0x1234567,"identity parse");
        require(pe.executable(0x1010) && !pe.executable(0x2010),"section classification");
        auto f=pe.function(0x1110);
        require(f && f->Unwind==0x3010 && !pe.function(0x1400),"function lookup");
        uint8_t unwind[8]{};
        require(pe.read(f->Unwind,unwind,sizeof(unwind)) && unwind[5]==0x0a,"machine-frame unwind metadata");
        require(!pe.read(UINT64_MAX,unwind,8),"RVA overflow rejected");
        require(!pe.read(0x1fff,unwind,8),"unmapped gap rejected");
        uint8_t stack[16]={1,2,3,4}, out[8]{};
        constexpr uint64_t base=0xffffa00000000000ull;
        require(nu::readRegion(base,stack,sizeof(stack),base+1,out,3) && out[0]==2,"snapshot address translation");
        require(!nu::readRegion(base,stack,sizeof(stack),base-1,out,1),"snapshot underflow rejected");
        require(!nu::readRegion(base,stack,sizeof(stack),UINT64_MAX,out,8),"snapshot overflow rejected");
        require(!nu::readRegion(base,stack,sizeof(stack),base+12,out,8),"snapshot truncation rejected");
        rejects(bytes,[](auto& b){ b.resize(80); });
        rejects(bytes,[](auto& b){ b[0x3f]=0xff; });
        rejects(bytes,[](auto& b){ b[0x188+12]=0; b[0x188+13]=0; });
        rejects(bytes,[](auto& b){ b[0x98+140]=35; });
        rejects(bytes,[](auto& b){ b[0x608]=0xff; b[0x60b]=0xff; });
        auto markers=bytes;
        markers[0x98+140]=48;
        auto word=[&](size_t at,uint32_t v) { std::memcpy(markers.data()+at,&v,4); };
        word(0x624,0x1400); word(0x628,0x1400); word(0x62c,0x3000);
        require(!nu::PeImage::parse(markers).function(0x1400),"empty pdata markers remain noncallable");
        auto writable=bytes;
        writable[0x188+40+39]|=0x80;
        auto mutablePe=nu::PeImage::parse(writable);
        require(!mutablePe.read(0x2000,out,8),"disk writable data cannot stand in for runtime memory");
        NU_SAMPLE sample{};
        NU_REGS expected{}, recovered{};
        auto kernel=nu::testContextSample(sample,expected);
        std::string error;
        require(nu::interruptedContext(sample,kernel,recovered,error),"pinned interrupted context");
        require(!std::memcmp(&expected,&recovered,sizeof(expected)),"all interrupted GPRs and control fields");
        const auto valid=sample;
        sample.InterruptedRip^=1;
        require(!nu::interruptedContext(sample,kernel,recovered,error),"machine RIP mismatch rejected");
        sample=valid; sample.NmiBytes[sample.Nmi.Size-40-0x170]^=1;
        require(!nu::interruptedContext(sample,kernel,recovered,error),"Ki return mismatch rejected");
        sample=valid; sample.NmiBytes[sample.Nmi.Size-40-0x2b0]^=1;
        require(!nu::interruptedContext(sample,kernel,recovered,error),"Kx return mismatch rejected");
        sample=valid; sample.Flags|=NU_F_NMI_TRUNCATED;
        require(!nu::interruptedContext(sample,kernel,recovered,error),"truncated NMI rejected");
        sample=valid; sample.Nmi.Size=40;
        require(!nu::interruptedContext(sample,kernel,recovered,error),"missing register saves rejected");
        sample=valid; sample.KernelBase+=0x1000;
        require(!nu::interruptedContext(sample,kernel,recovered,error),"kernel base mismatch rejected");
        sample=valid; kernel.Timestamp^=1;
        require(!nu::interruptedContext(sample,kernel,recovered,error),"kernel revision mismatch rejected");
        std::cout << "Context tests passed: all GPRs, original RSI, handler returns, target identity, and truncation.\n";
        std::cout << "Reader tests passed: identity, sections, unwind table, machine-frame metadata,\n"
                     "snapshot translation, malformed images, and missing-memory boundaries.\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n"; return 1;
    }
}
