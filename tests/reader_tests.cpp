#include "../analyzer/pe_image.h"
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
        uint8_t unwind[8]{};
        require(!pe.read(UINT64_MAX,unwind,8),"RVA overflow rejected");
        require(!pe.read(0x1fff,unwind,8),"unmapped gap rejected");
        uint8_t stack[16]={1,2,3,4}, out[8]{};
        constexpr uint64_t base=0xffffa00000000000ull;
        require(nu::readRegion(base,stack,sizeof(stack),base+1,out,3) && out[0]==2,"snapshot address translation");
        require(!nu::readRegion(base,stack,sizeof(stack),base-1,out,1),"snapshot underflow rejected");
        require(!nu::readRegion(base,stack,sizeof(stack),UINT64_MAX,out,8),"snapshot overflow rejected");
        require(!nu::readRegion(base,stack,sizeof(stack),base+12,out,8),"snapshot truncation rejected");
        std::cout << "PE mapping and snapshot bounds tests passed.\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n"; return 1;
    }
}
