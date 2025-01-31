#include "../analyzer/pe_image.h"
#include <iostream>
#include <stdexcept>
static void require(bool ok, const char* description) {
    if (!ok) throw std::runtime_error(description);
}
int main() {
    try {
        uint8_t stack[16]={1,2,3,4}, out[8]{};
        constexpr uint64_t base=0xffffa00000000000ull;
        require(nu::readRegion(base,stack,sizeof(stack),base+1,out,3) && out[0]==2,"snapshot address translation");
        require(!nu::readRegion(base,stack,sizeof(stack),base-1,out,1),"snapshot underflow rejected");
        require(!nu::readRegion(base,stack,sizeof(stack),UINT64_MAX,out,8),"snapshot overflow rejected");
        require(!nu::readRegion(base,stack,sizeof(stack),base+12,out,8),"snapshot truncation rejected");
        std::cout << "Snapshot bounds tests passed.\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n"; return 1;
    }
}
