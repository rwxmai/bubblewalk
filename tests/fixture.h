#pragma once
#include <cstdint>
#include <vector>
#include <algorithm>
#include <cstring>
#include "../include/protocol.h"

namespace nu {
/* test: Chain ALLOC_SMALL through PUSH_MACHFRAME in .xdata */
inline std::vector<uint8_t> testImage() {
    std::vector<uint8_t> b(0xa00);
    auto w16=[&](size_t at, uint16_t v) { b[at]=uint8_t(v); b[at+1]=uint8_t(v>>8); };
    auto w32=[&](size_t at, uint32_t v) { w16(at,uint16_t(v)); w16(at+2,uint16_t(v>>16)); };
    w16(0,0x5a4d); w32(0x3c,0x80); w32(0x80,0x4550);
    w16(0x84,0x8664); w16(0x86,3); w32(0x88,0x1234567);
    w16(0x94,0xf0); w16(0x98,0x20b);
    w32(0x98+56,0x4000); w32(0x98+60,0x200); w32(0x98+108,16);
    w32(0x98+136,0x2000); w32(0x98+140,36);
    for (uint32_t i=0;i<3;++i) {
        size_t h=0x188+i*40;
        w32(h+8,i?0x200:0x400); w32(h+12,0x1000+i*0x1000);
        w32(h+16,i?0x200:0x400); w32(h+20,i?0x600+(i-1)*0x200:0x200);
        w32(h+36,i?0x40000040:0x60000020);
    }
    std::fill(b.begin()+0x200,b.begin()+0x600,0x90);
    for (uint32_t i=0;i<3;++i) {
        w32(0x600+i*12,0x1000+i*0x100);
        w32(0x604+i*12,0x1100+i*0x100);
        w32(0x608+i*12,0x3000+i*0x10);
        size_t u=0x800+i*0x10;
        b[u]=1; b[u+1]=i==1?0:4; b[u+2]=1;
        b[u+4]=i==1?0:4; b[u+5]=i==1?0x0a:0x32;
        if (i!=1) {
            size_t code=0x200+i*0x100;
            b[code]=0x48; b[code+1]=0x83; b[code+2]=0xec; b[code+3]=0x20;
        }
    }
    return b;
}
}
