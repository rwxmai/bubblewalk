#pragma once
#include <cstdint>
#include <vector>
#include <algorithm>
#include <cstring>
#include "../include/protocol.h"
#include "../include/target_26100_1.h"

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

namespace nu {
/* test: Fill every interrupted GPR with a distinct nonzero sentinel */
inline NU_MODULE testContextSample(NU_SAMPLE& sample, NU_REGS& expected) {
    sample={};
    expected={};
    NU_MODULE kernel{};
    kernel.Base=0xfffff80010000000ull;
    kernel.Size=NU_TARGET_SIZE;
    kernel.Timestamp=NU_TARGET_TIMESTAMP;
    kernel.Checksum=NU_TARGET_CHECKSUM;
    kernel.Flags=NU_M_IDENTITY_VALID;
    sample.Version=NU_VERSION;
    sample.KernelBase=kernel.Base;
    sample.Nmi.Base=0xffffa00000008000ull;
    sample.Nmi.Size=0x800;
    sample.Entry.Rsp=sample.Nmi.Base;
    sample.Stack.Base=0xffffa00000108000ull;
    sample.Stack.Size=64;
    sample.InterruptedRip=kernel.Base+0x2010;
    sample.InterruptedRsp=sample.Stack.Base;
    sample.InterruptedCs=0x10;
    sample.InterruptedFlags=0x202;
    expected.Rip=sample.InterruptedRip;
    expected.Rsp=sample.InterruptedRsp;
    expected.Cs=0x10; expected.Ss=0x18; expected.Rflags=0x202;
    const size_t f=sample.Nmi.Size-40;
    auto put=[&](size_t at, uint64_t value) { std::memcpy(sample.NmiBytes+at, &value, 8); };
    put(f,expected.Rip); put(f+8,expected.Cs); put(f+16,expected.Rflags);
    put(f+24,expected.Rsp); put(f+32,expected.Ss);
    put(f-0x170,kernel.Base+NU_TARGET_KI_RETURN);
    put(f-0x2b0,kernel.Base+NU_TARGET_KX_RETURN);
    struct Slot { size_t Offset; uint64_t NU_REGS::*Member; };
    const Slot slots[]={
        {0x138,&NU_REGS::Rax},{0x130,&NU_REGS::Rcx},{0x128,&NU_REGS::Rdx},
        {0x120,&NU_REGS::R8},{0x118,&NU_REGS::R9},{0x110,&NU_REGS::R10},
        {0x108,&NU_REGS::R11},{0x10,&NU_REGS::Rbp},{0x18,&NU_REGS::Rsi},
        {0x1a8,&NU_REGS::Rbx},{0x1a0,&NU_REGS::Rdi},{0x190,&NU_REGS::R12},
        {0x188,&NU_REGS::R13},{0x180,&NU_REGS::R14},{0x178,&NU_REGS::R15}
    };
    for (size_t i=0; i<sizeof(slots)/sizeof(slots[0]); ++i) {
        expected.*(slots[i].Member)=0xaabbccdd00000000ull+i+1;
        put(f-slots[i].Offset,expected.*(slots[i].Member));
    }
    /* test: Poison Kx's RSI save after Ki has overwritten ESI */
    put(f-0x198,0xdeadbeef);
    return kernel;
}
}
