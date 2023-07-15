#if $(WARBIRD_ENABLE_VM_EXECUTION)
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>


namespace Warbird {

#ifdef _AMD64_
#include <pshpack1.h>
struct SAVED_REGS
{
    unsigned long long  P1Home;             // Allocated for the callee.
    unsigned long long  P2Home;             // Allocated for the callee.
    unsigned long long  P3Home;             // Allocated for the callee.
    unsigned long long  P4Home;             // Allocated for the callee.

    unsigned long long  SavedAX;
    unsigned long long  SavedCX;
    unsigned long long  SavedDX;
    unsigned long long  SavedBX;
    unsigned long long  SavedSP;
    unsigned long long  SavedBP;
    unsigned long long  SavedSI;
    unsigned long long  SavedDI;
    unsigned long long  SavedR8;
    unsigned long long  SavedR9;
    unsigned long long  SavedR10;
    unsigned long long  SavedR11;
    unsigned long long  SavedR12;
    unsigned long long  SavedR13;
    unsigned long long  SavedR14;
    unsigned long long  SavedR15;

    unsigned char overflowflag;
    unsigned char carryflag;
    unsigned char signflag;
    unsigned char zeroflag;
    unsigned long long xmm0[2];
    unsigned long long xmm1[2];
};
#include <poppack.h>
#endif
#ifdef _X86_
#include <pshpack1.h>
struct SAVED_REGS
{
    unsigned long  SavedAX;
    unsigned long  SavedCX;
    unsigned long  SavedDX;
    unsigned long  SavedBX;
    unsigned long  SavedSP;
    unsigned long  SavedBP;
    unsigned long  SavedSI;
    unsigned long  SavedDI;

    unsigned char overflowflag;
    unsigned char carryflag;
    unsigned char signflag;
    unsigned char zeroflag;
};
#include <poppack.h>
#endif


struct decoderState
{
    unsigned char *data;
};

void InitDecoder(decoderState *deco, unsigned char *data)
{
    deco->data = data;
}

enum VMExecRuntime0Regs
{
    VMRegEAX = 1,
    VMRegECX,
    VMRegEDX,
    VMRegEBX,
    VMRegESP,
    VMRegEBP,
    VMRegESI,
    VMRegEDI,
    VMRegAX,
    VMRegCX,
    VMRegDX,
    VMRegBX,
    VMRegSP,
    VMRegBP,
    VMRegSI,
    VMRegDI,
    VMRegAL,
    VMRegCL,
    VMRegDL,
    VMRegBL,
    VMRegSPL,
    VMRegBPL,
    VMRegSIL,
    VMRegDIL,
    VMRegAH,
    VMRegCH,
    VMRegDH,
    VMRegBH,

    VMRegRAX,
    VMRegRBX,
    VMRegRCX,
    VMRegRDX,
    VMRegRSI,
    VMRegRDI,
    VMRegRBP,
    VMRegRSP,
    VMRegR8,
    VMRegR9,
    VMRegR10,
    VMRegR11,
    VMRegR12,
    VMRegR13,
    VMRegR14,
    VMRegR15,
    VMRegR8D,
    VMRegR9D,
    VMRegR10D,
    VMRegR11D,
    VMRegR12D,
    VMRegR13D,
    VMRegR14D,
    VMRegR15D,

    VMRegR8W,
    VMRegR9W,
    VMRegR10W,
    VMRegR11W,
    VMRegR12W,
    VMRegR13W,
    VMRegR14W,
    VMRegR15W,

    VMRegR8B,
    VMRegR9B,
    VMRegR10B,
    VMRegR11B,
    VMRegR12B,
    VMRegR13B,
    VMRegR14B,
    VMRegR15B,

    VMRegXmm0,
    VMRegXmm1
};

enum VMExecRuntime0Funcs
{
    VMFuncMov = 1,
    VMFuncLea,
    VMFuncTst,
    VMFuncCmp,
    VMFuncCall,
    VMFuncJcc,
    VMFuncAdd,
    VMFuncSub,
    VMFuncRet,
    VMFuncPush,
    VMFuncPop,
    VMFuncJmp,
    VMFuncXor,
    VMFuncAnd,
    VMFuncOr,
    VMFuncRor,
    VMFuncRol,
    VMFuncSar,
    VMFuncShr,
    VMFuncShl,
    VMFuncNot,
    VMFuncMovsx,
    VMFuncMovzx,
    VMFuncCMovcc,
    VMFuncMovXmm,
    /// VMFuncMul,
    /// VMFuncDiv,
};

enum VMExecRuntime0Size
{
    VMSizeByte,
    VMSizeShort,
    VMSizeDWord,
#ifdef _AMD64_
    VMSizeQWord,
    VMSizeXMMWord,
#endif
};

enum VMExecRuntime0SrcTypes
{
    VMTypeReg = 1,
    VMTypeConst,
    VMTypeSym,
    VMTypeEa,
    VMTypeEaSym,
    VMTypeAddr,
    VMTypeCode
};

enum VMExecRuntime0CondCodes
{
    VMCondEQ = 1,
    VMCondNE,
    VMCondLT,
    VMCondGT,
    VMCondLE,
    VMCondGE,
    VMCondS,
    VMCondNS,
    VMCondB,
    VMCondA,
    VMCondBE,
    VMCondAE,
};

//...

__if_not_exists(__ImageBase)
{
    #if defined(_WIN64) && defined(_M_IA64)
    #pragma section(".base", long, read, write)
    EXTERN_C __declspec(allocate(".base")) IMAGE_DOS_HEADER __ImageBase;
    #else
    EXTERN_C IMAGE_DOS_HEADER __ImageBase;
    #endif
}

unsigned char g_fDebug = 0;

#ifdef VMEXEC_DEBUG
void vmdbgprintf(char format[], ...)
{
    va_list v;
    va_start(v, format);
    if (g_fDebug)
        vprintf(format, v);
    va_end(v);
}
#define dbgprint vmdbgprintf
#else
#define dbgprint
#endif

unsigned char getByte(decoderState *deco)
{
    dbgprint("                                  byte %02x    data %08x\n", *(deco->data), deco->data);
    return *(deco->data++);
}

unsigned char peekByte(decoderState *deco)
{
    return *(deco->data);
}

unsigned long getUlong(decoderState *deco)
{
    //
    size_t ul = 0;
    for (int i=0; i<4; i++)
    {
        ul = ul + (getByte(deco) << (i*8));
    }
    return (unsigned long)ul;
}

size_t fromReg(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint("   " __FUNCTION__ " %p %p\n", regs, deco->data);
    int regnum = getByte(deco);
    dbgprint("      fromReg regnum is 0x%x\n", regnum);
    switch (regnum)
    {
        case 0: return 0;
        case VMRegEAX: return (regs->SavedAX);
        case VMRegECX: return (regs->SavedCX);
        case VMRegEDX: return (regs->SavedDX);
        case VMRegEBX: return (regs->SavedBX);
        case VMRegESP: return (regs->SavedSP);
        case VMRegEBP: return (regs->SavedBP);
        case VMRegESI: return (regs->SavedSI);
        case VMRegEDI: return (regs->SavedDI);
        case VMRegAX: return (unsigned short)(regs->SavedAX);
        case VMRegCX: return (unsigned short)(regs->SavedCX);
        case VMRegDX: return (unsigned short)(regs->SavedDX);
        case VMRegBX: return (unsigned short)(regs->SavedBX);
        case VMRegSP: return (unsigned short)(regs->SavedSP);
        case VMRegBP: return (unsigned short)(regs->SavedBP);
        case VMRegSI: return (unsigned short)(regs->SavedSI);
        case VMRegDI: return (unsigned short)(regs->SavedDI);
        case VMRegAL: return (unsigned char)(regs->SavedAX);
        case VMRegCL: return (unsigned char)(regs->SavedCX);
        case VMRegDL: return (unsigned char)(regs->SavedDX);
        case VMRegBL: return (unsigned char)(regs->SavedBX);
        case VMRegBPL: return (unsigned char)(regs->SavedBP);
        case VMRegSPL: return (unsigned char)(regs->SavedSP);
        case VMRegSIL: return (unsigned char)(regs->SavedSI);
        case VMRegDIL: return (unsigned char)(regs->SavedDI);
        case VMRegAH: return ((unsigned short)(regs->SavedAX) >> 8);
        case VMRegCH: return ((unsigned short)(regs->SavedCX) >> 8);
        case VMRegDH: return ((unsigned short)(regs->SavedDX) >> 8);
        case VMRegBH: return ((unsigned short)(regs->SavedBX) >> 8);

#ifdef _AMD64_
        case VMRegRAX: return (regs->SavedAX);
        case VMRegRBX: return (regs->SavedBX);
        case VMRegRCX: return (regs->SavedCX);
        case VMRegRDX: return (regs->SavedDX);
        case VMRegRSI: return (regs->SavedSI);
        case VMRegRDI: return (regs->SavedDI);
        case VMRegRBP: return (regs->SavedBP);
        case VMRegRSP: return (regs->SavedSP);
        case VMRegR8: return (regs->SavedR8);
        case VMRegR9: return (regs->SavedR9);
        case VMRegR10: return (regs->SavedR10);
        case VMRegR11: return (regs->SavedR11);
        case VMRegR12: return (regs->SavedR12);
        case VMRegR13: return (regs->SavedR13);
        case VMRegR14: return (regs->SavedR14);
        case VMRegR15: return (regs->SavedR15);
        case VMRegR8D: return (unsigned long)(regs->SavedR8);
        case VMRegR9D: return (unsigned long)(regs->SavedR9);
        case VMRegR10D: return (unsigned long)(regs->SavedR10);
        case VMRegR11D: return (unsigned long)(regs->SavedR11);
        case VMRegR12D: return (unsigned long)(regs->SavedR12);
        case VMRegR13D: return (unsigned long)(regs->SavedR13);
        case VMRegR14D: return (unsigned long)(regs->SavedR14);
        case VMRegR15D: return (unsigned long)(regs->SavedR15);

        case VMRegR8W: return (unsigned short)(regs->SavedR8);
        case VMRegR9W: return (unsigned short)(regs->SavedR9);
        case VMRegR10W: return (unsigned short)(regs->SavedR10);
        case VMRegR11W: return (unsigned short)(regs->SavedR11);
        case VMRegR12W: return (unsigned short)(regs->SavedR12);
        case VMRegR13W: return (unsigned short)(regs->SavedR13);
        case VMRegR14W: return (unsigned short)(regs->SavedR14);
        case VMRegR15W: return (unsigned short)(regs->SavedR15);

        case VMRegR8B: return (unsigned char)(regs->SavedR8);
        case VMRegR9B: return (unsigned char)(regs->SavedR9);
        case VMRegR10B: return (unsigned char)(regs->SavedR10);
        case VMRegR11B: return (unsigned char)(regs->SavedR11);
        case VMRegR12B: return (unsigned char)(regs->SavedR12);
        case VMRegR13B: return (unsigned char)(regs->SavedR13);
        case VMRegR14B: return (unsigned char)(regs->SavedR14);
        case VMRegR15B: return (unsigned char)(regs->SavedR15);

#endif
        default:
            dbgprint("unknown reg in fromReg 0x%x\n", regnum);
            dbgprint("unknown reg in fromReg 0x%x\n", regnum);
            __debugbreak();
            dbgprint("unknown reg in fromReg 0x%x\n", regnum);
    }
    return 0;
}

// TARGET_TYPE_REG
void toReg(SAVED_REGS *regs, decoderState *deco, size_t value)
{
    dbgprint("   " __FUNCTION__ " %p %p\n", regs, deco->data);
    dbgprint("      toReg %p %p %Ix\n", regs, deco, value);

    int regnum = getByte(deco);
    dbgprint("            regnum is 0x%x\n", regnum);
    dbgprint("            val %Ix\n", value);

    switch (regnum)
    {
        case VMRegEAX: (regs->SavedAX) = (unsigned long)value; break;
        case VMRegEBX: (regs->SavedBX) = (unsigned long)value; break;
        case VMRegECX: (regs->SavedCX) = (unsigned long)value; break;
        case VMRegEDX: (regs->SavedDX) = (unsigned long)value; break;
        case VMRegEDI: (regs->SavedDI) = (unsigned long)value; break;
        case VMRegESI: (regs->SavedSI) = (unsigned long)value; break;
        case VMRegESP: (regs->SavedSP) = (unsigned long)value; break;
        case VMRegEBP: (regs->SavedBP) = (unsigned long)value; break;
        case VMRegAX: *((unsigned short*)&(regs->SavedAX)) = (unsigned short)value; break;
        case VMRegCX: *((unsigned short*)&(regs->SavedCX)) = (unsigned short)value; break;
        case VMRegDX: *((unsigned short*)&(regs->SavedDX)) = (unsigned short)value; break;
        case VMRegBX: *((unsigned short*)&(regs->SavedBX)) = (unsigned short)value; break;
        case VMRegSP: *((unsigned short*)&(regs->SavedSP)) = (unsigned short)value; break;
        case VMRegBP: *((unsigned short*)&(regs->SavedBP)) = (unsigned short)value; break;
        case VMRegSI: *((unsigned short*)&(regs->SavedSI)) = (unsigned short)value; break;
        case VMRegDI: *((unsigned short*)&(regs->SavedDI)) = (unsigned short)value; break;
        case VMRegAL: *((unsigned char*)&(regs->SavedAX)) = (unsigned char)value; break;
        case VMRegCL: *((unsigned char*)&(regs->SavedCX)) = (unsigned char)value; break;
        case VMRegDL: *((unsigned char*)&(regs->SavedDX)) = (unsigned char)value; break;
        case VMRegBL: *((unsigned char*)&(regs->SavedBX)) = (unsigned char)value; break;
        case VMRegAH: *(((unsigned char*)&(regs->SavedAX))+1) = (unsigned char)value; break;
        case VMRegCH: *(((unsigned char*)&(regs->SavedCX))+1) = (unsigned char)value; break;
        case VMRegDH: *(((unsigned char*)&(regs->SavedDX))+1) = (unsigned char)value; break;
        case VMRegBH: *(((unsigned char*)&(regs->SavedBX))+1) = (unsigned char)value; break;
        case VMRegBPL: *((unsigned char*)&(regs->SavedBP)) = (unsigned char)value; break;
        case VMRegSPL: *((unsigned char*)&(regs->SavedSP)) = (unsigned char)value; break;
        case VMRegSIL: *((unsigned char*)&(regs->SavedSI)) = (unsigned char)value; break;
        case VMRegDIL: *((unsigned char*)&(regs->SavedDI)) = (unsigned char)value; break;
#ifdef _AMD64_
        case VMRegRAX: (regs->SavedAX) = value; break;
        case VMRegRBX: (regs->SavedBX) = value; break;
        case VMRegRCX: (regs->SavedCX) = value; break;
        case VMRegRDX: (regs->SavedDX) = value; break;
        case VMRegRSI: (regs->SavedSI) = value; break;
        case VMRegRDI: (regs->SavedDI) = value; break;
        case VMRegRBP: (regs->SavedBP) = value; break;
        case VMRegRSP: (regs->SavedSP) = value; break;
        case VMRegR8: (regs->SavedR8) = value; break;
        case VMRegR9: (regs->SavedR9) = value; break;
        case VMRegR10: (regs->SavedR10) = value; break;
        case VMRegR11: (regs->SavedR11) = value; break;
        case VMRegR12: (regs->SavedR12) = value; break;
        case VMRegR13: (regs->SavedR13) = value; break;
        case VMRegR14: (regs->SavedR14) = value; break;
        case VMRegR15: (regs->SavedR15) = value; break;
        case VMRegR8D: (regs->SavedR8) = (unsigned long)value; break;
        case VMRegR9D: (regs->SavedR9) = (unsigned long)value; break;
        case VMRegR10D: (regs->SavedR10) = (unsigned long)value; break;
        case VMRegR11D: (regs->SavedR11) = (unsigned long)value; break;
        case VMRegR12D: (regs->SavedR12) = (unsigned long)value; break;
        case VMRegR13D: (regs->SavedR13) = (unsigned long)value; break;
        case VMRegR14D: (regs->SavedR14) = (unsigned long)value; break;
        case VMRegR15D: (regs->SavedR15) = (unsigned long)value; break;
        case VMRegR8W: *((unsigned short*)&(regs->SavedR8)) = (unsigned short)value; break;
        case VMRegR9W: *((unsigned short*)&(regs->SavedR9)) = (unsigned short)value; break;
        case VMRegR10W: *((unsigned short*)&(regs->SavedR10)) = (unsigned short)value; break;
        case VMRegR11W: *((unsigned short*)&(regs->SavedR11)) = (unsigned short)value; break;
        case VMRegR12W: *((unsigned short*)&(regs->SavedR12)) = (unsigned short)value; break;
        case VMRegR13W: *((unsigned short*)&(regs->SavedR13)) = (unsigned short)value; break;
        case VMRegR14W: *((unsigned short*)&(regs->SavedR14)) = (unsigned short)value; break;
        case VMRegR15W: *((unsigned short*)&(regs->SavedR15)) = (unsigned short)value; break;
        case VMRegR8B: *((unsigned char*)&(regs->SavedR8)) = (unsigned char)value; break;
        case VMRegR9B: *((unsigned char*)&(regs->SavedR9)) = (unsigned char)value; break;
        case VMRegR10B: *((unsigned char*)&(regs->SavedR10)) = (unsigned char)value; break;
        case VMRegR11B: *((unsigned char*)&(regs->SavedR11)) = (unsigned char)value; break;
        case VMRegR12B: *((unsigned char*)&(regs->SavedR12)) = (unsigned char)value; break;
        case VMRegR13B: *((unsigned char*)&(regs->SavedR13)) = (unsigned char)value; break;
        case VMRegR14B: *((unsigned char*)&(regs->SavedR14)) = (unsigned char)value; break;
        case VMRegR15B: *((unsigned char*)&(regs->SavedR15)) = (unsigned char)value; break;
#endif
        default:
            dbgprint("unknown reg in toReg 0x%x\n", regnum);
            dbgprint("unknown reg in toReg 0x%x\n", regnum);
            __debugbreak();
            dbgprint("unknown reg in toReg 0x%x\n", regnum);
    }
}

size_t addrEa(SAVED_REGS *regs, decoderState *deco, int type)
{
    dbgprint("   " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t offset = (long)getUlong(deco);
    if (type == VMTypeEaSym)
        offset += (size_t)((unsigned char*)&__ImageBase);
    size_t index = fromReg(regs, deco);
    size_t base = fromReg(regs, deco);
    size_t scale = getByte(deco);
    scale = (size_t)(1 << scale);

    dbgprint("            offset 0x%Ix, index 0x%Ix, base 0x%Ix, scale 0x%Ix\n", offset, index, base, scale);

    return offset + base + (index * scale);
}

size_t addrSym(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint("   " __FUNCTION__ " %p %p\n", regs, deco->data);
    (regs);
    unsigned long rva = getUlong(deco);
    dbgprint("            rva is %p\n", rva);
    void* rvanum = rva + (unsigned char*)&__ImageBase;
    return (size_t)rvanum;
}

size_t getSrcAddr(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint("   " __FUNCTION__ " %p %p\n", regs, deco->data);
    int sourcetype = getByte(deco);
    size_t result = 0;
    int sizetype = 0;
    dbgprint("            source type is 0x%x\n", sourcetype);
    switch (sourcetype)
    {
        case VMTypeSym:
            result = addrSym(regs, deco);
            sizetype = getByte(deco);
            switch(sizetype) {
                default:
                case VMSizeDWord:
                    result = *((unsigned long*)result);
                    break;
#ifdef _AMD64_
                case VMSizeQWord:
                    result = *((unsigned long long*)result);
                    break;
#endif
            }
            break;
        case VMTypeAddr:
            result = addrSym(regs, deco);
            getByte(deco); // unneeded size
            break;
        case VMTypeEa:
        case VMTypeEaSym:
            result = addrEa(regs, deco, sourcetype);
            // throw away the size, we just want the address
            getByte(deco);
            break;
        case VMTypeCode:
            result = getUlong(deco);
            break;
        default:
            dbgprint("unknown sourcetype in srcaddr 0x%x\n", sourcetype);
            dbgprint("unknown sourcetype in srcaddr 0x%x\n", sourcetype);
            __debugbreak();
            dbgprint("unknown sourcetype in srcaddr 0x%x\n", sourcetype);
    }
    return result;
}

size_t getSrcValue(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint("   " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t result;
    size_t rvanum = 0;
    int sizetype;
    int sourcetype = getByte(deco);
    dbgprint("            source type is 0x%x\n", sourcetype);
    switch (sourcetype)
    {
        case VMTypeReg:
            result = fromReg(regs, deco);
            break;
        case VMTypeConst:
            {
            size_t v = getUlong(deco);
            dbgprint("            const 0x%x\n", v);
            result = v;
            break;
            }
        case VMTypeSym:
            rvanum = addrSym(regs, deco);
            sizetype = getByte(deco);
            switch (sizetype)
            {
                case VMSizeByte:
                    result = *((unsigned char*)rvanum);
                    break;
                case VMSizeShort:
                    result = *((unsigned short*)rvanum);
                    break;
                default:
                case VMSizeDWord:
                    result = *((unsigned long*)rvanum);
                    break;
#ifdef _AMD64_
                case VMSizeQWord:
                    result = *((unsigned long long*)rvanum);
                    break;
#endif
            }
            break;
        case VMTypeAddr:
            result = addrSym(regs, deco);
            getByte(deco); // unneeded size
            break;
        case VMTypeEa:
        case VMTypeEaSym:
            rvanum = addrEa(regs, deco, sourcetype);
            sizetype = getByte(deco);
            switch (sizetype)
            {
                case VMSizeByte:
                    result = *((unsigned char*)rvanum);
                    break;
                case VMSizeShort:
                    result = *((unsigned short*)rvanum);
                    break;
                default:
                case VMSizeDWord:
                    result = *((unsigned long*)rvanum);
                    break;
#ifdef _AMD64_
                case VMSizeQWord:
                    result = *((unsigned long long*)rvanum);
                    break;
#endif
            }
            break;
        default:
            dbgprint("unknown sourcetype in srcval 0x%x\n", sourcetype);
            dbgprint("unknown sourcetype in srcval 0x%x\n", sourcetype);
            __debugbreak();
            dbgprint("unknown sourcetype in srcval 0x%x\n", sourcetype);
            return 0;
    }
    dbgprint("      value is 0x%x\n", result);
    return result;
}

void setTargetValue(SAVED_REGS *regs, decoderState *deco, size_t value)
{
    dbgprint("   " __FUNCTION__ " %p %p\n", regs, deco->data);
    int desttype = getByte(deco);
    dbgprint("            desttype is 0x%x\n", desttype);
    switch(desttype)
    {
        case VMTypeReg:
            toReg(regs, deco, value);
            break;
        case VMTypeEa:
        case VMTypeEaSym:
            {
            size_t addr = addrEa(regs, deco, desttype);
            int sizetype = getByte(deco);
            switch (sizetype)
            {
                case VMSizeByte:
                    *((unsigned char*)addr) = (unsigned char)value;
                    break;
                case VMSizeShort:
                    *((unsigned short*)addr) = (unsigned short)value;
                    break;
                default:
                case VMSizeDWord:
                    *((unsigned long*)addr) = (unsigned long)value;
                    break;
#ifdef _AMD64_
                case VMSizeQWord:
                    *((unsigned long long*)addr) = (unsigned long long)value;
                    break;
#endif
            }
            }
            break;
        case VMTypeSym:
            {
            size_t addr = addrSym(regs, deco);
            int sizetype = getByte(deco);
            switch (sizetype)
            {
                case VMSizeByte:
                    *((unsigned char*)addr) = (unsigned char)value;
                    break;
                case VMSizeShort:
                    *((unsigned short*)addr) = (unsigned short)value;
                    break;
                default:
                case VMSizeDWord:
                    *((unsigned long*)addr) = (unsigned long)value;
                    break;
#ifdef _AMD64_
                case VMSizeQWord:
                    *((unsigned long long*)addr) = (unsigned long long)value;
                    break;
#endif
            }
            }
            break;
        default:
            dbgprint("unknown target type 0x%x\n", desttype);
            dbgprint("unknown target type 0x%x\n", desttype);
            __debugbreak();
            dbgprint("unknown target type 0x%x\n", desttype);
    }
}

void
setflagsand(SAVED_REGS *regs, size_t value, size_t value2, int sizetype)
{
    switch(sizetype) {
        default:
        case VMSizeDWord:
        if (((unsigned long)value & (unsigned long)value2) == 0)
            regs->zeroflag = 1;
        else
            regs->zeroflag = 0;

        if (((unsigned long)value & (unsigned long)value2) & 0x80000000)
            regs->signflag = 1;
        else
            regs->signflag = 0;
    }
}

void
setflagssub(SAVED_REGS *regs, size_t value, size_t value2, int sizetype)
{
    switch(sizetype) {
        default:
        case VMSizeDWord:
        if ((unsigned long)value >= (unsigned long)value2)
            regs->carryflag = 0;
        else
            regs->carryflag = 1;

        if ((size_t)value == (size_t)value2)
            regs->zeroflag = 1;
        else
            regs->zeroflag = 0;

        if ((long)value > (long)value2)
            regs->signflag = 0;
        else
            regs->signflag = 1;
    }
}

int ccfunc(SAVED_REGS *regs, decoderState *deco)
{
    int taken = 0;
    unsigned char condCode = getByte(deco);
    switch(condCode)
    {
        case VMCondEQ:
            taken = (regs->zeroflag);
            dbgprint("  EQ - z\n");
            break;
        case VMCondNE:
            taken = (!regs->zeroflag);
            dbgprint("  NE - !z\n");
            break;
        case VMCondGT:
            taken = (!regs->signflag && !regs->zeroflag);
            dbgprint("  G - !s&!z\n");
            break;
        case VMCondLT:
            taken = (regs->signflag && !regs->zeroflag);
            dbgprint("  L - s&!z\n");
            break;
        case VMCondGE:
            taken = (!regs->signflag || regs->zeroflag);
            dbgprint("  GE - !s|z\n");
            break;
        case VMCondLE:
            taken = (regs->signflag || regs->zeroflag);
            dbgprint("  LE - s|z\n");
            break;
        case VMCondS:
            taken = (regs->signflag);
            dbgprint("  S - s\n");
            break;
        case VMCondNS:
            taken = (!regs->signflag);
            dbgprint("  NS - !s\n");
            break;
        case VMCondB:
            taken = (regs->carryflag);
            dbgprint("  NS - c\n");
            break;
        case VMCondA:
            taken = (!regs->carryflag && !regs->zeroflag);
            dbgprint("  NS - !c&!z\n");
            break;
        case VMCondBE:
            taken = (regs->carryflag || regs->zeroflag);
            dbgprint("  NS - c|z\n");
            break;
        case VMCondAE:
            taken = (!regs->carryflag);
            dbgprint("  NS - !c\n");
            break;
        default:
            dbgprint("unknown condition code: 0x%x\n", condCode);
            dbgprint("unknown condition code: 0x%x\n", condCode);
            __debugbreak();
            dbgprint("unknown condition code: 0x%x\n", condCode);
    }
    return taken;
}

void setTargetValueFalse(SAVED_REGS *regs, decoderState *deco, size_t value)
{
    dbgprint("   " __FUNCTION__ " %p %p\n", regs, deco->data);
    (value);
    int desttype = getByte(deco);
    dbgprint("            desttype is 0x%x\n", desttype);
    switch(desttype)
    {
        case VMTypeReg:
            getByte(deco); // unneeded reg num
            break;
        case VMTypeEa:
        case VMTypeEaSym:
            {
            addrEa(regs, deco, desttype);
            getByte(deco);
            // do nothing
            }
            break;
        case VMTypeSym:
            {
            addrSym(regs, deco);
            getByte(deco);
            // do nothing
            }
            break;
        default:
            dbgprint("unknown target type 0x%x\n", desttype);
            dbgprint("unknown target type 0x%x\n", desttype);
            __debugbreak();
            dbgprint("unknown target type 0x%x\n", desttype);
    }
}


#ifdef _AMD64_
// mov to/from xmm can't be standard, because we only pass results in size_t.
// this needs a full 128 bit move.
void movfuncfromxmm(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    unsigned long long value[2] = {0};

    size_t regnum = getByte(deco);
    switch (regnum)
    {
        case VMRegXmm0:
            value[0] = regs->xmm0[0];
            value[1] = regs->xmm0[1];
            break;
        case VMRegXmm1:
            value[0] = regs->xmm1[0];
            value[1] = regs->xmm1[1];
            break;
    }

    // for 128 byte moves, only support eatypes
    unsigned char type = getByte(deco);
    switch(type) {
        case VMTypeEa:
        case VMTypeEaSym:
            {
            size_t addr = addrEa(regs, deco, type);
            int sizetype = getByte(deco);
            if (sizetype != VMSizeXMMWord) { /*assert*/; }
            ((unsigned long long*)addr)[0] = value[0];
            ((unsigned long long*)addr)[1] = value[1];
            }
            break;
    }
    return;
}

void movfunctoxmm(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    unsigned long long value[2];

    // for 128 byte moves, only support eatypes
    unsigned char type = getByte(deco);
    switch(type) {
        case VMTypeEa:
        case VMTypeEaSym:
            {
            size_t addr = addrEa(regs, deco, type);
            int sizetype = getByte(deco);
            if (sizetype != VMSizeXMMWord) { /*assert*/; }
            value[0] = ((unsigned long long*)addr)[0];
            value[1] = ((unsigned long long*)addr)[1];
            }
            break;
    }

    size_t regnum = getByte(deco);
    switch (regnum)
    {
        case VMRegXmm0:
            regs->xmm0[0] = value[0];
            regs->xmm0[1] = value[1];
            break;
        case VMRegXmm1:
            regs->xmm1[0] = value[0];
            regs->xmm1[1] = value[1];
            break;
    }
}

void movxmmfunc(SAVED_REGS *regs, decoderState *deco)
{
    // if the reg is first, it's from xmm to something
    if (peekByte(deco) == VMTypeReg)
        return movfuncfromxmm(regs, deco);
    else
        return movfunctoxmm(regs, deco);
}
#endif // _AMD64_

void movfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t value = getSrcValue(regs, deco);
    setTargetValue(regs, deco, value);
}

void pushfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t value = getSrcValue(regs, deco);
    dbgprint("      saved stack loc is %p\n", regs->SavedSP);
    regs->SavedSP -= sizeof(size_t);
    dbgprint("      saved stack loc is %p, value %x\n", regs->SavedSP, value);
    *((size_t*)(regs->SavedSP)) = value;
}

void popfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t value = *((size_t*)(regs->SavedSP));
    dbgprint("      value is %x\n", value);
    dbgprint("      saved stack loc is %p\n", regs->SavedSP);
    regs->SavedSP += sizeof(size_t);
    dbgprint("      saved stack loc is %p\n", regs->SavedSP);
    setTargetValue(regs, deco, value);
}

void subfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t value = getSrcValue(regs, deco);
    size_t value2 = getSrcValue(regs, deco);

    int sizetype = 0;
    sizetype = getByte(deco);
    setflagssub(regs, value, value2, sizetype);

    size_t result = value - value2;
    setTargetValue(regs, deco, result);
}

void addfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t value = getSrcValue(regs, deco);
    size_t value2 = getSrcValue(regs, deco);
    size_t result = value + value2;
    setTargetValue(regs, deco, result);
}

void notfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t value = getSrcValue(regs, deco);
    size_t result = ~value;
    setTargetValue(regs, deco, result);
}

void xorfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t value = getSrcValue(regs, deco);
    size_t value2 = getSrcValue(regs, deco);
    size_t result = value ^ value2;
    setTargetValue(regs, deco, result);
}

void andfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t value = getSrcValue(regs, deco);
    size_t value2 = getSrcValue(regs, deco);
    size_t result = value & value2;

    int sizetype = getByte(deco);
    setflagsand(regs, value, value2, sizetype);

    setTargetValue(regs, deco, result);
}

void orfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t value = getSrcValue(regs, deco);
    size_t value2 = getSrcValue(regs, deco);
    size_t result = value | value2;
    setTargetValue(regs, deco, result);
}

void rorfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t value = getSrcValue(regs, deco);
    size_t value2 = getSrcValue(regs, deco);
    size_t result = 0;
    int sizetype = getByte(deco);
    switch(sizetype) {
        default:
        case VMSizeDWord:
            result = (value >> value2) | (value << (32 - value2));
            break;
        case VMSizeByte:
            result = (value >> value2) | (value << (8 - value2));
            break;
    }
    setTargetValue(regs, deco, result);
}

void rolfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t value = getSrcValue(regs, deco);
    size_t value2 = getSrcValue(regs, deco);
    size_t result = 0;
    int sizetype = getByte(deco);
    switch(sizetype) {
        default:
        case VMSizeDWord:
            result = (value << value2) | (value >> (32 - value2));
            break;
        case VMSizeByte:
            result = (value << value2) | (value >> (8 - value2));
            break;
    }
    setTargetValue(regs, deco, result);
}

void shrfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t value = getSrcValue(regs, deco);
    size_t value2 = getSrcValue(regs, deco);
    size_t result = value >> value2;
    setTargetValue(regs, deco, result);
}

void shlfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t value = getSrcValue(regs, deco);
    size_t value2 = getSrcValue(regs, deco);
    size_t result = value << value2;
    setTargetValue(regs, deco, result);
}

void leafunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t value = getSrcAddr(regs, deco);
    dbgprint("      value is 0x%x\n", value);
    setTargetValue(regs, deco, value);
}

void movsxfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t value = getSrcValue(regs, deco);
    unsigned char srcsize = getByte(deco);
    unsigned char dstsize = getByte(deco);
    switch (srcsize)
    {
        case VMSizeByte:
            value = (char)value;
            break;
        case VMSizeShort:
            value = (short)value;
            break;
        case VMSizeDWord:
            value = (long)value;
            break;
        default:
            __debugbreak();
    }
    switch (dstsize)
    {
        case VMSizeShort:
            value = (short)value;
            break;
        case VMSizeDWord:
            value = (long)value;
            break;
#ifdef _AMD64_
        case VMSizeQWord:
            value = (long long)value;
            break;
#endif
        default:
            __debugbreak();
    }
    setTargetValue(regs, deco, value);
}

void movzxfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t value = getSrcValue(regs, deco);
    unsigned char srcsize = getByte(deco);
    unsigned char dstsize = getByte(deco);
    switch (srcsize)
    {
        case VMSizeByte:
            value = (unsigned char)value;
            break;
        case VMSizeShort:
            value = (unsigned short)value;
            break;
        case VMSizeDWord:
            value = (unsigned long)value;
            break;
        default:
            __debugbreak();
    }
    switch (dstsize)
    {
        case VMSizeShort:
            value = (unsigned short)value;
            break;
        case VMSizeDWord:
            value = (unsigned long)value;
            break;
#ifdef _AMD64_
        case VMSizeQWord:
            value = (unsigned long long)value;
            break;
#endif
        default:
            __debugbreak();
    }
    setTargetValue(regs, deco, value);
}

void cmovccfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t value = getSrcValue(regs, deco);
    if (ccfunc(regs, deco))
    {
        dbgprint("       setting\n");
        setTargetValue(regs, deco, value);
    }
    else
    {
        dbgprint("       NOT setting\n");
        setTargetValueFalse(regs, deco, value);
    }
}


void tstfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t value = getSrcValue(regs, deco);
    size_t value2 = getSrcValue(regs, deco);

    int sizetype = getByte(deco);
    setflagsand(regs, value, value2, sizetype);
}

void cmpfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    size_t value = getSrcValue(regs, deco);
    size_t value2 = getSrcValue(regs, deco);

    int sizetype = getByte(deco);
    setflagssub(regs, value, value2, sizetype);
}

// decorate noreturn?
extern "C" void __fastcall VMExit(void *);

// from the RVA to the new location has - sizeof(rva)
#define JMP_OFFSET 4

void jmpfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    if (peekByte(deco) != VMTypeCode)
    {
        size_t addr = (size_t)getSrcAddr(regs, deco);
        // push address of target
        regs->SavedSP -= sizeof(size_t);
        *((size_t*)(regs->SavedSP)) = addr;
        dbgprint("      going to jmp to 0x%p\n", addr);

        VMExit(regs);
    }
    long newoffset = (long)getSrcAddr(regs, deco);
    dbgprint("      new offset target is 0x%x\n", newoffset);
    deco->data += newoffset - JMP_OFFSET;
}


// from the RVA to the new location has - sizeof(rva) + condition code byte
#define JCC_OFFSET 5

void jccfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);
    if (peekByte(deco) != VMTypeCode)
    {
        size_t addr = (size_t)getSrcAddr(regs, deco);

        if (ccfunc(regs, deco)) {
            // push address of target
            regs->SavedSP -= sizeof(size_t);
            *((size_t*)(regs->SavedSP)) = addr;
            dbgprint("      going to jcc to 0x%p\n", addr);

            VMExit(regs);
        } else {
            dbgprint("  not jccing tailcall\n");
        }
    }
    long newoffset = (long)getSrcAddr(regs, deco);
    dbgprint("      new offset target is 0x%x\n", newoffset);
    if (ccfunc(regs, deco)) {
        dbgprint("  taken\n");
        deco->data += newoffset - JCC_OFFSET;
    } else {
        dbgprint("  not taken\n");
    }
}

// decorate noreturn?
extern "C" void __fastcall VMReEntry();

// CALL (noreturn)
void callfunc(SAVED_REGS *regs, decoderState *deco)
{
    dbgprint(" " __FUNCTION__ " %p %p\n", regs, deco->data);

    size_t addr = getSrcAddr(regs, deco);
    dbgprint("      supposed to be doing a call to %p with 0x%x and 0x%x\n", addr, regs->SavedCX, regs->SavedDX);

    // push the return of the reentry
    regs->SavedSP -= sizeof(size_t);
    *((size_t*)(regs->SavedSP)) = (size_t)(void*)&VMReEntry;
    dbgprint("      going to return to 0x%p\n", (void*)&VMReEntry);
    // push address of target
    regs->SavedSP -= sizeof(size_t);
    *((size_t*)(regs->SavedSP)) = addr;
    dbgprint("      going to call to 0x%p\n", addr);

#ifdef _AMD64_
    // load offset of "return address" into the saved r12 value.
    // r12 has been added to the kill list of this calltuple
    // in the emulated function, therefore this is safe
    regs->SavedR12 = (size_t)(deco->data);
    dbgprint("      going to start emulating addr 0x%p\n", regs->SavedR12);
#endif
#ifdef _X86_
    // load offset of return address into saved ebx
    // ebx has been added to the kill list of this calltuple
    // in the emulated function, therefore this is safe
    regs->SavedBX = (size_t)(deco->data);
    dbgprint("      going to start emulating addr 0x%p\n", regs->SavedBX);
#endif

    dbgprint("      saved stack loc is %p\n", regs->SavedSP);
    VMExit(regs);
}


//
// The main function - reads data and calls functions to simulate instructions
//
void __fastcall VMExecMainLoop(void *x, void* y)
{
    decoderState deco;

    dbgprint("regs %p, decoder %p\n", y, x);
    SAVED_REGS *regs = (SAVED_REGS*)y;
    InitDecoder(&deco, (unsigned char*)x);

    dbgprint("saved stack loc is %p\n", regs->SavedSP);

    unsigned char procN = 0;
    while (procN != VMFuncRet)
    {
        procN = getByte(&deco);
        if (procN == VMFuncRet)
        {
            dbgprint("done\n");
            size_t retarg = getSrcValue(regs, &deco);
            size_t retaddr = *((size_t*)(regs->SavedSP));
            regs->SavedSP += retarg;
            *((size_t*)(regs->SavedSP)) = retaddr;
            return;
        }
#ifdef VMEXEC_DEBUG
        if (g_fDebug & 2)
        {
            DebugBreak();
        }
#endif
        switch(procN)
        {
            case VMFuncMov:
                movfunc(regs, &deco);
                break;
#ifdef _AMD64_
            case VMFuncMovXmm:
                movxmmfunc(regs, &deco);
                break;
#endif
            case VMFuncLea:
                leafunc(regs, &deco);
                break;
            case VMFuncTst:
                tstfunc(regs, &deco);
                break;
            case VMFuncCmp:
                cmpfunc(regs, &deco);
                break;
            case VMFuncJcc:
                // changes offset
                jccfunc(regs, &deco);
                break;
            case VMFuncAdd:
                addfunc(regs, &deco);
                break;
            case VMFuncSub:
                subfunc(regs, &deco);
                break;
            case VMFuncPush:
                pushfunc(regs, &deco);
                break;
            case VMFuncPop:
                popfunc(regs, &deco);
                break;
            case VMFuncCall:
                // never returns
                callfunc(regs, &deco);
                break;
            case VMFuncJmp:
                // changes offset
                jmpfunc(regs, &deco);
                break;
            case VMFuncXor:
                xorfunc(regs, &deco);
                break;
            case VMFuncAnd:
                andfunc(regs, &deco);
                break;
            case VMFuncOr:
                orfunc(regs, &deco);
                break;
            case VMFuncRor:
                rorfunc(regs, &deco);
                break;
            case VMFuncRol:
                rolfunc(regs, &deco);
                break;
            case VMFuncSar:
                shrfunc(regs, &deco);
                break;
            case VMFuncShr:
                shrfunc(regs, &deco);
                break;
            case VMFuncShl:
                shlfunc(regs, &deco);
                break;
            case VMFuncNot:
                notfunc(regs, &deco);
                break;
            case VMFuncMovsx:
                movsxfunc(regs, &deco);
                break;
            case VMFuncMovzx:
                movzxfunc(regs, &deco);
                break;
            case VMFuncCMovcc:
                cmovccfunc(regs, &deco);
                break;
            default:
                dbgprint("unknown proc 0x%x\n", procN);
                dbgprint("unknown proc 0x%x\n", procN);
                __debugbreak();
                dbgprint("unknown proc 0x%x\n", procN);
        }
    }
}

}

#endif

