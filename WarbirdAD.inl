//-----------------------------------------------------------------------------
//
// Copyright (C) Microsoft Corporation.  All Rights Reserved.
// 
// File: WarbirdAD.inl
//
// Description:
//
// Anti-Debug macro implementations
//
//-----------------------------------------------------------------------------

#pragma once

#if !defined(WARBIRD_KERNEL_MODE) && !defined(WARBIRD_AD_DISABLED)

#ifndef WARBIRDAD_INL
#define WARBIRDAD_INL

#include <crtdbg.h>

// from ntdef.h
__if_not_exists(NTSTATUS)
{
    typedef LONG NTSTATUS;
}

// from delayimp.h
__if_not_exists(__ImageBase)
{
    #if defined(_WIN64) && defined(_M_IA64)
    #pragma section(".base", long, read, write)
    EXTERN_C __declspec(allocate(".base")) IMAGE_DOS_HEADER __ImageBase;
    #else
    EXTERN_C IMAGE_DOS_HEADER __ImageBase;
    #endif
}

// from ntexapi.h
__if_not_exists(SYSTEM_KERNEL_DEBUGGER_INFORMATION)
{
    typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
        BOOLEAN KernelDebuggerEnabled;
        BOOLEAN KernelDebuggerNotPresent;
    } SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;
}

// from ntexapi.h
__if_not_exists(SYSTEM_INFORMATION_CLASS)
{
    typedef enum _SYSTEM_INFORMATION_CLASS {
        SystemKernelDebuggerInformation = 35,
    } SYSTEM_INFORMATION_CLASS;
}

// from ntpsapi_x.h
__if_not_exists(PROCESSINFOCLASS)
{
    typedef enum _PROCESSINFOCLASS {
        ProcessDebugPort = 7,
    } PROCESSINFOCLASS;
}

#ifdef _AMD64_
// from ntxcapi.h
EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
NtContinue (
    __in PCONTEXT ContextRecord,
    __in BOOLEAN TestAlert
    );
#endif

#if defined(_PREFAST_)
#pragma prefast(disable: 322, "We have lots of empty exception handlers, which is correct")
#endif

#if defined(_PREFAST_)
    #define WARBIRD_AD_ASSERT(x) __assume(x)
#elif defined(_PREFIX_)
    #if __cplusplus
        extern "C" void __pfx_assume(bool, const char *);
    #else
        void __pfx_assume(int, const char *);
    #endif
    #define WARBIRD_AD_ASSERT(x) __pfx_assume(x,"PREFIX")
#elif defined(WARBIRD_DEBUG)
    #define WARBIRD_AD_ASSERT(x) _ASSERTE(x)
#else
    #define WARBIRD_AD_ASSERT(x) __noop(x)
#endif


// Keywords:    all SEH-Safe
#define WARBIRD_AD_DUMMY_SETUP(_xx) DWORD_PTR ad_dummy_add_a_block_##_xx; ad_dummy_add_a_block_##_xx = 0;
#define WARBIRD_AD_DUMMY_IF(_xx)    if(ad_dummy_add_a_block_##_xx)

// Mask for the strings below
const BYTE ad_g_rgbSimpleMask[] =       { 0xd5, 0xc1, 0xe3, 0xc5, 0xd3, 0xc5, 0xe6, 0xc9, 0xe2 };

// "kernel32.dll" masked
const BYTE ad_g_rgbKernel32[] =         { 0xbe, 0xa4, 0x91, 0xab, 0xb6, 0xa9, 0xd5, 0xfb, 0xcc,
                                        0xb1, 0xad, 0x8f};
// "IsDebuggerPresent" masked
const BYTE ad_g_rgbIsDebuggerPres[] =   { 0x9c, 0xb2, 0xa7, 0xa0, 0xb1, 0xb0, 0x81, 0xae, 0x87,
                                        0xa7, 0x91, 0x91, 0xa0, 0xa0, 0xa0, 0x88, 0xbd};

// "ntdll.dll" masked
const BYTE ad_g_rgbNtdll[] =            { 0xbb, 0xb5, 0x87, 0xa9, 0xbf, 0xeb, 0x82, 0xa5, 0x8e };
// "ZwQueryInformationProcess" masked
const BYTE ad_g_rgbZwQIP[] =            { 0x8f, 0xb6, 0xb2, 0xb0, 0xb6, 0xb7, 0x9f, 0x80, 0x8c,
                                        0xb3, 0xae, 0x91, 0xa8, 0xb2, 0xb1, 0x8f, 0xa6, 0x8c,
                                        0x85, 0xb3, 0x8c, 0xa6, 0xb6, 0xb6, 0x95 };
// "ZwQuerySystemInformation" masked
const BYTE ad_g_rgbZwQSI[] =            { 0x8f, 0xb6, 0xb2, 0xb0, 0xb6, 0xb7, 0x9f, 0x9a, 0x9b,
                                        0xa6, 0xb5, 0x86, 0xa8, 0x9a, 0xab, 0x80, 0xa6, 0x90,
                                        0xb8, 0xa0, 0x97, 0xac, 0xbc, 0xab };

// "CreateFileA" masked
const BYTE ad_g_rgbCreateFileA[] =      { 0x96, 0xb3, 0x86, 0xa4, 0xa7, 0xa0, 0xa0, 0xa0, 0x8e,
                                        0xb0, 0x80 };
// "DeviceIoControl" masked
const BYTE ad_g_rgbDeviceIoControl[] =  { 0x91, 0xa4, 0x95, 0xac, 0xb0, 0xa0, 0xaf, 0xa6, 0xa1,
                                        0xba, 0xaf, 0x97, 0xb7, 0xbc, 0xa9 };
// "ExitProcess" masked
const BYTE ad_g_rgbExitProcess[] =      { 0x90, 0xb9, 0x8a, 0xb1, 0x83, 0xb7, 0x89, 0xaa, 0x87,
                                        0xa6, 0xb2 };
// "LoadLibraryA" masked
const BYTE ad_g_rgbLoadLibraryA[] =     { 0x99, 0xae, 0x82, 0xa1, 0x9f, 0xac, 0x84, 0xbb, 0x83,
                                        0xa7, 0xb8, 0xa2 };
// "MapViewOfFile" masked
const BYTE ad_g_rgbMapViewOfFile[] =    { 0x98, 0xa0, 0x93, 0x93, 0xba, 0xa0, 0x91, 0x86, 0x84,
                                        0x93, 0xa8, 0x8f, 0xa0 };
// "ReadFile" masked
const BYTE ad_g_rgbReadFile[] =         { 0x87, 0xa4, 0x82, 0xa1, 0x95, 0xac, 0x8a, 0xac };

// "VirtualProtect" masked
const BYTE ad_g_rgbVirtualProtect[] =   { 0x83, 0xa8, 0x91, 0xb1, 0xa6, 0xa4, 0x8a, 0x99, 0x90,
                                        0xba, 0xb5, 0x86, 0xa6, 0xa7 };

//Maximum length of an masked/unmasked string
#define WARBIRD_AD_MAX_UNMASKED_LEN     (25 + 1)

// xor-mask a zero-terminated byte array.
#define WARBIRD_AD_MASKSZ(in, out) WarbirdAD_MaskSZ((in), sizeof(in), (out))

__forceinline void WarbirdAD_MaskSZ(
                        __in_bcount(cbIn)   const BYTE* pbIn,
                        __in                unsigned    cbIn,
                        __out_bcount(cbIn + 1)
                        					PSTR       	szOut)
{
    int i = 0;
    const BYTE* pbEnd = pbIn + cbIn;
    PSTR szEnd = szOut + cbIn;

    WARBIRD_AD_ASSERT(WARBIRD_AD_MAX_UNMASKED_LEN >= (cbIn + 1));

    while(pbIn < pbEnd && szOut < szEnd)
    {
        *szOut++ = *pbIn++ ^ ad_g_rgbSimpleMask[i];
        ++i;
        i %= sizeof(ad_g_rgbSimpleMask);
    }

	*szOut = 0;
}


// Fire a breakpoint
#if defined(_AMD64_)
extern void Warbird_AD_FireBreakpoint(void);
#define FIREBREAKPOINT() Warbird_AD_FireBreakpoint()
#elif defined(_X86_)
#define FIREBREAKPOINT() {__asm int 3}
#else
#define FIREBREAKPOINT() DebugBreak()
#endif


//*****************************************************************************
//*****************************************************************************
//
// Call IsDebuggerPresent()
//
//*****************************************************************************
//*****************************************************************************

__forceinline void ad_DetectUMD_IDPOpen_1_Setup(__out FARPROC *ppIsDebuggerPresent)
{
    HMODULE hKernel32 = GetModuleHandleA("kernel32");

    *ppIsDebuggerPresent = 0;
    if(hKernel32)
        *ppIsDebuggerPresent = GetProcAddress(hKernel32, "IsDebuggerPresent");
}

// returns true if debugger is present
__forceinline bool ad_DetectUMD_IDPOpen_1_If(__in FARPROC* ppIsDebuggerPresent)
{
    bool fRet = false;
    if (*ppIsDebuggerPresent && (*ppIsDebuggerPresent)())
        fRet = true;
    return fRet;
}


// Keywords:    all SEH-Safe
#define WARBIRD_AD_DETECT_IDPOPEN_1_SETUP(_xx) \
    FARPROC ad_IDPOpen_1_pIsDebuggerPresent_##_xx; \
    ad_DetectUMD_IDPOpen_1_Setup(&ad_IDPOpen_1_pIsDebuggerPresent_##_xx);

#define WARBIRD_AD_DETECT_IDPOPEN_1_IF(_xx) \
    if(ad_DetectUMD_IDPOpen_1_If(&ad_IDPOpen_1_pIsDebuggerPresent_##_xx))


__forceinline void ad_DetectUMD_IDPMasked_1_Setup(__out FARPROC *ppIsDebuggerPresent)
{
    HMODULE hKernel32;
    CHAR abUnmasked[WARBIRD_AD_MAX_UNMASKED_LEN];

    WARBIRD_AD_MASKSZ(ad_g_rgbKernel32, abUnmasked);
    hKernel32 = GetModuleHandleA((const char*)abUnmasked);
    WARBIRD_AD_MASKSZ((BYTE*)abUnmasked, abUnmasked);

    *ppIsDebuggerPresent = 0;

    if(hKernel32)
    {
        WARBIRD_AD_MASKSZ(ad_g_rgbIsDebuggerPres, abUnmasked);
        *ppIsDebuggerPresent = GetProcAddress(hKernel32, (const char*)abUnmasked);
        WARBIRD_AD_MASKSZ((BYTE*)abUnmasked, abUnmasked);
    }
}

// returns true if debugger is present
__forceinline bool ad_DetectUMD_IDPMasked_1_If(__in FARPROC* ppIsDebuggerPresent)
{
    bool fRet = false;
    if(*ppIsDebuggerPresent && (*ppIsDebuggerPresent)())
        fRet = true;
    return fRet;
}

// Keywords:    all SEH-Safe
#define WARBIRD_AD_DETECT_IDPMASKED_1_SETUP(_xx) \
    FARPROC ad_IDPMasked_1_pIsDebuggerPresent_##_xx; \
    ad_DetectUMD_IDPMasked_1_Setup(&ad_IDPMasked_1_pIsDebuggerPresent_##_xx);

#define WARBIRD_AD_DETECT_IDPMASKED_1_IF(_xx) \
    if(ad_DetectUMD_IDPMasked_1_If(&ad_IDPMasked_1_pIsDebuggerPresent_##_xx))



//*****************************************************************************
//*****************************************************************************
//
// Check for usermode debugger by calling ZwQueryInformationProcess
// Based on mariuszj's code
//
//*****************************************************************************
//*****************************************************************************

typedef NTSTATUS (__stdcall *ZwQIPPtr)(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

__forceinline void ad_DetectUMD_ZwQIPOpen_1_Setup(__out ZwQIPPtr* ppQIP)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    *ppQIP = 0;
    if (hNtdll)
        *ppQIP = (ZwQIPPtr)GetProcAddress(hNtdll, "ZwQueryInformationProcess");
}

// returns false if debugger is detected.
__forceinline bool ad_DetectUMD_ZwQIPOpen_1_If(__in ZwQIPPtr* ppQIP)
{
    bool fClean = true;
    if (*ppQIP)
    {
        HANDLE hDebugPort = 0;
        DWORD rc = (*ppQIP)(GetCurrentProcess(), ProcessDebugPort,
                            (void*)&hDebugPort, sizeof(HANDLE), 0);
        if (!rc && hDebugPort)
            fClean = false;
    }
    return fClean;
}

// Keywords:    all SEH-Safe
#define WARBIRD_AD_DETECT_ZWQIPOPEN_1_SETUP(_xx) \
    ZwQIPPtr ad_ZwQIPOpen_1_pQIP_##_xx; \
    ad_DetectUMD_ZwQIPOpen_1_Setup(&ad_ZwQIPOpen_1_pQIP_##_xx);

#define WARBIRD_AD_DETECT_ZWQIPOPEN_1_IF(_xx) \
    if (!ad_DetectUMD_ZwQIPOpen_1_If(&ad_ZwQIPOpen_1_pQIP_##_xx))


// turns off bit 0x2 of *pwRet if debugger is detected.
__forceinline void ad_DetectUMD_ZwQIPOpen_2_Setup(__inout WORD* pwRet)
{
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    ZwQIPPtr pQIP = 0;
    if (hNtdll)
        pQIP = (ZwQIPPtr)GetProcAddress(hNtdll, "ZwQueryInformationProcess");

    if (pQIP)
    {
        HANDLE hDebugPort = 0;
        DWORD rc = pQIP(GetCurrentProcess(), ProcessDebugPort,
                        (void*)&hDebugPort, sizeof(HANDLE), 0);
        if (!rc && hDebugPort)
            *pwRet -= 0x12; // turn off bit 1
    }
    if (hNtdll)
        FreeLibrary(hNtdll);
}

// Keywords:    all SEH-Safe
#define WARBIRD_AD_DETECT_ZWQIPOPEN_2_SETUP(_xx) \
    WORD ad_ZwQIPOpen_2_wRet_##_xx; \
    ad_ZwQIPOpen_2_wRet_##_xx = 0x71f3; \
    ad_DetectUMD_ZwQIPOpen_2_Setup(&ad_ZwQIPOpen_2_wRet_##_xx);

#define WARBIRD_AD_DETECT_ZWQIPOPEN_2_IF(_xx) \
    if (!(ad_ZwQIPOpen_2_wRet_##_xx & 2))


__forceinline void ad_DetectUMD_ZwQIPOpen_3_Setup(__out HMODULE* phNtdll)
{
    *phNtdll = GetModuleHandleA("ntdll.dll");
}

// returns with bit 0x4 on if debugger is detected.
__forceinline WORD ad_DetectUMD_ZwQIPOpen_3_If(__in HMODULE hNtdll)
{
    WORD wRet = 0xf9f2;
    ZwQIPPtr pQIP = 0;
    if (hNtdll)
        pQIP = (ZwQIPPtr)GetProcAddress(hNtdll, "ZwQueryInformationProcess");

    if (pQIP)
    {
        HANDLE hDebugPort = 0;
        DWORD rc = pQIP(GetCurrentProcess(), ProcessDebugPort,
                        (void*)&hDebugPort, sizeof(HANDLE), 0);
        if (!rc && hDebugPort)
            wRet -= 6; // turn on bit 2
    }
    return wRet;
}

// Keywords:    all SEH-Safe
#define WARBIRD_AD_DETECT_ZWQIPOPEN_3_SETUP(_xx) \
    HMODULE ad_ZwQIPOpen_3_hNtdll_##_xx; \
    ad_DetectUMD_ZwQIPOpen_3_Setup(&ad_ZwQIPOpen_3_hNtdll_##_xx);

#define WARBIRD_AD_DETECT_ZWQIPOPEN_3_IF(_xx) \
    if (ad_DetectUMD_ZwQIPOpen_3_If(ad_ZwQIPOpen_3_hNtdll_##_xx) & 4)



// Keywords:    all SEH-Safe
#define WARBIRD_AD_DETECT_ZWQIPOPEN_4_SETUP(_xx) \
    bool ad_ZwQIPOpen_4_fDetected_##_xx;

#define WARBIRD_AD_DETECT_ZWQIPOPEN_4_IF(_xx) \
    { \
        HMODULE hNtdll = LoadLibraryA("ntdll.dll"); \
        ZwQIPPtr pQIP = 0; \
        char cRet = '9'; \
        if (hNtdll) \
            pQIP = (ZwQIPPtr)GetProcAddress(hNtdll, "ZwQueryInformationProcess"); \
        if (pQIP) \
        { \
            HANDLE hDebugPort = 0; \
            DWORD rc = pQIP(GetCurrentProcess(), ProcessDebugPort, \
                            (void*)&hDebugPort, sizeof(HANDLE), 0); \
            if (!rc && hDebugPort) \
                cRet -= 4; \
        } \
        if (hNtdll) \
            FreeLibrary(hNtdll); \
        ad_ZwQIPOpen_4_fDetected_##_xx = !(((cRet - '0')/3)-1); \
    } \
    if (ad_ZwQIPOpen_4_fDetected_##_xx)


__forceinline void ad_DetectUMD_ZwQIPMasked_1_Setup(__out ZwQIPPtr* ppQIP)
{
    CHAR abUnmasked[WARBIRD_AD_MAX_UNMASKED_LEN];

    WARBIRD_AD_MASKSZ(ad_g_rgbNtdll, abUnmasked);
    HMODULE hNtdll = GetModuleHandleA((const char*)abUnmasked);
    WARBIRD_AD_MASKSZ((BYTE*)abUnmasked, abUnmasked);

    *ppQIP = 0;
    if (hNtdll)
    {
        WARBIRD_AD_MASKSZ(ad_g_rgbZwQIP, abUnmasked);
        *ppQIP = (ZwQIPPtr)GetProcAddress(hNtdll, (const char*)abUnmasked);
        WARBIRD_AD_MASKSZ((BYTE*)abUnmasked, abUnmasked);
    }
}

// returns true if debugger is detected.
__forceinline bool ad_DetectUMD_ZwQIPMasked_1_If(__in ZwQIPPtr* ppQIP)
{
    bool fRet = false;
    if (*ppQIP)
    {
        HANDLE hDebugPort = 0;
        DWORD rc = (*ppQIP)(GetCurrentProcess(), ProcessDebugPort,
                            (void*)&hDebugPort, sizeof(HANDLE), 0);
        if (!rc && hDebugPort)
            fRet = true;
    }
    return fRet;
}

// Keywords:    all SEH-Safe
#define WARBIRD_AD_DETECT_ZWQIPMASKED_1_SETUP(_xx) \
    ZwQIPPtr ad_ZwQIPMasked_1_pQIP_##_xx; \
    ad_DetectUMD_ZwQIPMasked_1_Setup(&ad_ZwQIPMasked_1_pQIP_##_xx);

#define WARBIRD_AD_DETECT_ZWQIPMASKED_1_IF(_xx) \
    if (ad_DetectUMD_ZwQIPMasked_1_If(&ad_ZwQIPMasked_1_pQIP_##_xx))



// Description: Turns off bit 0x2 if debugger is detected.
// Keywords:    all SEH-Safe
#define WARBIRD_AD_DETECT_ZWQIPMASKED_2_SETUP(_xx) \
    WORD ad_ZwQIPMasked_2_wRet_##_xx; \
    ad_ZwQIPMasked_2_wRet_##_xx = 0x4153; \
    { \
        CHAR abUnmasked_ZwQIP_##_xx[WARBIRD_AD_MAX_UNMASKED_LEN]; \
        WARBIRD_AD_MASKSZ(ad_g_rgbNtdll, abUnmasked_ZwQIP_##_xx); \
        HMODULE hNtdll = LoadLibraryA((const char*)abUnmasked_ZwQIP_##_xx); \
        ZwQIPPtr pQIP = 0; \
        if (hNtdll) \
        { \
            WARBIRD_AD_MASKSZ(ad_g_rgbZwQIP, abUnmasked_ZwQIP_##_xx); \
            pQIP = (ZwQIPPtr)GetProcAddress(hNtdll, (const char*)abUnmasked_ZwQIP_##_xx); \
        } \
        WARBIRD_AD_MASKSZ((BYTE*)abUnmasked_ZwQIP_##_xx, abUnmasked_ZwQIP_##_xx); \
        if (pQIP) \
        { \
            HANDLE hDebugPort = 0; \
            DWORD rc = pQIP(GetCurrentProcess(), ProcessDebugPort, \
                            (void*)&hDebugPort, sizeof(HANDLE), 0); \
            if (!rc && hDebugPort) \
                ad_ZwQIPMasked_2_wRet_##_xx -= 2; \
        } \
        if (hNtdll) \
        { \
            FreeLibrary(hNtdll); \
        } \
    }

#define WARBIRD_AD_DETECT_ZWQIPMASKED_2_IF(_xx) \
    if (!(ad_ZwQIPMasked_2_wRet_##_xx & 2))



__forceinline void ad_DetectUMD_ZwQIPMasked_3_Setup(__out HMODULE* phNtdll)
{
    CHAR abUnmasked[WARBIRD_AD_MAX_UNMASKED_LEN];
    
    WARBIRD_AD_MASKSZ(ad_g_rgbNtdll, abUnmasked);
    *phNtdll = GetModuleHandleA((const char*)abUnmasked);
    WARBIRD_AD_MASKSZ((BYTE*)abUnmasked, abUnmasked);
}

// Keywords:    all SEH-Safe
#define WARBIRD_AD_DETECT_ZWQIPMASKED_3_SETUP(_xx) \
    HMODULE ad_ZwQIPMasked_3_hNtdll_##_xx; \
    ad_DetectUMD_ZwQIPMasked_3_Setup(&ad_ZwQIPMasked_3_hNtdll_##_xx);

// turns bit 0x4 off if debugger is detected.
#define WARBIRD_AD_DETECT_ZWQIPMASKED_3_IF(_xx) \
    WORD ad_ZwQIPMasked_3_wDetected_##_xx; \
    { \
        CHAR abUnmasked_ZwQIPMasked_3_##_xx[WARBIRD_AD_MAX_UNMASKED_LEN]; \
        ad_ZwQIPMasked_3_wDetected_##_xx = 0xba1d; \
        ZwQIPPtr pQIP = 0; \
        if (ad_ZwQIPMasked_3_hNtdll_##_xx) \
        { \
            WARBIRD_AD_MASKSZ(ad_g_rgbZwQIP, abUnmasked_ZwQIPMasked_3_##_xx); \
            pQIP = (ZwQIPPtr)GetProcAddress(ad_ZwQIPMasked_3_hNtdll_##_xx, \
                                            (const char*)abUnmasked_ZwQIPMasked_3_##_xx); \
        } \
        if (pQIP) \
        { \
            HANDLE hDebugPort = 0; \
            DWORD rc = pQIP(GetCurrentProcess(), ProcessDebugPort, \
                            (void*)&hDebugPort, sizeof(HANDLE), 0); \
            if (!rc && hDebugPort) \
                ad_ZwQIPMasked_3_wDetected_##_xx -= 4; \
        } \
        if (ad_ZwQIPMasked_3_hNtdll_##_xx) \
        { \
            WARBIRD_AD_MASKSZ((BYTE*)abUnmasked_ZwQIPMasked_3_##_xx, abUnmasked_ZwQIPMasked_3_##_xx); \
        } \
    } \
    if (!(ad_ZwQIPMasked_3_wDetected_##_xx & 4))



// Keywords:    all SEH-Safe
#define WARBIRD_AD_DETECT_ZWQIPMASKED_4_SETUP(_xx) \
    bool ad_ZwQIPMasked_4_fDetected_##_xx;

#define WARBIRD_AD_DETECT_ZWQIPMASKED_4_IF(_xx) \
    { \
        CHAR abUnmasked_ZwQIPMasked_4_##_xx[WARBIRD_AD_MAX_UNMASKED_LEN]; \
        WARBIRD_AD_MASKSZ(ad_g_rgbNtdll, abUnmasked_ZwQIPMasked_4_##_xx); \
        HMODULE hNtdll = LoadLibraryA((const char*)abUnmasked_ZwQIPMasked_4_##_xx); \
        ZwQIPPtr pQIP = 0; \
        char cRet = '7'; \
        if (hNtdll) \
        { \
            WARBIRD_AD_MASKSZ(ad_g_rgbZwQIP, abUnmasked_ZwQIPMasked_4_##_xx); \
            pQIP = (ZwQIPPtr)GetProcAddress(hNtdll, (const char*)abUnmasked_ZwQIPMasked_4_##_xx); \
        } \
        WARBIRD_AD_MASKSZ((BYTE*)abUnmasked_ZwQIPMasked_4_##_xx, abUnmasked_ZwQIPMasked_4_##_xx); \
        if (pQIP) \
        { \
            HANDLE hDebugPort = 0; \
            DWORD rc = pQIP(GetCurrentProcess(), ProcessDebugPort, \
                            (void*)&hDebugPort, sizeof(HANDLE), 0); \
            if (!rc && hDebugPort) \
                cRet -= 2; \
        } \
        if (hNtdll) \
        { \
            FreeLibrary(hNtdll); \
        } \
        ad_ZwQIPMasked_4_fDetected_##_xx = !(((cRet - '0')/3)-1); \
    } \
    if (ad_ZwQIPMasked_4_fDetected_##_xx)



//*****************************************************************************
//*****************************************************************************
//
// Check for NT kernel debugger by calling ZwQuerySystemInformation
// Based on mariuszj's code
//
//*****************************************************************************
//*****************************************************************************

typedef NTSTATUS (__stdcall *ZwQSIPtr)(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL);


__forceinline void ad_DetectKD_ZwQSIOpen_1_Setup(__out ZwQSIPtr* ppQSI)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    *ppQSI = 0;
    if (hNtdll)
        *ppQSI = (ZwQSIPtr)GetProcAddress(hNtdll, "ZwQuerySystemInformation");
}

__forceinline bool ad_DetectKD_ZwQSIOpen_1_If(__in ZwQSIPtr* ppQSI)
{
    bool fClean = true;
    if (ppQSI)
    {
        SYSTEM_KERNEL_DEBUGGER_INFORMATION skdi = { TRUE, FALSE };
        DWORD rc = (*ppQSI)(SystemKernelDebuggerInformation, &skdi, sizeof(skdi), NULL);
        if (!rc && skdi.KernelDebuggerEnabled)
            fClean = false;
    }
    return fClean;
}

// Keywords:    all SEH-Safe kernel
#define WARBIRD_AD_DETECT_ZWQSIOPEN_1_SETUP(_xx) \
    ZwQSIPtr ad_ZwQSIOpen_1_pQSI_##_xx; \
    ad_DetectKD_ZwQSIOpen_1_Setup(&ad_ZwQSIOpen_1_pQSI_##_xx);

#define WARBIRD_AD_DETECT_ZWQSIOPEN_1_IF(_xx) \
    if (!ad_DetectKD_ZwQSIOpen_1_If(&ad_ZwQSIOpen_1_pQSI_##_xx))



__forceinline void ad_DetectKD_ZwQSIOpen_2_Setup(__out HMODULE* phNtdll)
{
    *phNtdll = GetModuleHandleA("ntdll.dll");
}

// return 16 if clean, 24 if detected
__forceinline DWORD ad_DetectKD_ZwQSIOpen_2_If(__in HMODULE* phNtdll)
{
    DWORD dwRet = 16;
    ZwQSIPtr pQSI = 0;
    if (*phNtdll)
        pQSI = (ZwQSIPtr)GetProcAddress(*phNtdll, "ZwQuerySystemInformation");

    if (pQSI)
    {
        SYSTEM_KERNEL_DEBUGGER_INFORMATION skdi = { TRUE, FALSE };
        DWORD rc = pQSI(SystemKernelDebuggerInformation, &skdi, sizeof(skdi), NULL);
        if (!rc && skdi.KernelDebuggerEnabled)
            dwRet += 8;
    }
    return dwRet;
}

// Keywords:    all SEH-Safe kernel
#define WARBIRD_AD_DETECT_ZWQSIOPEN_2_SETUP(_xx) \
    HMODULE ad_ZwQSIOpen_2_hNtdll_##_xx; \
    ad_DetectKD_ZwQSIOpen_2_Setup(&ad_ZwQSIOpen_2_hNtdll_##_xx);

#define WARBIRD_AD_DETECT_ZWQSIOPEN_2_IF(_xx) \
    if (ad_DetectKD_ZwQSIOpen_2_If(&ad_ZwQSIOpen_2_hNtdll_##_xx) > 20)


// Description: Turn off bits 0x30 of wRet if debugger is present
// Keywords:    all SEH-Safe kernel
#define WARBIRD_AD_DETECT_ZWQSIMASKED_1_SETUP(_xx) \
    WORD ad_ZwQSIMasked_1_wRet_##_xx; \
    { \
        CHAR abUnmasked_ZwQSIMasked_1_##_xx[WARBIRD_AD_MAX_UNMASKED_LEN]; \
        ad_ZwQSIMasked_1_wRet_##_xx = 0xffff; \
        WARBIRD_AD_MASKSZ(ad_g_rgbNtdll, abUnmasked_ZwQSIMasked_1_##_xx); \
        HMODULE hNtdll = LoadLibraryA((const char*)abUnmasked_ZwQSIMasked_1_##_xx); \
        ZwQSIPtr pQSI = 0; \
        if (hNtdll) \
        { \
            WARBIRD_AD_MASKSZ(ad_g_rgbZwQSI, abUnmasked_ZwQSIMasked_1_##_xx); \
            pQSI = (ZwQSIPtr)GetProcAddress(hNtdll, (const char*)abUnmasked_ZwQSIMasked_1_##_xx); \
        } \
        WARBIRD_AD_MASKSZ((BYTE*)abUnmasked_ZwQSIMasked_1_##_xx, abUnmasked_ZwQSIMasked_1_##_xx); \
        if (pQSI) \
        { \
            SYSTEM_KERNEL_DEBUGGER_INFORMATION skdi = { TRUE, FALSE }; \
            DWORD rc = pQSI(SystemKernelDebuggerInformation, &skdi, sizeof(skdi), NULL); \
            if (!rc && skdi.KernelDebuggerEnabled) \
                ad_ZwQSIMasked_1_wRet_##_xx -= 0x30; \
        } \
        if (hNtdll) \
        { \
            FreeLibrary(hNtdll); \
        } \
    }

#define WARBIRD_AD_DETECT_ZWQSIMASKED_1_IF(_xx) \
    if (!(ad_ZwQSIMasked_1_wRet_##_xx & 0x10))


// Description: true if debugger is detected
// Keywords:    all SEH-Safe kernel
#define WARBIRD_AD_DETECT_ZWQSIMASKED_2_SETUP(_xx) \
    bool ad_ZwQSIMasked_2_fRet_##_xx; \
    ad_ZwQSIMasked_2_fRet_##_xx = false;

#define WARBIRD_AD_DETECT_ZWQSIMASKED_2_IF(_xx) \
    { \
        CHAR abUnmasked_ZwQSIMasked_2_##_xx[WARBIRD_AD_MAX_UNMASKED_LEN]; \
        WARBIRD_AD_MASKSZ(ad_g_rgbNtdll, abUnmasked_ZwQSIMasked_2_##_xx); \
        HMODULE hNtdll = LoadLibraryA((const char*)abUnmasked_ZwQSIMasked_2_##_xx); \
        ZwQSIPtr pQSI = 0; \
        if (hNtdll) \
        { \
            WARBIRD_AD_MASKSZ(ad_g_rgbZwQSI, abUnmasked_ZwQSIMasked_2_##_xx); \
            pQSI = (ZwQSIPtr)GetProcAddress(hNtdll, (const char*)abUnmasked_ZwQSIMasked_2_##_xx); \
        } \
        WARBIRD_AD_MASKSZ((BYTE*)abUnmasked_ZwQSIMasked_2_##_xx, abUnmasked_ZwQSIMasked_2_##_xx); \
        if (pQSI) \
        { \
            SYSTEM_KERNEL_DEBUGGER_INFORMATION skdi = { TRUE, FALSE }; \
            DWORD rc = pQSI(SystemKernelDebuggerInformation, &skdi, sizeof(skdi), NULL); \
            ad_ZwQSIMasked_2_fRet_##_xx = (!rc && skdi.KernelDebuggerEnabled); \
        } \
        if (hNtdll) \
        { \
            FreeLibrary(hNtdll); \
        } \
    } \
    if (ad_ZwQSIMasked_2_fRet_##_xx)
    


//*****************************************************************************
//*****************************************************************************
//
// Check for usermode debugger by looking at the TIB structure and TF bit
//
//*****************************************************************************
//*****************************************************************************

#if defined(_X86_) || defined(_AMD64_)

#ifdef _X86_
// returns 1 if debugger is present
__forceinline DWORD ad_DetectUMD_TIBNT_1_If()
{
    DWORD dwDetected;
    __asm
    {
        // this is IsDebuggerPresent() in NT.
        mov eax, fs:[0x18] // TIB ptr
        mov eax, [eax + 0x30] // PEB ptr
        movzx eax, byte ptr [eax + 2]
        mov dwDetected, eax
    }

    return dwDetected;
}
#else
extern BOOL Warbird_AD_UMD_TIBNT_1(void);
#define ad_DetectUMD_TIBNT_1_If() Warbird_AD_UMD_TIBNT_1()
#endif

// Keywords:    x86 amd64 SEH-Safe
#define WARBIRD_AD_DETECT_TIBNT_1_SETUP(_xx)

#define WARBIRD_AD_DETECT_TIBNT_1_IF(_xx) \
    if(ad_DetectUMD_TIBNT_1_If())


// puts 1 into *pdwDetected if debugger is present
#ifdef _X86_
__forceinline void ad_DetectUMD_TIBNT_2_Setup(__inout DWORD* pdwDetected)
{
    __asm
    {
        // this is IsDebuggerPresent() in NT.
        mov eax, fs:[0x18] // TIB ptr
        mov eax, [eax+0x30] // PEB ptr
        movzx eax, byte ptr [eax+2]
        mov ecx, pdwDetected
        mov [ecx], eax
    }
}
#else
extern void Warbird_AD_UMD_TIBNT_2(__inout DWORD *pdwDetected);
#define ad_DetectUMD_TIBNT_2_Setup(p) Warbird_AD_UMD_TIBNT_2(p)
#endif

// Keywords:    x86 amd64 SEH-Safe
#define WARBIRD_AD_DETECT_TIBNT_2_SETUP(_xx) \
    DWORD ad_TIBNT_2_dwDetected_##_xx; \
    ad_DetectUMD_TIBNT_2_Setup(&ad_TIBNT_2_dwDetected_##_xx);

#define WARBIRD_AD_DETECT_TIBNT_2_IF(_xx) \
    if(ad_TIBNT_2_dwDetected_##_xx)

#else
#define WARBIRD_AD_DETECT_TIBNT_1_SETUP(_xx)    WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_TIBNT_1_IF(_xx)       WARBIRD_AD_DUMMY_IF(_xx)

#define WARBIRD_AD_DETECT_TIBNT_2_SETUP(_xx)    WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_TIBNT_2_IF(_xx)       WARBIRD_AD_DUMMY_IF(_xx)
#endif


#ifdef _X86_
//
// set TF, see that it fires an exception to our handler
//

__forceinline int ad_ExceptFilter_SetTF(__inout DWORD* pdwDet)
{
    *pdwDet *= 12;
    return EXCEPTION_CONTINUE_EXECUTION;
}

// Keywords:    x86
#define WARBIRD_AD_DETECT_SETTF_1_SETUP(_xx) \
    DWORD ad_SetTF_1_dwDet_##_xx; \
    ad_SetTF_1_dwDet_##_xx = 2;

// returns 2 if debugger is detected, 0x18 otherwise
#define WARBIRD_AD_DETECT_SETTF_1_IF(_xx) \
    __try \
    { \
        __int16 wFlags; \
        __asm xor eax, eax \
        __asm pushf \
        __asm lea eax, wFlags \
        __asm or ax, 0x1000 \
        __asm mov wFlags, ax \
        __asm xor eax, eax \
        __asm { pop wFlags } \
        wFlags |= 0x107; \
        __asm push wFlags \
        __asm popf \
        __asm { mov ax, wFlags } \
    } \
    __except(ad_ExceptFilter_SetTF(&ad_SetTF_1_dwDet_##_xx)) {} \
    if (!(ad_SetTF_1_dwDet_##_xx & 0x10))



// Description: returns 0x11 if debugger is detected, 0xcc otherwise
// Keywords:    x86
#define WARBIRD_AD_DETECT_SETTF_2_SETUP(_xx) \
    DWORD ad_SetTF_2_dwDet_##_xx; ad_SetTF_2_dwDet_##_xx = 6809; \
    __try \
    { \
        __int16 wFlags; \
        __asm xor eax, eax \
        __asm pushf \
        __asm lea eax, wFlags \
        __asm mov bx, 0x40f0 \
        __asm and ax, bx \
        __asm mov wFlags, ax \
        __asm xor eax, eax \
        __asm { pop wFlags } \
        ad_SetTF_2_dwDet_##_xx = 17; \
        wFlags |= 0x101; \
        __asm push wFlags \
        __asm popf \
        __asm { lea edx, wFlags } \
    } \
    __except(ad_ExceptFilter_SetTF(&ad_SetTF_2_dwDet_##_xx)) {}

#define WARBIRD_AD_DETECT_SETTF_2_IF(_xx) \
    if (ad_SetTF_2_dwDet_##_xx != 0xcc)


#else
#define WARBIRD_AD_DETECT_SETTF_1_SETUP(_xx)    WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_SETTF_1_IF(_xx)       WARBIRD_AD_DUMMY_IF(_xx)

#define WARBIRD_AD_DETECT_SETTF_2_SETUP(_xx)    WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_SETTF_2_IF(_xx)       WARBIRD_AD_DUMMY_IF(_xx)
#endif



//*****************************************************************************
//*****************************************************************************
//
// Fire a breakpoint and see if it comes to our handler
//
//*****************************************************************************
//*****************************************************************************

#if defined(_X86_) || defined(_AMD64_)

// Decription:  __forceinline won't inline SEH, contrary to docs,
//              so this has to be a macro.
//              leaves the dword 393 if a debugger intercepts the int 3.
// Keywords:    x86 amd64
#define WARBIRD_AD_DETECT_INT3_1_SETUP(_xx) \
    DWORD ad_int3_1_dwDetected_##_xx; \
    ad_int3_1_dwDetected_##_xx = 393; \
    __try \
    { \
        __try \
        { \
            FIREBREAKPOINT(); \
        } \
        __except(GetExceptionCode() == STATUS_BREAKPOINT ? \
                 EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) \
        { \
            ad_int3_1_dwDetected_##_xx = 0; \
        } \
    } \
    __except(EXCEPTION_EXECUTE_HANDLER) {}

#define WARBIRD_AD_DETECT_INT3_1_IF(_xx) \
    if(ad_int3_1_dwDetected_##_xx)


// Keywords:    x86 amd64
#define WARBIRD_AD_DETECT_INT3_2_SETUP(_xx) \
    WORD ad_int3_2_wDetected_##_xx;

// leaves the dword 9963 if a debugger intercepts the int 3.
#define WARBIRD_AD_DETECT_INT3_2_IF(_xx) \
    ad_int3_2_wDetected_##_xx = 9963; \
    __try \
    { \
        __try \
        { \
            FIREBREAKPOINT(); \
        } \
        __except(GetExceptionCode() == STATUS_BREAKPOINT ? \
                 EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) \
        { \
            ad_int3_2_wDetected_##_xx = 0; \
        } \
    } \
    __except(EXCEPTION_EXECUTE_HANDLER) {} \
    if(ad_int3_2_wDetected_##_xx)


#else
#define WARBIRD_AD_DETECT_INT3_1_SETUP(_xx)         WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_INT3_1_IF(_xx)            WARBIRD_AD_DUMMY_IF(_xx)

#define WARBIRD_AD_DETECT_INT3_2_SETUP(_xx)         WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_INT3_2_IF(_xx)            WARBIRD_AD_DUMMY_IF(_xx)
#endif


//
// Fire an int 3 as above, but with the int instruction obfuscated
//
// The outer try is to catch the crash VC causes if it tries to single-step through;
// it becomes confused about instruction pointers, falls out of sync, and crashes within
// a few instructions.
// inside the asm, the emitted bytes are what you'd get if you said 'call next', with 'next:'
// at the pop eax.  VC (incorrectly, and fixed in VC7) throws C2705.  The idea is to use a
// call to push the instruction pointer, then pop into eax.  The stuff in between the call and
// the pop is misdirection, looks like a function boundary.
// then we back up to the call instruction, change it to an int 3, and rerun the loop.
// x86 handles its own pipeline sync; we don't need to FlushInstructionCache() (it's a noop).

// leaves bits on in the top word of pbDetected if a debugger intercepts the int 3.

#ifdef _X86_

// Keywords:    x86 selfmod
#define WARBIRD_AD_DETECT_INT3SELFMOD_1_SETUP(_xx) \
    BYTE* ad_int3selfmod_1_pbDetected_##_xx; \
    { \
        BYTE* pInstruction_##_xx; pInstruction_##_xx = 0; \
        DWORD dwProtect_##_xx; dwProtect_##_xx = PAGE_EXECUTE_READWRITE; \
        __try \
        { \
            __try \
            { \
                for (int i = 37; i < 79; i += 23) \
                { \
                    __asm _emit 0xe8 \
                    __asm _emit 0x07 \
                    __asm _emit 0x00 \
                    __asm _emit 0x00 \
                    __asm _emit 0x00 \
                    __asm xor eax, eax \
                    __asm pop ebp \
                    __asm ret \
                    __asm push ebp \
                    __asm mov ebp, esp \
                    __asm pop eax \
                    __asm { mov pInstruction_##_xx, eax } \
                    pInstruction_##_xx -= 5; \
                    WARBIRD_AD_ASSERT(pInstruction_##_xx >= (BYTE*)0x10000); \
                    VirtualProtect(pInstruction_##_xx, 1, dwProtect_##_xx, &dwProtect_##_xx); \
                    *pInstruction_##_xx ^= 0x24; \
                    VirtualProtect(pInstruction_##_xx, 1, dwProtect_##_xx, &dwProtect_##_xx); \
                } \
            } \
            __except(GetExceptionCode() == STATUS_BREAKPOINT ? \
                     EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) \
            { \
                VirtualProtect(pInstruction_##_xx, 1, dwProtect_##_xx, &dwProtect_##_xx); \
                *pInstruction_##_xx ^= 0x24; \
                VirtualProtect(pInstruction_##_xx, 1, dwProtect_##_xx, &dwProtect_##_xx); \
                pInstruction_##_xx = (BYTE*)0xf3c7; \
            } \
        } \
        __except(EXCEPTION_EXECUTE_HANDLER) {} \
        ad_int3selfmod_1_pbDetected_##_xx = pInstruction_##_xx; \
    }

#define WARBIRD_AD_DETECT_INT3SELFMOD_1_IF(_xx) \
    if ((DWORD(ad_int3selfmod_1_pbDetected_##_xx) & 0xffff) != DWORD(ad_int3selfmod_1_pbDetected_##_xx))

#else
#define WARBIRD_AD_DETECT_INT3SELFMOD_1_SETUP(_xx)  WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_INT3SELFMOD_1_IF(_xx)     WARBIRD_AD_DUMMY_IF(_xx)
#endif
    

//*****************************************************************************
//*****************************************************************************
//
// Check for a debugger using the hardware debug registers
//
//*****************************************************************************
//*****************************************************************************

#if defined(_X86_) || defined(_AMD64_)

// Zero the debug registers
__forceinline void ad_ZeroDRs(__out PCONTEXT pCtx)
{
    pCtx->Dr0=0;
    pCtx->Dr1=0;
    pCtx->Dr2=0;
    pCtx->Dr3=0;
    pCtx->Dr6=0;
    pCtx->Dr7=0;
}

// ensure the DRs are all zero.
// note the ad_SetDRs calls may not actually set the context if this isn't
// called from an exeption handler.
__forceinline int ad_CompareDRs(__inout PCONTEXT pCtx) // returns nonzero for a mismatch
{
    // if DR7 is non-zero assume a debugger is attached
    if (pCtx->Dr7 != 0)
    {
        // zero any active debug registers to erase breakpoints.
        // the caller is responsible for ensuring the DR values set are
        // actually applied
        ad_ZeroDRs(pCtx);
        return 1;
    }
    else
    {
        // ensure DR0 - DR3 contain zeros even if they are disabled.
        // Skip DR6.  It seems to change erratically, but it's output-only.
        WARBIRD_AD_ASSERT(0 == (pCtx->Dr0 | pCtx->Dr1 | pCtx->Dr2 | pCtx->Dr3));

        // zero any active debug registers to erase breakpoints.
        // the caller is responsible for ensuring the DR values set are
        // actually applied.
        ad_ZeroDRs(pCtx);
    }

    return 0;
}

// exception filter for AD_SETUP
// enable and zero all DRs to remove any existing breakpoints
// then disable all via control register to prevent future breakpoints
__forceinline int ad_ExceptFilter_DR_Setup(__inout EXCEPTION_POINTERS* pep, __inout char* pch)
{
    if ((*pch | 0x572) % 2) // bit 0 on?  then this is the first time through...
    {
        // first pass: enable all DRs and set to zero
        // REVIEW (scotb 2/11/03) rumor has it that on some platforms, the kernel
        // will not preserve the context of the DRs unless they are first set to a
        // non-zero value.

        ad_ZeroDRs(pep->ContextRecord);
        pep->ContextRecord->Dr7 |= 0x155;

#if defined(_AMD64_)
        *pch -= 1;

#elif defined(_X86_)
        __asm
        {
            mov ecx, pch
            mov bl, byte ptr [ecx]
            dec bl
            mov byte ptr [ecx], bl
        }
#endif
        // don't adjust eip.  this means that our changes will be applied, then the same
        // broken mov will be executed again, but with bit 0 of i off.
    }
    else
    {
        // second pass: disable all DRs
        // (nlewis) work around an NT4 BSOD (see uDRM raid #248)
        ad_ZeroDRs(pep->ContextRecord);

        // NOW we adjust past that fat mov instruction.
#if defined(_X86_)
        pep->ContextRecord->Eip += 11;
#elif defined(_AMD64_)
        pep->ContextRecord->Rip += 11;
#endif        
    }

#ifdef _AMD64_
    //On AMD64, to set the DRs we must call NtContinue instead of just returning
    NtContinue(pep->ContextRecord, FALSE);
#endif

    return EXCEPTION_CONTINUE_EXECUTION;
}


#if defined(_X86_)
#define WARBIRD_AD_CAUSE_CRASH1() {__asm mov dword ptr ds:[7978h], 4C71950Bh}
#elif defined(_AMD64_)
extern void Warbird_AD_AV4DebugRegisters(void);
#define WARBIRD_AD_CAUSE_CRASH1() Warbird_AD_AV4DebugRegisters();
#endif

// crash twice, the first time to write to the DRs so that we can accurately read from
// them, the second time to read and record them.  The state of bit 0 of ch controls what the
// exception filter does.
#define WARBIRD_AD_SETUP_DEBUG_REGISTERS() \
    { \
        char ch31; ch31 = 0x31; \
        __try \
        { \
            WARBIRD_AD_CAUSE_CRASH1(); \
        } \
        __except(ad_ExceptFilter_DR_Setup(GetExceptionInformation(), &ch31)) {} \
    }        

// exception expression for ad_DetectDR_SEH_AV_*
__forceinline int ad_ExceptFilter_DR_SEH_AV(__inout EXCEPTION_POINTERS* p, __out DWORD* pdwDetected)
{
    WARBIRD_AD_ASSERT(p->ContextRecord->ContextFlags & CONTEXT_DEBUG_REGISTERS);
    if (ad_CompareDRs(p->ContextRecord))
        *pdwDetected = 0x3719cc90;

#if defined(_X86_)
    p->ContextRecord->Eip += 8; // skip assignment
#elif defined(_AMD64_)
    p->ContextRecord->Rip += 3;

    //On AMD64, to set the DRs we must call NtContinue instead of just returning
    NtContinue(p->ContextRecord, FALSE);
#endif

    return EXCEPTION_CONTINUE_EXECUTION;
}



// turns on bits other than 0x1 in *pdwDetected if debug registers have changed since capture

// *(char*)0x31f8 = 0x5d;
// there's a mystery here; VC disassembles the above instruction to the asm below,
// but the asm below reassembles to a different byte sequence (the raw assembly
// version has the data segment override prefix 0x3e, which makes sense).  VC won't
// assemble "mov byte ptr [31f8h], 5dh", so...fine, eight bytes it is.

#if defined(_X86_)
#define WARBIRD_AD_CAUSE_CRASH2() {__asm mov byte ptr ds:[31f8h], 5dh}
#elif defined(_AMD64_)
#define WARBIRD_AD_CAUSE_CRASH2() {char *p = (char*)0x31f8; *p = 0x5d;}
#endif


// Keywords:    x86 amd64 DebugRegisters
#define WARBIRD_AD_DETECT_DR_SEH_AV_1_SETUP(_xx) \
    DWORD ad_SEH_AV_1_dwDetected_##_xx; \
    ad_SEH_AV_1_dwDetected_##_xx = 1; \
    __try \
    { \
        WARBIRD_AD_CAUSE_CRASH2(); \
    } \
    __except(ad_ExceptFilter_DR_SEH_AV(GetExceptionInformation(), &ad_SEH_AV_1_dwDetected_##_xx)) {}

#define WARBIRD_AD_DETECT_DR_SEH_AV_1_IF(_xx) \
    if (ad_SEH_AV_1_dwDetected_##_xx & 0x713ecc98) // random bits other than bit 0 on?


// turns on bits other than 0x2 on if debug registers have changed since last capture

#if defined(_X86_)
#define WARBIRD_AD_CAUSE_CRASH3() {__asm mov byte ptr ds:[0f319h], 99h}
#elif defined(_AMD64_)
#define WARBIRD_AD_CAUSE_CRASH3() {unsigned char *p = (unsigned char*)0xf319; *p = 0x99;}
#endif

// Keywords:    x86 amd64 DebugRegisters
#define WARBIRD_AD_DETECT_DR_SEH_AV_2_SETUP(_xx) \
    DWORD ad_SEH_AV_2_dwDetected_##_xx;

#define WARBIRD_AD_DETECT_DR_SEH_AV_2_IF(_xx) \
    ad_SEH_AV_2_dwDetected_##_xx = 2; \
    __try \
    { \
        WARBIRD_AD_CAUSE_CRASH3(); \
    } \
    __except(ad_ExceptFilter_DR_SEH_AV(GetExceptionInformation(), &ad_SEH_AV_2_dwDetected_##_xx)) {} \
    if (ad_SEH_AV_2_dwDetected_##_xx & 0x9b170244) // random bits other than bit 1 on?


//
//Divide by zero, catch the crash, and check for DR changes
//

// exception handler for ad_DetectDR_SEH_DIV0_*
__forceinline int ad_ExceptFilter_DR_SEH_DIV0(__inout EXCEPTION_POINTERS* p, __out DWORD* pbDetected)
{
    WARBIRD_AD_ASSERT(p->ContextRecord->ContextFlags & CONTEXT_DEBUG_REGISTERS);
    if (ad_CompareDRs(p->ContextRecord))
        *pbDetected = 0x3719cc90;

    // fix divide by 0
#if defined(_X86_)
    p->ContextRecord->Eax = 200;
    p->ContextRecord->Edx = 173;
#else
    p->ContextRecord->Rax = 200;
    p->ContextRecord->Rdx = 173;

    //On AMD64, to set the DRs we must call NtContinue instead of just returning
    NtContinue(p->ContextRecord, FALSE);
#endif

    return EXCEPTION_CONTINUE_EXECUTION;
}


#if defined(_X86_)
#define WARBIRD_AD_CAUSE_DIV0_1(_xx) __asm {mov edx, ad_SEH_DIV0_1_dwDet_##_xx __asm xor eax, eax __asm div eax}
#elif defined(_AMD64_)
extern void Warbird_AD_DivideByZero1(void);
#define WARBIRD_AD_CAUSE_DIV0_1(_xx) Warbird_AD_DivideByZero1()
#endif

// Decription:  turns on bits other than 0x8 if DRs have changed since last capture
// Keywords:    x86 amd64 DebugRegisters
#define WARBIRD_AD_DETECT_DR_SEH_DIV0_1_SETUP(_xx) \
    DWORD ad_SEH_DIV0_1_dwDet_##_xx; \
    ad_SEH_DIV0_1_dwDet_##_xx = 8; \
    __try \
    { \
        WARBIRD_AD_CAUSE_DIV0_1(_xx); \
    } \
    __except(ad_ExceptFilter_DR_SEH_DIV0(GetExceptionInformation(), &ad_SEH_DIV0_1_dwDet_##_xx)) {}

#define WARBIRD_AD_DETECT_DR_SEH_DIV0_1_IF(_xx) \
    if (ad_SEH_DIV0_1_dwDet_##_xx & 0x0375b067) // random bits other than bit 3 on?



#if defined(_X86_)
#define WARBIRD_AD_CAUSE_DIV0_2() {__asm mov edx, ad_ExceptFilter_DR_SEH_DIV0 __asm xor eax, eax __asm div eax}
#elif defined(_AMD64_)
extern void Warbird_AD_DivideByZero2(void);
#define WARBIRD_AD_CAUSE_DIV0_2() Warbird_AD_DivideByZero2()
#endif

// Description: sets bits other than 0x18 on if DRs have changed since last capture
// Keywords:    x86 amd64 DebugRegisters
#define WARBIRD_AD_DETECT_DR_SEH_DIV0_2_SETUP(_xx) \
    DWORD ad_SEH_DIV0_2_dwDet_##_xx;

#define WARBIRD_AD_DETECT_DR_SEH_DIV0_2_IF(_xx) \
    ad_SEH_DIV0_2_dwDet_##_xx = 0x18; \
    __try \
    { \
        WARBIRD_AD_CAUSE_DIV0_2(); \
    } \
    __except(ad_ExceptFilter_DR_SEH_DIV0(GetExceptionInformation(), &ad_SEH_DIV0_2_dwDet_##_xx)) {} \
    if (ad_SEH_DIV0_2_dwDet_##_xx & 0x8bd036e7) // random bits other than bits 3 and 4 on?


//
// spawn a thread to suspend us and look at our context, to check for DR changes
//
extern DWORD WINAPI WarbirdAD_ThreadCompareDRs(void* p);

// Description: puts 1 in dwDetected if DRs have changed since last capture, some big number otherwise.
// Keywords:    x86 amd64 SEH-Safe DebugRegisters
#define WARBIRD_AD_DETECT_DR_THREAD_1_SETUP(_xx) \
    DWORD ad_Thread_1_dwDetected_##_xx; \
    ad_Thread_1_dwDetected_##_xx = 0x1000; \
    { \
        HANDLE hMainThread; \
        if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), \
                             &hMainThread, 0, FALSE, DUPLICATE_SAME_ACCESS)) \
        { \
            WARBIRD_AD_ASSERT(!"DuplicateHandle failed (WARBIRD_AD_DETECT_THREAD_1_SETUP(_xx))"); \
        } \
        else \
        { \
            ad_Thread_1_dwDetected_##_xx |= 0x57b9fff0; \
            DWORD dwDummy; \
            HANDLE hThread = CreateThread(NULL, 0, WarbirdAD_ThreadCompareDRs, hMainThread, 0, &dwDummy); \
            WARBIRD_AD_ASSERT(hThread); \
            if (hThread) \
            { \
                if (WAIT_OBJECT_0 != WaitForSingleObject(hThread, INFINITE)) \
                    WARBIRD_AD_ASSERT(!"WaitForSingleObject failed (WARBIRD_AD_DETECT_THREAD_1_SETUP(_xx))"); \
                if (!GetExitCodeThread(hThread, &ad_Thread_1_dwDetected_##_xx)) \
                { \
                    ad_Thread_1_dwDetected_##_xx = 0xbaf03002; \
                    WARBIRD_AD_ASSERT(!"GetExitCodeThread failed (WARBIRD_AD_DETECT_THREAD_1_SETUP(_xx))"); \
                } \
                CloseHandle(hThread); \
            } \
        } \
    }

#define WARBIRD_AD_DETECT_DR_THREAD_1_IF(_xx) \
    if (0x4c9fa > (ad_Thread_1_dwDetected_##_xx & 0xe5937cb2))




// Keywords:    x86 amd64 SEH-Safe DebugRegisters
#define WARBIRD_AD_DETECT_DR_THREAD_2_SETUP(_xx) \
    DWORD ad_Thread_2_dwDetected_##_xx;

// 1 if DRs have changed since last capture, some big number otherwise.
#define WARBIRD_AD_DETECT_DR_THREAD_2_IF(_xx) \
    ad_Thread_2_dwDetected_##_xx = 0xbaadf00d; \
    { \
        HANDLE hMainThread; \
        if (DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), \
                             &hMainThread, 0, FALSE, DUPLICATE_SAME_ACCESS)) \
        { \
            DWORD dwDummy; \
            HANDLE hThread = CreateThread(NULL, 0, WarbirdAD_ThreadCompareDRs, hMainThread, 0, &dwDummy); \
            WARBIRD_AD_ASSERT(hThread); \
            if (hThread) \
            { \
                if (WAIT_OBJECT_0 != WaitForSingleObject(hThread, INFINITE)) \
                    WARBIRD_AD_ASSERT(!"WaitForSingleObject failed (WARBIRD_AD_DETECT_THREAD_2_IF(_xx))"); \
                if (!GetExitCodeThread(hThread, &ad_Thread_2_dwDetected_##_xx)) \
                { \
                    ad_Thread_2_dwDetected_##_xx = 0xffffffff; \
                    WARBIRD_AD_ASSERT(!"GetExitCodeThread failed (WARBIRD_AD_DETECT_THREAD_2_IF(_xx))"); \
                } \
                CloseHandle(hThread); \
            } \
        } \
        else \
            WARBIRD_AD_ASSERT(!"DuplicateHandle failed (WARBIRD_AD_DETECT_THREAD_2_IF(_xx))"); \
    } \
    if (0xc153b2 > (ad_Thread_2_dwDetected_##_xx & 0xd9bb259c))


// Description: Check for a breakpoint on the thread function
// Keywords:    all SEH-Safe
#define WARBIRD_AD_DETECT_BP_DR_THREADFUNC_SETUP(_xx)

#define WARBIRD_AD_DETECT_BP_DR_THREADFUNC_IF(_xx) \
    if (*(BYTE*)WarbirdAD_ThreadCompareDRs == 0xcc)

#else
#define WARBIRD_AD_SETUP_DEBUG_REGISTERS()

#define WARBIRD_AD_DETECT_DR_SEH_AV_1_SETUP(_xx)        WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_DR_SEH_AV_1_IF(_xx)           WARBIRD_AD_DUMMY_IF(_xx)

#define WARBIRD_AD_DETECT_DR_SEH_AV_2_SETUP(_xx)        WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_DR_SEH_AV_2_IF(_xx)           WARBIRD_AD_DUMMY_IF(_xx)

#define WARBIRD_AD_DETECT_DR_SEH_DIV0_1_SETUP(_xx)      WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_DR_SEH_DIV0_1_IF(_xx)         WARBIRD_AD_DUMMY_IF(_xx)

#define WARBIRD_AD_DETECT_DR_SEH_DIV0_2_SETUP(_xx)      WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_DR_SEH_DIV0_2_IF(_xx)         WARBIRD_AD_DUMMY_IF(_xx)

#define WARBIRD_AD_DETECT_DR_THREAD_1_SETUP(_xx)        WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_DR_THREAD_1_IF(_xx)           WARBIRD_AD_DUMMY_IF(_xx)

#define WARBIRD_AD_DETECT_DR_THREAD_2_SETUP(_xx)        WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_DR_THREAD_2_IF(_xx)           WARBIRD_AD_DUMMY_IF(_xx)

#define WARBIRD_AD_DETECT_BP_DR_THREADFUNC_SETUP(_xx)   WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_BP_DR_THREADFUNC_IF(_xx)      WARBIRD_AD_DUMMY_IF(_xx)
#endif


//*****************************************************************************
//*****************************************************************************
//
// Check for SoftICE
// Based on mariuszj's code
//
//*****************************************************************************
//*****************************************************************************

//
// detect softice by looking for its drivers by name
//
#define SIC(x) (x ^ (char)(((DWORD_PTR)ad_g_rgbKernel32 >> 8) & 0xFF))
const char ad_rgcSoftIce1[] = {SIC('\\'),SIC('\\'),SIC('.'),SIC('\\'),SIC('N'),SIC('T'),SIC('I'),SIC('C'),SIC('E')};
const char ad_rgcSoftIce2[] = {SIC('\\'),SIC('\\'),SIC('.'),SIC('\\'),SIC('S'),SIC('I'),SIC('C'),SIC('E')};
const char ad_rgcSoftIce3[] = {SIC('\\'),SIC('\\'),SIC('.'),SIC('\\'),SIC('S'),SIC('I'),SIC('W'),SIC('V'),SIC('I'),SIC('D')};

const char * const ad_rgszDrivers[] = {
    ad_rgcSoftIce1,
    ad_rgcSoftIce2,
    ad_rgcSoftIce3
};

const unsigned ad_rgccDrivers[] =
{
    sizeof(ad_rgcSoftIce1),
    sizeof(ad_rgcSoftIce2),
    sizeof(ad_rgcSoftIce3)
};    

__forceinline BYTE ad_Detect_SI_Drivers_1_Setup()
{
    BYTE bDetected = 0;
    for (int i = 0; i < (sizeof(ad_rgszDrivers)/sizeof(ad_rgszDrivers[0])); ++i)
    {
        char szDriver[MAX_PATH];
        UINT j;

        if(ad_rgccDrivers[i] >= sizeof(szDriver))
            continue;

        for(j = 0; j < ad_rgccDrivers[i]; j++)
        {
            szDriver[j] = SIC(ad_rgszDrivers[i][j]);
        }            

        szDriver[j] = 0;
        
        HANDLE hDriver = CreateFileA(szDriver, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
            NULL);
        if (hDriver != INVALID_HANDLE_VALUE)
        {
            CloseHandle(hDriver);
            ++bDetected;
        }
    }
    return bDetected;
}


// Keywords:    all SEH-Safe SoftICE
#define WARBIRD_AD_DETECT_SI_DRIVERS_1_SETUP(_xx) \
    BYTE ad_SI_Drivers_1_bDetected_##_xx; \
    ad_SI_Drivers_1_bDetected_##_xx = ad_Detect_SI_Drivers_1_Setup();

#define WARBIRD_AD_DETECT_SI_DRIVERS_1_IF(_xx) \
    if (ad_SI_Drivers_1_bDetected_##_xx)
    


__forceinline BYTE ad_Detect_SI_Drivers_2_If()
{
    for (int i = (sizeof(ad_rgszDrivers)/sizeof(ad_rgszDrivers[0])) - 1; i >= 0; --i)
    {
        char szDriver[MAX_PATH];
        UINT j;

        if(ad_rgccDrivers[i] >= sizeof(szDriver))
            continue;

        for(j = 0; j < ad_rgccDrivers[i]; j++)
        {
            szDriver[j] = SIC(ad_rgszDrivers[i][j]);
        }            

        szDriver[j] = 0;
        
        HANDLE hDriver = CreateFileA(szDriver, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
            NULL);
        if (hDriver != INVALID_HANDLE_VALUE)
        {
            CloseHandle(hDriver);
            return 17;
        }
    }
    return 0;
}

// Keywords:    all SEH-Safe SoftICE
#define WARBIRD_AD_DETECT_SI_DRIVERS_2_SETUP(_xx)

#define WARBIRD_AD_DETECT_SI_DRIVERS_2_IF(_xx) \
    if (ad_Detect_SI_Drivers_2_If())


//
// detect softice by looking for a boundschecker backdoor
//
#ifdef _X86_
//Need to disable the "frame pointer register 'ebp' modified by inline assembly code' warning/error
#pragma warning(disable: 4731)

// Keywords:    x86 SoftICE
#define WARBIRD_AD_DETECT_SI_BCHK_1_SETUP(_xx) \
    BYTE ad_SI_Bchk_1_bDetected_##_xx; \
    ad_SI_Bchk_1_bDetected_##_xx = 1; \
    __try \
    { \
        __asm push ebp \
        __asm mov ebp, 'BCHK' \
        __asm mov eax, 4 \
        __asm int 3 \
        __asm pop ebp \
        __asm { mov [ad_SI_Bchk_1_bDetected_##_xx], al } \
    } \
    __except(GetExceptionCode() == STATUS_BREAKPOINT ? \
                 EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {}

#define WARBIRD_AD_DETECT_SI_BCHK_1_IF(_xx) \
    if (ad_SI_Bchk_1_bDetected_##_xx < 1)



// Keywords:    x86 SoftICE
#define WARBIRD_AD_DETECT_SI_BCHK_2_SETUP(_xx) \
    WORD ad_SI_Bchk_2_wDetected_##_xx;

#define WARBIRD_AD_DETECT_SI_BCHK_2_IF(_xx) \
    ad_SI_Bchk_2_wDetected_##_xx = 4; \
    __try \
    { \
        __asm push ebp \
        __asm mov ebp, 'BCHK' \
        __asm mov eax, 4 \
        __asm int 3 \
        __asm pop ebp \
        __asm movsx eax, al \
        __asm { mov ad_SI_Bchk_2_wDetected_##_xx, ax } \
    } \
    __except(GetExceptionCode() != STATUS_BREAKPOINT ? \
                 EXCEPTION_CONTINUE_SEARCH : EXCEPTION_EXECUTE_HANDLER) {} \
    if (ad_SI_Bchk_2_wDetected_##_xx < 3)


// Description: Detect softice by looking for int 0x41 services, based on mariuszj's code
// Keywords:    x86 SoftICE
#define WARBIRD_AD_DETECT_SI_INT41_1_SETUP(_xx) \
    WORD ad_SI_Int41_1_wDetected_##_xx; \
    ad_SI_Int41_1_wDetected_##_xx = 0x1000; \
    __try \
    { \
        ad_SI_Int41_1_wDetected_##_xx = 0; \
        __asm mov ax, 0x4f \
        __asm int 0x41 \
        __asm { mov ad_SI_Int41_1_wDetected_##_xx, ax } \
    } \
    __except(EXCEPTION_EXECUTE_HANDLER) {}

#define WARBIRD_AD_DETECT_SI_INT41_1_IF(_xx) \
    if (ad_SI_Int41_1_wDetected_##_xx > 0x1000)
   


// Keywords:    x86 SoftICE
#define WARBIRD_AD_DETECT_SI_INT41_2_SETUP(_xx) \
    WORD ad_SI_Int41_2_wDetected_##_xx;

#define WARBIRD_AD_DETECT_SI_INT41_2_IF(_xx) \
    ad_SI_Int41_2_wDetected_##_xx = 0; \
    __try \
    { \
        ad_SI_Int41_2_wDetected_##_xx = 16; \
        __asm mov ax, 0x4f \
        __asm int 0x41 \
        __asm { mov ad_SI_Int41_2_wDetected_##_xx, ax } \
    } \
    __except(EXCEPTION_EXECUTE_HANDLER) {} \
    if (ad_SI_Int41_2_wDetected_##_xx != 16)

 
// Description: Detect softice by looking for an SI/DI backdoor
// Keywords:    x86 SoftICE
#define WARBIRD_AD_DETECT_SI_FGJM_1_SETUP(_xx) \
    DWORD ad_SI_FGJM_1_dwDetected_##_xx; \
    ad_SI_FGJM_1_dwDetected_##_xx = 8192; \
    __try \
    { \
        __asm mov si, 'FG' \
        __asm mov di, 'JM' \
        __asm { int 3 } \
        ad_SI_FGJM_1_dwDetected_##_xx -= 4095; \
    } \
    __except(EXCEPTION_EXECUTE_HANDLER) {}

#define WARBIRD_AD_DETECT_SI_FGJM_1_IF(_xx) \
    if (ad_SI_FGJM_1_dwDetected_##_xx % 2)



// Keywords:    x86 SoftICE
#define WARBIRD_AD_DETECT_SI_FGJM_2_SETUP(_xx) \
    DWORD ad_SI_FGJM_2_dwDetected_##_xx;

#define WARBIRD_AD_DETECT_SI_FGJM_2_IF(_xx) \
    ad_SI_FGJM_2_dwDetected_##_xx = 7; \
    __try \
    { \
        __asm mov di, 'JM' \
        __asm mov si, 'FG' \
        __asm { int 3 } \
        ++ad_SI_FGJM_2_dwDetected_##_xx; \
    } \
    __except(EXCEPTION_EXECUTE_HANDLER) {} \
    if (!(ad_SI_FGJM_2_dwDetected_##_xx & 2))


// Description: Detect softice by checking privilege level on int 1 gate
// Keywords:    x86 SoftICE
#define WARBIRD_AD_DETECT_SI_GATEDPL_1_SETUP(_xx) \
    WORD ad_SI_GateDPL_1_wDetected_##_xx; \
    __try \
    { \
        __asm { int 1 } \
    } \
    __except(EXCEPTION_EXECUTE_HANDLER) \
    { \
        ad_SI_GateDPL_1_wDetected_##_xx = (GetExceptionCode() != STATUS_ACCESS_VIOLATION); \
    }

#define WARBIRD_AD_DETECT_SI_GATEDPL_1_IF(_xx) \
    if (ad_SI_GateDPL_1_wDetected_##_xx)


// Keywords:    x86 SoftICE
#define WARBIRD_AD_DETECT_SI_GATEDPL_2_SETUP(_xx) \
    bool ad_SI_GateDPL_2_fDetected_##_xx;

#define WARBIRD_AD_DETECT_SI_GATEDPL_2_IF(_xx) \
    __try \
    { \
        __asm { int 1 } \
    } \
    __except(EXCEPTION_EXECUTE_HANDLER) \
    { \
        ad_SI_GateDPL_2_fDetected_##_xx = (GetExceptionCode() == STATUS_ACCESS_VIOLATION); \
    } \
    if (!ad_SI_GateDPL_2_fDetected_##_xx)


#else
#define WARBIRD_AD_DETECT_SI_BCHK_1_SETUP(_xx)      WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_SI_BCHK_1_IF(_xx)         WARBIRD_AD_DUMMY_IF(_xx)

#define WARBIRD_AD_DETECT_SI_BCHK_2_SETUP(_xx)      WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_SI_BCHK_2_IF(_xx)         WARBIRD_AD_DUMMY_IF(_xx)

#define WARBIRD_AD_DETECT_SI_INT41_1_SETUP(_xx)     WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_SI_INT41_1_IF(_xx)        WARBIRD_AD_DUMMY_IF(_xx)

#define WARBIRD_AD_DETECT_SI_INT41_2_SETUP(_xx)     WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_SI_INT41_2_IF(_xx)        WARBIRD_AD_DUMMY_IF(_xx)

#define WARBIRD_AD_DETECT_SI_FGJM_1_SETUP(_xx)      WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_SI_FGJM_1_IF(_xx)         WARBIRD_AD_DUMMY_IF(_xx)

#define WARBIRD_AD_DETECT_SI_FGJM_2_SETUP(_xx)      WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_SI_FGJM_2_IF(_xx)         WARBIRD_AD_DUMMY_IF(_xx)

#define WARBIRD_AD_DETECT_SI_GATEDPL_1_SETUP(_xx)   WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_SI_GATEDPL_1_IF(_xx)      WARBIRD_AD_DUMMY_IF(_xx)

#define WARBIRD_AD_DETECT_SI_GATEDPL_2_SETUP(_xx)   WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_SI_GATEDPL_2_IF(_xx)      WARBIRD_AD_DUMMY_IF(_xx)
#endif


//*****************************************************************************
//*****************************************************************************
//
// Ping some interesting APIs for breakpoints
//
//*****************************************************************************
//*****************************************************************************

#if defined(_X86_) || defined(_AMD64_)

__forceinline BYTE ad_Detect_Kernel32_Breakpoint(__in_bcount(cbAPI) const BYTE* pbAPI, __in unsigned cbAPI)
{
    BYTE bRet = 0;
    CHAR abUnmasked[WARBIRD_AD_MAX_UNMASKED_LEN]; \

    WARBIRD_AD_MASKSZ(ad_g_rgbKernel32, abUnmasked);
    HMODULE hKernel32 = GetModuleHandleA((const char*)abUnmasked);
    if(hKernel32)
    {
        WARBIRD_AD_ASSERT(WARBIRD_AD_MAX_UNMASKED_LEN >= (cbAPI + 1));
        WarbirdAD_MaskSZ(pbAPI, cbAPI, abUnmasked);
        BYTE* pproc = (BYTE*)GetProcAddress(hKernel32, (const char*)abUnmasked);
        if(pproc)
            bRet = *pproc;
    }
    
    WARBIRD_AD_MASKSZ((BYTE*)abUnmasked, abUnmasked);
    return bRet;
}
    
// Keywords:    x86 amd64 SEH-Safe
#define WARBIRD_AD_DETECT_BP_CREATEFILEA_SETUP(_xx)
#define WARBIRD_AD_DETECT_BP_CREATEFILEA_IF(_xx) \
    if (ad_Detect_Kernel32_Breakpoint(ad_g_rgbCreateFileA, sizeof(ad_g_rgbCreateFileA)) == 0xcc)
    
// Keywords:    x86 amd64 SEH-Safe
#define WARBIRD_AD_DETECT_BP_DEVICEIOCONTROL_SETUP(_xx)
#define WARBIRD_AD_DETECT_BP_DEVICEIOCONTROL_IF(_xx) \
    if (ad_Detect_Kernel32_Breakpoint(ad_g_rgbDeviceIoControl, sizeof(ad_g_rgbDeviceIoControl)) == 0xcc)
    
// Keywords:    x86 amd64 SEH-Safe
#define WARBIRD_AD_DETECT_BP_EXITPROCESS_SETUP(_xx)
#define WARBIRD_AD_DETECT_BP_EXITPROCESS_IF(_xx) \
    if (ad_Detect_Kernel32_Breakpoint(ad_g_rgbExitProcess, sizeof(ad_g_rgbExitProcess)) == 0xcc)
    
// Keywords:    x86 amd64 SEH-Safe
#define WARBIRD_AD_DETECT_BP_LOADLIBRARYA_SETUP(_xx)
#define WARBIRD_AD_DETECT_BP_LOADLIBRARYA_IF(_xx) \
    if (ad_Detect_Kernel32_Breakpoint(ad_g_rgbLoadLibraryA, sizeof(ad_g_rgbLoadLibraryA)) == 0xcc)
    
// Keywords:    x86 amd64 SEH-Safe
#define WARBIRD_AD_DETECT_BP_MAPVIEWOFFILE_SETUP(_xx)
#define WARBIRD_AD_DETECT_BP_MAPVIEWOFFILE_IF(_xx) \
    if (ad_Detect_Kernel32_Breakpoint(ad_g_rgbMapViewOfFile, sizeof(ad_g_rgbMapViewOfFile)) == 0xcc)
    
// Keywords:    x86 amd64 SEH-Safe
#define WARBIRD_AD_DETECT_BP_READFILE_SETUP(_xx)
#define WARBIRD_AD_DETECT_BP_READFILE_IF(_xx) \
    if (ad_Detect_Kernel32_Breakpoint(ad_g_rgbReadFile, sizeof(ad_g_rgbReadFile)) == 0xcc)
    
// Keywords:    x86 amd64 SEH-Safe
#define WARBIRD_AD_DETECT_BP_VIRTUALPROTECT_SETUP(_xx)
#define WARBIRD_AD_DETECT_BP_VIRTUALPROTECT_IF(_xx) \
    if (ad_Detect_Kernel32_Breakpoint(ad_g_rgbVirtualProtect, sizeof(ad_g_rgbVirtualProtect)) == 0xcc)

    

//*****************************************************************************
//*****************************************************************************
//
// Sweep the IAT for breakpoints
// Based on mariuszj's code
//
//*****************************************************************************
//*****************************************************************************
__forceinline void ad_Import_BPs_Detect(__inout DWORD *pdwDetected)
{
    const IMAGE_DOS_HEADER* pDOSHeader = &__ImageBase;
    const BYTE* pBase = (BYTE*)pDOSHeader;
    const UNALIGNED IMAGE_NT_HEADERS* pNTHeader = (IMAGE_NT_HEADERS*)(pBase + pDOSHeader->e_lfanew);

    //Check for overflow and that the NT signature is present    
    if( (DWORD_PTR)pNTHeader < (DWORD_PTR)pDOSHeader ||
        (DWORD_PTR)pNTHeader + sizeof(*pNTHeader) <= (DWORD_PTR)pNTHeader ||
        IMAGE_NT_SIGNATURE != pNTHeader->Signature)
        return;

#pragma prefast(suppress: 26000, "We know we are reading past the end of IMAGE_DOS_HEADER, but not IMAGE_NT_HEADERS")
    IMAGE_DATA_DIRECTORY iddIT = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    UNALIGNED IMAGE_IMPORT_DESCRIPTOR* pImports = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + iddIT.VirtualAddress);
    
    for (int i = 0; pImports[i].Characteristics; ++i)
    {
        DWORD_PTR* pHintNameTable = (DWORD_PTR*)(pBase + pImports[i].OriginalFirstThunk);
        BYTE** pIAT = (BYTE**)(pBase+pImports[i].FirstThunk);
        for (int j = 0; pHintNameTable[j]; ++j)
        {
            if (pIAT[j] && *pIAT[j] == 0xcc)
                *pdwDetected |= (0xff & *pIAT[j]);
        }
    }
}

// Keywords:    x86 amd64 SEH-Safe
#define WARBIRD_AD_DETECT_IMPORT_BPS_SETUP(_xx) \
    DWORD ad_Import_BPs_dwDetected_##_xx;

#define WARBIRD_AD_DETECT_IMPORT_BPS_IF(_xx) \
    ad_Import_BPs_dwDetected_##_xx = 1; \
    ad_Import_BPs_Detect(&ad_Import_BPs_dwDetected_##_xx); \
    if (ad_Import_BPs_dwDetected_##_xx > 0x40)

#else // #if defined(_X86_) || defined(_AMD64_)

//IA64 uses a different instruction coding for breakpoints
#define WARBIRD_AD_DETECT_BP_CREATEFILEA_SETUP(_xx)     WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_BP_CREATEFILEA_IF(_xx)        WARBIRD_AD_DUMMY_IF(_xx)
    
#define WARBIRD_AD_DETECT_BP_DEVICEIOCONTROL_SETUP(_xx) WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_BP_DEVICEIOCONTROL_IF(_xx)    WARBIRD_AD_DUMMY_IF(_xx)
    
#define WARBIRD_AD_DETECT_BP_EXITPROCESS_SETUP(_xx)     WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_BP_EXITPROCESS_IF(_xx)        WARBIRD_AD_DUMMY_IF(_xx)
    
#define WARBIRD_AD_DETECT_BP_LOADLIBRARYA_SETUP(_xx)    WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_BP_LOADLIBRARYA_IF(_xx)       WARBIRD_AD_DUMMY_IF(_xx)
    
#define WARBIRD_AD_DETECT_BP_MAPVIEWOFFILE_SETUP(_xx)   WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_BP_MAPVIEWOFFILE_IF(_xx)      WARBIRD_AD_DUMMY_IF(_xx)
    
#define WARBIRD_AD_DETECT_BP_READFILE_SETUP(_xx)        WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_BP_READFILE_IF(_xx)           WARBIRD_AD_DUMMY_IF(_xx)
    
#define WARBIRD_AD_DETECT_BP_VIRTUALPROTECT_SETUP(_xx)  WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_BP_VIRTUALPROTECT_IF(_xx)     WARBIRD_AD_DUMMY_IF(_xx)

#define WARBIRD_AD_DETECT_IMPORT_BPS_SETUP(_xx)         WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_DETECT_IMPORT_BPS_IF(_xx)            WARBIRD_AD_DUMMY_IF(_xx)

#endif // #if defined(_X86_) || defined(_AMD64_)



//*****************************************************************************
//*****************************************************************************
//
// Red Herrings: Do some things the other checks do, but don't act upon them
//
//*****************************************************************************
//*****************************************************************************

// red herring IsDebuggerPresent
__forceinline void ad_RedHerring_IDP_Setup(__out void** ppIsDebuggerPresent)
{
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    *ppIsDebuggerPresent = 0;
    if (hKernel32)
    {
        *ppIsDebuggerPresent = GetProcAddress(hKernel32, "IsDebuggerPresent");
        FreeLibrary(hKernel32);
    }
}
    
// Keywords:    all SEH-Safe
#define WARBIRD_AD_RH_IDP_SETUP(_xx) \
    void* ad_RH_IDP_pIsDebuggerPresent_##_xx; \
    ad_RedHerring_IDP_Setup(&ad_RH_IDP_pIsDebuggerPresent_##_xx);

#define WARBIRD_AD_RH_IDP_IF(_xx) \
    if (::GetTickCount() == 0)



// red herring breakpoint


// Keywords:    x86 amd64
#define WARBIRD_AD_RH_INT3_SETUP(_xx) \
    DWORD ad_RH_int3_dwDetected_##_xx; \
    ad_RH_int3_dwDetected_##_xx = 53; \
    __try \
    { \
        __try \
        { \
            FIREBREAKPOINT(); \
        } \
        __except(GetExceptionCode() == STATUS_BREAKPOINT ? \
                 EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) \
        { \
            ad_RH_int3_dwDetected_##_xx = 0; \
        } \
    } \
    __except(EXCEPTION_EXECUTE_HANDLER) {}

#define WARBIRD_AD_RH_INT3_IF(_xx) \
    if (::GetTickCount() == 0)


// red herring ud2
#ifdef _X86_
// Keywords:    x86
#define WARBIRD_AD_RH_UD2_SETUP(_xx) \
    DWORD ad_RH_ud2_dwDetected_##_xx; \
    ad_RH_ud2_dwDetected_##_xx = 53; \
    __try \
    { \
        __try \
        { \
            __asm ud2 \
        } \
        __except(GetExceptionCode() == STATUS_BREAKPOINT ? \
                 EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) \
        { \
            ad_RH_ud2_dwDetected_##_xx = 0; \
        } \
    } \
    __except(EXCEPTION_EXECUTE_HANDLER) {}

#define WARBIRD_AD_RH_UD2_IF(_xx) \
    if (::GetTickCount() == 0)

#else
#define WARBIRD_AD_RH_UD2_SETUP(_xx)   WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_RH_UD2_IF(_xx)      WARBIRD_AD_DUMMY_IF(_xx)
#endif


// red herring ZwQSI
__forceinline void ad_RedHerring_ZwQSI_Setup(__out ZwQSIPtr* ppQSI)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    *ppQSI = 0;
    if (hNtdll)
        *ppQSI = (ZwQSIPtr)GetProcAddress(hNtdll, "ZwQuerySystemInformation");
}

__forceinline bool ad_RedHerring_ZwQSI_If(__in ZwQSIPtr* ppQSI)
{
    bool fClean = true;
    if (*ppQSI)
    {
        SYSTEM_KERNEL_DEBUGGER_INFORMATION skdi = { TRUE, FALSE };
        DWORD rc = (*ppQSI)(SystemKernelDebuggerInformation, &skdi, sizeof(skdi), NULL);
        if (!rc && skdi.KernelDebuggerEnabled)
            fClean = false;
    }
    return fClean;
}

// Keywords:    all SEH-Safe
#define WARBIRD_AD_RH_ZWQSI_SETUP(_xx) \
    ZwQSIPtr ad_RH_ZwQSI_pQSI_##_xx; \
    ad_RedHerring_ZwQSI_Setup(&ad_RH_ZwQSI_pQSI_##_xx);

#define WARBIRD_AD_RH_ZWQSI_IF(_xx) \
    if (ad_RedHerring_ZwQSI_If(&ad_RH_ZwQSI_pQSI_##_xx) && \
        ::GetTickCount() == 0)


#if defined(_X86_) || defined(_AMD64_)

// red herring AV
#if defined(_X86_)
#define WARBIRD_AD_RH_AV_1()    __asm { mov byte ptr ds:[5521h], 5dh }
#else
#define WARBIRD_AD_RH_AV_1()    { int *p = (int*)0x5521; *p = 0x5d;}
#endif

// Keywords:    x86 amd64
#define WARBIRD_AD_RH_AV_SETUP(_xx) \
    DWORD ad_RH_AV_dwDetected_##_xx; \
    ad_RH_AV_dwDetected_##_xx = 1; \
    __try \
    { \
        WARBIRD_AD_RH_AV_1(); \
    } \
    __except(ad_ExceptFilter_DR_SEH_AV(GetExceptionInformation(), &ad_RH_AV_dwDetected_##_xx)) {}

#define WARBIRD_AD_RH_AV_IF(_xx) \
    if ((ad_RH_AV_dwDetected_##_xx & 0x713ecc98) && \
        (::GetTickCount() == 0))


// Description: Red herring DIV0
// Keywords:    x86 amd64
#define WARBIRD_AD_RH_DIV0_SETUP(_xx) \
    DWORD ad_SEH_DIV0_1_dwDet_##_xx; \
    ad_SEH_DIV0_1_dwDet_##_xx = 8; \
    __try \
    { \
        WARBIRD_AD_CAUSE_DIV0_1(_xx); \
    } \
    __except(ad_ExceptFilter_DR_SEH_DIV0(GetExceptionInformation(), &ad_SEH_DIV0_1_dwDet_##_xx)) {}

#define WARBIRD_AD_RH_DIV0_IF(_xx) \
    if ((ad_SEH_DIV0_1_dwDet_##_xx & 0x0375b067) && \
        (::GetTickCount() == 0))

#else
#define WARBIRD_AD_RH_AV_SETUP(_xx)     WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_RH_AV_IF(_xx)        WARBIRD_AD_DUMMY_IF(_xx)

#define WARBIRD_AD_RH_DIV0_SETUP(_xx)   WARBIRD_AD_DUMMY_SETUP(_xx)
#define WARBIRD_AD_RH_DIV0_IF(_xx)      WARBIRD_AD_DUMMY_IF(_xx)
#endif

#endif //!WARBIRDAD_INL

#endif // !defined(WARBIRD_KERNEL_MODE)