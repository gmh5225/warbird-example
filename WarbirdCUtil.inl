#ifdef __cplusplus  
namespace WarbirdRuntime {
#endif // _cpluplus

//
// Size of the common fields of the runtime argument structures.
//
#define RVA_BIT_COUNT               28
#define FUNCTION_SIZE_BIT_COUNT     28
#define KEY_BIT_COUNT               64
#define CHECKSUM_BIT_COUNT           8
#define HASH_BIT_COUNT              64
#define CONDITION_CODE_BIT_COUNT     4
#define STACK_SIZE_BIT_COUNT        28

#define NUMBER_FEISTEL64_ROUNDS     10

//
// Warbird operation types. Indicates for which operation the argument structure
// is for.
//
typedef enum {
    WbOperationNone,
    WbOperationDecryptEncryptionSegment,
    WbOperationReEncryptEncryptionSegment,
    WbOperationHeapExecuteCall,
    WbOperationHeapExecuteReturn,
    WbOperationHeapExecuteUnconditionalBranch,
    WbOperationHeapExecuteConditionalBranch,
    WbOperationProcessEnd,
    WbOperationProcessStartup,
} WbOperationType;

typedef struct _FEISTEL64_ROUND_DATA
{
    unsigned long FunctionID;
    unsigned long Rand0;
    unsigned long Rand1;
    unsigned long Rand2;
} FEISTEL64_ROUND_DATA, PFEISTEL64_ROUND_DATA;

typedef struct _ENCRYPTION_BLOCK {
    unsigned long bUnitialized:1;
    unsigned long bData:1;
    unsigned long ulChecksum:CHECKSUM_BIT_COUNT;
    unsigned long ulRva:RVA_BIT_COUNT;
    unsigned long ulSize:FUNCTION_SIZE_BIT_COUNT;
} ENCRYPTION_BLOCK, *PENCRYPTION_BLOCK;

typedef struct _ENCRYPTION_SEGMENT {
    unsigned long ulVersion;
    unsigned long ulSegmentID;
    unsigned __int64 ullKey;
    FEISTEL64_ROUND_DATA bRoundData[NUMBER_FEISTEL64_ROUNDS];
    unsigned long cBlocks;
    ENCRYPTION_BLOCK Blocks[1];
} ENCRYPTION_SEGMENT, *PENCRYPTION_SEGMENT;

//
// System call heap execution runtime structures and runtime
//
typedef struct _HEAP_EXECUTE_CALL_ARGUMENT {
    unsigned long ulVersion;
    unsigned long ulCheckStackSize;
    unsigned long ulChecksum:CHECKSUM_BIT_COUNT;
    unsigned long ulWrapperChecksum:CHECKSUM_BIT_COUNT;
    unsigned long ulRva:RVA_BIT_COUNT;
    unsigned long ulSize:FUNCTION_SIZE_BIT_COUNT;
    unsigned long ulWrapperRva:RVA_BIT_COUNT;
    unsigned long ulWrapperSize:FUNCTION_SIZE_BIT_COUNT;
    unsigned __int64 ullKey;
    FEISTEL64_ROUND_DATA RoundData[NUMBER_FEISTEL64_ROUNDS];
} HEAP_EXECUTE_CALL_ARGUMENT, *PHEAP_EXECUTE_CALL_ARGUMENT;

//
// Warbird kernel configuration. The user mode process passes this configuration
// to the kernel when it is first started.
//
typedef struct _PROCESS_STARTUP_ARGUMENT {
    unsigned long ulVersion;
    unsigned long cMaxHeapExecutedCacheEntries;
    void* pPreAllocatedReadExecuteMemory;
    unsigned long cbPreAllocatedReadExecuteMemory;
} PROCESS_STARTUP_ARGUMENT, *PPROCESS_STARTUP_ARGUMENT;

typedef struct _PROCESS_STARTUP_ARGUMENT_LIST {
    unsigned __int64 eType;
    PPROCESS_STARTUP_ARGUMENT pArguments;
} PROCESS_STARTUP_ARGUMENT_LIST, *PPROCESS_STARTUP_ARGUMENT_LIST;

#ifdef __cplusplus  
}; // namespace WarbirdRuntime
#endif // _cpluplus
#if defined(WARBIRD_KERNEL_MODE)
#include <ntos.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <minwindef.h>
#include <winerror.h>
#include <bcrypt.h>
extern "C" void* _AddressOfReturnAddress();
#else // defined(WARBIRD_KERNEL_MODE)
#include <windows.h>
#include <strsafe.h>
#include <malloc.h>
#include <intrin.h>
#endif // defined(WARBIRD_KERNEL_MODE)
#include <limits.h>
#ifdef _M_E2
#include <ntarch.h>
#undef PAGE_SIZE 
#define PAGE_SIZE NTARCH_PAGE_SIZE
#elif defined(_X86_) || defined(_AMD64_) || defined(_ARM_) || defined(_ARM64_)
#undef PAGE_SIZE 
#define PAGE_SIZE 0x1000
#endif // _M_E2

//
// Warbird runtime's use intrinsics to reduce hookable attack points
//
#pragma intrinsic(memcpy, memcmp, memset)

#define STRINGIZE(x) #x

#if !defined(ALG_TYPE_ANY)
#define ALG_TYPE_ANY                    (0)
#endif
#if !defined(ALG_CLASS_ANY)
#define ALG_CLASS_ANY                   (0)
#endif
#if !defined(ALG_CLASS_HASH)
#define ALG_CLASS_HASH                  (4 << 13)
#endif
#if !defined(ALG_SID_SHA_256)
#define ALG_SID_SHA_256                 12
#endif
#if !defined(ALG_SID_SHA_512)
#define ALG_SID_SHA_512                 14
#endif
#if !defined(CALG_SHA_512)
#define CALG_SHA_512            (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_512)
#endif


#if defined(_WIN64)
#define _InterlockedCompareExchangeSizeT    _InterlockedCompareExchange64
#define _InterlockedDecrementSizeT          _InterlockedDecrement64
#define _InterlockedExchangeSizeT           _InterlockedExchange64
#else
#define _InterlockedCompareExchangeSizeT    _InterlockedCompareExchange
#define _InterlockedDecrementSizeT          _InterlockedDecrement
#define _InterlockedExchangeSizeT           _InterlockedExchange
#endif

#if defined(WARBIRD_DEBUG)
#define DebugPrint                          CUtil::DebugPrintFunc
#define WARBIRD_ASSERT                      CUtil::AssertFunc
#else
#define DebugPrint                          __noop
#define WARBIRD_ASSERT                      __noop
#endif

#ifndef HRESULT_FROM_NTSTATUS
#define HRESULT_FROM_NTSTATUS(x)      ((HRESULT) ((x) | FACILITY_NT_BIT))  
#endif // HRESULT_FROM_NTSTATUS

#ifndef WARBIRD_KERNEL_MODE

#define SystemCodeFlowTransition 185

EXTERN_C ULONG WINAPI
NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

#endif // !WARBIRD_KERNEL_MODE

#if defined(WARBIRD_KERNEL_MODE)
/*++

Description:

    Define ZwFlushInstructionCache (from zwapi.h)

--*/
EXTERN_C
NTSYSAPI
NTSTATUS
NTAPI
ZwFlushInstructionCache (
    __in HANDLE ProcessHandle,
    __in_opt PVOID BaseAddress,
    __in SIZE_T Length
    );

#ifndef ALG_ID
typedef unsigned int ALG_ID;
#endif

#endif


// Random seed used to create this file is : $(RandomSeed)

int __cdecl TestWarbirdRuntime(int x)
{
    return x * x;
}

namespace WarbirdRuntime
{

EXTERN_C IMAGE_DOS_HEADER __ImageBase;
volatile UINT64 g_preferedImageBase = 0x123456789ABCDEF;

extern volatile UINT64 g_preferedImageBase;

class CUtil
{
public:
#ifdef WARBIRD_DEBUG
    static VOID
    AssertFunc(BOOL x)
    {
        if (!x)
        {
            __debugbreak();
        }
    }

    static VOID
    DebugPrintFunc(
        __in    PCSTR       pszFormatString,
        ...
        )
    {
        char szMessage[1024];
        va_list arguments;
        va_start(arguments, pszFormatString);

        vsprintf_s(szMessage, ARRAYSIZE(szMessage), pszFormatString, arguments);

#if defined(WARBIRD_KERNEL_MODE)
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, (PSTR)szMessage); 
#else
        vprintf(pszFormatString, arguments);

        OutputDebugStringA(szMessage);

#endif // WARBIRD_KERNEL_MODE

        va_end(arguments);
    }
#endif // WARBIRD_DEBUG

    template <class T> 
    static T* 
    AddOffset(
        __in    T*          pSource,
                INT_PTR     nOffset
        )
    {
        return reinterpret_cast<T*>(reinterpret_cast<BYTE*>(pSource) + nOffset);
    }

    template <class T> 
    static CONST T* 
    AddOffset(
        __in    CONST T*    pSource,
                INT_PTR     nOffset
        )
    {
        return reinterpret_cast<CONST T*>(reinterpret_cast<CONST BYTE*>(pSource) + nOffset);
    }

    template <class T> 
    static T* 
    SubOffset(
        __in    T*          pSource, 
                INT_PTR     nOffset
        )
    {
        return reinterpret_cast<T*>(reinterpret_cast<BYTE*>(pSource) - nOffset);
    }

    template <class T> 
    static CONST T* 
    SubOffset(
        __in    CONST T*    pSource, 
                INT_PTR     nOffset
        )
    {
        return reinterpret_cast<CONST T*>(reinterpret_cast<CONST BYTE*>(pSource) - nOffset);
    }

    static INT_PTR 
    GetOffset(
        __in    CONST VOID*     pTarget,
        __in    CONST VOID*     pSource
        )
    {
        return reinterpret_cast<CONST BYTE*>(pTarget) - reinterpret_cast<CONST BYTE*>(pSource);
    }

    template <class T>
    static T 
    RoundDown(
        T       x, 
        SIZE_T  y
        )
    {
        WARBIRD_ASSERT((y & (y - 1)) == 0);
        return reinterpret_cast<T>(reinterpret_cast<SIZE_T>(x) & ~(y-1));
    }

    template <class T>
    static T 
    RoundUp(
        T       x, 
        SIZE_T  y
        )
    {
        return RoundDown(reinterpret_cast<T>(reinterpret_cast<SIZE_T>(x) + (y - 1)), y);
    }

    static UINT_PTR
    GetImageBase(
        VOID
        )
    {
        WARBIRD_ASSERT(__ImageBase.e_magic == IMAGE_DOS_SIGNATURE);
        return (UINT_PTR)&__ImageBase;
    }

    static UINT_PTR
    GetPreferedImageBase(
        VOID
        )
    {
        return (UINT_PTR)g_preferedImageBase;
    }

    static IMAGE_NT_HEADERS*
    GetImageNtHeaders(
        __in    UINT_PTR    pImageBase
        )
    {
        IMAGE_DOS_HEADER* pImageDosHeader = 
            reinterpret_cast<IMAGE_DOS_HEADER*>((void*)pImageBase);

        WARBIRD_ASSERT(pImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE);
        WARBIRD_ASSERT(pImageDosHeader->e_lfanew >= sizeof(IMAGE_DOS_HEADER));

        IMAGE_NT_HEADERS* pImageNtHeaders = 
            reinterpret_cast<IMAGE_NT_HEADERS*>(AddOffset((void*)pImageBase, pImageDosHeader->e_lfanew));

        WARBIRD_ASSERT(pImageNtHeaders->Signature == IMAGE_NT_SIGNATURE);

        return pImageNtHeaders;
    }

    DECLSPEC_NOINLINE static VOID* 
    GetCurrentSp(
        )
    {
        return AddOffset(_AddressOfReturnAddress(), sizeof(VOID*));
    }

    static VOID
    FillRandom(
        __out_bcount(nSize) PVOID   pMemory, 
                            SIZE_T  nSize
        )
    {
        // Fill the target buffer with random stuff on the last page of the stack
        // (which will with high probability be in memory, so we won't take a page-in hit).

        PVOID pSrc = RoundDown(GetCurrentSp(), PAGE_SIZE);

        PVOID pDst = pMemory;
        PVOID pEnd = AddOffset(pMemory, nSize);

        while (pDst < pEnd)
        {
            CUtil::Memcpy(
                pDst,
                pSrc,
                min(PAGE_SIZE, GetOffset(pEnd, pDst))
                );

            pDst = AddOffset(pDst, PAGE_SIZE);
        }
    }

    static VOID 
    FlushCpuCache(
        __in_bcount_opt(nSize)  CONST VOID*     pBaseAddress,
                                SIZE_T          nSize
        )
    {
#if defined(_X86_) || defined(_AMD64_)

        // X86 and AMD64 have transparent caches, so we don't need to call 
        // FlushInstructionCache (which is a noop anyway).

        UNREFERENCED_PARAMETER(pBaseAddress);
        UNREFERENCED_PARAMETER(nSize);

#elif defined(WARBIRD_KERNEL_MODE)

        ZwFlushInstructionCache(
            NtCurrentProcess(),
            const_cast<VOID*>(pBaseAddress),
            nSize
            );

#else
        DWORD LastError = GetLastError();

        FlushInstructionCache(
            GetCurrentProcess(),
            pBaseAddress,
            nSize
            );

        SetLastError(LastError);

#endif
    }

    static ULONG64
    ReadCpuTimeStamp(
        )
    {
#if defined(_M_ARM)
        return __rdpmccntr64();
#elif defined(_M_ARM64)
        // Timer statistics obtained via intrinsics that access the coprocessor
        // The ARM64_SYSREG macro creates an argument for ReadStatusReg. The
        // exact definition is in winnt.h
        return _ReadStatusReg(ARM64_SYSREG(3,3, 9,13,0)); 
#else
        return ReadTimeStampCounter();
#endif
    }

    //
    // Basic implementation of memcpy. A call to memcpy is a hookable attack
    // point. If the hacker sets a breakpoint on memcpy they can detect when
    // the function/data is decrypted into the clear. The pragma intrinsic is
    // only a hint to the compiler. The compiler might still decide to convert
    // the intrinsic into a call to improve performance.
    //
    static __forceinline void*
    Memcpy(
        __out_bcount_full(cbCount)  void*       pDst,
        __in_bcount(cbCount) const  void*       pSrc,
        __in                        size_t      cbCount
        )
    {
        //
        // Make the source parameter volatile to prevent the compiler from
        // converting this loop into a call to memcpy.
        //
        volatile const char *pIn = (const char *)pSrc;
        volatile char *pOut = (char *)pDst;
        while (cbCount--)
        {
            *pOut++ = *pIn++;
        }
        return pDst;
    }

    //
    // Basic implementation of memset. A call to memset is a hookable attack
    // point. The parameter is casted to a volatile to try and prevent the
    // compiler from converting the loop into a call to memset.
    //
    static __forceinline void*
    Memset(
        __out_bcount(cbCount)   VOID    *pSrc,
        __in                    CHAR    nValue,
        __in                    SIZE_T  cbCount
        )
    {
        //
        // Make the source parameter volatile to prevent the compiler from
        // converting this loop into a call to memset.
        //
        volatile char *vptr = (volatile char *)pSrc;
        while (cbCount--)
        {
            *vptr = (char)nValue;
            vptr++;
        }
        return pSrc;
    }


}; //class CUtil

}; // namespace WarbirdRuntime