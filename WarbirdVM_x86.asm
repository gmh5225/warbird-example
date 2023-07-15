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
#ifdef _M_IX86

#if $(WARBIRD_ENABLE_VM_EXECUTION)

.686

SavedRegs struct
SavedAx         dd ?
SavedCx         dd ?
SavedDx         dd ?
SavedBx         dd ?
SavedSp         dd ?
SavedBp         dd ?
SavedSi         dd ?
SavedDi         dd ?
SavedRegs ends


_TEXT$00 segment para 'CODE'

; "void __fastcall Warbird::VMExecMainLoop(void *,void *)" (?VMExecMainLoop@Warbird@@YIXPAX0@Z)
    extrn ?VMExecMainLoop@Warbird@@YIXPAX0@Z:near

    @VMReEntry@0 proc public
        sub esp, 1000

        mov dword ptr SavedRegs.SavedAx[esp], eax
    ;    mov dword ptr SavedRegs.SavedBx[esp], ebx
        mov dword ptr SavedRegs.SavedCx[esp], ecx
        mov dword ptr SavedRegs.SavedDx[esp], edx
        mov dword ptr SavedRegs.SavedSi[esp], esi
        mov dword ptr SavedRegs.SavedDi[esp], edi
        mov dword ptr SavedRegs.SavedBp[esp], ebp
        lea eax, [esp + 1000]
        mov dword ptr SavedRegs.SavedSp[esp], eax

        mov ecx, ebx
        mov edx, esp
        call ?VMExecMainLoop@Warbird@@YIXPAX0@Z

        mov eax, dword ptr SavedRegs.SavedAx[esp]
        mov ecx, dword ptr SavedRegs.SavedCx[esp]
        mov edx, dword ptr SavedRegs.SavedDx[esp]
        mov ebx, dword ptr SavedRegs.SavedBx[esp]
        mov esi, dword ptr SavedRegs.SavedSi[esp]
        mov edi, dword ptr SavedRegs.SavedDi[esp]
        mov ebp, dword ptr SavedRegs.SavedBp[esp]
        mov esp, dword ptr SavedRegs.SavedSp[esp]
        ret
    @VMReEntry@0 endp

    @VMExit@4 proc public
    ; reg pointer in ecx
        mov eax, dword ptr SavedRegs.SavedAx[ecx]
        mov ebx, dword ptr SavedRegs.SavedBx[ecx]
        mov edx, dword ptr SavedRegs.SavedDx[ecx]
        mov esi, dword ptr SavedRegs.SavedSi[ecx]
        mov edi, dword ptr SavedRegs.SavedDi[ecx]
        mov ebp, dword ptr SavedRegs.SavedBp[ecx]
        mov esp, ecx
        mov ecx, dword ptr SavedRegs.SavedCx[ecx]
        mov esp, dword ptr SavedRegs.SavedSp[esp]
        ret
    @VMExit@4 endp


_TEXT$00 ends

#endif

#endif