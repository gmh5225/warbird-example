#if $(HEAP_EXECUTION_SYSTEM_CALLS)

namespace WarbirdRuntime {

    ULONG g_ulSubSystemCallID = SystemCodeFlowTransition;

    HEAP_EXECUTE_CALL_ARGUMENT g_dummyArgument;

    ULONG __declspec(noinline)
    EnclaveWrapper()
    {
        return 0;
    }

    ULONG
    CallEnclaveFunction(
        PVOID* pArguments
        )
    {
        NtQuerySystemInformation(
            /*(SYSTEM_INFORMATION_CLASS)*/g_ulSubSystemCallID,
            (PVOID)pArguments,
            sizeof(pArguments),
            NULL
            );

        return 0;
    }

    HRESULT
    WarbirdProcessInitialize(
        PPROCESS_STARTUP_ARGUMENT pStartupArguments
        )
    {
        PROCESS_STARTUP_ARGUMENT_LIST list;
        list.eType = WbOperationProcessStartup;
        list.pArguments = pStartupArguments;
        NtQuerySystemInformation(
            /*(SYSTEM_INFORMATION_CLASS)*/g_ulSubSystemCallID,
            &list,
            sizeof(list),
            NULL
            );

        return S_OK;
    }

}; // namespace WarbirdRuntime;

#endif // HEAP_EXECUTION_SYSTEM_CALLS


#if $(WARBIRD_ENABLE_HEAP_EXECUTION)

#if defined(__cplusplus)
extern "C" {
#endif

// _ReturnAddress and _AddressOfReturnAddress should be prototyped before use 
void * _AddressOfReturnAddress(void);
void * _ReturnAddress(void);

#pragma intrinsic(_AddressOfReturnAddress)

#if _CONTROL_FLOW_GUARD_SHADOW_STACK

void WarbirdWriteToControlStack(void *Rsp, UINT_PTR Value);
void* WarbirdReadFromControlStack(void *Rsp);

// On platforms that don't support control stacks, this may AV.
// As a workaround, swallow the AV.
void* WarbirdReadFromControlStackInterop(void *Rsp)
{
    void *value = NULL;

    __try
    {
        value = WarbirdReadFromControlStack(Rsp);
    } __except(EXCEPTION_EXECUTE_HANDLER)
    {
    }

    return value;
}

#endif

#if defined(__cplusplus)
} // extern "C"
#endif

/**
  *
  * Heap Execution Runtime Functionality
  *
  **/
namespace WarbirdRuntime
{

//
// The extra padding is needed on ARM to ensure that the target buffer is
// aligned on the same byte as the source buffer. This is a requirement for
// ARM's ldr instruction.
//
#if defined(_ARM_) || defined(_ARM64_)
#define HEAP_EXECUTED_BUFFER_ALIGNMENT_PADDING 0x0F
#else
#define HEAP_EXECUTED_BUFFER_ALIGNMENT_PADDING 0x00
#endif // _ARM_


#pragma section(".data$wbrdIb", read, write)
__declspec(allocate(".data$wbrdIb"))
UINT_PTR g_imageBaseForHeapExecution = 0x012345678;

__forceinline
HRESULT
HeapExecutionRuntimeInit(
    )
{
    return S_OK;
}

__forceinline
VOID
HeapExecutionRuntimeCleanup(
    )
{
    return;
}

#pragma warbird(begin_for $(RI) 1 $(NumHeapExecutionRuntimes) 1)
struct HEAP_EXECUTION_SEGMENT_ARGUMENTS_$(RI)
{
#pragma warbird(begin_shuffle)
    ULONG   Rva:RVA_BIT_COUNT;
#pragma warbird(next_shuffle)
    ULONG   Size:FUNCTION_SIZE_BIT_COUNT;
#pragma warbird(next_shuffle)
    ULONG   Checksum:CHECKSUM_BIT_COUNT;
#pragma warbird(next_shuffle)
    ULONG64 Key:KEY_BIT_COUNT;
#pragma warbird(end_shuffle)
};

struct HEAP_EXECUTION_CALL_ARGUMENTS_$(RI)
{
#pragma warbird(begin_shuffle)
    ULONG   MaxSegmentSize:FUNCTION_SIZE_BIT_COUNT;
#pragma warbird(next_shuffle)
    ULONG   ImageBaseOffset:FUNCTION_SIZE_BIT_COUNT;
#pragma warbird(next_shuffle)
    ULONG   CheckStackSize:STACK_SIZE_BIT_COUNT;
#pragma warbird(next_shuffle)
    ULONG   Rva:RVA_BIT_COUNT;
#pragma warbird(next_shuffle)
    ULONG   Size:FUNCTION_SIZE_BIT_COUNT;
#pragma warbird(next_shuffle)
    ULONG   Checksum:CHECKSUM_BIT_COUNT;
#pragma warbird(next_shuffle)
    ULONG64 Key:KEY_BIT_COUNT;
#pragma warbird(end_shuffle)
};

struct HEAP_EXECUTION_UNCONDITIONAL_BRANCH_ARGUMENTS_$(RI)
{
#pragma warbird(begin_shuffle)
    ULONG   Offset:FUNCTION_SIZE_BIT_COUNT;
#pragma warbird(next_shuffle)
    ULONG   Rva:RVA_BIT_COUNT;
#pragma warbird(end_shuffle)
};

struct HEAP_EXECUTION_CONDITIONAL_BRANCH_ARGUMENTS_$(RI)
{
#pragma warbird(begin_shuffle)
    //
    // Tells the runtime how to compare the two passed in values e.g. 
    // JNE, JEQ, JS, JZ etc.
    //
    ULONG   ConditionCode:CONDITION_CODE_BIT_COUNT;
#pragma warbird(next_shuffle)
    ULONG   FallThroughRva:RVA_BIT_COUNT;
#pragma warbird(next_shuffle)
    ULONG   BranchRva:RVA_BIT_COUNT;
#pragma warbird(next_shuffle)
    ULONG   BranchOffset:FUNCTION_SIZE_BIT_COUNT;
#pragma warbird(end_shuffle)
};
#pragma warbird(end_for)

template<
    SIZE_T Runtime,
    BYTE Skew,
    typename Cipher,
    typename HashFunction,
    typename SegmentArguments,
    typename CallArguments,
    typename UnconditionalBranchArguments,
    typename ConditionalBranchArguments
    >
class CHeapExecution
{
public:
    static VOID
    __fastcall Initialize(
        VOID
        )
    {
        //
        // Instantiate the conditional comparison functions so the get generated
        // by the front end compiler and can be discovered by warbird in the
        // back end compiler.
        //

        ConditionalBranchArguments arguments;
        ConditionalBranch<unsigned char>(&arguments, 0, 1);
        ConditionalBranch<unsigned short>(&arguments, 0, 1);
        ConditionalBranch<unsigned int>(&arguments, 0, 1);
        ConditionalBranch<unsigned __int64>(&arguments, 0, 1);
        ConditionalBranch<signed char>(&arguments, 0, 1);
        ConditionalBranch<short>(&arguments, 0, 1);
        ConditionalBranch<int>(&arguments, 0, 1);
        ConditionalBranch<__int64>(&arguments, 0, 1);
        ConditionalBranch<float>(&arguments, 0, 1);
        ConditionalBranch<double>(&arguments, 0, 1);
    }

    static PVOID __declspec(noinline)
    __fastcall DirectCall(
        __in    CallArguments*   pArguments
        )
    {
        DebugPrint(
            "Decrypt Direct call Arguments Rva 0x%X, Size 0x%X, Checksum 0x%X, Key 0x%I64X\n",
            pArguments->Rva,
            pArguments->Size,
            pArguments->Checksum,
            pArguments->Key
            );

        WarbirdCrypto::CKey Key;
        Key.u64 = pArguments->Key;

        //
        // Allocate a buffer and decrypt the function's first segment into this
        // buffer.
        //
        UINT_PTR pTargetBuffer = (UINT_PTR)AllocateAndDecrypt(
            pArguments->Rva,
            pArguments->Size,
            pArguments->MaxSegmentSize,
            Key,
            pArguments->Checksum
            );

        if (pArguments->ImageBaseOffset)
        {
            //
            // Update the function with the modified image base.
            //
            UINT_PTR imageBase = CUtil::GetImageBase();
            UINT_PTR pBufferStartAddress = pTargetBuffer;
#ifdef _ARM_
            //
            // On ARM the function address is always odd. Unset the low bit to
            // get the true start of the function.
            //
            pBufferStartAddress &= ~0x1;
#endif // _ARM_


            PBYTE pImageBaseFixup = (PBYTE)pBufferStartAddress + pArguments->ImageBaseOffset;
            CUtil::Memcpy(pImageBaseFixup, &imageBase, sizeof(imageBase));

            DebugPrint("Applied image base fixup at %X %p to address %p\n",
                pArguments->ImageBaseOffset,
                imageBase,
                pBufferStartAddress
                );
        }

        if (pArguments->CheckStackSize)
        {
            DebugPrint(
                "Expanding the stack _chkstack %d\n",
                pArguments->CheckStackSize
                );

            //
            // TODO: Change to a for loop to prevent the security cookies from
            // getting inserted into this runtime function.
            //
            _alloca(pArguments->CheckStackSize);
        }

        //
        // Now that the code is decrypted and the image base is applied flush
        // the Cpu cache. If the cache is not flushed the previous bytes in
        // this buffer could be executed causing a crash.
        //
        FlushSegmentCpuCache(pTargetBuffer);

        //
        // Return the allocated buffer so it can be called indirectly.
        //
        return (PVOID)pTargetBuffer;
    }

    template<typename Type>
    static PVOID __declspec(noinline)
    __fastcall ConditionalBranch(
        __in    ConditionalBranchArguments*     pArguments,
                Type                            nLhs,
                Type                            nRhs
        )
    {
        PVOID pTargetBuffer = NULL;
        ULONG nOffsetIntoSegment = 0;
        SegmentArguments* pSelectedSegment = NULL;

        SegmentArguments* pBranchSegment = pArguments->BranchRva ?
            (SegmentArguments*)(CUtil::GetImageBase() + pArguments->BranchRva) : NULL;

        SegmentArguments* pFallThroughSegment = pArguments->FallThroughRva ?
            (SegmentArguments*)(CUtil::GetImageBase() + pArguments->FallThroughRva) : NULL;

        DebugPrint(
            "[%p] Decrypt conditional branch Target Rva 0x%X (Offset %d, Size %d), Fall Through Rva 0x%X (Size %d)\n",
            (UINT_PTR)_ReturnAddress(),
            pArguments->BranchRva,
            pArguments->BranchOffset,
            pBranchSegment ? pBranchSegment->Size : 0,
            pArguments->FallThroughRva,
            pFallThroughSegment ? pFallThroughSegment->Size : 0
            );

        //
        // Figure out if we should branch or fall through
        //
        BOOL bBranch = IsConditionSatisfied(
            (ConditionCode)pArguments->ConditionCode,
            nLhs,
            nRhs
            );

        //
        // Select which segment to branch to
        //
        pSelectedSegment = bBranch ? pBranchSegment : pFallThroughSegment;
        if (bBranch)
        {
            pSelectedSegment = pBranchSegment;
            nOffsetIntoSegment = pArguments->BranchOffset;
        }
        else
        {
            pSelectedSegment = pFallThroughSegment;
        }

        //
        // Check if the selected segment is in the same or a different
        // segment.
        //
        if (pSelectedSegment != NULL)
        {
            //
            // A non zero RVA indicates that the code transitions to a new heap
            // executed segment. We need to allocate a buffer and decrypt the new
            // target segment into this buffer.
            //

            WarbirdCrypto::CKey Key;
            Key.u64 = pSelectedSegment->Key;

            //
            // Decrypt the selected target segment into an allocated buffer
            //
            pTargetBuffer = ReallocateAndDecrypt(
                (UINT_PTR)_ReturnAddress() - 1, // The current buffer for this segment
                pSelectedSegment->Rva,
                pSelectedSegment->Size,
                Key,
                pSelectedSegment->Checksum
                );

            //
            // Swap out the return address so we end up in the target segment when
            // the function returns.
            //
            UINT_PTR* pAddressOfReturnAddress = (UINT_PTR*)_AddressOfReturnAddress();

#if _CONTROL_FLOW_GUARD_SHADOW_STACK
            BOOL bUpdateControlStack = ((UINT_PTR) WarbirdReadFromControlStackInterop(pAddressOfReturnAddress) == *pAddressOfReturnAddress);
#endif

            *pAddressOfReturnAddress = (UINT_PTR)pTargetBuffer + nOffsetIntoSegment;

#if _CONTROL_FLOW_GUARD_SHADOW_STACK
            if (bUpdateControlStack) {
                // Reflect the update to the control stack (workaround).
                WarbirdWriteToControlStack(pAddressOfReturnAddress, (UINT_PTR) pTargetBuffer + nOffsetIntoSegment);
            }
#endif
        }
        else
        {
            //
            // Since the RVA is zero the selected target is still in the same
            // segment. Tell the conditional branch instruction, that follows the
            // call to this runtime function, if it should branch or fall
            // through. A return value of 999 tells the conditional branch
            // instruction to branch. Any other value indicates a fall through
            //
            pTargetBuffer = bBranch ? PVOID((UINT_PTR)999) : NULL;
        }

        return pTargetBuffer;
    }

    static PVOID __declspec(noinline)
    __fastcall UnconditionalBranchWithOffset(
        __in    UnconditionalBranchArguments*    pArguments
        )
    {
        UINT_PTR* ppAddressOfReturnAddress = (UINT_PTR*)_AddressOfReturnAddress();
        SegmentArguments* pSegment = (SegmentArguments*)
            (CUtil::GetImageBase() + pArguments->Rva);


        return (PVOID)UnconditionalBranchWorker(pSegment, pArguments->Offset, ppAddressOfReturnAddress);
    }

    static PVOID __declspec(noinline)
    __fastcall UnconditionalBranch(
        __in    SegmentArguments*    pArguments
        )
    {
        UINT_PTR* ppAddressOfReturnAddress = (UINT_PTR*)_AddressOfReturnAddress();
        return (PVOID)UnconditionalBranchWorker(pArguments, 0, ppAddressOfReturnAddress);
    }

    static UINT_PTR __forceinline
    __fastcall  UnconditionalBranchWorker(
        __in    SegmentArguments*    pSegment,
                ULONG                nOffset,
        __in    UINT_PTR*            ppAddressOfReturnAddress
        )
    {
        UINT_PTR pTargetBuffer = NULL;

        DebugPrint(
            "[%p] Decrypt Uncoditional Branch Rva 0x%X, Size 0x%X, Checksum 0x%X, Key 0x%I64X, Offset %d\n",
            *ppAddressOfReturnAddress,
            pSegment->Rva,
            pSegment->Size,
            pSegment->Checksum,
            pSegment->Key,
            nOffset
            );

        WarbirdCrypto::CKey Key;
        Key.u64 = pSegment->Key;

        //
        // Decrypt the selected target segment into an allocated buffer
        //
        pTargetBuffer = (UINT_PTR)ReallocateAndDecrypt(
            *ppAddressOfReturnAddress - 1, // The current buffer for this segment
            pSegment->Rva,
            pSegment->Size,
            Key,
            pSegment->Checksum
            );

        pTargetBuffer += nOffset;

#if _CONTROL_FLOW_GUARD_SHADOW_STACK
        BOOL bUpdateControlStack = ((UINT_PTR) WarbirdReadFromControlStackInterop(ppAddressOfReturnAddress) == *ppAddressOfReturnAddress);
#endif

        //
        // Swap out the return address so we end up in the target segment when
        // the function returns.
        //
        *ppAddressOfReturnAddress = (UINT_PTR)pTargetBuffer;

#if _CONTROL_FLOW_GUARD_SHADOW_STACK
        if (bUpdateControlStack) {
            // Reflect the update to the control stack (workaround).
            WarbirdWriteToControlStack(ppAddressOfReturnAddress, (UINT_PTR) pTargetBuffer);
        }
#endif

        return pTargetBuffer;
    }

    static void __declspec(noinline)
    __fastcall Cleanup(
        __in    PBYTE   pBuffer
        )
    {
        UNREFERENCED_PARAMETER(pBuffer);
        //
        // If this debug flag is set do not free the buffers so the heap
        // executed segments can be dumped in the debugger and examined.
        //
        if (pBuffer)
        {
            DebugPrint("Free buffer %p\n", pBuffer);

            g_MemoryAllocator.FreeMemory(pBuffer);
        }
    }

private:
    static PVOID __forceinline
    AllocateAndDecrypt(
        ULONG                       nSourceRva,
        ULONG                       nSize,
        ULONG                       nMaxSegmentSize,
        WarbirdCrypto::CKey         Key,
        WarbirdCrypto::CChecksum    Checksum
        )
    {
        UINT_PTR pSourceBuffer = CUtil::GetImageBase() + nSourceRva;
        UINT_PTR pTargetBuffer = NULL;
        BYTE nAlignment = 0;

        //
        // Expand the allocated size for padding. The padding is needed on ARM
        // to ensure that the target buffer is aligned on the same byte as
        // the source buffer. Normally we just need to expand the size by
        // alignment padding + nAlignment but for multi block heap execution we
        // reuse the same buffer and do not know the alignment of the other
        // segments. So we have to assume the worst case that nAlignment is the
        // max alignment padding size (HEAP_EXECUTED_BUFFER_ALIGNMENT_PADDING).
        //
        nAlignment = nSourceRva & HEAP_EXECUTED_BUFFER_ALIGNMENT_PADDING;
        nMaxSegmentSize += HEAP_EXECUTED_BUFFER_ALIGNMENT_PADDING * 2;

        //
        // Allocate a buffer big enough to store the largest heap executed
        // segment (for heap executed function). When multi-block heap execution
        // branches to the next segment it reuses the current buffer.
        //
        //
        // Allocate a buffer (no need to check the result for NULL - the call
        // will block until memory is allocated).
        //
        pTargetBuffer = (UINT_PTR) g_MemoryAllocator.AllocateMemory(
            nMaxSegmentSize
            );
        WARBIRD_ASSERT(pTargetBuffer != NULL);

        //
        // Make sure the target buffer is aligned on the same byte as the source
        // buffer. This is a requirement for the ARM ldr instruction. Earlier
        // the allocate size was increased to handle this scenario.
        //
        pTargetBuffer += HEAP_EXECUTED_BUFFER_ALIGNMENT_PADDING;
        pTargetBuffer = ((pTargetBuffer & ~HEAP_EXECUTED_BUFFER_ALIGNMENT_PADDING) | nAlignment);

        DebugPrint("Allocated buffer %p, Start Address %p, Size %d\n",
            pTargetBuffer,
            pTargetBuffer,
            nMaxSegmentSize
            );

        //
        // Copy and Decrypt the function into the allocated buffer
        //
        DecryptWorker(
            (PBYTE)pSourceBuffer, 
            (PBYTE)pTargetBuffer, 
            nSize,
            Key,
            nSourceRva,
            Checksum
            );

#ifdef _ARM_
        //
        // On ARM the PC register is always odd for a thumb functions. And
        // windows only supports thumb mode.
        //
        pTargetBuffer |= 1;
#endif // _ARM_

        return (PBYTE)pTargetBuffer;
    }

    static VOID __forceinline
    FlushSegmentCpuCache(
        __in    UINT_PTR    pMemory
        )
    {
        PVOID pStartAddress = NULL;
        SIZE_T nSize = 0;

        //
        // Get the buffer the function was decrypted into.
        //
        g_MemoryAllocator.QueryAllocation((PVOID)pMemory, (PVOID*)&pStartAddress, &nSize);
        WARBIRD_ASSERT(pStartAddress != NULL);

        //
        // Flush all bytes in the buffer not just the decrypted bytes. This
        // makes it a bit harder for the hacker to find where the code is in the
        // buffer. The CPU cache needs to be flushed so the bytes previously in
        // this buffer are not executed by mistake (stale cache).
        //
        CUtil::FlushCpuCache(pStartAddress, nSize);
    }

    static PVOID __forceinline
    ReallocateAndDecrypt(
        UINT_PTR                    pBuffer,
        ULONG                       nSourceRva,
        ULONG                       nSourceSize,
        WarbirdCrypto::CKey         Key,
        WarbirdCrypto::CChecksum    Checksum
        )
    {
        UINT_PTR pSourceBuffer = CUtil::GetImageBase() + nSourceRva;
        UINT_PTR pStartAddress;
        SIZE_T nSize;
        BYTE nAlignment = 0;

        //
        // The alignment is needed on ARM to ensure that the target buffer is
        // aligned on the same byte as the source buffer.
        //
        nAlignment = nSourceRva & HEAP_EXECUTED_BUFFER_ALIGNMENT_PADDING;

        //
        // Find the start of the buffer used by the current heap executed
        // segment.
        //
        BOOL bFound = g_MemoryAllocator.QueryAllocation((PVOID)pBuffer, (PVOID*)&pStartAddress, &nSize);

        WARBIRD_ASSERT(nSourceSize <= nSize);
        DebugPrint("Reallocated buffer %p, Start Address %p, Size %d\n",
            pBuffer,
            pStartAddress,
            nSize
            );

        WARBIRD_ASSERT(bFound && nSize != 0);
        UNREFERENCED_PARAMETER(bFound);

        //
        // Make sure the target buffer is aligned on the same byte as the source
        // buffer. This is a requirement for the ARM ldr instruction. During the
        // initial allocation the allocate size was increased to handle this
        // scenario.
        //
        pStartAddress += HEAP_EXECUTED_BUFFER_ALIGNMENT_PADDING;
        pStartAddress = ((pStartAddress & ~HEAP_EXECUTED_BUFFER_ALIGNMENT_PADDING) | nAlignment);

        pBuffer = (UINT_PTR)pStartAddress;

        //
        // Copy and Decrypt the function into the same buffer. It is okay to
        // reuse the buffer because the buffer was allocated big enough to store
        // the largest segment of this heap executed function.
        //
        DecryptWorker(
            (PBYTE)pSourceBuffer,
            (PBYTE)pBuffer,
            nSourceSize,
            Key,
            nSourceRva,
            Checksum
            );

        //
        // Now that the code is decrypted flush the Cpu cache. If the cache is
        // not flushed the previous bytes in this buffer could be executed
        // causing a crash.
        //
        FlushSegmentCpuCache(pBuffer);

#ifdef _ARM_
        //
        // On ARM the PC register is always odd for a thumb functions. And
        // windows only supports thumb mode.
        //
        pBuffer |= 1;
#endif // _ARM_

        return (PVOID)pBuffer;
    }

    static void __forceinline
    __fastcall DecryptWorker(
        __in_bcount(nBytes)     CONST BYTE*                 pSource,
        __out_bcount(nBytes)    BYTE*                       pTarget,
                                SIZE_T                      nBytes,
                                WarbirdCrypto::CKey         Key,
                                ULONG                       IV,
                                WarbirdCrypto::CChecksum    Checksum
        )
    {
        DebugPrint("Decrypt %p into %p Size = %d\n", pSource, pTarget, nBytes);
        DebugPrint("%p into %p Size = %d\n", pSource, pTarget, nBytes);
        DebugPrint("ln 0x%p\n", pSource);
        DebugPrint("u 0x%p 0x%p+0x%X\n", pTarget, pTarget, nBytes);

        Cipher cipher;
        WarbirdCrypto::CChecksum CalcChecksum;

        cipher.Decrypt(
            pSource,
            pTarget,
            nBytes,
            Key,
            IV,
            &CalcChecksum
            );

        if (CalcChecksum != Checksum)
        {
#ifdef WARBIRD_TEST
            g_pTestClass->ReportVerifyFailure();
#else
            CTermination::TrashStack();
#endif
        }
    }

    template<typename Type>
    static BOOL __forceinline
    IsConditionSatisfied(
        ConditionCode       nConditionCode,
        Type                nLhs,
        Type                nRhs
        )
    {
        //
        // Compare the two values based on the condition code. Signed and
        // unsigned are treated the same because of the type template. A
        // different runtime and compare function is created for each type e.g.
        // UINT8, UINT32, INT32, INT32
        //
        BOOL bBranch = FALSE;
        switch(nConditionCode)
        {
            case ConditionCodeEq:
                bBranch = nLhs == nRhs;
                break;

            case ConditionCodeNe:
                bBranch = nLhs != nRhs;
                break;

            case ConditionCodeGe:
            case ConditionCodeUge:
                bBranch = nLhs >= nRhs;
                break;

            case ConditionCodeGt:
            case ConditionCodeUgt:
                bBranch = nLhs > nRhs;
                break;

            case ConditionCodeLe:
            case ConditionCodeUle:
                bBranch = nLhs <= nRhs;
                break;

            case ConditionCodeLt:
            case ConditionCodeULt:
                bBranch = nLhs < nRhs;
                break;

            case ConditionCodeBt:
                //
                // Checks if the specified bit (rhs) in rhs is set. Should only
                // be called for integer values
                //
                bBranch = IsBtConditionSatisfied<Type>(nLhs, nRhs);
                break;

            case ConditionCodeNo:
            case ConditionCodeNp:
            case ConditionCodeNs:
            case ConditionCodeO:
            case ConditionCodeP:
            case ConditionCodeS:
            case ConditionCodeLbc:
            case ConditionCodeLbs:
                //
                // Never expected to see these condition codes since the
                // compare/branch is replaced pre lower
                //
                WARBIRD_ASSERT(false);
                break;

            case ConditionCodeNone:
                //
                // The condition code should be set to something!!! Warbird
                // probably forgot to set it or it is tampered
                //
                break;

            default:
                //
                // Unknown condition code
                //
                WARBIRD_ASSERT(false);
                break;
        }

        return bBranch;
    }

    template<typename Type>
    static BOOL __forceinline
    IsBtConditionSatisfied(
        Type                nLhs,
        Type                nRhs
        )
    {
        //
        // Checks if the specified bit (rhs) in rhs is set. Should only
        // be called for integer values
        //
        return (nLhs & ((Type)1 << nRhs)) != 0;
    }

    template<>
    static BOOL __forceinline
    IsBtConditionSatisfied<float>(
        float               nLhs,
        float               nRhs
        )
    {
        //
        // Checks if the specified bit (rhs) in rhs is set. Should only
        // be called for integer values
        //
        UNREFERENCED_PARAMETER(nLhs);
        UNREFERENCED_PARAMETER(nRhs);
        WARBIRD_ASSERT(FALSE);
        return FALSE;
    }

    template<>
    static BOOL __forceinline
    IsBtConditionSatisfied<double>(
        double              nLhs,
        double              nRhs
        )
    {
        //
        // Checks if the specified bit (rhs) in rhs is set. Should only
        // be called for integer values
        //
        UNREFERENCED_PARAMETER(nLhs);
        UNREFERENCED_PARAMETER(nRhs);
        WARBIRD_ASSERT(FALSE);
        return FALSE;
    }




}; // class CHeapExecution

//
// Instantiate the heap execution runtimes so warbird can discover the
// encrypt/decrypt functions
//
#pragma warbird(begin_for $(RI) 1 $(NumHeapExecutionRuntimes) 1)
template class CHeapExecution<
    $(RI)-1,                                                // Runtime ID
    34,                                                     // Skew / shift values
    $(HeapExecution$(RI)Cipher),                            // Encryption Cipher
    $(HeapExecution$(RI)HashFunction),                      // HashFunction to create a hash based key
    HEAP_EXECUTION_SEGMENT_ARGUMENTS_$(RI),                 // Contains all information about a segment
    HEAP_EXECUTION_CALL_ARGUMENTS_$(RI),                    // Call Argument structure
    HEAP_EXECUTION_UNCONDITIONAL_BRANCH_ARGUMENTS_$(RI),    // Unconditional Argument Structure
    HEAP_EXECUTION_CONDITIONAL_BRANCH_ARGUMENTS_$(RI)       // Conditional Argument Structure
    >;
#pragma warbird(end_for)

}; // namespace WarbirdRuntime

#endif
