#if $(WARBIRD_ENABLE_VERIFICATION)
/**
  *
  * Verification Runtime Functionality
  *
  **/
namespace WarbirdRuntime
{

#pragma warbird(begin_for $(VI) 1 $(NumVerificationRuntimes) 1)
struct VERIFIED_BLOCK_DATA_$(VI)
{
#pragma warbird(begin_shuffle)
    // Address of the verified block.
    ULONG64   nRva: RVA_BIT_COUNT;
#pragma warbird(next_shuffle)
    // Size of the block.
    ULONG64   nSize: FUNCTION_SIZE_BIT_COUNT;
#pragma warbird(next_shuffle)
    ULONG64   dummy1: 3;
#pragma warbird(next_shuffle)
    ULONG64   dummy2: 3;
#pragma warbird(next_shuffle)
    ULONG64   dummy3: 2;
#pragma warbird(end_shuffle)
};

struct VERIFIED_SEGMENT_DATA_CONST_$(VI)
{
#pragma warbird(begin_shuffle)
    // Has this segment been processed with Warbird?
    ULONG   fIsProcessed: 1;
#pragma warbird(next_shuffle)
    // Number of blocks in the segment.
    ULONG   nNumBlocks: 30;
#pragma warbird(next_shuffle)
    // Adding dummy bits for padding
    ULONG   dummy: 1;
#pragma warbird(end_shuffle)
    // List of blocks.
    VERIFIED_BLOCK_DATA_$(VI)  Blocks[1];
};

struct VERIFIED_SEGMENT_DATA_READ_WRITE_$(VI)
{
    unsigned __int64 Hash;
};

#define APPLY_RELOC_FOR_HASH_FLAG  0x8000000000000000;

#pragma warbird(end_for)

template<SIZE_T Runtime, typename HashFunction, typename VerifySegment, typename VerifySegmentReadWrite>
class CVerifier
{
public:
    __forceinline
    static BOOL
    Verify(
        __in    ULONG*          pnRva,
        __in    ULONG*          pnRvaReadWrite
        )
    {
        VerifySegment* pVerifySegment = (VerifySegment*)((ULONG_PTR)(*pnRva) + CUtil::GetImageBase());
        VerifySegmentReadWrite* pVerifySegmentReadWrite = (VerifySegmentReadWrite*)((ULONG_PTR)(*pnRvaReadWrite) + CUtil::GetImageBase());
        return VerifyActual(pVerifySegment, pVerifySegmentReadWrite);
    }

    __forceinline
    static BOOL
    VerifyActual(
        __in    VerifySegment*  pverifySegment,
        __in    VerifySegmentReadWrite* pVerifySegmentReadWrite
        )
    {
        WARBIRD_ASSERT(pverifySegment != NULL && pVerifySegmentReadWrite != NULL);

        unsigned __int64 StoredHash = pVerifySegmentReadWrite->Hash;
        unsigned __int64 mask = APPLY_RELOC_FOR_HASH_FLAG; 
        BOOL bApplyReloc = FALSE;


        if ((StoredHash & mask) == mask)
        {
            bApplyReloc = TRUE;
        }

        DebugPrint(
            "%s Number of blocks %d and bApplyReloc %d\n",
            __FUNCTION__,
            pverifySegment->nNumBlocks,
            bApplyReloc
            );

        HashFunction hashFunction;
        WarbirdCrypto::CHash Hash = 0;
        hashFunction.Reset(&Hash);

        for (ULONG i=0; i<pverifySegment->nNumBlocks; i++)
        {
            DebugPrint(
                "%s Buffer Rva %X Size %X\n",
                __FUNCTION__,
                pverifySegment->Blocks[i].nRva,
                pverifySegment->Blocks[i].nSize
                );

#ifdef WARBIRD_TEST
            g_pTestClass->IncrementVerifyCount();
#endif

            GetHash(pverifySegment->Blocks[i].nRva, pverifySegment->Blocks[i].nSize, &hashFunction, bApplyReloc, &Hash);
        }

        if ((Hash | mask) != (StoredHash | mask))
        {
            DebugPrint(
                "Calculated hash %I64X %s passed in hash %I64X\n",
                Hash | mask,
                (Hash | mask) == (StoredHash | mask) ? "matched" : "did not match",
                (StoredHash | mask)
                );

#ifdef WARBIRD_TEST
            g_pTestClass->ReportVerifyFailure();
#else
            //
            // Hashes did not match
            //
            CTermination::TrashStack();
#endif
        }
        else
        {
            if (bApplyReloc)
            {
                hashFunction.Reset(&Hash);
                for (ULONG i=0; i<pverifySegment->nNumBlocks; i++)
                {
                    GetHash(pverifySegment->Blocks[i].nRva, pverifySegment->Blocks[i].nSize, &hashFunction, FALSE, &Hash);
                }

                Hash &= ~mask;

                DebugPrint(
                    "Updating the hash from %I64X to %I64X\n",
                    pVerifySegmentReadWrite->Hash,
                    Hash
                    );

                _InterlockedCompareExchange64((volatile __int64*)&pVerifySegmentReadWrite->Hash, Hash, StoredHash);
            }
        }

        return TRUE;
    }

    __forceinline
    static HRESULT
    GetHash(
        __in    ULONG                           nRva,
        __in    ULONG                           nSize,
        __in    WarbirdCrypto::CHashFunction*   pHashFunction,
        __in    BOOL                            bApplyReloc,
        __out   WarbirdCrypto::CHash*           pHash
        )
    {
        HRESULT hr = S_OK;

        PBYTE pBuffer = (PBYTE)(CUtil::GetImageBase() + (ULONG_PTR)nRva); 
        CPrivateRelocationsTable relocations;
        PRIVATE_RELOCATION_ITEM nReloc = {0};

        bool hasNextReloc = false;
        
        if (bApplyReloc)
        {
            relocations.Init(nRva, nSize);
            hasNextReloc = relocations.GetNextReloc(&nReloc);
        }

        for(ULONG nByteIndex = 0; nByteIndex < nSize;)
        {
            if (bApplyReloc && 
                hasNextReloc &&
                nByteIndex + nRva == nReloc.RVA )
            {
                BYTE relocBuffer[16];
                SIZE_T nRelocBytes = relocations.ApplyRelocation(
                    &pBuffer[nByteIndex],
                    nReloc.RelocationType,
                    CUtil::GetPreferedImageBase() - CUtil::GetImageBase(),
                    relocBuffer
                    );
                ULONG nRelocIndex = 0;
                for(nRelocIndex = 0; nRelocIndex < nRelocBytes; ++nRelocIndex)
                {
                    pHashFunction->Update(pHash, relocBuffer[nRelocIndex]);
                }
                nByteIndex += nRelocIndex;

                hasNextReloc = relocations.GetNextReloc(&nReloc);
            }
            else
            {
                pHashFunction->Update(pHash, pBuffer[nByteIndex]);
                ++nByteIndex;
            }
        }

        return hr;     
    }
}; // class CVerification

#pragma warbird(begin_for $(VI) 1 $(NumVerificationRuntimes) 1)
template class CVerifier<$(VI)-1, $(Verification$(VI)HashFunction), VERIFIED_SEGMENT_DATA_CONST_$(VI), VERIFIED_SEGMENT_DATA_READ_WRITE_$(VI)>;
#pragma warbird(end_for)

}; // namespace WarbirdRuntime

#pragma warbird(begin_foreach $(ID) $(VerifiedSegmentIDs))

namespace WarbirdRuntime {
#define WARBIRD_VERIFICATION_SECTION_CONST_$(ID)  STRINGIZE(.rdata$wbrdverif##$(ID))
#define WARBIRD_VERIFICATION_SECTION_READ_WRITE_$(ID)  STRINGIZE(.data$wbrdverif##$(ID))

#pragma section(WARBIRD_VERIFICATION_SECTION_CONST_$(ID), read)

__declspec(allocate(WARBIRD_VERIFICATION_SECTION_CONST_$(ID)))
__declspec(selectany) VERIFIED_SEGMENT_DATA_CONST_$(VerifiedSegment$(ID)RuntimeIndex)      g_VerifiedSegmentData_$(ID);

#pragma section(WARBIRD_VERIFICATION_SECTION_READ_WRITE_$(ID), read, write)

__declspec(allocate(WARBIRD_VERIFICATION_SECTION_READ_WRITE_$(ID)))
__declspec(selectany) VERIFIED_SEGMENT_DATA_READ_WRITE_$(VerifiedSegment$(ID)RuntimeIndex)      g_VerifiedSegmentDataReadWrite_$(ID);
};

EXTERN_C __forceinline VOID __fastcall WarbirdVerifySegment$(ID)Inline(
    )
{
    //
    // If the image isn't Warbird processed, don't touch the hash, as the 
    // customers expect our macros to succeed in an unobfuscated image.
    // TODO: Find a better way to do this. Although the fIsProcessed is 
    // buried in a different location in each individualized pData,
    // it still gives the hacker an easy way to deactivate verification.
    //
    if (WarbirdRuntime::g_VerifiedSegmentData_$(ID).fIsProcessed)
    {
        WarbirdRuntime::CVerifier<$(VerifiedSegment$(ID)RuntimeIndex)-1, 
            $(Verification$(VerifiedSegment$(ID)RuntimeIndex)HashFunction), 
            WarbirdRuntime::VERIFIED_SEGMENT_DATA_CONST_$(VerifiedSegment$(ID)RuntimeIndex),
            WarbirdRuntime::VERIFIED_SEGMENT_DATA_READ_WRITE_$(VerifiedSegment$(ID)RuntimeIndex)>::VerifyActual(&WarbirdRuntime::g_VerifiedSegmentData_$(ID), &WarbirdRuntime::g_VerifiedSegmentDataReadWrite_$(ID));
    }
}

EXTERN_C __declspec(noinline) VOID __fastcall WarbirdVerifySegment$(ID)NoInline(
    )
{
    WarbirdVerifySegment$(ID)Inline();
}

#pragma warbird(end_foreach)

#endif