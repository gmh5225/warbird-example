#if $(WARBIRD_ENABLE_ENCRYPTION)

/**
  *
  * Encryption Runtime Functionality
  *
  **/

namespace WarbirdRuntime
{

CLock g_encryptionLock;

//
// Boolean that indicates if the encryption lock has been initialized yet. If
// RuntimeInit fails warbird automatically calls cleanup. However, the lock can
// only be deleted if its was initialized. RuntimeInit can fail before encryption
// and this lock are initialized.
//
BOOL g_bEncryptionInitialized = FALSE;

__forceinline
HRESULT
EncryptionRuntimeInit()
{
    HRESULT hr = S_OK;

    hr = g_encryptionLock.Init();
    if (SUCCEEDED(hr))
    {
        g_bEncryptionInitialized = TRUE;
#if defined(WARBIRD_VSM_TEST)
        SetupBcrypt();
#endif // defined (WARBIRD_VSM_TEST))
    }

    return hr;
}

__forceinline
VOID
EncryptionRuntimeCleanup()
{
    if (g_bEncryptionInitialized)
    {   
        g_encryptionLock.Cleanup();
        g_bEncryptionInitialized = FALSE;
#if defined(WARBIRD_VSM_TEST)
        ShutDownBcrypt();
#endif // defined (WARBIRD_VSM_TEST))
    }
}

#pragma warbird(begin_for $(RI) 1 $(NumEncryptionRuntimes) 1)
struct ENCRYPTED_BLOCK_DATA_CONST_$(RI)
{
#pragma warbird(begin_shuffle)
    ULONG                   RVA:RVA_BIT_COUNT;
#pragma warbird(next_shuffle)
    ULONG                   nSize:FUNCTION_SIZE_BIT_COUNT;
#pragma warbird(next_shuffle)
    ULONG                   fIsData:1;
#pragma warbird(end_shuffle)
};

struct ENCRYPTED_BLOCK_DATA_READ_WRITE_$(RI)
{
#pragma warbird(begin_shuffle)
    WORD                    dummy1:2;
#pragma warbird(next_shuffle)
    WORD                    dummy2:3;
#pragma warbird(next_shuffle)
    WORD                    dummy3:1;
#pragma warbird(next_shuffle)
    WORD                    fIsEncrypted:1;
#pragma warbird(next_shuffle)
    WORD                    fIsRelocated:1;
#pragma warbird(next_shuffle)
    WORD                    Checksum:CHECKSUM_BIT_COUNT;
#pragma warbird(end_shuffle)
};

struct ENCRYPTED_SEGMENT_DATA_CONST_$(RI)
{
#pragma warbird(begin_shuffle)
    ULONG                   fIsProcessed:1;
#pragma warbird(next_shuffle)
    ULONG                   nSegmentIndex:8;
#pragma warbird(next_shuffle)
    ULONG                   nNumBlocks:16;
#pragma warbird(next_shuffle)
    ULONG64                 Key:KEY_BIT_COUNT;
#pragma warbird(next_shuffle)
    //
    // Padding need work around compiler bug. When warbird expands the structure
    // to greater than 64 bytes the alignment of the front end symbol changes from 
    // 4 to 8 bytes. But the back end symbol's alignment is not updated.
    // dbchecks asserts because the alignments of the BE/FE symbols are not the
    // same.
    //
    BYTE                    padding[64];
#pragma warbird(end_shuffle)
    ENCRYPTED_BLOCK_DATA_CONST_$(RI)  Blocks[1];
};

struct ENCRYPTED_SEGMENT_DATA_READ_WRITE_$(RI)
{
    enum
    {
        MAX_DECRYPT_COUNT = static_cast<ULONG>(-1),
    };
    ULONG                   DecryptCount;
    ENCRYPTED_BLOCK_DATA_READ_WRITE_$(RI)  Blocks[1];
};

#pragma warbird(end_for)

//
// Helper class to manage making memory pages writable while decrypting/encrypting segments. 
// The class manages the protection on a range of memory pages level, so that if there are 
// multiple encrypted blocks on the same memory page range, we do the costly setting/resetting 
// memory protection operations only once before/after processing all the blocks.
// The class contains implementations for kernel mode and user mode, and a thin wrapper common 
// to both.
//
class CMemoryProtectionChangeHelper
{
public:
    BOOL
    Init(SIZE_T nSegmentIndex, BOOL bEncrypting) 
    {
        m_pRangeStart = NULL;
        m_nRangeSize = 0;
        m_nMappedPagesOffset = 0;
        m_bEncrypting = bEncrypting;
        m_nSegmentIndex = nSegmentIndex;
        
        return InitInternal();
    }

    BOOL    Cleanup()
    {
        BOOL result;

        RevertCurrentRangeProtection( );
        result = RevertImageProtection();

        m_pRangeStart = NULL;
        m_nRangeSize = 0;
        m_nMappedPagesOffset = 0;
        m_bEncrypting = FALSE;
        m_nSegmentIndex = 0;

        return result;
    }

    BYTE* 
    MakeWritable(
        __in_bcount(nSize)  CONST BYTE* pAddress,
        __in                SIZE_T      nSize,
        __in                SIZE_T      nSegmentIndex
        )
    {
        // If the specified address does not fall into the range that is currently marked as writable, 
        // create a new writable range. The if statement also handles the first call, where we don't 
        // have a range yet (range start and size are zero to begin with, so the specified address 
        // cannot be in the range from 0 to 0).

        if(m_nSegmentIndex != nSegmentIndex)
        {
            WARBIRD_ASSERT(FALSE);
        }

        if (!(pAddress >= m_pRangeStart && pAddress + nSize < m_pRangeStart + m_nRangeSize))
        {
            // First, revert page protections for the current range (only if there is one - 
            // otherwise RevertCurrentRangeProtection will act as a NOP).

            RevertCurrentRangeProtection();

            // Then, calculate the range of memory pages that cover the requested address range.

            m_pRangeStart = const_cast<BYTE*>(CUtil::RoundDown(pAddress, PAGE_SIZE));
            m_nRangeSize  = CUtil::RoundUp(pAddress + nSize, PAGE_SIZE) - m_pRangeStart;

            // And make the range writable (through separate implementations for kernel and user mode).

            if (!MakeCurrentRangeWritable())
            {
                // If unable to make the range writable, return failure.

                return NULL;
            }
        }

        // If we got to here, return the address. 
        // m_nMappedPagesOffset will be non-zero only in kernel mode.

        return const_cast<BYTE*>(pAddress) + m_nMappedPagesOffset;
    }

private:
    // Starting address of the region, rounded down to system page size.
    BYTE*   m_pRangeStart;

    // Size of the region, rounded up to system page size.
    SIZE_T  m_nRangeSize;

    // Offset from the read-only address to the read/write address. Only for kernel mode. 
    SSIZE_T m_nMappedPagesOffset;

    // Whether the code is being encrypted or decrypted determines when the execute
    // privilge is added or removed.
    BOOL m_bEncrypting;

    // Segment being encrypted/decrypted
    SIZE_T m_nSegmentIndex;
    
#if defined(WARBIRD_KERNEL_MODE)
//
// Kernel mode helper. In order to modify read-only kernel pages, we page them in, 
// lock them so that they don't get paged out, and map them to a separate system address,
// with read/write permissions. After we decrypt the encrypted segment, we unlock
// the pages, which also marks the original virtual address as modified, so that the 
// modified physical memory pages get written to the memory in case they need to be
// paged out later.
//
private:
    BOOL
    InitInternal()
    {
        m_pMDL = NULL;
        m_pVsmMDL = NULL;
        m_fPagesAreLocked = FALSE;
        
        m_pVsmRangeStart = NULL;
        m_pVsmRangeStartWritableAddress = NULL;
        m_nVsmRangeSize = 0;
        m_nVsmSegmentIndex = 0;

        return MakeSegmentWritable();
    }

    BOOL 
    MakeCurrentRangeWritable( )
    {
        //
        // Resetting the variable to make sure cleanup
        // operates on the right MDL address
        //
        m_nMappedPagesOffset = 0; 

        // If this is a VSM enabled binary, code blocks are already modified. 
        // Modify if not VSM or VSM and is a data block
        if(!ModifySegmentProperties())
        {
            m_nMappedPagesOffset = m_pVsmRangeStartWritableAddress - m_pVsmRangeStart;
            return TRUE;
        }

        // Allocate a Memory Descriptor List to map the buffer.
        m_pMDL = IoAllocateMdl(
            m_pRangeStart, 
            static_cast<ULONG>(m_nRangeSize), 
            FALSE, 
            FALSE,
            NULL
                               );
            
        if (m_pMDL != NULL)
        {
            // Lock the pages, so that they cannot be paged out and they stay at the same physical 
            // address while we modify them from a second mapping (at a different virtual address). 
            // IoModifyAccess flag is critical here, if IoReadAccess is used instead, modifications 
            // that are made through the second mapping won't be reflected on the first mapping, so 
            // next time physical memory is paged out and back in, modifications will be lost!!!
             
            __try
            {
                LOCK_OPERATION Operation = IoModifyAccess;
                MmProbeAndLockPages(
                    m_pMDL, 
                    KernelMode, 
                    Operation
                                    );
                m_fPagesAreLocked = TRUE;
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                m_fPagesAreLocked = FALSE;
            }
            
            if (m_fPagesAreLocked)
            {
                // Get a new virtual address for the buffer.
                
                PBYTE pRangeStartSystemAddress = static_cast<PBYTE>
                    (MmGetSystemAddressForMdlSafe(
                        m_pMDL, 
                        (MM_PAGE_PRIORITY)(HighPagePriority  | MdlMappingNoExecute)));
                
                if (pRangeStartSystemAddress != NULL)
                {
                    m_nMappedPagesOffset = pRangeStartSystemAddress - m_pRangeStart;
                    return TRUE;
                }
            }
        }
        return FALSE;
    }
    
    BOOL 
    ModifySegmentProperties()
    {
#if ($(WARBIRD_VSM_VERSION) == 2)
        if( (m_pRangeStart >= m_pVsmRangeStart) && 
            ((m_pRangeStart + m_nRangeSize) <= (m_pVsmRangeStart + m_nVsmRangeSize)) )
        {
            // the properties have already been modfied for the entire block
            return FALSE;
        }
        else
        {
            return TRUE;
        }
#else  // ($(WARBIRD_VSM_VERSION) == 2)
        return TRUE;
#endif // ($(WARBIRD_VSM_VERSION) == 2)
    }
        

    BOOL
    MakeSegmentWritable()
    {
        BOOL result = TRUE;
#if ($(WARBIRD_VSM_VERSION) == 2)
        DWORD index;
        for (index = 0; index < $(NumSegments); index++)
        {
            if (g_VsmSegmentIndex[index].SegId == m_nSegmentIndex)
            {
                break;
            }
        }
        if(index == $(NumSegments))
        {
            // No VSM information associated with this segment
            return TRUE;
        }
        
        m_nVsmSegmentIndex = index;
        m_pVsmRangeStart = (BYTE*) ((ULONG_PTR)g_VsmSegmentIndex[m_nVsmSegmentIndex].Rva + CUtil::GetImageBase());
        m_nVsmRangeSize = g_VsmSegmentIndex[m_nVsmSegmentIndex].Pages * PAGE_SIZE;
        // Allocate a Memory Descriptor List to map the buffer.
        m_pVsmMDL = IoAllocateMdl(
            (PVOID) m_pVsmRangeStart,
            static_cast<ULONG>(m_nVsmRangeSize), 
            FALSE, 
            FALSE,
            NULL
            );

        if (m_pVsmMDL == NULL)
        {
            result = FALSE;
        }
        else 
        {
            // Pages are locked before decryption and unlocked after encryption. But 
            // to turn off the execute permission we need to create a middle and lock the
            // pages again so the MDL adequately reflects the locked state. This bumps the
            // count up to two on the physical pages so an unlock is done to take the count
            // back to one. 
            //
            // There is big assumption, if the ProbeAndLock fails during the decrypt
            // phase it will also fail during the encrypt phase so the counts are
            // accurate.
            __try
            {
                LOCK_OPERATION Operation = IoModifyAccess;
                MmProbeAndLockPages(
                    m_pVsmMDL, 
                    KernelMode, 
                    Operation );

                // 
                // Make sure pages are non-executable before we try to write 
                // to them.
                if(!ConvertPageProperties(TRUE))
                {
                    MmUnlockPages(m_pVsmMDL);
                    result = FALSE;
                }
                else 
                {

                    if(!m_bEncrypting)
                    {
                        PVOID handle;
                        PVOID VA = (PVOID) ((ULONG_PTR)g_VsmSegmentIndex[m_nVsmSegmentIndex].Rva + CUtil::GetImageBase());
                        handle = MmLockPagableDataSection(VA);
                        m_nLocks++;
                    }
                    
                    m_pVsmRangeStartWritableAddress = static_cast<PBYTE>
                        (MmGetSystemAddressForMdlSafe(
                            m_pVsmMDL, 
                            (MM_PAGE_PRIORITY)(HighPagePriority | MdlMappingNoExecute)));
                }
                
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                result = FALSE;
                m_nAborts++;
            }

        }

        if(!result && m_pVsmMDL != NULL)
        {
            IoFreeMdl(m_pVsmMDL);
            m_pVsmMDL = NULL;
        }
#endif // ($(WARBIRD_VSM_VERSION) == 2)
        return result;
    }

    BOOL
    RevertImageProtection()
    {
        BOOL result = TRUE;
#if ($(WARBIRD_VSM_VERSION) == 2)
        if (m_pVsmMDL != NULL)
        {
            if(m_bEncrypting)
            {
                PVOID handle;
                // Call it here to get the handle, guaranteed to be the same as when the decryption happened.
                PVOID VA = (PVOID) ((ULONG_PTR)g_VsmSegmentIndex[m_nVsmSegmentIndex].Rva + CUtil::GetImageBase());
                handle = MmLockPagableDataSection(VA);
                m_nLocks++;

                // Need to call this twice, once to remove the lock for decrypting and once for encrypting
                MmUnlockPagableImageSection(handle);
                m_nUnlocks++;
                MmUnlockPagableImageSection(handle);
                m_nUnlocks++;
            }
            else 
            {
                result = ConvertPageProperties(FALSE);
            }

            MmUnlockPages(m_pVsmMDL);
            IoFreeMdl(m_pVsmMDL);
            m_pVsmMDL = NULL;

        }
        m_pVsmRangeStart = NULL;
        m_pVsmRangeStartWritableAddress = NULL;
        m_nVsmRangeSize = 0;
        m_nVsmSegmentIndex = 0;
        m_nMappedPagesOffset = 0;
#endif // ($(WARBIRD_VSM_VERSION) == 2)
        return result;
    }

    VOID 
    RevertCurrentRangeProtection( )
    {
        if (m_pMDL != NULL)
        {
            if( m_nMappedPagesOffset != 0)
            {
                MmUnmapLockedPages(
                    m_pRangeStart + m_nMappedPagesOffset,
                    m_pMDL);
                m_nMappedPagesOffset = 0;
            }
            
            if (m_fPagesAreLocked)
            {
                MmUnlockPages(m_pMDL);
                m_fPagesAreLocked = FALSE;
            }

            IoFreeMdl(m_pMDL);
            m_pMDL = NULL;
        }
    }

    //
    // Start == true when starting the encypted/decrypt pass
    //       == false when doing cleanup
    BOOL
    ConvertPageProperties(BOOL disableExecute)
    {
#if ($(WARBIRD_VSM_VERSION) == 2)

        NTSTATUS Status;
        VSM_HASH_TABLE* table = GetVsmHashTable();
        ULONG pages = g_VsmSegmentIndex[m_nVsmSegmentIndex].Pages;
        ULONG hashIndex = g_VsmSegmentIndex[m_nVsmSegmentIndex].Index;
        ULONG flag;
                
        // If we starting either encrypting or decrypting
        // then we need to disable execute (operations will
        // require write ability to the pages)
        if(disableExecute)
        {
            flag = MM_CHANGE_DISABLE_EXECUTE;
        }
        else 
        {
            flag = MM_CHANGE_ENABLE_EXECUTE;
            if (m_pVsmRangeStartWritableAddress != NULL)
            {
                // Unmap the writable pages, the underlying
                // pages cannot be marked executable when
                // they can be written to
                MmUnmapLockedPages(
                    m_pVsmRangeStartWritableAddress,
                    m_pVsmMDL);
                m_pVsmRangeStartWritableAddress = NULL;
            }
        }

#if defined(WARBIRD_VSM_TEST)
        Status = WarbirdRuntime::MmChangeImageProtection(
            m_pVsmMDL,
            table->Hashes[hashIndex].HashBuffer,
            pages * $(WARBIRD_VSM_HASH_LENGTH),
            flag);
#else  // defined(WARBIRD_VSM_TEST)
        Status = MmChangeImageProtection(
            m_pVsmMDL,
            table->Hashes[hashIndex].HashBuffer,
            pages * $(WARBIRD_VSM_HASH_LENGTH),
            flag);
#endif // defined(WARBIRD_VSM_TEST)
        if(!NT_SUCCESS(Status))
        {
            return FALSE;
        }

#else  // ($(WARBIRD_VSM_VERSION) == 2)
        UNREFERENCED_PARAMETER(disableExecute);
#endif // ($(WARBIRD_VSM_VERSION) == 2)
        return TRUE;
    } 

private:

    // Memory desriptor list that holds the page range.
    MDL*    m_pMDL;

    // Used for for VSM locking
    MDL*    m_pVsmMDL;

    // Set to TRUE after pages are locked in memory.
    BOOL    m_fPagesAreLocked;

    // For VSM the whole region is made writeable
    BYTE*   m_pVsmRangeStart;
    
    // Alternate pages are made writable (point to the same physical pages)
    BYTE*   m_pVsmRangeStartWritableAddress;

    // Total size of the current VSM section
    SIZE_T m_nVsmRangeSize;
 
    // Index into VSM global structures for the current VSM section
    SIZE_T m_nVsmSegmentIndex;

    // Counters
    static SIZE_T m_nLocks;
    static SIZE_T m_nUnlocks;
    static SIZE_T m_nAborts;

#else // defined(WARBIRD_KERNEL_MODE)

//
// User mode helper is more straightforward; we just mark the page(s) as R/W/X 
// during the operations.
//
private:
    BOOL
    InitInternal(
        )
    {
        m_fPageProtectionChanged = FALSE;
        m_OldProtect = 0;
        return TRUE;
    }

    BOOL 
    MakeCurrentRangeWritable(
        )
    {
        // Enable automatic code generation so the page properties can be
        // changed to read-write-execute. Disabled when class goes out of
        // scope

        AutoEnableDynamicCodeGen codeGen(true);

        m_fPageProtectionChanged = VirtualProtect( 
            m_pRangeStart,
            m_nRangeSize, 
            PAGE_EXECUTE_READWRITE, 
            &m_OldProtect
            );

        return m_fPageProtectionChanged;
    }

    BOOL
    RevertImageProtection()
    {
        return TRUE;
    }
   
    VOID 
    RevertCurrentRangeProtection(
        )
    {
        if (m_fPageProtectionChanged)
        {
            // Enable automatic code generation in case the old pages properties
            // use execute.

            AutoEnableDynamicCodeGen codeGen(true);

            VirtualProtect( 
                m_pRangeStart,
                m_nRangeSize, 
                m_OldProtect, 
                &m_OldProtect
                );

            m_fPageProtectionChanged = FALSE;
        }
    }

  public:
        
private:
    // Set to TRUE if VirtualProtect succeeds.
    BOOL    m_fPageProtectionChanged;

    // Previous access protection value.
    DWORD   m_OldProtect;

#endif // defined(WARBIRD_KERNEL_MODE)

}; // class CMemoryProtectionChangeHelper


template<
    SIZE_T Runtime,
    typename Cipher, 
    typename HashFunction,
    typename EncryptedSegmentConstData,
    typename EncryptedSegmentReadWriteData
    >
class CEncryption
{
public:

    static HRESULT
    Encrypt(
        __in    EncryptedSegmentConstData*      pEncryptedSegmentConstData,
        __in    EncryptedSegmentReadWriteData*  pEncryptedSegmentReadWriteData
        )
    {
        HRESULT hr = S_OK;

        if (!pEncryptedSegmentConstData->fIsProcessed)
            return S_OK;

        g_encryptionLock.Acquire();

        DebugPrint("%s DecryptCount %d\n", __FUNCTION__, pEncryptedSegmentReadWriteData->DecryptCount);

        if (pEncryptedSegmentReadWriteData->DecryptCount == 1)
        {
            //
            // Only encrypt the segment if it is in the clear. The count should
            // never be negative. Encryption is done on best effort basis - if there's
            // a failure during encryption (such as an out-of-memory condition) we may 
            // leave some blocks in the clear. This is considered "okay" because the 
            // hacker has already seen them in the clear in memory at least once before.
            //
            hr = DoCrypt(pEncryptedSegmentConstData, pEncryptedSegmentReadWriteData, TRUE);

            pEncryptedSegmentReadWriteData->DecryptCount = 0;

        }
        else if (pEncryptedSegmentReadWriteData->DecryptCount == EncryptedSegmentReadWriteData::MAX_DECRYPT_COUNT)
        {
            //
            // If the counter reached max, then WARBIRD_DECRYPT/WARBIRD_ENCRYPT must be unbalanced.
            // This is a warbird usage bug. In order not to wraparound, stop counting and leave the 
            // segment in the clear.
            //
            WARBIRD_ASSERT(FALSE);
        }
        else if (pEncryptedSegmentReadWriteData->DecryptCount == 0)
        {
            //
            // Trying to encrypt an already encrypted segment is a warbird usage bug.
            //
            WARBIRD_ASSERT(FALSE);
        }
        else
        {
            //
            // Otherwise, decrement the counter.
            //
            pEncryptedSegmentReadWriteData->DecryptCount -= 1;
        }

        g_encryptionLock.Release();

        return hr;
    }

    static HRESULT
    Decrypt(
        __in    EncryptedSegmentConstData*      pEncryptedSegmentConstData,
        __in    EncryptedSegmentReadWriteData*  pEncryptedSegmentReadWriteData
        )
    {
        HRESULT hr = S_OK;

        if (!pEncryptedSegmentConstData->fIsProcessed)
        {
            return S_OK;
        }

        g_encryptionLock.Acquire();

        DebugPrint("%s DecryptCount %d\n", __FUNCTION__, pEncryptedSegmentReadWriteData->DecryptCount);

        if (pEncryptedSegmentReadWriteData->DecryptCount == 0)
        {
            //
            // Only decrypt the segment if it is encrypted. However, increment the
            // decrypt count only if decryption succeeds. If there's a failure during 
            // decryption (such as an out-of-memory condition), we may leave some blocks 
            // in the clear, but we will return an error HRESULT and leave the retry/no retry 
            // decision to the caller.
            //
            hr = DoCrypt(pEncryptedSegmentConstData, pEncryptedSegmentReadWriteData, FALSE);

            if (SUCCEEDED(hr))
            {
                pEncryptedSegmentReadWriteData->DecryptCount = 1;
            }
        }
        else if (pEncryptedSegmentReadWriteData->DecryptCount == EncryptedSegmentReadWriteData::MAX_DECRYPT_COUNT)
        {
            //
            // If the counter reached max, then WARBIRD_DECRYPT/WARBIRD_ENCRYPT must be unbalanced. 
            // This is a warbird usage bug. In order not to wraparound, stop counting and leave the 
            // segment in the clear.
            //
            WARBIRD_ASSERT(FALSE);
        }
        else
        {
            //
            // Otherwise, increment the counter.
            //
            pEncryptedSegmentReadWriteData->DecryptCount += 1;
        }

        g_encryptionLock.Release();

        return hr;
    }

    static void
    Print(
        __in    EncryptedSegmentConstData*      pEncryptionSegment
        )
    {
        DebugPrint("Encryption Segment %p\n", pEncryptionSegment);
        DebugPrint("  SegmentID = %d\n", pEncryptionSegment->nSegmentIndex);
        DebugPrint("  nNumBlocks = %d\n", pEncryptionSegment->nNumBlocks);
        for(ULONG i = 0; i < pEncryptionSegment->nNumBlocks; ++i)
        {
            DebugPrint("  Block[%d]\n", i);
            DebugPrint("    Rva %X\n", pEncryptionSegment->Blocks[i].RVA);
            DebugPrint("    Size %X\n", pEncryptionSegment->Blocks[i].nSize);
        }
    }

private:

    static HRESULT
    DoCrypt(
        __in    EncryptedSegmentConstData*      pEncryptedSegmentConstData,
        __in    EncryptedSegmentReadWriteData*  pEncryptedSegmentReadWriteData,
                BOOL                            bEncrypt
        )
    {
        HRESULT hr = S_OK;

        CMemoryProtectionChangeHelper MemoryProtectionChangeHelper;
        if(!MemoryProtectionChangeHelper.Init(pEncryptedSegmentConstData->nSegmentIndex, bEncrypt))
        {
            return E_ACCESSDENIED;
        }

        for (ULONG nBlockIndex = 0;
             nBlockIndex < pEncryptedSegmentConstData->nNumBlocks && SUCCEEDED(hr);
             ++nBlockIndex)
        {
            //
            // Calculate the location of the symbol to decrypt
            //
            CONST BYTE* pSource = (CONST BYTE*) (pEncryptedSegmentConstData->Blocks[nBlockIndex].RVA + CUtil::GetImageBase());
            ULONG nSize = pEncryptedSegmentConstData->Blocks[nBlockIndex].nSize;

            // Mark the memory pages that cover the block as writable
            BYTE* pTarget = NULL;
            
            pTarget = MemoryProtectionChangeHelper.MakeWritable(pSource, nSize, pEncryptedSegmentConstData->nSegmentIndex);
            if (pTarget != NULL)
            { 
                WarbirdCrypto::CKey Key;
                Key.u64 = pEncryptedSegmentConstData->Key;

                if (bEncrypt)
                {
                    if (pEncryptedSegmentReadWriteData->Blocks[nBlockIndex].fIsEncrypted == FALSE)
                    {
                        WarbirdCrypto::CChecksum Checksum;

                        Encrypt(
                            pSource,
                            pTarget,
                            nSize,
                            Key,
                            pEncryptedSegmentConstData->Blocks[nBlockIndex].RVA,
                            &Checksum
                            );

                        pEncryptedSegmentReadWriteData->Blocks[nBlockIndex].Checksum = Checksum;
                        pEncryptedSegmentReadWriteData->Blocks[nBlockIndex].fIsEncrypted = TRUE;
                    }
                }
                else
                {
                    if (pEncryptedSegmentReadWriteData->Blocks[nBlockIndex].fIsEncrypted == TRUE)
                    {
                        Decrypt(
                            pSource,
                            pTarget,
                            nSize,
                            Key,
                            pEncryptedSegmentConstData->Blocks[nBlockIndex].RVA,
                            pEncryptedSegmentReadWriteData->Blocks[nBlockIndex].Checksum,
                            pEncryptedSegmentReadWriteData->Blocks[nBlockIndex].fIsRelocated ? FALSE : TRUE
                            );
                        
                        pEncryptedSegmentReadWriteData->Blocks[nBlockIndex].fIsRelocated = TRUE;
                        pEncryptedSegmentReadWriteData->Blocks[nBlockIndex].fIsEncrypted = FALSE;
                    }
                }
            }
            else
            {
                hr = E_OUTOFMEMORY;
            }
        }

        if(!MemoryProtectionChangeHelper.Cleanup())
        {
#ifdef WARBIRD_TEST
            g_pTestClass->ReportVerifyFailure();
#else // WARBIRD_TEST
            CTermination::TrashStack();
#endif // WARBIRD_TEST
        }

        return hr;
    }

    static VOID
    Encrypt(
        __in_bcount(nBytes)     CONST BYTE*                 pSource,
        __out_bcount(nBytes)    BYTE*                       pTarget,
        __in                    SIZE_T                      nBytes,
                                WarbirdCrypto::CKey         Key,
                                ULONG                       IV,
        __out                   WarbirdCrypto::CChecksum*   pChecksum
        )
    {
        DebugPrint("  Buffer %p Size %d\n", pSource, nBytes);

        Cipher cipher;

        cipher.Encrypt(
            pSource,
            pTarget,
            nBytes,
            Key,
            IV,
            pChecksum
            );
    }

    static VOID
    Decrypt(
        __in_bcount(nBytes)     CONST BYTE*                 pSource,
        __out_bcount(nBytes)    BYTE*                       pTarget,
        __in                    SIZE_T                      nBytes,
                                WarbirdCrypto::CKey         Key,
                                ULONG                       IV,
                                WarbirdCrypto::CChecksum    Checksum,
        __in                    BOOL                        bHandleRelocations
        )
    {
        CPrivateRelocationsTable relocations;

        if (bHandleRelocations)
        {
            relocations.Init((ULONG)(pSource - (BYTE*)CUtil::GetImageBase()), static_cast<ULONG> (nBytes));

            ApplyRelocations(
                relocations,
                pTarget - pSource,
                CUtil::GetPreferedImageBase() - CUtil::GetImageBase()
                );
        }

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

        if (bHandleRelocations)
        {
            ApplyRelocations(
                relocations,
                pTarget - pSource,
                CUtil::GetImageBase() - CUtil::GetPreferedImageBase()
                );
        }

        if (CalcChecksum != Checksum)
        {
#ifdef WARBIRD_TEST
            g_pTestClass->ReportVerifyFailure();
#else  // WARBIRD_TEST
            CTermination::TrashStack();
#endif // WARBIRD_TEST
        }

        //
        // Clear the instruction cache otherwise the CPU might attempt to execute
        // encrypted instructions.
        //
        CUtil::FlushCpuCache(pSource, nBytes);
    }

    static VOID
    ApplyRelocations(
        CPrivateRelocationsTable    relocations,
        UINT_PTR                    nSourceToTargetDelta,
        UINT_PTR                    nRelocationDelta
        )
    {
        PRIVATE_RELOCATION_ITEM nReloc = {0};

        while (relocations.GetNextReloc(&nReloc))
        {
            BYTE* pReloc = (BYTE*) CUtil::GetImageBase() + 
                nReloc.RVA;

            relocations.ApplyRelocation(
                pReloc,
                nReloc.RelocationType,
                nRelocationDelta,
                pReloc + nSourceToTargetDelta
                );
        }
    }
};

#if defined(WARBIRD_KERNEL_MODE)
__declspec(selectany) SIZE_T CMemoryProtectionChangeHelper::m_nLocks = 0;
__declspec(selectany) SIZE_T CMemoryProtectionChangeHelper::m_nUnlocks = 0;
__declspec(selectany) SIZE_T CMemoryProtectionChangeHelper::m_nAborts = 0;
#endif // defined(WARBIRD_KERNEL_MODE)

}; // namespace WarbirdRuntime




#if defined(WARBIRD_VSM_TEST) && !defined(WARBIRD_KERNEL_MODE_PRESET)
#undef WARBIRD_KERNEL_MODE
#endif //defined(WARBIRD_VSM_TEST) && !defined(WARBIRD_KERNEL_MODE_PRESET)

#endif // $(WARBIRD_ENABLE_ENCRYPTION)
