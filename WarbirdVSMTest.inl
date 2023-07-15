// 
// Emulation support for running in two modes when 
// 1) User-mode 
//      WARBIRD_VSM_TEST - is defined
//      WARBIRD_KERNEL_MODE - is defined locally
//      WARBIRD_KERNEL_MODE_PRESET - is not defined
// 2) Kernel-mode : uses kernel Mm functions except for MmChangeImageProtection
//      WARBIRD_VSM_TEST - is defined
//      WARBIRD_KERNEL_MODE - is defined
//      WARBIRD_KERNEL_MODE_PRESET - is defined
//
#if defined(WARBIRD_VSM_TEST)

namespace WarbirdRuntime
{

// Dummy Mode - fakes kernel
#if defined(WARBIRD_KERNEL_MODE)
// Test mode + kernel mode implies we do not have the VSM available but are running
// in kernel
#define WARBIRD_KERNEL_MODE_PRESET
#else  // WARBIRD_KERNEL_MODE
// For VSM_TEST -  emulate some of the kernel functions in user mode
#define WARBIRD_KERNEL_MODE 1
#endif // WARBIRD_KERNEL_MODE

#if defined(WARBIRD_KERNEL_MODE_PRESET)
#define ZeroMemory RtlZeroMemory 
#else  // defined(WARBIRD_KERNEL_MODE_PRESET)

// Psuedo Kernel mode (actually running in user-mode - for testing only!)

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

typedef enum _LOCK_OPERATION {
  IoReadAccess,
  IoWriteAccess,
  IoModifyAccess
} LOCK_OPERATION;

typedef enum _MM_PAGE_PRIORITY {
  LowPagePriority,
  NormalPagePriority = 16,
  HighPagePriority = 32,
} MM_PAGE_PRIORITY;

#ifndef MdlMappingNoExecute
#define MdlMappingNoExecute     0x40000000  // Create the mapping as noexecute
#endif // MdlMappingNoExecute

#define MDL_MAPPED_TO_SYSTEM_VA     0x0001
#define MDL_PAGES_LOCKED            0x0002
#define MDL_SOURCE_IS_NONPAGED_POOL 0x0004
#define MDL_ALLOCATED_FIXED_SIZE    0x0008
#define MDL_PARTIAL                 0x0010
#define MDL_PARTIAL_HAS_BEEN_MAPPED 0x0020
#define MDL_IO_PAGE_READ            0x0040
#define MDL_WRITE_OPERATION         0x0080
#define MDL_PARENT_MAPPED_SYSTEM_VA 0x0100
#define MDL_LOCK_HELD               0x0200

typedef struct _MDL
{
    PVOID StartVa;
    ULONG ByteCount;
    ULONG MdlFlags;
} MDL, *PMDL, *PMDLX;

typedef struct _Irp
{
    PVOID dummy;
} IRP, *PIRP;

typedef enum _MODE {
    KernelMode,
    UserMode,
    MaximumMode
} MODE;

#define KPROCESSOR_MODE int

typedef BOOL BOOLEAN;
typedef ULONG NTSTATUS;

PVOID
MmLockPagableDataSection (
    _In_ PVOID AddressWithinSection
    )
{
    return AddressWithinSection;
}

VOID
MmUnlockPagableImageSection(
    IN PVOID ImageSectionHandle
    )
{
    UNREFERENCED_PARAMETER(ImageSectionHandle);
}

PMDL IoAllocateMdl(
  _In_opt_     PVOID VirtualAddress,
  _In_         ULONG Length,
  _In_         BOOLEAN SecondaryBuffer,
  _In_         BOOLEAN ChargeQuota,
  _Inout_opt_  PIRP Irp
)
{
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(SecondaryBuffer);
    UNREFERENCED_PARAMETER(ChargeQuota);
    UNREFERENCED_PARAMETER(Irp);
    PMDL m = new MDL;
    m->StartVa = VirtualAddress;
    m->ByteCount = Length;
    return m;
}

VOID MmProbeAndLockPages(
  _Inout_  PMDLX MemoryDescriptorList,
  _In_     KPROCESSOR_MODE AccessMode,
  _In_     LOCK_OPERATION Operation
)
{
    UNREFERENCED_PARAMETER(AccessMode);

    DWORD protect;
    DWORD OldProtect;

    switch(Operation)
    {
        case IoReadAccess:
            protect = PAGE_READONLY;
            break;
        case IoWriteAccess:
        case IoModifyAccess:
        default:
            protect = PAGE_READWRITE;
    }

    VirtualProtect( 
        MemoryDescriptorList->StartVa,
        MemoryDescriptorList->ByteCount,
        protect, 
        &OldProtect );
}

PVOID MmGetSystemAddressForMdlSafe(
  _In_  PMDL Mdl,
  _In_  MM_PAGE_PRIORITY Priority
)
{
    UNREFERENCED_PARAMETER(Priority);
    return Mdl->StartVa;
}

VOID MmUnlockPages(
  _Inout_  PMDL MemoryDescriptorList
)
{
    UNREFERENCED_PARAMETER(MemoryDescriptorList);
}

VOID
MmUnmapLockedPages (
    _In_ PVOID BaseAddress,
    _Inout_ PMDL MemoryDescriptorList
    )
{
    UNREFERENCED_PARAMETER(BaseAddress);
    UNREFERENCED_PARAMETER(MemoryDescriptorList);

    return;
}

VOID IoFreeMdl(
  _In_  PMDL Mdl
)
{
    delete Mdl;
}
#endif  // defined(WARBIRD_KERNEL_MODE_PRESET)

typedef NTSTATUS (WINAPI * PFNBCryptOpenAlgorithmProvider)(
    __out                           BCRYPT_ALG_HANDLE   *phAlgorithm,
    __in                            LPCWSTR             pszAlgId,
    __in_opt                        LPCWSTR             pszImplementation,
    __in                            ULONG               dwFlags
    );

typedef NTSTATUS (WINAPI * PFNBCryptCreateHash)(
    __inout                         BCRYPT_ALG_HANDLE   hAlgorithm,
    __out                           BCRYPT_HASH_HANDLE  *phHash,
    __out_bcount_full(cbHashObject) PUCHAR              pbHashObject,
    __in                            ULONG               cbHashObject,
    __in_bcount_opt(cbSecret)       PUCHAR              pbSecret,
    __in                            ULONG               cbSecret,
    __in                            ULONG               dwFlags
    );

typedef NTSTATUS (WINAPI * PFNBCryptHashData)(
    __inout                 BCRYPT_HASH_HANDLE          hHash,
    __in_bcount(cbInput)    PUCHAR                      pbInput,
    __in                    ULONG                       cbInput,
    __in                    ULONG                       dwFlags
    );

typedef NTSTATUS (WINAPI * PFNBCryptFinishHash)(
    __inout                     BCRYPT_HASH_HANDLE      hHash,
    __out_bcount_full(cbOutput) PUCHAR                  pbOutput,
    __in                        ULONG                   cbOutput,
    __in                        ULONG                   dwFlags
    );

typedef NTSTATUS (WINAPI * PFNBCryptCloseAlgorithmProvider)(
    __inout                     BCRYPT_ALG_HANDLE       hAlgorithm,
    __in                        ULONG                   dwFlags
    );

typedef NTSTATUS (WINAPI * PFNBCryptDestroyHash)(
    __inout                     BCRYPT_HASH_HANDLE      hHash
    );

HMODULE g_hBcryptPrimitives = NULL;
PFNBCryptCreateHash g_pfnBCryptCreateHash = NULL;
PFNBCryptHashData g_pfnBCryptHashData = NULL;
PFNBCryptFinishHash g_pfnBCryptFinishHash = NULL;
PFNBCryptCloseAlgorithmProvider g_pfnBCryptCloseAlgorithmProvider = NULL;
PFNBCryptDestroyHash g_pfnBCryptDestroyHash = NULL;
BCRYPT_ALG_HANDLE g_hSignatureHashProvider = NULL;

BOOL SetupBcrypt( )
{

    PFNBCryptOpenAlgorithmProvider pfnBCryptOpenAlgorithmProvider = NULL;
#if defined(WARBIRD_KERNEL_MODE_PRESET)
    pfnBCryptOpenAlgorithmProvider = BCryptOpenAlgorithmProvider;
    g_pfnBCryptCreateHash = BCryptCreateHash;
    g_pfnBCryptHashData = BCryptHashData;
    g_pfnBCryptFinishHash = BCryptFinishHash;
    g_pfnBCryptCloseAlgorithmProvider = BCryptCloseAlgorithmProvider;
    g_pfnBCryptDestroyHash = BCryptDestroyHash;
#else  // defined(WARBIRD_KERNEL_MODE_PRESET)
    if(g_hBcryptPrimitives == NULL)
    {
        g_hBcryptPrimitives = LoadLibraryEx(
            "bcrypt.dll", 
            NULL, 
            LOAD_LIBRARY_SEARCH_SYSTEM32 );
        
        if (g_hBcryptPrimitives)
        {
            pfnBCryptOpenAlgorithmProvider = (PFNBCryptOpenAlgorithmProvider)GetProcAddress(g_hBcryptPrimitives, "BCryptOpenAlgorithmProvider");
            g_pfnBCryptCreateHash = (PFNBCryptCreateHash)GetProcAddress(g_hBcryptPrimitives, "BCryptCreateHash");
            g_pfnBCryptHashData = (PFNBCryptHashData)GetProcAddress(g_hBcryptPrimitives, "BCryptHashData");
            g_pfnBCryptFinishHash = (PFNBCryptFinishHash)GetProcAddress(g_hBcryptPrimitives, "BCryptFinishHash");
            g_pfnBCryptCloseAlgorithmProvider = (PFNBCryptCloseAlgorithmProvider)GetProcAddress(g_hBcryptPrimitives, "BCryptCloseAlgorithmProvider");
            g_pfnBCryptDestroyHash = (PFNBCryptDestroyHash)GetProcAddress(g_hBcryptPrimitives, "BCryptDestroyHash");

        }
        else 
        {
            return FALSE;
        }
    }
#endif // defined(WARBIRD_KERNEL_MODE_PRESET)
    LPCWSTR algId;
    HRESULT hr;
    VSM_HASH_TABLE* table = GetVsmHashTable();

    if ( (table->Version == 2) && (table->HashAlgorithm == CALG_SHA_512) )
    {
        algId = BCRYPT_SHA512_ALGORITHM;
    }
    else 
    {
        algId = BCRYPT_SHA256_ALGORITHM;
    }

    hr = HRESULT_FROM_NT(pfnBCryptOpenAlgorithmProvider(
                             &g_hSignatureHashProvider,
                             algId,
                             NULL,
                             0 ));
    if(FAILED(hr))
    {
        return FALSE;
    }
    

    return TRUE;
}

void ShutDownBcrypt()
{
    if (g_hSignatureHashProvider)
    {
        g_pfnBCryptCloseAlgorithmProvider(g_hSignatureHashProvider, 0);
    }
#if defined(WARBIRD_KERNEL_MODE_PRESET)
#else  // defined(WARBIRD_KERNEL_MODE_PRESET)
    if (g_hBcryptPrimitives)
    {
        FreeLibrary(g_hBcryptPrimitives);
        g_hBcryptPrimitives = NULL;
    }
#endif // defined(WARBIRD_KERNEL_MODE_PRESET)
}

HRESULT VerifyCodePages( _In_reads_bytes_(PageCount * PAGE_SIZE) PVOID BaseAddress,
                         _In_ SIZE_T TotalSize,
                         PVOID SignatureBlock,
                         ULONG SignatureSize)
{

    HRESULT hr = S_OK;
    
    BCRYPT_HASH_HANDLE hHash = NULL;
    PBYTE pBuffer = (BYTE *)BaseAddress;
    ULONG nSize = PAGE_SIZE;
    ULONG PageCount = (ULONG) (TotalSize / PAGE_SIZE);
    ULONG HashLength = 0;
    BYTE bHash[512/8];
    PBYTE bHashStart = NULL;

    SIZE_T HashLimit = SignatureSize / $(WARBIRD_VSM_HASH_LENGTH);
    VSM_HASH_TABLE* table = GetVsmHashTable();
    
    WARBIRD_ASSERT(PageCount == SignatureSize / $(WARBIRD_VSM_HASH_LENGTH));

    if(HashLimit != PageCount)
    {
        return E_ACCESSDENIED;
    }
            
    if ( (table->Version == 2) && (table->HashAlgorithm == CALG_SHA_512) )
    {
        HashLength = 512 / 8;
        if(table->Flag == WARBIRD_VSM_HASH_UPPER_HALF)
        {
            bHashStart = &(bHash[HashLength/2]);
        }
        else
        {
            bHashStart = bHash;
        }
    }
    else 
    {
        HashLength = 256 / 8;
        bHashStart = bHash;
    }

    for (ULONG pageIndex = 0; pageIndex < PageCount; pageIndex++)
    {
        PBYTE pData = pBuffer + pageIndex*nSize;
        ZeroMemory(bHash, HashLength);

        hr = HRESULT_FROM_NT(g_pfnBCryptCreateHash(
                                 g_hSignatureHashProvider,
                                 &hHash,
                                 NULL, 
                                 0, 
                                 NULL,
                                 0,
                                 0 )); 
        if(FAILED(hr))
        {
            goto Cleanup;
        }
        

#if defined(_M_IX86)
        //
        // We need to handle relocations when we are calculating the page hashes.
        // We cannot use the private relocation table in this case because the 
        // compiler is outlining some code when using the flag d2dbstressoutline 
        // which is not encrypted and hence relocations are not part of the private 
        // relocation table but only part of the OS relocation table.
        //
        ULONG nRva = (ULONG)((ULONG_PTR)pData - WarbirdRuntime::CUtil::GetImageBase());
        WarbirdRuntime::CRelocations relocations;
        relocations.Init(nRva, nSize);
        
        WarbirdRuntime::COSRelocationBlock UNALIGNED* pOSRelocationBlock;
        SIZE_T  nOSRelocationItem;
        
        bool hasNextReloc = relocations.GetNext(&nOSRelocationItem, &pOSRelocationBlock);
        
        for(SIZE_T nByteIndex = 0; nByteIndex < nSize;)
        {
            if (hasNextReloc && 
                (nByteIndex + nRva == pOSRelocationBlock->RVA() + (*pOSRelocationBlock)[nOSRelocationItem].Offset))
            {
                BYTE relocBuffer[16] = {0};
                SIZE_T nRelocBytes = relocations.ApplyRelocation(
                    &pData[nByteIndex],
                    (*pOSRelocationBlock)[nOSRelocationItem].Type,
                    WarbirdRuntime::CUtil::GetPreferedImageBase() - WarbirdRuntime::CUtil::GetImageBase(),
                    relocBuffer
                                                                 );
                
                hr = HRESULT_FROM_NT(g_pfnBCryptHashData(hHash, relocBuffer, nRelocBytes, 0));
                nByteIndex += nRelocBytes;
                hasNextReloc = relocations.GetNext(&nOSRelocationItem, &pOSRelocationBlock);
            }
            else
            {
                hr = HRESULT_FROM_NT(g_pfnBCryptHashData(hHash, &pData[nByteIndex], 1, 0));
                ++nByteIndex;
            }
            if(FAILED(hr))
            {
                goto Cleanup;
            }
        }
#else  // defined(_M_IX86)
        hr = HRESULT_FROM_NT(g_pfnBCryptHashData(hHash, pData, nSize, 0));
        if(FAILED(hr))
        {
            goto Cleanup;
        }
#endif // defined(_M_IX86)

        hr = HRESULT_FROM_NT(g_pfnBCryptFinishHash(hHash, bHash, HashLength, 0));
        if(FAILED(hr))
        {
            goto Cleanup;
        }
        
        PVOID signature = (PVOID) (((PBYTE)SignatureBlock) + (pageIndex * $(WARBIRD_VSM_HASH_LENGTH)));
        ULONG difference = memcmp( bHashStart, signature, $(WARBIRD_VSM_HASH_LENGTH) );
        if(difference != 0)
        {
            hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            goto Cleanup;
        }
        
        g_pfnBCryptDestroyHash(hHash);
        hHash = NULL;
    } // For

#if !defined(WARBIRD_KERNEL_MODE_PRESET)
    // If emulating KERNEL mode in UserMode there is only one set of
    // virtual pages, therefore the protection must be set back to read-execute
    //
    // This is not necessary in kernel mode because there are separate virtual pages
    // pointing to the same physical pages. 
    if(SUCCEEDED(hr))
    {
        // Enable automatic code generation so the page properties can be
        // changed to read-execute. Disabled when class goes out of scope.

        AutoEnableDynamicCodeGen codeGen(true);

        DWORD OldProtect;
        VirtualProtect(BaseAddress,
                       TotalSize,
                       PAGE_EXECUTE_READ,
                       &OldProtect);
    } 
#endif // !defined(WARBIRD_KERNEL_MODE_PRESET)


  Cleanup:
    if (hHash)
    {
        g_pfnBCryptDestroyHash(hHash);
        hHash = NULL;
    }

    return hr;
}


// Coming soon for HVCI
NTSTATUS 
MmChangeImageProtection(
    PMDL CodeMdl,
    PVOID SignatureAddress,
    SIZE_T SignatureSize,
    ULONG ExecuteFlags)
{
#if !defined(WARBIRD_KERNEL_MODE_PRESET)
    if(ExecuteFlags ==  MM_CHANGE_ENABLE_EXECUTE)
    {
        if(FAILED(VerifyCodePages(CodeMdl->StartVa,
                                  CodeMdl->ByteCount,
                                  SignatureAddress,
                                  SignatureSize)))
        {
            return (NTSTATUS) -1;
        }
    }
#else  // !defined(WARBIRD_KERNEL_MODE_PRESET)
    UNREFERENCED_PARAMETER(CodeMdl);
    UNREFERENCED_PARAMETER(SignatureAddress);
    UNREFERENCED_PARAMETER(SignatureSize);
    UNREFERENCED_PARAMETER(ExecuteFlags);
#endif // !defined(WARBIRD_KERNEL_MODE_PRESET)
    return STATUS_SUCCESS;
}

}  // WarbirdRuntime


#endif // defined(WARBIRD_VSM_TEST)