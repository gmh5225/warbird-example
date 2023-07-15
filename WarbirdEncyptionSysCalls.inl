#if $(ENCRYPTION_SYSTEM_CALLS)

namespace WarbirdRuntime {

#pragma warbird(begin_foreach $(ID) $(EncryptedSegmentIDs))

//
// List of all symbols in this segment. Assign the global a value so it is not
// put in the uninitialized section (BSS).
//
__declspec(selectany) ENCRYPTION_SEGMENT g_EncryptedSegmentSystemCall_$(ID) = {$(ID)};

EXTERN_C HRESULT __fastcall WarbirdEncryptSegment$(ID)Inline()
{
    ULONG_PTR arguments[] = {
        2, // Operation Type In Place Encrypt,
        (ULONG_PTR)CUtil::GetImageBase(),
        (ULONG_PTR)CUtil::GetPreferedImageBase(),
        (ULONG_PTR)g_PrivateRelocationsTable + CUtil::GetImageBase(),
        (ULONG_PTR)g_PrivateRelocationsTableCount,
        (ULONG_PTR)&g_EncryptedSegmentSystemCall_$(ID)
    };

    return HRESULT_FROM_NTSTATUS(NtQuerySystemInformation(
        /*(SYSTEM_INFORMATION_CLASS)*/SystemCodeFlowTransition,
        (PVOID)&arguments,
        sizeof(arguments),
        NULL
        ));
}

EXTERN_C HRESULT __fastcall WarbirdEncryptSegment$(ID)NoInline()
{
    return WarbirdEncryptSegment$(ID)Inline();
}

EXTERN_C HRESULT __fastcall WarbirdDecryptSegment$(ID)Inline()
{
    ULONG_PTR arguments[] = {
        1, // Operation Type In Place Decrypt,
        (ULONG_PTR)CUtil::GetImageBase(),
        (ULONG_PTR)CUtil::GetPreferedImageBase(),
        (ULONG_PTR)g_PrivateRelocationsTable + CUtil::GetImageBase(),
        (ULONG_PTR)g_PrivateRelocationsTableCount,
        (ULONG_PTR)&g_EncryptedSegmentSystemCall_$(ID)
    };

    return HRESULT_FROM_NTSTATUS(NtQuerySystemInformation(
        /*(SYSTEM_INFORMATION_CLASS)*/SystemCodeFlowTransition,
        (PVOID)&arguments,
        sizeof(arguments),
        NULL
        ));
}

EXTERN_C HRESULT __fastcall WarbirdDecryptSegment$(ID)NoInline()
{
    return WarbirdDecryptSegment$(ID)Inline();
}

#pragma warbird(end_foreach)

}; // namespace WarbirdRuntime

#else // ENCRYPTION_SYSTEM_CALLS

#pragma warbird(begin_foreach $(ID) $(EncryptedSegmentIDs))

namespace WarbirdRuntime {
//
// The warbird globals need to be in a read write section so warbird can
// populate and expand these globals during compile time. By default the
// globals end up in the BSS section and in the windows tree are never
// initailized.
//
#define WARBIRD_ENCRYPTION_SECTION_CONST_$(ID)  STRINGIZE(.rdata$wbrdencr##$(ID))
#define WARBIRD_ENCRYPTION_SECTION_READ_WRITE_$(ID)  STRINGIZE(.data$wbrdencr##$(ID))

#pragma section(WARBIRD_ENCRYPTION_SECTION_CONST_$(ID), read)

__declspec(allocate(WARBIRD_ENCRYPTION_SECTION_CONST_$(ID)))
__declspec(selectany) ENCRYPTED_SEGMENT_DATA_CONST_$(EncryptedSegment$(ID)RuntimeIndex) g_EncryptedSegmentConstData_$(ID);

#pragma section(WARBIRD_ENCRYPTION_SECTION_READ_WRITE_$(ID), read, write)

__declspec(allocate(WARBIRD_ENCRYPTION_SECTION_READ_WRITE_$(ID)))
__declspec(selectany) ENCRYPTED_SEGMENT_DATA_READ_WRITE_$(EncryptedSegment$(ID)RuntimeIndex) g_EncryptedSegmentReadWriteData_$(ID);

}

EXTERN_C __forceinline HRESULT __fastcall WarbirdEncryptSegment$(ID)Inline()
{
    return WarbirdRuntime::CEncryption<$(EncryptedSegment$(ID)RuntimeIndex)-1,
        $(EncryptionRuntime$(EncryptedSegment$(ID)RuntimeIndex)Cipher), 
        $(EncryptionRuntime$(EncryptedSegment$(ID)RuntimeIndex)HashFunction),
        WarbirdRuntime::ENCRYPTED_SEGMENT_DATA_CONST_$(EncryptedSegment$(ID)RuntimeIndex),
        WarbirdRuntime::ENCRYPTED_SEGMENT_DATA_READ_WRITE_$(EncryptedSegment$(ID)RuntimeIndex)>::Encrypt(
                                                                    &WarbirdRuntime::g_EncryptedSegmentConstData_$(ID),
                                                                    &WarbirdRuntime::g_EncryptedSegmentReadWriteData_$(ID));
}

EXTERN_C __declspec(noinline) HRESULT __fastcall WarbirdEncryptSegment$(ID)NoInline()
{
    return WarbirdEncryptSegment$(ID)Inline();
}

EXTERN_C __forceinline HRESULT __fastcall WarbirdDecryptSegment$(ID)Inline()
{
    return WarbirdRuntime::CEncryption<$(EncryptedSegment$(ID)RuntimeIndex)-1,
        $(EncryptionRuntime$(EncryptedSegment$(ID)RuntimeIndex)Cipher), 
        $(EncryptionRuntime$(EncryptedSegment$(ID)RuntimeIndex)HashFunction),
        WarbirdRuntime::ENCRYPTED_SEGMENT_DATA_CONST_$(EncryptedSegment$(ID)RuntimeIndex),
        WarbirdRuntime::ENCRYPTED_SEGMENT_DATA_READ_WRITE_$(EncryptedSegment$(ID)RuntimeIndex)>::Decrypt(
                                                                    &WarbirdRuntime::g_EncryptedSegmentConstData_$(ID),
                                                                    &WarbirdRuntime::g_EncryptedSegmentReadWriteData_$(ID));
}

EXTERN_C __declspec(noinline) HRESULT __fastcall WarbirdDecryptSegment$(ID)NoInline()
{
    return WarbirdDecryptSegment$(ID)Inline();
}

#pragma warbird(end_foreach)

#endif // ENCRYPTION_SYSTEM_CALLS