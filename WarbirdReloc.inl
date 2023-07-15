namespace WarbirdRuntime
{

// Image base defined in delayimp.h
EXTERN_C IMAGE_DOS_HEADER __ImageBase;

/*++

    Description:

        Represents a relocation item in the private format used in this 
        program.
--*/
#include <pshpack1.h>
struct PRIVATE_RELOCATION_ITEM
{
    ULONG   RVA: RVA_BIT_COUNT;
    ULONG   RelocationType: 4;
};
#include <poppack.h>

volatile ULONG g_PrivateRelocationsTable = 0x12456908;
volatile ULONG g_PrivateRelocationsTableCount = 0x12456908;

/*++

    Description:

        Represents relocations stored in the binary in the private format used 
        in this program.

--*/
#include <pshpack1.h>
class CPrivateRelocationsTable
{
public:
    CPrivateRelocationsTable()
    {
        m_pItems = NULL;
        m_nNumItems = 0;
        m_nFirstIndex = 0;
    }

    VOID
    Init(
        __in    ULONG   nRVA, 
        __in    ULONG   nSize
        )
    {
        m_pItems = (PRIVATE_RELOCATION_ITEM*)((ULONG_PTR)(g_PrivateRelocationsTable) + CUtil::GetImageBase());
        m_nNumItems = g_PrivateRelocationsTableCount;
        m_nFirstIndex = static_cast<ULONG> (FindFirstReloc(nRVA));
        m_nEndRva = nRVA + nSize;
        m_nCurrentIndex = m_nFirstIndex;
    }

    bool
    GetNextReloc(
        __out   PRIVATE_RELOCATION_ITEM     *nReloc
        )
    {
        if (m_nCurrentIndex < m_nNumItems  &&
            m_pItems[m_nCurrentIndex].RVA < m_nEndRva)
        {
            *nReloc = m_pItems[m_nCurrentIndex];
             
            m_nCurrentIndex++;
            return true;
        }
        return false;
    }

    SIZE_T
    FindFirstReloc(
        __in    ULONG   BeginRVA
        )
    {
        int nLow = 0;
        int nHigh = m_nNumItems - 1;

        while (nHigh >= nLow) 
        {
            int nMiddle = (nLow + nHigh) / 2;

            if (BeginRVA < m_pItems[nMiddle].RVA)
            {
                nHigh = nMiddle - 1;
            } 
            else if (BeginRVA > m_pItems[nMiddle].RVA) 
            {
                nLow = nMiddle + 1;
            } 
            else 
            {
                return nMiddle;
            }
        }

        return nLow;
    }

    SIZE_T
    ApplyRelocation(
        __in    CONST VOID* pInBuffer,
                USHORT      nRelocationType,
                UINT_PTR    nDelta,
        __out   VOID*       pOutBuffer
        ) const
    {
        SIZE_T nRelocationTypeSize = 0;

        switch (nRelocationType)
        {
            case IMAGE_REL_BASED_HIGHLOW:
            {
                unsigned __int32 UNALIGNED* pAddress = (unsigned __int32 UNALIGNED*)pOutBuffer;
                WARBIRD_ASSERT(nDelta == static_cast<__int32>(nDelta));
                *pAddress = *(__int32 UNALIGNED*)pInBuffer + static_cast<__int32>(nDelta);
                nRelocationTypeSize = sizeof(__int32);
                break;
            }

#ifdef _WIN64

            case IMAGE_REL_BASED_DIR64:
            {
                unsigned __int64 UNALIGNED* pAddress = (unsigned __int64 UNALIGNED*)pOutBuffer;
                *pAddress = *(__int64 UNALIGNED*)pInBuffer + nDelta;
                nRelocationTypeSize = sizeof(__int64);
                break;
            }

#endif //_WIN64

#ifdef _ARM_
            case IMAGE_REL_BASED_THUMB_MOV32:
            {
                // Still need to figure out how to do this for ARM with an inout
                // buffer
                ULONG nAddress;
                *(PUINT64)pOutBuffer = *(PUINT64)pInBuffer;
                nAddress = ThumbExtractImmediate16((PUSHORT)pOutBuffer + 0) |
                       (ThumbExtractImmediate16((PUSHORT)pOutBuffer + 2) << 16);
                nAddress += (ULONG)nDelta;

                ThumbInsertImmediate16((PUSHORT)pOutBuffer + 0, (USHORT)nAddress);
                ThumbInsertImmediate16((PUSHORT)pOutBuffer + 2, nAddress >> 16);
                nRelocationTypeSize = sizeof(__int64);
                break;
            }
#endif //_ARM_

            case IMAGE_REL_BASED_ABSOLUTE:
                //
                // Padding relocation, do nothing
                //
                break;

            default:
                // Unknown Relocation type
                DebugPrint("Unknown relocation type %d\n", nRelocationType);
                WARBIRD_ASSERT(false);
                nRelocationTypeSize = SIZE_T(-1);
                break;
        }

        return nRelocationTypeSize;
    }

    USHORT
    ThumbExtractImmediate16(
        __in_ecount(2) PUSHORT OpcodePtr
        ) const
    {
        return ((OpcodePtr[0] << 12) & 0xf000) |  // bits[15:12] in OP0[3:0]
               ((OpcodePtr[0] <<  1) & 0x0800) |  // bits[11]    in OP0[10]
               ((OpcodePtr[1] >>  4) & 0x0700) |  // bits[10:8]  in OP1[14:12]
               ((OpcodePtr[1] >>  0) & 0x00ff);   // bits[7:0]   in OP1[7:0]
    }

    VOID
    ThumbInsertImmediate16(
        __inout_ecount(2) PUSHORT OpcodePtr,
        __in USHORT Immediate
        ) const
    {
        USHORT Opcode0;
        USHORT Opcode1;

        Opcode0 = OpcodePtr[0];
        Opcode1 = OpcodePtr[1];
        Opcode0 &= ~((0xf000 >> 12) | (0x0800 >> 1));
        Opcode1 &= ~((0x0700 <<  4) | (0x00ff << 0));
        Opcode0 |= (Immediate & 0xf000) >> 12;   // bits[15:12] in OP0[3:0]
        Opcode0 |= (Immediate & 0x0800) >>  1;   // bits[11]    in OP0[10]
        Opcode1 |= (Immediate & 0x0700) <<  4;   // bits[10:8]  in OP1[14:12]
        Opcode1 |= (Immediate & 0x00ff) <<  0;   // bits[7:0]   in OP1[7:0]
        OpcodePtr[0] = Opcode0;
        OpcodePtr[1] = Opcode1;
    }

private:

    // Number of relocations in the private relocation table
    ULONG                       m_nNumItems;

    // Pointer to the list of all relocations in the table
    PRIVATE_RELOCATION_ITEM*    m_pItems;

    // Index of the first relocation for a given RVA
    ULONG                       m_nFirstIndex;

    // Ending RVA 
    ULONG                       m_nEndRva;

    // Current index in to relocation table
    ULONG                       m_nCurrentIndex;
}; // class CPrivateRelocationsTable

#include <poppack.h> 

#if defined(WARBIRD_VSM_TEST)

//
// This code is used by the user mode VSM test to handle
// relcoations. We cannot use the private relocation table
// in this case because the compiler is outlining some code
// when using the flag d2dbstressoutline which is not encrypted
// and hence relocations are not part of the private relocation
// table but only part of the OS relocation table.
//

#include <pshpack1.h>
struct OS_RELOCATION_ITEM
{
    USHORT Offset:12;
    USHORT Type:4;
};
#include <poppack.h>

/*++

    Description:

        Represents a relocation block in the format used by the OS loader.
        The block stores all relocations in a 4K page.

--*/
#include <pshpack1.h>
class COSRelocationBlock
{
public:
    // Returns the virtual address of the base of the relocations block.
    ULONG RVA(
        ) const
    {
        return m_RVA;
    }

    // Returns the number of relocation items in the relocations block.
    SIZE_T NumItems(
        ) const
    {
        return (m_SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(OS_RELOCATION_ITEM);
    }

    // Retrieves the specified relocation item.
    CONST OS_RELOCATION_ITEM& operator [](
        SIZE_T  n
        ) const
    {
        WARBIRD_ASSERT(n < NumItems());

        return m_Items[n];
    }

    // Returns a pointer to the next relocation block in the .reloc section.
    COSRelocationBlock UNALIGNED* Next(
        )
    {
        return CUtil::AddOffset(this, m_SizeOfBlock);
    }

private:
    ULONG               m_RVA;
    ULONG               m_SizeOfBlock;
    OS_RELOCATION_ITEM  m_Items[1];
};
#include <poppack.h>

class CRelocations
{
public:
    CRelocations(
        ) :
        m_nEndBase(0),
        m_nEndOffset(0),
        m_pOSRelocationBlockEnd(NULL),
        m_pOSRelocationBlock(NULL),
        m_nOSRelocationItem(0)
    {
    }

    /*++

        Description:

            Initializes the enumeration object.

        Arguments:

            BeginRVA
                Beginning address of the region we will enumerate relocations for.

            nSize
                Size of the region we will enumerate relocations for.

        Return Value:

            None.

    --*/
    VOID
    Init(
                ULONG       BeginRVA,
                SIZE_T      nSize
        )
    {
        IMAGE_NT_HEADERS* pImageNtHeaders = (IMAGE_NT_HEADERS*)CUtil::GetImageNtHeaders(CUtil::GetImageBase());
        IMAGE_DATA_DIRECTORY* pRelocationDirectory =
                &pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        VOID* pRelocationTable = CUtil::AddOffset((void*)CUtil::GetImageBase(),  pRelocationDirectory->VirtualAddress);

        // Calculate the limits of the region we are interested in.

        SIZE_T nBeginBase = BeginRVA & ~(OS_RELOCATION_PAGE_SIZE - 1);
        SIZE_T nBeginOffset = BeginRVA - nBeginBase;

        SIZE_T EndRVA = BeginRVA + nSize;
        m_nEndBase = EndRVA & ~(OS_RELOCATION_PAGE_SIZE - 1);
        m_nEndOffset = EndRVA - m_nEndBase;

        DebugPrint("rrinit start %x\n", nBeginBase);
        DebugPrint("rrinit end %x\n", m_nEndBase);

        m_pOSRelocationBlock = reinterpret_cast<COSRelocationBlock UNALIGNED*>(pRelocationTable);
        m_pOSRelocationBlockEnd = CUtil::AddOffset(m_pOSRelocationBlock, pRelocationDirectory->Size);

        // Skip the relocation blocks until we go past the last block or the block
        // that contains the beginning of the address range.

        while (m_pOSRelocationBlock != m_pOSRelocationBlockEnd &&
            m_pOSRelocationBlock->RVA() < nBeginBase)
        {
            m_pOSRelocationBlock = m_pOSRelocationBlock->Next();
        }

        m_nOSRelocationItem = 0;

        // If we are on the block where the address range begins, skip relocations
        // until we go past the first relocation in the address range.

        if (m_pOSRelocationBlock != m_pOSRelocationBlockEnd &&
            m_pOSRelocationBlock->RVA() == nBeginBase)
        {
            while (m_nOSRelocationItem != m_pOSRelocationBlock->NumItems() &&
                (*m_pOSRelocationBlock)[m_nOSRelocationItem].Offset < nBeginOffset)
            {
                ++m_nOSRelocationItem;
            }
        }
    }

    /*++

        Description:

            Finds the next relocation in the .reloc section corresponding to
            the specified address range.
            GetNext() calls GetNextAll() to get the next relocation. If it's
            type is IMAGE_REL_BASED_ABSOLUTE then it's just padding, so it
            skips it and tries to find the next one.

        Arguments:

            pnOSRelocationItem
                Pointer to the location that will receive the index of the next
                relocation item.

            ppOSRelocationBlock
                Pointer to the location that will receive a pointer to the
                relocation block the item is located in.

        Return Value:

            true if we found another relocation in the address range, false
            otherwise.

    --*/
    bool
    GetNext(
        __out   SIZE_T*                         pnOSRelocationItem,
        __out   COSRelocationBlock UNALIGNED**  ppOSRelocationBlock
        )
    {
        bool                            fRet = false;
        COSRelocationBlock UNALIGNED*   pOSRelocationBlock = NULL;
        SIZE_T                          nOSRelocationItem = 0;

        do
        {
            fRet = GetNextAll(
                        &nOSRelocationItem,
                        &pOSRelocationBlock
                        );
            if (fRet)
            {
                //found a valid relocation item
                if ((*pOSRelocationBlock)[nOSRelocationItem].Type != IMAGE_REL_BASED_ABSOLUTE)
                {
                    *pnOSRelocationItem = nOSRelocationItem;
                    *ppOSRelocationBlock = pOSRelocationBlock;
                    break;
                }
                //else - this is just padding, skip it - try the next one
            }
        }
        while(fRet);

        return fRet;
    }

    SIZE_T
    ApplyRelocation(
        __in    CONST VOID* pInBuffer,
                USHORT      nRelocationType,
                UINT_PTR    nDelta,
        __out   VOID*       pOutBuffer
        ) const
    {
        SIZE_T nRelocationTypeSize = 0;

        switch (nRelocationType)
        {
            case IMAGE_REL_BASED_HIGHLOW:
            {
                unsigned __int32 UNALIGNED* pAddress = (unsigned __int32 UNALIGNED*)pOutBuffer;
                WARBIRD_ASSERT(nDelta == static_cast<__int32>(nDelta));
                *pAddress = *(__int32 UNALIGNED*)pInBuffer + static_cast<__int32>(nDelta);
                nRelocationTypeSize = sizeof(__int32);
                break;
            }

#ifdef _WIN64

            case IMAGE_REL_BASED_DIR64:
            {
                unsigned __int64 UNALIGNED* pAddress = (unsigned __int64 UNALIGNED*)pOutBuffer;
                *pAddress = *(__int64 UNALIGNED*)pInBuffer + nDelta;
                nRelocationTypeSize = sizeof(__int64);
                break;
            }

#endif //_WIN64

#ifdef _ARM_
            case IMAGE_REL_BASED_THUMB_MOV32:
            {
                // Still need to figure out how to do this for ARM with an inout
                // buffer
                ULONG nAddress;
                *(PUINT64)pOutBuffer = *(PUINT64)pInBuffer;
                nAddress = ThumbExtractImmediate16((PUSHORT)pOutBuffer + 0) |
                       (ThumbExtractImmediate16((PUSHORT)pOutBuffer + 2) << 16);
                nAddress += (ULONG)nDelta;

                ThumbInsertImmediate16((PUSHORT)pOutBuffer + 0, (USHORT)nAddress);
                ThumbInsertImmediate16((PUSHORT)pOutBuffer + 2, nAddress >> 16);
                nRelocationTypeSize = sizeof(__int64);
                break;
            }
#endif //_ARM_

            case IMAGE_REL_BASED_ABSOLUTE:
                //
                // Padding relocation, do nothing
                //
                break;

            default:
                // Unknown Relocation type
                DebugPrint("Unknown relocation type %d\n", nRelocationType);
                WARBIRD_ASSERT(false);
                nRelocationTypeSize = SIZE_T(-1);
                break;
        }

        return nRelocationTypeSize;
    }

    /*++

        Description:

            Finds the next relocation in the .reloc section corresponding to
            the specified address range.

        Arguments:

            pnOSRelocationItem
                Pointer to the location that will receive the index of the next
                relocation item.

            ppOSRelocationBlock
                Pointer to the location that will receive a pointer to the
                relocation block the item is located in.

        Return Value:

            true if we found another relocation in the address range, false
            otherwise.

    --*/
    bool
    GetNextAll(
        __out   SIZE_T*                         pnOSRelocationItem,
        __out   COSRelocationBlock UNALIGNED**  ppOSRelocationBlock
        )
    {
        *pnOSRelocationItem = 0;
        *ppOSRelocationBlock = NULL;

        // If we are past the last block or didn't find any blocks to begin
        // with, then exit.

        if (m_pOSRelocationBlock == m_pOSRelocationBlockEnd ||
            m_pOSRelocationBlock->RVA() > m_nEndBase)
        {
            return false;
        }

        // While there are no relocations left on this block, proceed to the next.

        while (m_pOSRelocationBlock != m_pOSRelocationBlockEnd &&
            m_nOSRelocationItem == m_pOSRelocationBlock->NumItems())
        {
            m_pOSRelocationBlock = m_pOSRelocationBlock->Next();

            // If we went past the last block or past the block that contains
            // the end of the address range, then exit.

            if (m_pOSRelocationBlock == m_pOSRelocationBlockEnd ||
                m_pOSRelocationBlock->RVA() > m_nEndBase)
            {
                return false;
            }

            m_nOSRelocationItem = 0;
        }

        // If we are on the block that contains the end of the address range
        // and went past the end, then exit.

        if (m_pOSRelocationBlock->RVA() == m_nEndBase &&
            (*m_pOSRelocationBlock)[m_nOSRelocationItem].Offset >= m_nEndOffset)
        {
            return false;
        }

        // Return this relocation and proceed to the next.

        *pnOSRelocationItem = m_nOSRelocationItem;
        *ppOSRelocationBlock = m_pOSRelocationBlock;

        ++m_nOSRelocationItem;

        return true;
    }

    USHORT
    ThumbExtractImmediate16(
        __in_ecount(2) PUSHORT OpcodePtr
        ) const
    {
        return ((OpcodePtr[0] << 12) & 0xf000) |  // bits[15:12] in OP0[3:0]
               ((OpcodePtr[0] <<  1) & 0x0800) |  // bits[11]    in OP0[10]
               ((OpcodePtr[1] >>  4) & 0x0700) |  // bits[10:8]  in OP1[14:12]
               ((OpcodePtr[1] >>  0) & 0x00ff);   // bits[7:0]   in OP1[7:0]
    }

    VOID
    ThumbInsertImmediate16(
        __inout_ecount(2) PUSHORT OpcodePtr,
        __in USHORT Immediate
        ) const
    {
        USHORT Opcode0;
        USHORT Opcode1;

        Opcode0 = OpcodePtr[0];
        Opcode1 = OpcodePtr[1];
        Opcode0 &= ~((0xf000 >> 12) | (0x0800 >> 1));
        Opcode1 &= ~((0x0700 <<  4) | (0x00ff << 0));
        Opcode0 |= (Immediate & 0xf000) >> 12;   // bits[15:12] in OP0[3:0]
        Opcode0 |= (Immediate & 0x0800) >>  1;   // bits[11]    in OP0[10]
        Opcode1 |= (Immediate & 0x0700) <<  4;   // bits[10:8]  in OP1[14:12]
        Opcode1 |= (Immediate & 0x00ff) <<  0;   // bits[7:0]   in OP1[7:0]
        OpcodePtr[0] = Opcode0;
        OpcodePtr[1] = Opcode1;
    }

private:
    // Relocation block page size as defined by the OS loader. Note that the
    // size is currently the same for 32bit and 64bit images.
    static CONST SIZE_T OS_RELOCATION_PAGE_SIZE = 4096;

    // Base of the page that contains the end of the address range to
    // enumerate relocations in.
    SIZE_T                          m_nEndBase;

    // Offset within the page that contains the end of the address range to
    // enumerate relocations in.
    SIZE_T                          m_nEndOffset;

    // End of the .reloc section.
    COSRelocationBlock UNALIGNED*   m_pOSRelocationBlockEnd;

    // Currently enumerated relocations block.
    COSRelocationBlock UNALIGNED*   m_pOSRelocationBlock;

    // Currently enumerated relocation item.
    SIZE_T                          m_nOSRelocationItem;
}; // class CRelocations
#endif

}; // namespace WarbirdRuntime
