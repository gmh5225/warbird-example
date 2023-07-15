/**
  *
  * Memory Allocator
  *
  **/

namespace WarbirdRuntime
{

#if $(WARBIRD_ENABLE_HEAP_EXECUTION) && !defined(WARBIRD_KERNEL_MODE)

class CMemoryAllocator
{
public:
    HRESULT 
    Init(
        )
    {
        // Initialize the lock.
        m_nEmptied = 0;
        m_BlockListLock.Init();

        // Allocate the first block.
        m_pCurrentBlock = CBlock::Allocate(FALSE);

        if (m_pCurrentBlock != NULL)
        {
            m_nNumBlocks = 1;
            m_nMaxBlocks = 1;
            return S_OK;
        }
        else
        {
            m_nNumBlocks = 0;
            m_nMaxBlocks = 0;
            return E_OUTOFMEMORY;
        }

    }

    VOID 
    Cleanup(
        )
    {
        // Free all blocks.

        CBlock* pBlock = m_pCurrentBlock;

        while (pBlock != NULL)
        {
            CBlock* pBlockToFree = pBlock;
            pBlock = pBlock->m_pNext;
            pBlockToFree->Free();
            --m_nNumBlocks;
        }
        
        m_pCurrentBlock = NULL;
        WARBIRD_ASSERT(m_nNumBlocks == 0);
    }

    PVOID 
    AllocateMemory(
        SIZE_T nSize
        )
    {
        WARBIRD_ASSERT(nSize > 0 && nSize < CBlock::MaxAllocationSize());

        PVOID pMemory = NULL;

        // Go in an infinite loop until we allocate the memory.

        for (;;)
        {
            // Take the shared lock and walk the block list.

            m_BlockListLock.AcquireShared();

            for (CBlock* pBlock = m_pCurrentBlock; pBlock != NULL; pBlock = pBlock->m_pNext)
            {
                pMemory = pBlock->AllocateMemory(nSize);

                if (pMemory != NULL)
                {
                    break;
                }
            }

            m_BlockListLock.ReleaseShared();

            // If allocation succeeded, exit.

            if (pMemory != NULL)
            {
                break;
            }
            
            // If not, allocate a new block after leaving the lock.

            CBlock* pNewBlock = CBlock::Allocate(TRUE);

            if (pNewBlock != NULL)
            {
                // If allocation is successful, take the exclusive lock and 
                // store the new block at the top of the linked list.

                m_BlockListLock.AcquireExclusive();

                pNewBlock->m_pNext = m_pCurrentBlock;
                m_pCurrentBlock = pNewBlock;
                ++m_nNumBlocks;
                if(m_nNumBlocks > m_nMaxBlocks)
                {
                    m_nMaxBlocks = m_nNumBlocks;
                }
                m_BlockListLock.ReleaseExclusive();
            }
        }

        WARBIRD_ASSERT(pMemory != NULL);
        return pMemory;
    }

    VOID 
    FreeMemory(
        __in PVOID pMemory
        )
    {
        CBlock* pBlockToFree = NULL;

        // Take the shared lock and walk the block list to find the memory.

        m_BlockListLock.AcquireShared();

        for (CBlock* pBlock = m_pCurrentBlock; pBlock != NULL; pBlock = pBlock->m_pNext)
        {
            if (pBlock->Contains(pMemory))
            {
                // Free the slot(s).

                pBlock->FreeMemory(pMemory);

                // If the whole block is empty after this free, and it's not the only block left, 
                // mark it as deletable.

                if (pBlock->IsEmpty())
                {
                    pBlockToFree = pBlock;
                }

                break;
            }
        }

        m_BlockListLock.ReleaseShared();

        // If the block is found to be deletable, take the exclusive lock and test again.

        if (pBlockToFree != NULL)
        {
            BOOL fOkayToFree = FALSE;

            m_BlockListLock.AcquireExclusive();

            for (CBlock** ppBlock = &m_pCurrentBlock; *ppBlock != NULL; ppBlock = &(*ppBlock)->m_pNext)
            {
                if (*ppBlock == pBlockToFree && (*ppBlock)->IsEmpty())
                {
                    if (m_nNumBlocks > 1)
                    {
                        *ppBlock = (*ppBlock)->m_pNext;
                        --m_nNumBlocks;
                        fOkayToFree = TRUE;
                    }
                    else 
                    {
                        (*ppBlock)->ResetPermissions();
                        m_nEmptied++;
                    }
                    break;
                }
            }

            m_BlockListLock.ReleaseExclusive();

            // If the block is okay to free, free it after leaving the exclusive lock.

            if (fOkayToFree)
            {
                pBlockToFree->Free();
            }
        }
    }

    BOOL 
    QueryAllocation(
        __in    PVOID       pMemory, 
        __out   PVOID*      ppStartAddress, 
        __out   SIZE_T*     pnSize
        )
    {
        BOOL fFound = FALSE;

        // Take the shared lock and walk the block list to find the memory.

        m_BlockListLock.AcquireShared();

        for (CBlock* pBlock = m_pCurrentBlock; pBlock != NULL; pBlock = pBlock->m_pNext)
        {
            if (pBlock->Contains(pMemory))
            {
                fFound = TRUE;
                pBlock->QueryAllocation(pMemory, ppStartAddress, pnSize);
                break;
            }
        }

        m_BlockListLock.ReleaseShared();

        return fFound;
    }

private:
    class CBlock
    {
    private:
        enum SLOT_STATE : BYTE
        {
            // Indicates that the slot is free.
            FREE_SLOT,

            // Indicates that the slot is the last slot in the allocation.
            LAST_SLOT_IN_ALLOCATION,

            // Indicates that the slot is allocated, and it's not the last one in the allocation.
            MIDDLE_SLOT_IN_ALLOCATION,
        };

        enum : SIZE_T
        {
            // Block size is 64K to match with VirtualAlloc granularity.
            BLOCK_SIZE = 64 * 1024,

            // Slot size is 64 bytes, which covers average heap executed block size.
            SLOT_SIZE = 64,

            // Calculate how many SLOT_SIZE byte slots fit into a BLOCK_SIZE block.
            // We need some bookkeeping data for the entire block (a lock, "next" 
            // pointer for the linked list, and unwind info for an exception handler),
            // so subtract the size of these from BLOCK_SIZE. Then, we need some 
            // bookkeeping data per slot (just an entry in the slot states array),
            // so add this size to SLOT_SIZE. Divide the two to get the final result.
            PER_BLOCK_BOOKKEEPING_SIZE = sizeof(CRWLock) + sizeof(CBlock*) + sizeof(BOOL) + sizeof(CTermination::CFunctionTable),
            PER_SLOT_BOOKKEEPING_SIZE = sizeof(SLOT_STATE),
            NUM_SLOTS = (BLOCK_SIZE - PER_BLOCK_BOOKKEEPING_SIZE) / (SLOT_SIZE + PER_SLOT_BOOKKEEPING_SIZE),

            // Magic value to indicate "slot not found" condition.
            SLOT_NOT_FOUND = static_cast<SIZE_T>(-1),
        };

        // An allocation slot is defined as an array of SLOT_SIZE bytes.
        typedef BYTE SLOT[SLOT_SIZE];

    public:
        // Allocates a new block.
        static CBlock* 
        Allocate(BOOL makeExecutable)
        {
            // Preserve system LastError value across system API calls.

            DWORD LastError = GetLastError();

            C_ASSERT(sizeof(CBlock) <= BLOCK_SIZE);

            // Enable automatic code generation so read-write-execute pages can
            // be allocated. Disabled when class goes out of scope

            AutoEnableDynamicCodeGen codeGen(makeExecutable ? true : false);

            CBlock* pNewBlock = static_cast<CBlock*>(VirtualAlloc(
                NULL, 
                BLOCK_SIZE, 
                MEM_COMMIT | MEM_RESERVE,
                makeExecutable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE
                ));

            if (pNewBlock != NULL)
            {
                // Fill the buffer with random code.
                CUtil::FillRandom(pNewBlock, BLOCK_SIZE);

                // Only architectures with table based exception handling,
                // register an exception handler in order to catch exceptions 
                // thrown from code executing in the buffer.

                BOOL fResult = pNewBlock->m_FunctionTable.Init(
                    pNewBlock->m_Slots,
                    sizeof(pNewBlock->m_Slots)
                    );

                if (fResult == FALSE)
                {
                    // Exception handler registration may fail since 
                    // internally it uses HeapAlloc. In this case, 
                    // free the allocated buffer.

                    VirtualFree(
                        pNewBlock, 
                        0, 
                        MEM_RELEASE
                        );

                    pNewBlock = NULL;
                }
            }

            if (pNewBlock != NULL)
            {
                // Mark the block as executable (unless it was the first one)
                pNewBlock->m_IsRWX = makeExecutable;

                // Initialize the lock.
                pNewBlock->m_SlotStatesLock.Init();

                // Initialize linked list next pointer.

                pNewBlock->m_pNext = NULL;

                // Set the slot states to free.
                CUtil::Memset(pNewBlock->m_SlotStates, FREE_SLOT, NUM_SLOTS * sizeof(SLOT_STATE));
            }

            SetLastError(LastError);

            return pNewBlock;
        }

        // Frees a block.
        VOID 
        Free(
            )
        {
            // Preserve system LastError value across system API calls.

            DWORD LastError = GetLastError();

            m_FunctionTable.Cleanup();

            VirtualFree(
                this, 
                0, 
                MEM_RELEASE
                );

            SetLastError(LastError);
        }

        VOID ResetPermissions()
        {
            // assert(IsEmpty());
            DWORD OldProtect;
            VirtualProtect(
                this,
                BLOCK_SIZE,
                PAGE_READWRITE,
                &OldProtect);
            m_IsRWX = FALSE;
            // assert(OldProtect == PAGE_EXECUTE_READWRITE);
        }
               
        static SIZE_T 
        MaxAllocationSize()
        {
            return SLOT_SIZE * NUM_SLOTS;
        }

        BOOL 
        Contains(
            __in PVOID pMemory
            ) const
        {
            return pMemory >= m_Slots &&
                   pMemory < CUtil::AddOffset(m_Slots, MaxAllocationSize());
        }

        BOOL 
        IsEmpty(
            )
        {
            // Take the shared lock and check if there are any allocated slots.

            m_SlotStatesLock.AcquireShared();

            SIZE_T nFirstAllocatedSlot = FindFirstAllocatedSlot(0, NUM_SLOTS);

            m_SlotStatesLock.ReleaseShared();

            // If there are no allocated slots, return TRUE.

            return nFirstAllocatedSlot == SLOT_NOT_FOUND;
        }

        PVOID 
        AllocateMemory(
            SIZE_T nSize
            )
        {
            PVOID pMemory = NULL;

            if (nSize > 0)
            {
                // Determine the minimum number of slots necessary to cover the desired size.

                SIZE_T nNumSlotsToAlloc = (nSize + (SLOT_SIZE - 1)) / SLOT_SIZE;
                
                // Try to allocate starting from a random slot offset. 

                SIZE_T nRandomSlot = g_Rand.Random(0, NUM_SLOTS - nNumSlotsToAlloc);

                pMemory = AllocateSlots(
                    nRandomSlot, 
                    NUM_SLOTS - nNumSlotsToAlloc, 
                    nNumSlotsToAlloc
                    );

                // If no slots are available in the range [random start slot, last slot], 
                // try the range [first slot, random start slot].

                if (pMemory == NULL)
                {
                    pMemory = AllocateSlots(
                        0, 
                        nRandomSlot,
                        nNumSlotsToAlloc
                        );
                }

                // If allocation succeeded, return a random offset within the slot.

                if (pMemory != NULL)
                {
                    pMemory = CUtil::AddOffset(
                        pMemory, 
                        g_Rand.Random(0, (SLOT_SIZE * nNumSlotsToAlloc) - nSize)
                        );
                }
            }

            return pMemory;
        }

        VOID 
        FreeMemory(
            __in    PVOID   pMemory
            )
        {
            // Take the exclusive lock, and mark all the slots in the allocation as free. 

            m_SlotStatesLock.AcquireExclusive();

            INT_PTR nFirstSlot, nLastSlot;
            FindAllocatedSlotRange(pMemory, &nFirstSlot, &nLastSlot);

            if (nFirstSlot <= nLastSlot)
            {
                CUtil::Memset(
                    &m_SlotStates[nFirstSlot],
                    FREE_SLOT,
                    (nLastSlot - nFirstSlot + 1) * sizeof(SLOT_STATE)
                    );
            }

            m_SlotStatesLock.ReleaseExclusive();
        }

        VOID 
        QueryAllocation(
            __in    PVOID       pMemory, 
            __out   PVOID*      ppStartAddress, 
            __out   SIZE_T*     pnSize
            )
        {
            // Take the shared lock and find the first and last slots in the allocation.

            m_SlotStatesLock.AcquireShared();

            INT_PTR nFirstSlot, nLastSlot;
            FindAllocatedSlotRange(pMemory, &nFirstSlot, &nLastSlot);

            m_SlotStatesLock.ReleaseShared();

            // Return the results.

            *ppStartAddress = m_Slots[nFirstSlot];
            *pnSize = SLOT_SIZE * (nLastSlot - nFirstSlot + 1);
        }

    private:
        PVOID 
        AllocateSlots(
            SIZE_T  nFirst, 
            SIZE_T  nLast, 
            SIZE_T  nNumSlotsToAlloc
            )
        {
            PVOID pMemory = NULL;

            // Take the shared lock, and search for nNumSlotsToAlloc free slots in the in the slot allocation map.

            m_SlotStatesLock.AcquireShared();

            SIZE_T nFirstSlotToAllocate = nFirst;

            for (;;)
            {
                // Find the first free slot.

                nFirstSlotToAllocate = FindFirstFreeSlot(
                    nFirstSlotToAllocate, 
                    nLast - nFirstSlotToAllocate + 1
                    );

                // If not found, then it means the block is full, exit search.

                if (nFirstSlotToAllocate == SLOT_NOT_FOUND)
                {
                    break;
                }

                // Find the first allocated slot after the free slot.

                SIZE_T nNextAllocatedSlot = FindFirstAllocatedSlot(
                    nFirstSlotToAllocate + 1, 
                    nNumSlotsToAlloc - 1
                    );

                // If the first allocated slot is more than nNumSlotsToAlloc away, then
                // it means we have found a free space for the the allocation.

                if (nNextAllocatedSlot == SLOT_NOT_FOUND)
                {
                    break;
                }

                // Continue searching at an index one past the last allocated block.

                nFirstSlotToAllocate = nNextAllocatedSlot + 1;
            }
    
            m_SlotStatesLock.ReleaseShared();

            // If we found a free space for allocation, take the exclusive lock and check again.

            if (nFirstSlotToAllocate != SLOT_NOT_FOUND)
            {
                m_SlotStatesLock.AcquireExclusive();

                if (FindFirstAllocatedSlot(nFirstSlotToAllocate, nNumSlotsToAlloc) == SLOT_NOT_FOUND)
                {
                    // If the slots are still free while we are in the exclusive lock, it's time to
                    // mark them as allocated now.

                    pMemory = m_Slots[nFirstSlotToAllocate];

                    // Mark the middle slots (if any).
                    if (nNumSlotsToAlloc > 0)
                    {
                        CUtil::Memset(
                            &m_SlotStates[nFirstSlotToAllocate],
                            MIDDLE_SLOT_IN_ALLOCATION,
                            (nNumSlotsToAlloc - 1) * sizeof(SLOT_STATE)
                            );
                    }

                    // Mark the last slot.

                    m_SlotStates[nFirstSlotToAllocate + nNumSlotsToAlloc - 1] = LAST_SLOT_IN_ALLOCATION;

                    if(m_IsRWX == FALSE)
                    {
                        // Enable automatic code generation so the page properties can be
                        // changed to read-write-execute. Disabled when class goes out of
                        // scope

                        AutoEnableDynamicCodeGen codeGen(true);

                        DWORD OldProtect;
                        VirtualProtect(this,
                                       BLOCK_SIZE,
                                       PAGE_EXECUTE_READWRITE,
                                       &OldProtect);
                        m_IsRWX = TRUE;
                        // assert(OldProtect == PAGE_READWRITE);
                        
                    }

                }

                m_SlotStatesLock.ReleaseExclusive();
            }

            return pMemory;
        }

        // Scans the nNumSlots number of slots after the nStartingSlot, and returns 
        // the index of the first free slot if found, or SLOT_NOT_FOUND otherwise.
        SIZE_T 
        FindFirstFreeSlot(
            SIZE_T  nStartingSlot, 
            SIZE_T  nNumSlots
            ) const
        {
            for (SIZE_T i = nStartingSlot; i < nStartingSlot + nNumSlots; ++i)
            {
                if (m_SlotStates[i] == FREE_SLOT)
                {
                    return i;
                }
            }

            return SLOT_NOT_FOUND;
        }

        // Scans the nNumSlots number of slots after the nStartingSlot, and returns 
        // the index of the first allocated slot if found, or SLOT_NOT_FOUND otherwise.
        SIZE_T 
        FindFirstAllocatedSlot(
            SIZE_T  nStartingSlot, 
            SIZE_T  nNumSlots
            ) const
        {
            for (SIZE_T i = nStartingSlot; i < nStartingSlot + nNumSlots; ++i)
            {
                if (m_SlotStates[i] != FREE_SLOT)
                {
                    return i;
                }
            }

            return SLOT_NOT_FOUND;
        }

        VOID FindAllocatedSlotRange(
            __in    PVOID       pMemory,
            __out   INT_PTR*    pnFirstSlot,
            __out   INT_PTR*    pnLastSlot
            )
        {
            // Convert the address to a slot index.

            SIZE_T nMiddleSlot = CUtil::GetOffset(pMemory, m_Slots) / SLOT_SIZE;

            // First, walk back until we go past the first slot, or hit a non-MIDDLE_SLOT_IN_ALLOCATION
            // (which must be a free slot or the last slot in the previous allocation).

            for (*pnFirstSlot = nMiddleSlot - 1; 
                *pnFirstSlot >= 0 && m_SlotStates[*pnFirstSlot] == MIDDLE_SLOT_IN_ALLOCATION; 
                *pnFirstSlot = *pnFirstSlot - 1)
            {
            }

            // Now we must have walked past the first block in allocation, so back up one slot.

            *pnFirstSlot = *pnFirstSlot + 1;

            // Next, walk forward until we hit a hit a non-MIDDLE_SLOT_IN_ALLOCATION (which must be 
            // the last slot in allocation assuming that the slot states array is filled properly).

            for (*pnLastSlot = nMiddleSlot; 
                m_SlotStates[*pnLastSlot] == MIDDLE_SLOT_IN_ALLOCATION; 
                *pnLastSlot = *pnLastSlot + 1)
            {
            }

            WARBIRD_ASSERT(*pnLastSlot < NUM_SLOTS);
        }


    private:
        SLOT                            m_Slots[NUM_SLOTS];

    private:
        // Multiple-Reader-Single-Writer Lock that protects the slot usage table.
        CRWLock                         m_SlotStatesLock;

        // Is the block RWX or RW
        BOOL                            m_IsRWX;

    public:
        // The Next pointer to maintain the linked list in the outer class.
        // Marked as public so that the outer class can access and modify it.
        // Protected by m_BlockListLock in the outer class.
        CBlock*                         m_pNext;

    private:
        CTermination::CFunctionTable    m_FunctionTable;

    private:
        // Maintains the usage state of each slot. Protected by m_SlotStatesLock.
        SLOT_STATE                      m_SlotStates[NUM_SLOTS];

    }; // class CBlock

  private:
    // Head pointer of the listed list of allocated blocks.
    CBlock* m_pCurrentBlock;

    // Multiple-Reader-Single-Writer Lock that protects the linked list.
    CRWLock m_BlockListLock;

    // Number of allocated blocks in the link list.
    SIZE_T  m_nNumBlocks;

    SIZE_T  m_nEmptied;
    SIZE_T  m_nMaxBlocks;

}; // class CMemoryAllocator

CMemoryAllocator g_MemoryAllocator;

#endif

}; // namespace WarbirdRuntime 