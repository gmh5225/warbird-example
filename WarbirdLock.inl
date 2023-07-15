/**
  *
  * Lock
  *
  **/

namespace WarbirdRuntime
{

// Implements a lightweight multiple-reader-single-writer lock.
class CRWLock
{
private:
    enum : LONG_PTR
    {
        FREE = 0,
        FIRST_SHARED = 1,
        EXCLUSIVE = -1,
    };

public:
    VOID 
    Init(
        )
    {
        m_Lock = FREE;
    }

    VOID 
    AcquireShared(
        )
    {
        // Try transitioning the state from FREE to 1ST_SHARED lock.

        LONG_PTR ExpectedOldValue = FREE;
        LONG_PTR DesiredNewValue = FIRST_SHARED;

        for (;;)
        {
            LONG_PTR OldValue = _InterlockedCompareExchangeSizeT(&m_Lock, DesiredNewValue, ExpectedOldValue);

            if (OldValue == ExpectedOldValue)
            {
                // If we successfully transitioned the state, exit.

                break;
            }
            else if (OldValue == EXCLUSIVE)
            {
                // If the lock is held exclusively, continue spinning.
            }
            else 
            {
                // If some other thread(s) grabbed the shared lock, try incrementing the refcount.

                ExpectedOldValue = OldValue;
                DesiredNewValue = OldValue + 1;

                // Assert that the new lock state is not FREE or EXCLUSIVE, which are invalid states 
                // for holding a shared lock.

                WARBIRD_ASSERT(DesiredNewValue != FREE && DesiredNewValue != EXCLUSIVE);
            }

            // Continue spinning.
        }
    }

    VOID 
    ReleaseShared(
        )
    {
        // Assert that the lock state is not FREE or EXCLUSIVE, which are invalid states 
        // for holding a shared lock.

        WARBIRD_ASSERT(m_Lock != FREE && m_Lock != EXCLUSIVE);

        // Decrement the refcount.

        _InterlockedDecrementSizeT(&m_Lock);
    }

    VOID 
    AcquireExclusive(
        )
    {
        // Try transitioning the state from FREE to EXCLUSIVE lock.

        LONG_PTR ExpectedOldValue = FREE;
        LONG_PTR DesiredNewValue = EXCLUSIVE;

        for (;;)
        {
            LONG_PTR OldValue = _InterlockedCompareExchangeSizeT(&m_Lock, DesiredNewValue, ExpectedOldValue);

            if (OldValue == ExpectedOldValue)
            {
                // If we successfully transitioned the state, exit.

                break;
            }

            // Continue spinning.
        }
    }

    VOID 
    ReleaseExclusive(
        )
    {
        // Mark the lock as FREE.

        WARBIRD_ASSERT(m_Lock == EXCLUSIVE);
        _InterlockedExchangeSizeT(&m_Lock, FREE);
    }

private:
    LONG_PTR    m_Lock;

}; //class CRWLock

#if defined(WARBIRD_KERNEL_MODE)

// Wrapper around FAST_MUTEX
class CLock
{
public:
    HRESULT 
    Init(
        )
    {
        ExInitializeFastMutex(&m_FastMutex);

        return S_OK;
    }

    VOID 
    Cleanup(
        )
    {
    }

    VOID 
    Acquire(
        )
    {
        ExAcquireFastMutex(&m_FastMutex);
    }

    VOID 
    Release(
        )
    {
        ExReleaseFastMutex(&m_FastMutex);
    }

private:
    FAST_MUTEX m_FastMutex;

}; // class CLock

#else // defined(WARBIRD_KERNEL_MODE)

// Wrapper around CRITICAL_SECTION
class CLock
{
public:
    HRESULT 
    Init(
        )
    {
        HRESULT hr = S_OK;

        __try
        {
            InitializeCriticalSection(&m_CriticalSection);
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }

        return hr;
    }

    VOID 
    Cleanup(
        )
    {
        DeleteCriticalSection(&m_CriticalSection);
    }

    VOID 
    Acquire(
        )
    {
        EnterCriticalSection(&m_CriticalSection);
    }

    VOID 
    Release(
        )
    {
        LeaveCriticalSection(&m_CriticalSection);
    }

private:
    CRITICAL_SECTION m_CriticalSection;

}; // class CLock

#endif // defined(WARBIRD_KERNEL_MODE)

}; // namespace WarbirdRuntime