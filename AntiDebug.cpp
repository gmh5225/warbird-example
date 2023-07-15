//-----------------------------------------------------------------------------
//
// Copyright (C) Microsoft Corporation.  All Rights Reserved.
//
// File: AntiDebug.cpp
//
// Description:
//
// Warbird Anti-Debugging Helper Functions
//
//-----------------------------------------------------------------------------

#if (defined(_X86_) || defined(_AMD64_)) && !defined(WARBIRD_KERNEL_MODE) && !defined(WARBIRD_AD_DISABLED)

DWORD WINAPI WarbirdAD_ThreadCompareDRs(void* p)
{
    DWORD dwRet = 0xf3b02c90;
    HANDLE hMainThread = (HANDLE)p;

    if(-1 != SuspendThread(hMainThread))
    {
        CONTEXT context;
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if(GetThreadContext(hMainThread, &context))
        {
            if(ad_CompareDRs(&context))
                dwRet = 1;
        }
        ResumeThread(hMainThread);
    }

    CloseHandle(hMainThread);
    return dwRet;
}

#endif // #if (defined(_X86_) || defined(_AMD64_)) && !defined(WARBIRD_KERNEL_MODE)