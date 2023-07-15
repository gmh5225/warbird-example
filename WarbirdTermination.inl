/**
  *
  * Termination
  *
  **/

namespace WarbirdRuntime
{

class CTermination
{
public:
    // If we detect tampering, we want to terminate execution without letting 
    // the hacker easily understand what he did wrong. To make this happen, 
    // we clear the stack and the registers in an ASM helper function, and 
    // jump to a C function that exits the process.
    static VOID
    __declspec(noinline) TrashStack(
        )
    {
        TrashStack(TerminationFunction);
    }

#if !defined(WARBIRD_KERNEL_MODE)

#if defined(_M_AMD64)

    // On architectures with table based exception handling (AMD64 and ARM), 
    // we don't support exceptions unwinding across a heap executed function
    // because we don't register proper unwind information for these functions.
    // Any such exception during runtime means a bug in the obfuscated code.
    //
    // So, if we detect an exception across a heap executed function;
    //
    // 1) We want to catch the exception and terminate the process, rather than letting 
    //    the unwind logic make random decisions based on the random data on the stack
    //    (which would be a security risk).
    //
    // 2) We would like to pass the EXCEPTION_RECORD and CONTEXT structs to Watson,
    //     so that we get actionable minidumps to fix the bug.
    //
    // To make this happen, we need to register an exception handler function with the OS
    // to call with the EXCEPTION_RECORD and CONTEXT parameters. To register this handler,
    // we need to call RtlAddFunctionTable API with a RUNTIME_FUNCTION struct that covers 
    // the heap execution buffer and points to an UNWIND_INFO struct that points to the 
    // exception handler.
            
    class CFunctionTable
    {
    public:
        BOOL Init(
            __in    PVOID   pBegin, 
                    ULONG   nSize
            )
        {
            // First, fill in a RUNTIME_FUNCTION that covers the buffer and points to the UNWIND_INFO.

            FunctionTable[0].BeginAddress = 0;
            FunctionTable[0].EndAddress = nSize;
            FunctionTable[0].UnwindData = static_cast<ULONG>(CUtil::GetOffset(&UnwindInfo, pBegin));

            // Then, fill in an UNWIND_INFO that declares an exception handler and has no unwind codes. 

            UnwindInfo.Version = 1;
            UnwindInfo.Flags = UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER;
            UnwindInfo.SizeOfProlog = 0;
            UnwindInfo.CountOfCodes = 0;
            UnwindInfo.FrameRegister = 0;
            UnwindInfo.FrameOffset = 0;
            UnwindInfo.RvaExceptionHandler = static_cast<ULONG>(CUtil::GetOffset(&JmpIndirect, pBegin));

            // Since the RVA fields are 32bit offsets relative to the start of the buffer, 
            // and since the buffer may be located anywhere in the 64bit memory, the fields
            // may not be wide enough to point to the exception handler function in the image.
            // So, we need to create a stub function that jumps to the function in the image.
            // Assemble "jmp qword ptr [ExceptionHandler]".

            JmpIndirect.Opcode[0] = 0xFF;
            JmpIndirect.Opcode[1] = 0x25;
            JmpIndirect.Offset = static_cast<ULONG>(CUtil::GetOffset(&pExceptionHandler, &JmpIndirect + 1));
            pExceptionHandler = ExceptionHandler;

            // Flush the CPU cache for generated code (this is a NOP for AMD64, but it's good
            // for documenting that we generate code here).

            CUtil::FlushCpuCache(&JmpIndirect, sizeof(JmpIndirect));

            return RtlAddFunctionTable(
                FunctionTable, 
                1, 
                reinterpret_cast<ULONG_PTR>(pBegin)
                );
        }

        VOID Cleanup(
            )
        {
            RtlDeleteFunctionTable(FunctionTable);
        }

    private:
        // Pointer to the exception handler routine in the image.
        PVOID               pExceptionHandler;

        // Declare a function table with a single RUNTIME_FUNCTION entry.
        RUNTIME_FUNCTION    FunctionTable[1];

        // UNWIND_INFO struct has a fixed header, followed by an array of 0 or more 
        // UNWIND_CODE structs, and (optionally) an RVA of the exception handler.
        // Since we won't register any UNWIND_CODE's in our UNWIND_INFO, the following 
        // accurately represents the memory layout:
        struct
        {
            UCHAR           Version : 3;
            UCHAR           Flags : 5;
            UCHAR           SizeOfProlog;
            UCHAR           CountOfCodes;
            UCHAR           FrameRegister : 4;
            UCHAR           FrameOffset : 4;
            ULONG           RvaExceptionHandler;
        }
        UnwindInfo;

        // jmp qword ptr [ExceptionHandler]
        #pragma pack(push, 1)
        struct
        {
            BYTE            Opcode[2];
            ULONG           Offset;
        }
        JmpIndirect;
        #pragma pack(pop)
    };

#elif defined(_M_E2)

    class CFunctionTable
    {
    public:
        BOOL Init(
            __in    PVOID   pBegin,
                    ULONG   nSize
            )
        {
            // First, fill in a RUNTIME_FUNCTION that covers the buffer and points to the UNWIND_INFO.
            // Low two bits of UnwindData must be set to zero to indicate that we are using a separate
            // UNWIND_INFO struct (as opposed to packing the unwind data in the RUNTIME_FUNCTION).
            // This is implicitly achieved; since both the UNWIND_INFO and the buffer are ULONG aligned,
            // the low two bits of the RVA is always zero.

            FunctionTable[0].BeginAddress = 0;
            FunctionTable[0].UnwindData = ULONG(CUtil::GetOffset(&UnwindInfo, pBegin));

            // Then, fill in an UNWIND_INFO that declares an exception handler and has no unwind codes.

            UnwindInfo.X = 1;                       // X=1 indicates presence of exception data
            UnwindInfo.CS = 0;                      // CS=0 indicates original pdata section
            UnwindInfo.FunctionLength = nSize / 4;  // must be divided by 4 according to the convention
            UnwindInfo.FrameSize = 0;               // no allocated stack
            UnwindInfo.LR = 0;                      // LR not saved
            UnwindInfo.FP = 0;                      // FP not saved
            UnwindInfo.Home = 0;                    // registers not homed
            UnwindInfo.NVReg = 0;                   // no non-volatiles saved
            UnwindInfo.RvaExceptionHandler = ULONG(CUtil::GetOffset(&ExceptionHandler, pBegin));

            return RtlAddFunctionTable(
                FunctionTable,
                1,
                reinterpret_cast<ULONG_PTR>(pBegin)
                );
        }

        VOID Cleanup(
            )
        {
            RtlDeleteFunctionTable(FunctionTable);
        }

    private:
        // Declare a function table with a single RUNTIME_FUNCTION entry.
        RUNTIME_FUNCTION    FunctionTable[1];

        // UNWIND_INFO struct that registers 1 unwind code word and an exception handler.
        struct
        {
            ULONG           X: 1;
            ULONG           CS: 2;
            ULONG           FunctionLength: 11;
            ULONG           FrameSize: 10;
            ULONG           LR: 1;
            ULONG           FP: 1;
            ULONG           Home: 1;
            ULONG           NVReg: 5;
            ULONG           RvaExceptionHandler;
        }
        UnwindInfo;
    };

#elif defined(_M_ARM64)

    class CFunctionTable
    {
    public:
        BOOL Init(
            __in    PVOID   pBegin,
                    ULONG   nSize
            )
        {
            // First, fill in a RUNTIME_FUNCTION that covers the buffer and points to the UNWIND_INFO.
            // Low two bits of UnwindData must be set to zero to indicate that we are using a separate 
            // UNWIND_INFO struct (as opposed to packing the unwind data in the RUNTIME_FUNCTION). 
            // This is implicitly achieved; since both the UNWIND_INFO and the buffer are ULONG aligned, 
            // the low two bits of the RVA is always zero.

            FunctionTable[0].BeginAddress = 0;
            FunctionTable[0].UnwindData = ULONG(CUtil::GetOffset(&UnwindInfo, pBegin));

            // Then, fill in an UNWIND_INFO that declares an exception handler and has no unwind codes. 

            UnwindInfo.FunctionLength = nSize / 4;  // must be divided by 4 according to the convention
            UnwindInfo.Version = 0;                 // version is currently defined as 0
            UnwindInfo.X = 1;                       // X=1 indicates presence of exception data
            UnwindInfo.E = 0;                       // E=0 indicates we need a scope word
            UnwindInfo.EpilogCount = 0;             // No exception scopes
            UnwindInfo.CodeWords = 1;               // A single 32bit word to contain all unwind codes
            UnwindInfo.UnwindCode[0] = 0xE4;        // We need just one unwind code: 0xe4 (end)
            UnwindInfo.UnwindCode[1] = 0;
            UnwindInfo.UnwindCode[2] = 0;
            UnwindInfo.UnwindCode[3] = 0;
            UnwindInfo.RvaExceptionHandler = ULONG(CUtil::GetOffset(&ExceptionHandler, pBegin));

            return RtlAddFunctionTable(
                FunctionTable, 
                1, 
                reinterpret_cast<ULONG_PTR>(pBegin)
                );
        }

        VOID Cleanup(
            )
        {
            RtlDeleteFunctionTable(FunctionTable);
        }

    private:
        // Declare a function table with a single RUNTIME_FUNCTION entry.
        RUNTIME_FUNCTION    FunctionTable[1];

        // UNWIND_INFO struct that registers 1 unwind code word and an exception handler.
        struct
        {
            ULONG           FunctionLength: 18;
            ULONG           Version: 2;
            ULONG           X: 1;
            ULONG           E: 1;
            ULONG           EpilogCount: 5;
            ULONG           CodeWords: 5;
            BYTE            UnwindCode[4];
            ULONG           RvaExceptionHandler;
        }
        UnwindInfo;
    };

#elif defined(_M_ARM)

    class CFunctionTable
    {
    public:
        BOOL Init(
            __in    PVOID   pBegin,
                    ULONG   nSize
            )
        {
            // First, fill in a RUNTIME_FUNCTION that covers the buffer and points to the UNWIND_INFO.
            // The low bit of BeginAddress must be set to 1 to indicate thumb mode.
            // Low two bits of UnwindData must be set to zero to indicate that we are using a separate 
            // UNWIND_INFO struct (as opposed to packing the unwind data in the RUNTIME_FUNCTION). 
            // This is implicitly achieved; since both the UNWIND_INFO and the buffer are ULONG aligned, 
            // the low two bits of the RVA is always zero.

            FunctionTable[0].BeginAddress = 1;
            FunctionTable[0].UnwindData = CUtil::GetOffset(&UnwindInfo, pBegin);

            // Then, fill in an UNWIND_INFO that declares an exception handler and has no unwind codes. 

            UnwindInfo.FunctionLength = nSize / 2;  // must be divided by 2 according to the convention
            UnwindInfo.Version = 0;                 // version is currently defined as 0
            UnwindInfo.X = 1;                       // X=1 indicates presence of exception data
            UnwindInfo.E = 0;                       // E=0 indicates we need a scope word
            UnwindInfo.F = 1;                       // F=1 means this is a function fragment (i.e. no prolog/epilog)
            UnwindInfo.EpilogCount = 0;             // No exception scopes
            UnwindInfo.CodeWords = 1;               // A single 32bit word to contain all unwind codes
            UnwindInfo.UnwindCode[0] = 0xFF;        // We need just one unwind code: 0xff (end)
            UnwindInfo.UnwindCode[1] = 0;
            UnwindInfo.UnwindCode[2] = 0;
            UnwindInfo.UnwindCode[3] = 0;
            UnwindInfo.RvaExceptionHandler = CUtil::GetOffset(&ExceptionHandler, pBegin) | 1;

            return RtlAddFunctionTable(
                FunctionTable, 
                1, 
                reinterpret_cast<ULONG_PTR>(pBegin)
                );
        }

        VOID Cleanup(
            )
        {
            RtlDeleteFunctionTable(FunctionTable);
        }

    private:
        // Declare a function table with a single RUNTIME_FUNCTION entry.
        RUNTIME_FUNCTION    FunctionTable[1];

        // UNWIND_INFO struct that registers 1 unwind code word and an exception handler.
        struct 
        {
            ULONG           FunctionLength: 18;
            ULONG           Version: 2;
            ULONG           X: 1;
            ULONG           E: 1;
            ULONG           F: 1;
            ULONG           EpilogCount: 5;
            ULONG           CodeWords: 4;
            BYTE            UnwindCode[4];
            ULONG           RvaExceptionHandler;
        } 
        UnwindInfo;
    };

#elif defined(_M_IX86)

    // On X86, we let the exceptions unwind across heap executed functions. 
    // We leak the heap execution buffer, but at least there's no undefined behavior 
    // during unwind (as opposed to architectures that do table based exception handling).

    class CFunctionTable
    {
    public:
        BOOL Init(
            __in    PVOID   pBegin, 
                    ULONG   nSize
            )
        {
            UNREFERENCED_PARAMETER(pBegin);
            UNREFERENCED_PARAMETER(nSize);

            return TRUE;
        }

        VOID Cleanup(
            )
        {
        }
    };

#endif

#endif // !defined(WARBIRD_KERNEL_MODE)

private:
    static DECLSPEC_NORETURN VOID 
    Abort(
        __in    EXCEPTION_RECORD*   pExceptionRecord,
        __in    CONTEXT*            pContextRecord
        )
    {
#if defined(WARBIRD_KERNEL_MODE)

        UNREFERENCED_PARAMETER(pContextRecord);

        KeBugCheckEx(
            KERNEL_MODE_EXCEPTION_NOT_HANDLED,
            pExceptionRecord == NULL ? STATUS_FATAL_APP_EXIT : pExceptionRecord->ExceptionCode,
            reinterpret_cast<ULONG_PTR>(pExceptionRecord == NULL ? _ReturnAddress() : pExceptionRecord->ExceptionAddress),
            0,
            0
            );

#elif (WINVER >= _WIN32_WINNT_WIN7)

        // On Win7 and above, use RaiseFailFastException to bring up Watson and terminate.
        RaiseFailFastException(
            pExceptionRecord, 
            pContextRecord, 
            0
            );

#else 

        EXCEPTION_RECORD ExceptionRecord;

        if (pExceptionRecord == NULL)
        {
            // If no EXCEPTION_RECORD is passed in, construct one. 
            pExceptionRecord = &ExceptionRecord;            
            ZeroMemory(pExceptionRecord, sizeof(EXCEPTION_RECORD));
            pExceptionRecord->ExceptionCode = STATUS_FATAL_APP_EXIT;
            pExceptionRecord->ExceptionFlags = EXCEPTION_NONCONTINUABLE;
            pExceptionRecord->ExceptionAddress = _ReturnAddress();
        }
        else
        {
            // Otherwise, reassure that the exception is not continuable. 
            pExceptionRecord->ExceptionFlags |= EXCEPTION_NONCONTINUABLE;
        }

        CONTEXT ContextRecord;

        if (pContextRecord == NULL)
        {
            // If no CONTEXT is passed in, construct one. 
            pContextRecord = &ContextRecord;
            ZeroMemory(pContextRecord, sizeof(CONTEXT));
            RtlCaptureContext(pContextRecord);
        }

        // Fill the exception pointers for UnhandledExceptionFilter. 
        EXCEPTION_POINTERS ExceptionPointers;
        ExceptionPointers.ExceptionRecord = pExceptionRecord;
        ExceptionPointers.ContextRecord = pContextRecord;

        // Make sure any filter already in place is deleted.
        SetUnhandledExceptionFilter(NULL);

        // Invoke Watson or JIT debugger if configured.
        UnhandledExceptionFilter(&ExceptionPointers);

        // UnhandledExceptionFilter will return if it detects that a debugger is 
        // connected. In this case, terminate the process.
        TerminateProcess(GetCurrentProcess(), pExceptionRecord->ExceptionCode);

#endif
    }

    // ExceptionHandler is called when we detect an exception unwinding across 
    // a heap executed function. This means a bug in the obfuscated code, so 
    // we want as much information as possible in the Watson report, so we call 
    // Abort with proper EXCEPTION_RECORD and CONTEXT structs in this case.
    static EXCEPTION_DISPOSITION __cdecl 
    ExceptionHandler(
        __in    EXCEPTION_RECORD*   pExceptionRecord,
        __in    VOID*               pEstablisherFrame,
        __inout CONTEXT*            pContextRecord,
        __inout VOID*               pDispatcherContext
        )
    {
        UNREFERENCED_PARAMETER(pEstablisherFrame);
        UNREFERENCED_PARAMETER(pDispatcherContext);

        Abort(pExceptionRecord, pContextRecord);
    }

    // TerminationFunction is called when we detect tamper. In this case,
    // we want to leave the attacker as little information as possible when 
    // we exit the process, so we call Abort with no info.
    static INT_PTR WINAPI 
    TerminationFunction(
        )
    {
        Abort(NULL, NULL);
    }

    // Clears the stack and registers, and jumps to termination function.
    // Since this is hard to do with C code, the function is implemented in 
    // architecture dependent ASM files.
    static VOID __fastcall
    TrashStack(
        FARPROC pTerminationFunction
        );

}; //class CTermination

}; // namespace WarbirdRuntime 