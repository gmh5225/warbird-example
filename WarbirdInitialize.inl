namespace WarbirdRuntime {
HRESULT
WarbirdProcessInitialize(
    PPROCESS_STARTUP_ARGUMENT pStartupArguments
    );
}; // namespace WarbirdRuntime

namespace WarbirdRuntime
{

/*++

    Description:

        Performs global initialization for the runtime support lib.
    
        Adding the __declspec(safebuffers) would make sure that the compiler
        will not emit a GS cookie for the function. Sticking a cookie check in
        the entry functions that call RuntimeInit and RuntimeCleanup will surely
        fail since the cookie value will change in the middle
        (upon entering these functions, the cookie value saved on the stack 
        will be the default value, but then the original entry point will 
        initialize the cookie to a random value, so the check at the end 
        will fail).

        It's okay if the compiler sticks cookie checks into RuntimeInit or 
        RuntimeCleanup, the cookie value won't change in the middle of them. 
        The only downside is the cookie check is less secure because the cookie 
        value is not random.

    Arguments:

        None.

    Returns:

        S_OK if successful, an error code otherwise.

--*/
#if defined(WARBIRD_KERNEL_MODE)
#pragma code_seg("INIT")
#endif

//
// Pre allocated buffers for the heap executed calls that use system calls.
// Normally the kernel would allocate these buffers but the memory manager does
// not expose an API to allocate executable memory if dynamic code generation is
// disabled. 
// TODO: Remove when memory manager exposes this API.
//
#if $(HEAP_EXECUTION_SYSTEM_CALL_PRE_ALLOCATED_BUFFER_SIZE)
#pragma section("wbrdrx", read, write)
#pragma comment(linker, "/section:wbrdrx,ER")
BYTE __declspec(allocate("wbrdrx")) g_readExecuteMemory[$(HEAP_EXECUTION_SYSTEM_CALL_PRE_ALLOCATED_BUFFER_SIZE)];
#endif // HEAP_EXECUTION_SYSTEM_CALL_PRE_ALLOCATED_BUFFER_SIZE

HRESULT 
RuntimeInit(
    void
    )
{
    HRESULT hr = S_OK;

    g_Rand.Init(static_cast<LONG>(CUtil::ReadCpuTimeStamp() & LONG_MAX));

#if $(WARBIRD_ENABLE_HEAP_EXECUTION) && !defined(WARBIRD_KERNEL_MODE)

    if (SUCCEEDED(hr))
    {
        hr = g_MemoryAllocator.Init();
    }

#endif

#if $(WARBIRD_ENABLE_ENCRYPTION)

    if (SUCCEEDED(hr))
    {
        hr = EncryptionRuntimeInit();
    }

#endif

#if $(WARBIRD_ENABLE_HEAP_EXECUTION) && !defined(WARBIRD_KERNEL_MODE)

    if (SUCCEEDED(hr))
    {
        hr = HeapExecutionRuntimeInit();
    }

#endif

#if $(HEAP_EXECUTION_SYSTEM_CALLS)
    if (SUCCEEDED(hr))
    {
        PROCESS_STARTUP_ARGUMENT startup;

        startup.cMaxHeapExecutedCacheEntries = $(HEAP_EXECUTED_CACHE_ENTRIES);
        startup.pPreAllocatedReadExecuteMemory = NULL;
        startup.cbPreAllocatedReadExecuteMemory = 0;

#if $(HEAP_EXECUTION_SYSTEM_CALL_PRE_ALLOCATED_BUFFER_SIZE)
        startup.pPreAllocatedReadExecuteMemory = g_readExecuteMemory;
        startup.cbPreAllocatedReadExecuteMemory = sizeof(g_readExecuteMemory);
#endif // HEAP_EXECUTION_SYSTEM_CALL_PRE_ALLOCATED_BUFFER_SIZE

        hr = WarbirdRuntime::WarbirdProcessInitialize(
            &startup
            );
    }
#endif

    return hr;
}

#if defined(WARBIRD_KERNEL_MODE)
#pragma code_seg()
#endif

/*++

    Description:

        Performs global cleanup for the runtime support lib.

    Arguments:

        None.

    Returns:

        None.

--*/

VOID 
RuntimeCleanup(
    void
    )
{
#if $(WARBIRD_ENABLE_HEAP_EXECUTION) && !defined(WARBIRD_KERNEL_MODE)

    HeapExecutionRuntimeCleanup();

#endif

#if $(WARBIRD_ENABLE_ENCRYPTION)

    EncryptionRuntimeCleanup();

#endif

#if $(WARBIRD_ENABLE_HEAP_EXECUTION) && !defined(WARBIRD_KERNEL_MODE)

    g_MemoryAllocator.Cleanup();

#endif
}

// "C" entry points for these functions

extern "C" HRESULT __stdcall WarbirdRuntimeInit(
    )
{
    return RuntimeInit();
}

extern "C" void __stdcall WarbirdRuntimeCleanup(
    )
{
    RuntimeCleanup();
}

#if defined(WARBIRD_KERNEL_MODE)

/*++

    Description:

        Stores the original unload handler. 

--*/
PDRIVER_UNLOAD g_pOriginalEntryDriverUnload = NULL;

/*++

    Description:

        NewDriverEntry() will change the DriverObject struct to register 
        this function as the unload handler. When this function is called
        during driver unload, it will call the original unload handler
        (if any) and do the cleanup for the runtime support lib.

    Arguments:

        DriverObject
            Caller-supplied pointer to a DRIVER_OBJECT structure.

    Returns:

        None.

--*/
VOID NTAPI 
NewDriverUnload( 
    __inout DRIVER_OBJECT*      DriverObject 
    )
{
    if (g_pOriginalEntryDriverUnload != NULL)
    {
        g_pOriginalEntryDriverUnload(DriverObject);
    }

    RuntimeCleanup();
}

/*++

    Description:

        Stores the original entry point of the driver. It should be initialized to a
        value other than 0 because the symbol would end up in .bss section
        if it is either uninitialized or initialized to 0.

--*/
volatile ULONG g_nRvaOriginalEntryDriver = 0x1;

/*++

    Description:

        If the tool is processing a kernel mode SYS, it will inject this 
        function, set it as the entry point of the module, and redirect 
        the OriginalDriverEntry() call in it to the original entry point. 
        This allows us to initialize runtime support lib before any 
        original code is run and do the cleanup after the original code
        exits. 
        
        Note that the declaration of the entry point must exactly match
        the one the OS is expecting (for WinXP, the entry point is 
        called by IopLoadDriver in base\ntos\io\iomgr\internal.c)

    Arguments:

        DriverObject
            Caller-supplied pointer to a DRIVER_OBJECT structure.

        RegistryPath
            Pointer to a counted Unicode string specifying the path to the 
            driver's registry key.

    Returns:

        STATUS_SUCCESS if successful, error status value otherwise.

--*/
#pragma code_seg("INIT")

__declspec(safebuffers)
NTSTATUS NTAPI 
NewDriverEntry(
    __inout DRIVER_OBJECT*      DriverObject,
    __in    UNICODE_STRING*     RegistryPath
    )
{
    HRESULT hr = RuntimeInit();

    if (FAILED(hr))
    {
        RuntimeCleanup();

        return STATUS_FAILED_DRIVER_ENTRY;
    }

    PDRIVER_INITIALIZE pOriginalEntryDriver = (PDRIVER_INITIALIZE)(g_nRvaOriginalEntryDriver + CUtil::GetImageBase());

    NTSTATUS Status = pOriginalEntryDriver(
        DriverObject,
        RegistryPath
        );

    if (!NT_SUCCESS(Status))
    {
        RuntimeCleanup();

        return Status;
    }

    g_pOriginalEntryDriverUnload = DriverObject->DriverUnload;

    DriverObject->DriverUnload = NewDriverUnload;

    return Status;
}

#pragma code_seg()

    //
    // TODO:: Need to handle export drivers
    // Currently there is one export driver using warbird (audio.sys) and 
    // this component is currently calling the warbird entry explicitly
    // in their initilization code.
    // Reference: //depot/winmain/drivers/wdm/audio/drm/krm/drmk/device.cpp#4

#else

/*++

    Description:

        Stores the original entry point of the exe. Initialize it to a value
        other than 0. If not it is put in the .bss section

--*/
    
typedef ULONG (__cdecl *MAIN_FUNCTION)(
);

volatile ULONG g_nRvaOriginalEntryMain = 0x1;

/*++

    Description:

        If the tool is processing a user mode EXE, it will inject this 
        function, set it as the entry point of the module, and redirect 
        the OriginalMain() call in it to the original entry point. 
        This allows us to initialize runtime support lib before any 
        original code is run and do the cleanup after the original code
        exits. 
        
        Note that the declaration of the entry point must exactly match
        the one the OS is expecting (for WinXP, the entry point is 
        called by BaseThreadStart in base\win32\client\support.c)

    Arguments:

        None.

    Returns:

        Exit code.

--*/
__declspec(safebuffers)
ULONG WINAPI 
NewEntryMain(
    void
    )
{
    HRESULT hr = S_OK;
    ULONG nResult = 0;
        
    hr = RuntimeInit();

    if (FAILED(hr))
    {
        goto CleanUp;
    }

    MAIN_FUNCTION pOriginalEntryMain = (MAIN_FUNCTION)(g_nRvaOriginalEntryMain + CUtil::GetImageBase());

    nResult = pOriginalEntryMain();

CleanUp:
    RuntimeCleanup();

    return FAILED(hr) ? hr : nResult;
}

/*++

    Description:

        Stores the original entry point of the dll. Initialize it to a value
        other than 0. If not it is put in the .bss section

--*/
typedef BOOL (WINAPI *DLL_MAIN_FUNCTION)(
__in    HINSTANCE   hInstance,
        ULONG       nReason,
__in    VOID*       pReserved
);

volatile ULONG g_nRvaOriginalEntryDllMain = 0x1;

/*++

    Description:

        If the tool is processing a user mode DLL, it will inject this 
        function, set it as the entry point of the module, and redirect 
        the OriginalDllMain() call in it to the original entry point. 
        This allows us to initialize runtime support lib before any 
        original code is run and do the cleanup after the original code
        exits. 
        
        Note that the declaration of the entry point must exactly match
        the one the OS is expecting (for WinXP, the entry point is 
        called by LdrpRunInitializeRoutines in base\ntdll\ldrsnap.c)

    Arguments:

        hInstance
            Handle to the DLL module.

        nReason
            Indicates why the DLL entry-point function is being called.

        pReserved
            Not used.

    Returns:

        TRUE if successful, FALSE otherwise.

--*/
__declspec(safebuffers)
BOOL WINAPI 
NewEntryDllMain(
    __in    HINSTANCE   hInstance,
            ULONG       nReason,
    __in    VOID*       pReserved
    )
{
    BOOL fResult = TRUE;
    HRESULT hr = S_OK;

    DLL_MAIN_FUNCTION pOriginalEntryDllMain = (DLL_MAIN_FUNCTION)(g_nRvaOriginalEntryDllMain + CUtil::GetImageBase());

    if (nReason == DLL_PROCESS_ATTACH)
    {
        hr = RuntimeInit();

        if (FAILED(hr))
        {
            RuntimeCleanup();
            fResult = FALSE;
            goto CleanUp;
        }
    }

    fResult = pOriginalEntryDllMain(
        hInstance,
        nReason,
        pReserved
        );

    if (nReason == DLL_PROCESS_DETACH)
    {
        RuntimeCleanup();
    }

CleanUp:
    return fResult;
}

#endif // defined (WARBIRD_KERNEL_MODE)

}; // namespace WarbirdRuntime