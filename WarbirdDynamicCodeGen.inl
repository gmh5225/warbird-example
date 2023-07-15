/**
  *
  * Allows a thread to enable dynamic code generation for ACG.
  *
  **/

#undef THREAD_DYNAMIC_CODE_ALLOW
#define THREAD_DYNAMIC_CODE_ALLOW   1     // Opt-out of dynamic code generation.

namespace WarbirdRuntime
{

#if defined(WARBIRD_KERNEL_MODE)
class AutoEnableDynamicCodeGen
{
public:
    AutoEnableDynamicCodeGen(bool enable = true)
    {
        UNREFERENCED_PARAMETER(enable);
    }
};
#else
class AutoEnableDynamicCodeGen
{
public:
    //
    // These structures are and callback prototypes are declared in windows header
    // files but the updated definitions are not yet in the compiler tree so the
    // structures are redefined inside this class. Once the new definitions make
    // it to the compiler branch these definitions can be removed.
    //

    #pragma warning(push)
    #pragma warning(disable : 4201) // nonstandard extension used : nameless struct/union
#if !defined(_HRESULT_DEFINED)
typedef LONG HRESULT
#define S_OK    0
#endif 

#include "guiddef.h"

#if !defined(__IUnknown_INTERFACE_DEFINED__)
#define __IUnknown_INTERFACE_DEFINED__

    typedef __declspec(novtable) struct IUnknown
    {
        public:
            virtual HRESULT STDMETHODCALLTYPE QueryInterface(_In_ REFIID riid, _COM_Outptr_ void ** ppvObject) = 0;
            virtual ULONG STDMETHODCALLTYPE AddRef( void) = 0;
            virtual ULONG STDMETHODCALLTYPE Release( void) = 0;

            template<class Q>
            HRESULT
#ifdef _M_CEE_PURE
            __clrcall
#else
            STDMETHODCALLTYPE
#endif
            QueryInterface(_COM_Outptr_ Q** pp)
            {
                return QueryInterface(__uuidof(Q), (void **)pp);
            }

        };
#endif 

#ifndef __IEditionUpgradeHelper_INTERFACE_DEFINED__
#define __IEditionUpgradeHelper_INTERFACE_DEFINED__
    typedef struct __declspec(uuid("D3E9E342-5DEB-43B6-849E-6913B85D503A")) __declspec(novtable) IEditionUpgradeHelper 
        : public IUnknown
    {
        public:
            virtual HRESULT STDMETHODCALLTYPE CanUpgrade(_Out_ BOOL *isAllowed) = 0;
            virtual HRESULT STDMETHODCALLTYPE UpdateOperatingSystem(_In_ LPCWSTR contentId) = 0;
            virtual HRESULT STDMETHODCALLTYPE ShowProductKeyUI( void) = 0;
            virtual HRESULT STDMETHODCALLTYPE GetOsProductContentId(_Out_ LPWSTR *contentId) = 0;
            virtual HRESULT STDMETHODCALLTYPE GetGenuineLocalStatus(_Out_ BOOL *isGenuine) = 0;
            virtual HRESULT STDMETHODCALLTYPE DisableAcgEnforcement(_In_ BOOL isEnforcementSet) = 0;
    };

    GUID CLSID_EditionUpgradeHelper = {0x01776DF3,0xB9AF,0x4E50,0x9B,0x1C,0x56,0xE9,0x31,0x16,0xD7,0x04};
#endif 

#if !defined(__objidlbase_h__) && !defined(__objidl_h__)
    typedef struct tagMULTI_QI
    {
        const GUID *pIID;
        IUnknown *pItf;
        HRESULT hr;
    } 	MULTI_QI;
#endif

    typedef enum _THREAD_INFORMATION_CLASS {
        ThreadMemoryPriority,
        ThreadAbsoluteCpuPriority,
        ThreadDynamicCodePolicy,
        ThreadInformationClassMax
    } THREAD_INFORMATION_CLASS;

    typedef struct _PROCESS_MITIGATION_DYNAMIC_CODE_POLICY {
        union {
            ULONG Flags;
            struct {
                ULONG ProhibitDynamicCode : 1;
                ULONG AllowThreadOptOut : 1;
                ULONG ReservedFlags : 30;
            } DUMMYSTRUCTNAME;
        } DUMMYUNIONNAME;
    } PROCESS_MITIGATION_DYNAMIC_CODE_POLICY, *PPROCESS_MITIGATION_DYNAMIC_CODE_POLICY;

    typedef
    BOOL
    (WINAPI *PGET_PROCESS_MITIGATION_POLICY_PROC)(
        _In_  HANDLE                    hProcess,
        _In_  PROCESS_MITIGATION_POLICY MitigationPolicy,
        _Out_ PVOID                     lpBuffer,
        _In_  SIZE_T                    dwLength
        );

    typedef
    BOOL
    (WINAPI *PSET_THREAD_INFORMATION_PROC)(
        _In_ HANDLE                   hThread,
        _In_ THREAD_INFORMATION_CLASS ThreadInformationClass,
        _In_reads_bytes_(ThreadInformationSize) PVOID ThreadInformation,
        _In_ DWORD                    ThreadInformationSize
        );

    typedef
    BOOL
    (WINAPI *PGET_THREAD_INFORMATION_PROC)(
        _In_ HANDLE                   hThread,
        _In_ THREAD_INFORMATION_CLASS ThreadInformationClass,
        _Out_writes_bytes_(ThreadInformationSize) PVOID ThreadInformation,
        _In_ DWORD                    ThreadInformationSize
    );

    typedef
    HRESULT
    (__stdcall  *PCO_CREATE_INSTANCE_FROM_APP_PROC)(
        _In_     REFCLSID                rclsid,
        _In_opt_ IUnknown            *punkOuter,
        _In_     DWORD               dwClsCtx,
        _In_opt_ void                *reserved,
        _In_     DWORD               dwCount,
        _Inout_  MULTI_QI            *pResults                                                
     );
    #pragma warning(pop)

public:
    AutoEnableDynamicCodeGen(bool enable = true) : enabled(false)
    {
        if (enable == false)
        {
            return;
        }

        //
        // Snap the dynamic code generation policy for this process so that we
        // don't need to resolve APIs and query it each time. We expect the policy
        // to have been established upfront.
        //
        // processPolicyObtained is volaitile so the compiler does not change
        // the order of the instructions causing a thread to use uninitialized
        // static class members.
        //

        if (processPolicyObtained == false)
        {
            HMODULE module = GetModuleHandleW(L"api-ms-win-core-processthreads-l1-1-3.dll");

            if (module != nullptr)
            {
                GetProcessMitigationPolicyProc = (PGET_PROCESS_MITIGATION_POLICY_PROC) GetProcAddress(module, "GetProcessMitigationPolicy");
                SetThreadInformationProc = (PSET_THREAD_INFORMATION_PROC) GetProcAddress(module, "SetThreadInformation");
                GetThreadInformationProc = (PGET_THREAD_INFORMATION_PROC) GetProcAddress(module, "GetThreadInformation");
            }

            if ((GetProcessMitigationPolicyProc == nullptr) ||
                (!GetProcessMitigationPolicyProc(GetCurrentProcess(), ProcessDynamicCodePolicy, &processPolicy, sizeof(processPolicy))))
            {
                processPolicy.ProhibitDynamicCode = 0;
            }

            processPolicyObtained = true;
        }

        //
        // The process is not prohibiting dynamic code or does not allow threads
        // to opt out.  In either case, return to the caller.
        //
        // N.B. It is OK that this policy is mutable at runtime. If a process
        //      really does not allow thread opt-out, then the call below will fail
        //      benignly.
        //

        if (processPolicy.ProhibitDynamicCode == 0)
        {
            return;
        }

        if (processPolicy.AllowThreadOptOut == 0)
        {

            //
            // If the process is an appcontainer and the CCIIFA pointer was
            // initialized, call in to the broker to turn off the flag.
            // 
            if ((disableACGCalled == false))
            {
                LoadCoCreateInstanceProc();
                if (CoCreateInstanceFromAppProc != nullptr)
                {
                    DisableAcgFromAppContainer(TRUE);
                    disableACGCalled = true;
                }
            }
        }

        if (SetThreadInformationProc == nullptr || GetThreadInformationProc == nullptr)
        {
            return;
        }

        // 
        // If dynamic code is already allowed for this thread, then don't attempt to allow it again.
        //

        DWORD threadPolicy;

        if ((GetThreadInformationProc(GetCurrentThread(), ThreadDynamicCodePolicy, &threadPolicy, sizeof(DWORD))) &&
            (threadPolicy == THREAD_DYNAMIC_CODE_ALLOW))
        {
            return;
        }

        threadPolicy = (enable) ? THREAD_DYNAMIC_CODE_ALLOW : 0;

        (VOID) SetThreadInformationProc(GetCurrentThread(), ThreadDynamicCodePolicy, &threadPolicy, sizeof(DWORD));

        enabled = true;
    }

    ~AutoEnableDynamicCodeGen()
    {
        if (enabled)
        {
            DWORD threadPolicy = 0;

            (VOID) SetThreadInformationProc(GetCurrentThread(), ThreadDynamicCodePolicy, &threadPolicy, sizeof(DWORD));

            enabled = false;
        }
    }

private:

    //
    // This API attempts to change the dynamic code policy by calling into the
    // Licensing app broker. If this fails, Warbird runtime will attempt to
    // change the policy directly
    //
    void LoadCoCreateInstanceProc()
    {
        HMODULE module = GetModuleHandleW(L"api-ms-win-core-com-l1-1-1.dll");
        if (module == nullptr)
        {
            //
            // The API is present in combase, which may not be loaded in every
            // process. In that case, use LoadLibrary
            //
            module = LoadLibraryW(L"api-ms-win-core-com-l1-1-1.dll");
            if (module == nullptr)
            {
                return; 
            }
        }

        CoCreateInstanceFromAppProc = (PCO_CREATE_INSTANCE_FROM_APP_PROC) GetProcAddress(module, "CoCreateInstanceFromApp");
    }

    //
    // This API Calls into the Licensing Broker to turn off ACG enforcement
    //
    bool DisableAcgFromAppContainer(BOOL disableFlag)
    {
        MULTI_QI mq = {0};                                               
        GUID rEditionHelper = __uuidof(IEditionUpgradeHelper);
        WCHAR binaryName[MAX_PATH] = {0};
        
        mq.hr = S_OK;
        mq.pItf = NULL;
        mq.pIID = &rEditionHelper;

        LONG resultCode = CoCreateInstanceFromAppProc(CLSID_EditionUpgradeHelper, nullptr,  0x1, nullptr, 1, &mq); 
        if (resultCode != S_OK)
        {
            return false;
        }
        GetModuleFileNameW((HMODULE) CUtil::GetImageBase(), binaryName, MAX_PATH);
        IEditionUpgradeHelper* upgradeHelper = ((static_cast <IEditionUpgradeHelper *> (mq.pItf)));
        resultCode = upgradeHelper->DisableAcgEnforcement(disableFlag);

        if (resultCode != S_OK)
        {
            return false;
        }

        return true;
    }        

    bool enabled;

    static PGET_PROCESS_MITIGATION_POLICY_PROC GetProcessMitigationPolicyProc;
    static PSET_THREAD_INFORMATION_PROC SetThreadInformationProc;
    static PGET_THREAD_INFORMATION_PROC GetThreadInformationProc;
    static PCO_CREATE_INSTANCE_FROM_APP_PROC CoCreateInstanceFromAppProc;
    static PROCESS_MITIGATION_DYNAMIC_CODE_POLICY processPolicy;

    // Used to determine if the statics have been initialized. This is volatile
    // so the compile does not change the order of the instructions in the
    // constructor.

    volatile static bool processPolicyObtained;
    volatile static bool disableACGCalled;

};

AutoEnableDynamicCodeGen::PGET_PROCESS_MITIGATION_POLICY_PROC AutoEnableDynamicCodeGen::GetProcessMitigationPolicyProc = NULL;
AutoEnableDynamicCodeGen::PSET_THREAD_INFORMATION_PROC AutoEnableDynamicCodeGen::SetThreadInformationProc = NULL;
AutoEnableDynamicCodeGen::PGET_THREAD_INFORMATION_PROC AutoEnableDynamicCodeGen::GetThreadInformationProc = NULL;
AutoEnableDynamicCodeGen::PCO_CREATE_INSTANCE_FROM_APP_PROC AutoEnableDynamicCodeGen::CoCreateInstanceFromAppProc = NULL;
AutoEnableDynamicCodeGen::PROCESS_MITIGATION_DYNAMIC_CODE_POLICY AutoEnableDynamicCodeGen::processPolicy;
volatile bool AutoEnableDynamicCodeGen::processPolicyObtained = false;
volatile bool AutoEnableDynamicCodeGen::disableACGCalled = false;

#endif // #if defined(WARBIRD_KERNEL_MODE)

} // namespace WarbirdRuntime
