/**
  *
  * Hash Functions
  *
  **/

namespace WarbirdCrypto
{
// Must be kept in sync with Configuration values
#define WARBIRD_VSM_HASH_NO_MODIFIER 0x0
#define WARBIRD_VSM_HASH_LOWER_HALF  0x1
#define WARBIRD_VSM_HASH_UPPER_HALF  0x2

typedef unsigned __int64    CHash;

/*++

Description:

    Base class for Warbird hash functions

--*/
class CHashFunction
{
public:
    virtual VOID 
    Reset(
        __out CHash*    pHash
        ) = 0;

    virtual VOID 
    Update(
        __inout CHash*  pHash,
                BYTE    Data
        ) = 0;

    VOID
    Update(
        __inout             CHash*  pHash,
        __in_bcount(nBytes) PBYTE   pData,
                            SIZE_T  nBytes
        )
    {
        for (SIZE_T i = 0; i < nBytes; ++i)
        {
            Update(pHash, pData[i]);
        }
    }
};

/*++

Description:

    The XOR hash function simply XORs bytes. Only to be used for debugging.

--*/
#if !defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) && !defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)
template<BYTE iv>
#endif //defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) && !defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)
class CHashFunctionXor : public CHashFunction
{
public:

#if defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM)

    static std::shared_ptr<CHashFunctionXor>
    CreateRandom(
        )
    {
        std::shared_ptr<CHashFunctionXor> pHashFunction(new CHashFunctionXor);

        pHashFunction->iv = (BYTE) Random(0, 0xFF);

        return pHashFunction;
    }

#endif //defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM)

#if defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

    static std::shared_ptr<CHashFunctionXor>
    CreateFromType(
        __in    PCSTR   pszTypeName
        )
    {
        std::shared_ptr<CHashFunctionXor> pHashFunction;

        ULONG iv = 0;

        if (sscanf_s(pszTypeName, "WarbirdCrypto::CHashFunctionXor<%d>", &iv) == 1)
        {
            pHashFunction.reset(new CHashFunctionXor);
            pHashFunction->iv = (BYTE) iv;
        }

        return pHashFunction;
    }

    std::string
    GetName(
        ) const
    {
        std::ostringstream Name;

        Name << "WarbirdCrypto::CHashFunctionXor<" << (ULONG) iv << '>';

        return Name.str();
    }

#endif //defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

    __forceinline VOID 
    Reset(
        __out CHash*    pHash
        )
    {
        *pHash = iv;
    }

    __forceinline VOID 
    Update(
        __inout CHash*  pHash,
                BYTE    Data
        )
    {
        *pHash ^= Data;
    }

#if defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)
private:
    BYTE iv;
#endif //defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)
};


/*++

Description:

    Defines the hash function developed for the SCP tool.

--*/
#if !defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) && !defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)
template<
    SIZE_T  MacBodyID0, 
    SIZE_T  MacBodyID1, 
    SIZE_T  MacBodyID2, 
    ULONG64 Key64
    >
#endif //defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) && !defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)
class CHashFunctionSCP : public CHashFunction
{
public:

#if defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM)

    static std::shared_ptr<CHashFunctionSCP>
    CreateRandom(
        )
    {
        std::shared_ptr<CHashFunctionSCP> pHashFunction(new CHashFunctionSCP);

        for (SIZE_T i = 0; i < NUM_ROUNDS; ++i)
        {
            pHashFunction->MacBodyIDs[i] = Random(0, MAX_BODY_TYPE);
        }
        
        FillRandom(&pHashFunction->Key64, sizeof(pHashFunction->Key64));

        return pHashFunction;
    }

#endif //defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM)

#if defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

    static std::shared_ptr<CHashFunctionSCP>
    CreateFromType(
        __in    PCSTR   pszTypeName
        )
    {
        std::shared_ptr<CHashFunctionSCP> pHashFunction;

        if (strncmp(pszTypeName, "WarbirdCrypto::CHashFunctionSCP<", strlen("WarbirdCrypto::CHashFunctionSCP<")) == 0)
        {
            pHashFunction.reset(new CHashFunctionSCP);

            std::istringstream Name(pszTypeName + strlen("WarbirdCrypto::CHashFunctionSCP<"));

            char Comma;

            for (SIZE_T i = 0; i < NUM_ROUNDS; ++i)
            {
                Name >> pHashFunction->MacBodyIDs[i] >> Comma;
            }

            Name >> pHashFunction->Key64;
        }

        return pHashFunction;
    }

    std::string
    GetName(
        ) const
    {
        std::ostringstream Name;

        Name << "WarbirdCrypto::CHashFunctionSCP<";

        for (SIZE_T i = 0; i < NUM_ROUNDS; ++i)
        {
             Name << MacBodyIDs[i] << ',';
        }

        Name << Key64 << '>';

        return Name.str();
    }

    VOID
    CallMacBody(
                SIZE_T          nRound,
        __inout ULARGE_INTEGER& r, 
                ULONG           aParam, 
                ULONG           bParam
        )
    {
        switch (MacBodyIDs[nRound])
        {
            case 0: return MacBody<0>(r, aParam, bParam);
            case 1: return MacBody<1>(r, aParam, bParam);
            case 2: return MacBody<2>(r, aParam, bParam);
            case 3: return MacBody<3>(r, aParam, bParam);
            default: return;
        }
    }

#else //defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

    #define CallMacBody(nRound, r, aParam, bParam)  \
                                                    \
        MacBody<MacBodyID##nRound>(                 \
            r,                                      \
            aParam,                                 \
            bParam                                  \
            );                                      \

#endif //defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

    __forceinline VOID 
    Reset(
        __out CHash*    pHash
        )
    {
        *pHash = 0;
    }

    __forceinline VOID 
    Update(
        __inout CHash*  pHash,
                BYTE    Data
        )
    {
        ULARGE_INTEGER r;

        ULARGE_INTEGER Key;
        Key.QuadPart = Key64;

        ULARGE_INTEGER& Hash = *(ULARGE_INTEGER*)pHash;

        // MAC header
        r.LowPart = Data;           // get next input byte
        r.LowPart += Key.LowPart;   // add key to input
        Hash.LowPart += r.LowPart;  // add input to sum
        r.LowPart += Hash.HighPart; // chain previous result

        // MAC bodies
        CallMacBody(0, r, Key.LowPart, LOWORD(Key.HighPart));
        CallMacBody(1, r, Key.LowPart, LOWORD(Key.HighPart));
        CallMacBody(2, r, Key.LowPart, LOWORD(Key.HighPart));

        // MAC footer
        Hash.HighPart = r.LowPart;  // chain
        Hash.LowPart += r.LowPart;  // sum
    }

private:
    enum : SIZE_T
    { 
        NUM_ROUNDS = 3,
        MAX_BODY_TYPE = 3,
    };

    template <SIZE_T nBodyID>
    __forceinline VOID
    MacBody(
        __inout ULARGE_INTEGER& r, 
                ULONG           aParam, 
                ULONG           bParam
        );

    template <> __forceinline static VOID MacBody<0>(__inout ULARGE_INTEGER& r, ULONG aParam, ULONG bParam)
    {
        r.LowPart = RotateRight32(r.LowPart * aParam, bParam & 31);
    }

    template <> __forceinline static VOID MacBody<1>(__inout ULARGE_INTEGER& r, ULONG aParam, ULONG)
    {
        r.QuadPart = UInt32x32To64(r.LowPart, aParam);
        r.LowPart += r.HighPart;
    }

    template <> __forceinline static VOID MacBody<2>(__inout ULARGE_INTEGER& r, ULONG aParam, ULONG)
    {
        r.QuadPart = UInt32x32To64(r.LowPart, aParam);

        r.HighPart = r.LowPart + 2*r.HighPart - 0x7FFFFFFF;
        r.HighPart -= ((signed) r.LowPart >> 31) & 0x7FFFFFFF;
        r.HighPart += ((signed) r.HighPart >> 31) & 0x7FFFFFFF;

        r.LowPart = r.HighPart;
    }

    template <> __forceinline static VOID MacBody<3>(__inout ULARGE_INTEGER& r, ULONG aParam, ULONG bParam)
    {
        r.LowPart = RotateRight32(r.LowPart, aParam & 15) ^
            RotateLeft32(r.LowPart * bParam, aParam & 15);
    }

#if defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)
private:
    SIZE_T  MacBodyIDs[NUM_ROUNDS];
    ULONG64 Key64;
#endif //defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)
};

#if defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

inline std::shared_ptr<CHashFunction>
HashFunctionCreateFromType(
    PCSTR   pszTypeName
    )
{
    std::shared_ptr<CHashFunction> pHashFunction;

    if ((pHashFunction = CHashFunctionSCP::CreateFromType(pszTypeName)) != NULL ||
        (pHashFunction = CHashFunctionXor::CreateFromType(pszTypeName)) != NULL)
    {
    }

    return pHashFunction;
}

#endif //defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

}; // namespace WarbirdCrypto
