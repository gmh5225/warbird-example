/**
  *
  * Ciphers
  *
  **/

namespace WarbirdCrypto
{

#if defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM)
#define WARBIRD_MEMCPY(pTarget, pSource, nBytes) memcpy(pTarget, pSource, nBytes);
#define WARBIRD_MEMSET(pTarget, pSource, nBytes) memset(pTarget, pSource, nBytes);
#else
#define WARBIRD_MEMCPY(pTarget, pSource, nBytes) WarbirdRuntime::CUtil::Memcpy((PVOID)pTarget, (PVOID)pSource, nBytes);
#define WARBIRD_MEMSET(pBuffer, nValue, nBytes) WarbirdRuntime::CUtil::Memset(pBuffer, nValue, nBytes);
#endif // WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM

typedef unsigned __int8     CChecksum;

union CKey
{
    UCHAR       u8[8];
    USHORT      u16[4];
    ULONG       u32[2];
    ULONG64     u64;
};

/*++

Description:

    Base class for Warbird ciphers

--*/
class CCipher
{
public:
    virtual VOID 
    Encrypt(
        __in_bcount(nBytes)     CONST BYTE*         pSource,
        __out_bcount(nBytes)    BYTE*               pTarget,
                                SIZE_T              nBytes,
                                CKey                Key,
                                ULONG               IV,
        __out                   CChecksum*          pChecksum
        ) = 0;

    virtual VOID 
    Decrypt(
        __in_bcount(nBytes)     CONST BYTE*         pSource,
        __out_bcount(nBytes)    BYTE*               pTarget,
                                SIZE_T              nBytes,
                                CKey                Key,
                                ULONG               IV,
        __out                   CChecksum*          pChecksum
        ) = 0;

#if defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

    virtual std::string
    GetName(
        ) const = 0;

#endif //defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

    BOOL
    IsSane(
        )
    {
        CONST SIZE_T CIPHER_SANITY_BUFFER_SIZE = 256;

        CKey Key1;
        CKey Key2;

        Key1.u64 = 0x0123456789ABCDEF;
        Key2.u64 = Key1.u64 ^ 1;

        ULONG IV = 0;
        CChecksum ChecksumPlain;
        CChecksum ChecksumDecrypted;

        BYTE    Plain[CIPHER_SANITY_BUFFER_SIZE] = { 0 };
        BYTE    EncryptedWithKey1[CIPHER_SANITY_BUFFER_SIZE];
        BYTE    EncryptedWithKey2[CIPHER_SANITY_BUFFER_SIZE];
        BYTE    DecryptedWithKey1[CIPHER_SANITY_BUFFER_SIZE];
        BYTE    DecryptedWithKey2[CIPHER_SANITY_BUFFER_SIZE];

        // TEST: plaintext to opaque ciphertext back to plaintext

        Encrypt(Plain, EncryptedWithKey1, CIPHER_SANITY_BUFFER_SIZE, Key1, IV, &ChecksumPlain);
        Decrypt(EncryptedWithKey1, DecryptedWithKey1, CIPHER_SANITY_BUFFER_SIZE, Key1, IV, &ChecksumDecrypted);

        if (memcmp(Plain, DecryptedWithKey1, CIPHER_SANITY_BUFFER_SIZE) != 0 ||
            ChecksumDecrypted != ChecksumPlain)
        {
            return FALSE;
        }

        // Make sure that we have decent cipher text

        if (PatternSearch(DecryptedWithKey1, EncryptedWithKey1, CIPHER_SANITY_BUFFER_SIZE))
        {
            return FALSE;
        }

        // TEST: single bit change in key produces dramatically different ciphertext

        Encrypt(Plain, EncryptedWithKey2, CIPHER_SANITY_BUFFER_SIZE, Key2, IV, &ChecksumPlain);

        if (PatternSearch(EncryptedWithKey2, EncryptedWithKey1, CIPHER_SANITY_BUFFER_SIZE))
        {
            return FALSE;
        }

        // TEST: decrypt with different key gets bad plaintext

        Decrypt(EncryptedWithKey1, DecryptedWithKey2, CIPHER_SANITY_BUFFER_SIZE, Key2, IV, &ChecksumDecrypted);

        if (PatternSearch(DecryptedWithKey2, EncryptedWithKey1, CIPHER_SANITY_BUFFER_SIZE) ||
            ChecksumDecrypted == ChecksumPlain)
        {
            return FALSE;
        }

        // TEST: single bit modified ciphertext to infinitely garbled plaintext

        EncryptedWithKey1[0] ^= 1;
        Decrypt(EncryptedWithKey1, DecryptedWithKey1, CIPHER_SANITY_BUFFER_SIZE, Key1, IV, &ChecksumDecrypted);

        if (PatternSearch(DecryptedWithKey1, Plain, CIPHER_SANITY_BUFFER_SIZE) ||
            ChecksumDecrypted == ChecksumPlain)
        {
            return FALSE;
        }

        return TRUE;
    }

    BOOL
    PatternSearch(
        __in_bcount(nBytes)    CONST BYTE*  pBuffer1, 
        __in_bcount(nBytes)    CONST BYTE*  pBuffer2, 
                               SIZE_T       nBytes
        )
    {
        CONST SIZE_T CIPHER_SANITY_PATTERN_LEN = 4;

        for (SIZE_T i = 0; i < nBytes - CIPHER_SANITY_PATTERN_LEN; i++)
        {
            for (SIZE_T j = i; j < nBytes - CIPHER_SANITY_PATTERN_LEN; j++)
            {
                if (memcmp(&pBuffer1[i], &pBuffer2[j], CIPHER_SANITY_PATTERN_LEN) == 0)
                {
                    return TRUE;
                }
            }
        }

        return FALSE;
    }
};

/*++

Description:

    The NOP cipher simply copies the plaintext into ciphertext without any encryptions.
    Only to be used for debugging.

--*/
class CCipherNop : public CCipher
{
public:

#if defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM)

    static std::shared_ptr<CCipherNop>
    CreateRandom(
        )
    {
        return std::shared_ptr<CCipherNop>(new CCipherNop);
    }

#endif //defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM)

#if defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

    static std::shared_ptr<CCipherNop>
    CreateFromType(
        __in    PCSTR   pszTypeName
        )
    {
        std::shared_ptr<CCipherNop> pCipher;

        if (strncmp(pszTypeName, "WarbirdCrypto::CCipherNop", strlen("WarbirdCrypto::CCipherNop")) == 0)
        {
            pCipher.reset(new CCipherNop);
        }

        return pCipher;
    }

    virtual std::string
    GetName(
        ) const
    {
        return "WarbirdCrypto::CCipherNop";
    }

#endif //defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

    __forceinline VOID
    Encrypt(
        __in_bcount(nBytes)     CONST BYTE*         pSource,
        __out_bcount(nBytes)    BYTE*               pTarget,
                                SIZE_T              nBytes,
                                CKey                Key,
                                ULONG               IV,
        __out                   CChecksum*          pChecksum
        )
    {
        if (nBytes > 0)
        {
            *pChecksum = pSource[nBytes - 1];
            WARBIRD_MEMCPY(pTarget, pSource, nBytes);
        }

        UNREFERENCED_PARAMETER(Key);
        UNREFERENCED_PARAMETER(IV);
    }

    __forceinline VOID
    Decrypt(
        __in_bcount(nBytes)     CONST BYTE*         pSource,
        __out_bcount(nBytes)    BYTE*               pTarget,
                                SIZE_T              nBytes,
                                CKey                Key,
                                ULONG               IV,
        __out                   CChecksum*          pChecksum
        )
    {
        if (nBytes > 0)
        {
            WARBIRD_MEMCPY(pTarget, pSource, nBytes);
            *pChecksum = pTarget[nBytes - 1];
        }

        UNREFERENCED_PARAMETER(Key);
        UNREFERENCED_PARAMETER(IV);
    }
};

/*++

Description:

    The XOR cipher simply XORs bytes with an IV. Only to be used for debugging.

--*/
#if !defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) && !defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)
template<BYTE iv>
#endif //!defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) && !defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)
class CCipherXor : public CCipher
{
public:

#if defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM)

    static std::shared_ptr<CCipherXor>
    CreateRandom(
        )
    {
        std::shared_ptr<CCipherXor> pCipher(new CCipherXor);

        pCipher->iv = (BYTE) Random(0, 0xFF);

        return pCipher;
    }

#endif //defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM)

#if defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

    static std::shared_ptr<CCipherXor>
    CreateFromType(
        __in    PCSTR   pszTypeName
        )
    {
        std::shared_ptr<CCipherXor> pCipher;

        ULONG iv = 0;

        if (sscanf_s(pszTypeName, "WarbirdCrypto::CCipherXor<%d>", &iv) == 1)
        {
            pCipher.reset(new CCipherXor);
            pCipher->iv = (BYTE) iv;
        }

        return pCipher;
    }

    virtual std::string
    GetName(
        ) const
    {
        std::ostringstream Name;

        Name << "WarbirdCrypto::CCipherXor<" << (ULONG) iv << '>';
        
        return Name.str();
    }

#endif //defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

    __forceinline VOID 
    Encrypt(
        __in_bcount(nBytes)     CONST BYTE*         pSource,
        __out_bcount(nBytes)    BYTE*               pTarget,
                                SIZE_T              nBytes,
                                CKey                Key,
                                ULONG               IV,
        __out                   CChecksum*          pChecksum
        )
    {
        if (nBytes > 0)
        {
            *pChecksum = pSource[nBytes - 1];

            BYTE nPreviousByte = iv;

            for (SIZE_T i = 0; i < nBytes; ++i)
            {
                BYTE value = pSource[i];
                pTarget[i] = value ^ nPreviousByte;
                nPreviousByte = value;
            }
        }

        UNREFERENCED_PARAMETER(Key);
        UNREFERENCED_PARAMETER(IV);
    }

    __forceinline VOID 
    Decrypt(
        __in_bcount(nBytes)     CONST BYTE*         pSource,
        __out_bcount(nBytes)    BYTE*               pTarget,
                                SIZE_T              nBytes,
                                CKey                Key,
                                ULONG               IV,
        __out                   CChecksum*          pChecksum
        )
    {
        if (nBytes > 0)
        {
            BYTE nPreviousByte = iv;

            for (SIZE_T i = 0; i < nBytes; ++i)
            {
                pTarget[i] = pSource[i] ^ nPreviousByte;
                nPreviousByte = pTarget[i];
            }

            *pChecksum = pTarget[nBytes - 1];
        }

        UNREFERENCED_PARAMETER(Key);
        UNREFERENCED_PARAMETER(IV);
    }

#if defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)
private:
    BYTE iv;
#endif //defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

};

/*++

Description:

    Defines the cipher developed by BBorn.

--*/
#if !defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) && !defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)
template <
    SIZE_T Round_0_FunctionID, ULONG Round_0_Rand0, ULONG Round_0_Rand1, ULONG Round_0_Rand2,
    SIZE_T Round_1_FunctionID, ULONG Round_1_Rand0, ULONG Round_1_Rand1, ULONG Round_1_Rand2,
    SIZE_T Round_2_FunctionID, ULONG Round_2_Rand0, ULONG Round_2_Rand1, ULONG Round_2_Rand2,
    SIZE_T Round_3_FunctionID, ULONG Round_3_Rand0, ULONG Round_3_Rand1, ULONG Round_3_Rand2,
    SIZE_T Round_4_FunctionID, ULONG Round_4_Rand0, ULONG Round_4_Rand1, ULONG Round_4_Rand2,
    SIZE_T Round_5_FunctionID, ULONG Round_5_Rand0, ULONG Round_5_Rand1, ULONG Round_5_Rand2,
    SIZE_T Round_6_FunctionID, ULONG Round_6_Rand0, ULONG Round_6_Rand1, ULONG Round_6_Rand2,
    SIZE_T Round_7_FunctionID, ULONG Round_7_Rand0, ULONG Round_7_Rand1, ULONG Round_7_Rand2,
    SIZE_T Round_8_FunctionID, ULONG Round_8_Rand0, ULONG Round_8_Rand1, ULONG Round_8_Rand2,
    SIZE_T Round_9_FunctionID, ULONG Round_9_Rand0, ULONG Round_9_Rand1, ULONG Round_9_Rand2
    >
#endif //!defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) && !defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)
class CCipherFeistel64 : public CCipher
{
public:
#if defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)
    typedef SIZE_T (*PFN_RANDOM)(
        SIZE_T nMin,
        SIZE_T nMax,
        PVOID pContext
        );

    static std::shared_ptr<CCipherFeistel64>
    CreateRandom(
        PFN_RANDOM pfnRandom,
        PVOID pContext
        )
    {
        ULONG   Input = 0;
        ULONG   Output;

        CKey Key;
        Key.u64 = 0x0123456789ABCDEF;

        std::shared_ptr<CCipherFeistel64> pCipher(new CCipherFeistel64);

        do
        {
            std::set<SIZE_T>    UsedFunctionIDs;
            std::set<ULONG>     ObservedOutputs;

            ObservedOutputs.insert(Input);

            for (SIZE_T i = 0; i < NUM_ROUNDS; ++i)
            {
                do
                {
                    // Select a round function that hasn't been selected before

                    do
                    {
                        pCipher->m_Rounds[i].FunctionID = (ULONG)pfnRandom(0, MAX_ROUND_FUNCTION, pContext);
                    }
                    while (UsedFunctionIDs.find(pCipher->m_Rounds[i].FunctionID) != UsedFunctionIDs.end());

                    // Select random data bytes for the round

                    pCipher->m_Rounds[i].Rand0 = (ULONG)pfnRandom(0, 0xFF, pContext);
                    pCipher->m_Rounds[i].Rand1 = (ULONG)pfnRandom(0, 0xFF, pContext);
                    pCipher->m_Rounds[i].Rand2 = (ULONG)pfnRandom(0, 0xFF, pContext);

                    Output = pCipher->CallRoundFunction(i, Key, Input);
                }
                while (ObservedOutputs.find(Output) != ObservedOutputs.end());

                UsedFunctionIDs.insert(pCipher->m_Rounds[i].FunctionID);
                ObservedOutputs.insert(Output);
            }
        }
        while(!pCipher->IsSane());

        return pCipher;
    }
#endif // defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

#if defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM)

    static SIZE_T DefaultRandom(SIZE_T min, SIZE_T max, PVOID pContext)
    {
        UNREFERENCED_PARAMETER(pContext);
        return Random(min, max);
    }

    static std::shared_ptr<CCipherFeistel64>
    CreateRandom(
        )
    {
        return CreateRandom(CCipherFeistel64::DefaultRandom, NULL);
    }

#endif //defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM)

#if defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

    static std::shared_ptr<CCipherFeistel64>
    CreateFromType(
        __in    PCSTR   pszTypeName
        )
    {
        std::shared_ptr<CCipherFeistel64> pCipher;

        if (strncmp(pszTypeName, "WarbirdCrypto::CCipherFeistel64<", strlen("WarbirdCrypto::CCipherFeistel64<")) == 0)
        {
            pCipher.reset(new CCipherFeistel64);

            std::istringstream Name(pszTypeName + strlen("WarbirdCrypto::CCipherFeistel64<"));

            for (SIZE_T i = 0; i < NUM_ROUNDS; ++i)
            {
                char Comma;

                if (i > 0)
                {
                    Name >> Comma;
                }

                Name >> pCipher->m_Rounds[i].FunctionID >> Comma 
                     >> pCipher->m_Rounds[i].Rand0 >> Comma 
                     >> pCipher->m_Rounds[i].Rand1 >> Comma 
                     >> pCipher->m_Rounds[i].Rand2;
            }
        }

        return pCipher;
    }

    std::string
    GetName(
        ) const
    {
        std::ostringstream Name;

        Name << "WarbirdCrypto::CCipherFeistel64<";

        for (SIZE_T i = 0; i < NUM_ROUNDS; ++i)
        {
            if (i > 0)
            {
                Name << ',';
            }

            Name << m_Rounds[i].FunctionID << ',' 
                 << m_Rounds[i].Rand0 << ',' 
                 << m_Rounds[i].Rand1 << ',' 
                 << m_Rounds[i].Rand2;
        }

        Name << '>';

        return Name.str();
    }

    ULONG 
    CallRoundFunction(
        SIZE_T  nRound,
        CKey    Key, 
        ULONG   Input
        )
    {
        switch (m_Rounds[nRound].FunctionID)
        {
            case 0: return RoundFunction<0>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 1: return RoundFunction<1>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 2: return RoundFunction<2>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 3: return RoundFunction<3>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 4: return RoundFunction<4>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 5: return RoundFunction<5>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 6: return RoundFunction<6>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 7: return RoundFunction<7>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 8: return RoundFunction<8>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 9: return RoundFunction<9>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 10: return RoundFunction<10>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 11: return RoundFunction<11>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 12: return RoundFunction<12>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 13: return RoundFunction<13>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 14: return RoundFunction<14>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 15: return RoundFunction<15>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 16: return RoundFunction<16>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 17: return RoundFunction<17>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 18: return RoundFunction<18>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 19: return RoundFunction<19>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 20: return RoundFunction<20>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 21: return RoundFunction<21>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 22: return RoundFunction<22>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 23: return RoundFunction<23>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 24: return RoundFunction<24>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 25: return RoundFunction<25>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 26: return RoundFunction<26>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 27: return RoundFunction<27>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 28: return RoundFunction<28>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 29: return RoundFunction<29>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            case 30: return RoundFunction<30>(m_Rounds[nRound].Rand0, m_Rounds[nRound].Rand1, m_Rounds[nRound].Rand2, nRound, Key, Input);
            default: return 0;
        }
    }

#else //defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

    #define CallRoundFunction(nRound, Key, Input)   \
                                                    \
        RoundFunction<Round_##nRound##_FunctionID>( \
            Round_##nRound##_Rand0,                 \
            Round_##nRound##_Rand1,                 \
            Round_##nRound##_Rand2,                 \
            nRound,                                 \
            Key,                                    \
            Input                                   \
            );                                      \

#endif //defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

public:
    __forceinline VOID 
    Encrypt(
        __in_bcount(nBytes)     CONST BYTE*         pSource,
        __out_bcount(nBytes)    BYTE*               pTarget,
                                SIZE_T              nBytes,
                                CKey                Key,
                                ULONG               IV,
        __out                   CChecksum*          pChecksum
        )
    {
        if (nBytes > 0)
        {
            *pChecksum = pSource[nBytes - 1];

            CONST SIZE_T nBlockSize = 8;
            ULARGE_INTEGER PrevPlaintext;
            ULARGE_INTEGER Plaintext;
            ULARGE_INTEGER Data;

            Data.LowPart = ~IV;
            Data.HighPart = IV;

            SIZE_T nOddBytes = nBytes % nBlockSize;

            if (nOddBytes == 0)
            {
                PrevPlaintext.QuadPart = 0;
            }
            else
            {
                // Use decrypted IV to encrypt odd bytes

                Data.LowPart ^= CallRoundFunction(9, Key, Data.HighPart);
                Data.HighPart ^= CallRoundFunction(8, Key, Data.LowPart);  

                Data.LowPart ^= CallRoundFunction(7, Key, Data.HighPart);
                Data.HighPart ^= CallRoundFunction(6, Key, Data.LowPart);  

                Data.LowPart ^= CallRoundFunction(5, Key, Data.HighPart);
                Data.HighPart ^= CallRoundFunction(4, Key, Data.LowPart);  

                Data.LowPart ^= CallRoundFunction(3, Key, Data.HighPart);
                Data.HighPart ^= CallRoundFunction(2, Key, Data.LowPart);  

                Data.LowPart ^= CallRoundFunction(1, Key, Data.HighPart);
                Data.HighPart ^= CallRoundFunction(0, Key, Data.LowPart);  

                Plaintext.QuadPart = 0;
                WARBIRD_MEMCPY(&Plaintext, pSource, nOddBytes);

                Data.LowPart ^= Plaintext.LowPart;
                Data.HighPart ^= Plaintext.HighPart;

                PrevPlaintext.QuadPart = Plaintext.QuadPart;

                WARBIRD_MEMSET(((BYTE*)&Data) + nOddBytes, 0, nBlockSize - nOddBytes);
                WARBIRD_MEMCPY(pTarget, &Data, nOddBytes);
            }

            CONST ULARGE_INTEGER* pSource64 = reinterpret_cast<CONST ULARGE_INTEGER*>(pSource + nOddBytes);
            ULARGE_INTEGER* pTarget64 = reinterpret_cast<ULARGE_INTEGER*>(pTarget + nOddBytes);

            for (SIZE_T nBlock = 0; nBlock < nBytes / nBlockSize; ++nBlock)
            {
                Plaintext.QuadPart = pSource64->QuadPart;
                ++pSource64;
        
                Data.LowPart ^= Plaintext.LowPart;
                Data.HighPart ^= Plaintext.HighPart;

                Data.HighPart ^= CallRoundFunction(0, Key, Data.LowPart);  
                Data.LowPart ^= CallRoundFunction(1, Key, Data.HighPart);

                Data.HighPart ^= CallRoundFunction(2, Key, Data.LowPart);  
                Data.LowPart ^= CallRoundFunction(3, Key, Data.HighPart);

                Data.HighPart ^= CallRoundFunction(4, Key, Data.LowPart);  
                Data.LowPart ^= CallRoundFunction(5, Key, Data.HighPart);

                Data.HighPart ^= CallRoundFunction(6, Key, Data.LowPart);  
                Data.LowPart ^= CallRoundFunction(7, Key, Data.HighPart);

                Data.HighPart ^= CallRoundFunction(8, Key, Data.LowPart);  
                Data.LowPart ^= CallRoundFunction(9, Key, Data.HighPart);

                Data.LowPart ^= PrevPlaintext.LowPart;
                Data.HighPart ^= PrevPlaintext.HighPart;

                PrevPlaintext.QuadPart = Plaintext.QuadPart;

                pTarget64->LowPart = Data.LowPart;
                pTarget64->HighPart = Data.HighPart;
                ++pTarget64;
            }
        }
    }

    __forceinline VOID 
    Decrypt(
        __in_bcount(nBytes)     CONST BYTE*         pSource,
        __out_bcount(nBytes)    BYTE*               pTarget,
                                SIZE_T              nBytes,
                                CKey                Key,
                                ULONG               IV,
        __out                   CChecksum*          pChecksum
        )
    {
        if (nBytes > 0)
        {
            CONST SIZE_T nBlockSize = 8;
            ULARGE_INTEGER PrevCiphertext;
            ULARGE_INTEGER Ciphertext;
            ULARGE_INTEGER Data;

            int nOddBytes = nBytes % nBlockSize;

            if (nOddBytes == 0)
            {
                Data.LowPart = 0;
                Data.HighPart = 0;

                PrevCiphertext.HighPart = IV;
                PrevCiphertext.LowPart = ~IV;
            }
            else
            {
                // Use decrypted IV to encrypt odd bytes
    
                Data.LowPart = ~IV;
                Data.HighPart = IV;

                Data.LowPart ^= CallRoundFunction(9, Key, Data.HighPart);
                Data.HighPart ^= CallRoundFunction(8, Key, Data.LowPart);  

                Data.LowPart ^= CallRoundFunction(7, Key, Data.HighPart);
                Data.HighPart ^= CallRoundFunction(6, Key, Data.LowPart);  

                Data.LowPart ^= CallRoundFunction(5, Key, Data.HighPart);
                Data.HighPart ^= CallRoundFunction(4, Key, Data.LowPart);  

                Data.LowPart ^= CallRoundFunction(3, Key, Data.HighPart);
                Data.HighPart ^= CallRoundFunction(2, Key, Data.LowPart);  

                Data.LowPart ^= CallRoundFunction(1, Key, Data.HighPart);
                Data.HighPart ^= CallRoundFunction(0, Key, Data.LowPart);  

                Ciphertext.QuadPart = 0;
                WARBIRD_MEMCPY(&Ciphertext, pSource, nOddBytes);

                Data.LowPart ^= Ciphertext.LowPart;
                Data.HighPart ^= Ciphertext.HighPart;

                PrevCiphertext.QuadPart = Ciphertext.QuadPart;

                WARBIRD_MEMSET(((PBYTE)&Data) + nOddBytes, 0, nBlockSize - nOddBytes);
                WARBIRD_MEMCPY(pTarget, &Data, nOddBytes);
            }

            CONST ULARGE_INTEGER* pSource64 = reinterpret_cast<CONST ULARGE_INTEGER*>(pSource + nOddBytes);
            ULARGE_INTEGER* pTarget64 = reinterpret_cast<ULARGE_INTEGER*>(pTarget + nOddBytes);

            for (SIZE_T nBlock = 0; nBlock < nBytes / nBlockSize; ++nBlock)
            {
                Ciphertext.QuadPart = pSource64->QuadPart;
                ++pSource64;

                Data.LowPart ^= Ciphertext.LowPart;
                Data.HighPart ^= Ciphertext.HighPart;

                // Decrypt runs the rounds in reverse order

                Data.LowPart ^= CallRoundFunction(9, Key, Data.HighPart);
                Data.HighPart ^= CallRoundFunction(8, Key, Data.LowPart);  

                Data.LowPart ^= CallRoundFunction(7, Key, Data.HighPart);
                Data.HighPart ^= CallRoundFunction(6, Key, Data.LowPart);  

                Data.LowPart ^= CallRoundFunction(5, Key, Data.HighPart);
                Data.HighPart ^= CallRoundFunction(4, Key, Data.LowPart);  

                Data.LowPart ^= CallRoundFunction(3, Key, Data.HighPart);
                Data.HighPart ^= CallRoundFunction(2, Key, Data.LowPart);  

                Data.LowPart ^= CallRoundFunction(1, Key, Data.HighPart);
                Data.HighPart ^= CallRoundFunction(0, Key, Data.LowPart);  

                Data.LowPart ^= PrevCiphertext.LowPart;
                Data.HighPart ^= PrevCiphertext.HighPart;

                PrevCiphertext.QuadPart = Ciphertext.QuadPart;

                pTarget64->LowPart = Data.LowPart;
                pTarget64->HighPart = Data.HighPart;
                ++pTarget64;
            }

            *pChecksum = pTarget[nBytes - 1];
        }
    }

private:
    enum : SIZE_T
    {
        NUM_ROUNDS = 10,
        MAX_ROUND_FUNCTION = 30,
        USHORTS_PER_KEY = sizeof(CKey) / sizeof(USHORT),
        ULONGS_PER_KEY = sizeof(CKey) / sizeof(ULONG),
    };

    template <SIZE_T FunctionID> 
    __forceinline static ULONG 
    RoundFunction(
        ULONG   Rand0, 
        ULONG   Rand1, 
        ULONG   Rand2, 
        SIZE_T  nRound, 
        CKey    Key, 
        ULONG   Data32
        );

    template <> __forceinline static ULONG RoundFunction<0>(ULONG Rand0, ULONG Rand1, ULONG, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return ((Data32 ^ GetSecondaryKey16(Key, nRound, Rand0)) * GetPrimaryKey16(Key, nRound))
            + (Data32 >> Limit(Rand1, 1, 15));
    }
    template <> __forceinline static ULONG RoundFunction<1>(ULONG Rand0, ULONG Rand1, ULONG, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return ((Data32 - GetSecondaryKey16(Key, nRound, Rand0)) * GetPrimaryKey16(Key, nRound))
            - (Data32 >> Limit(Rand1, 1, 15));
    }
    template <> __forceinline static ULONG RoundFunction<2>(ULONG Rand0, ULONG Rand1, ULONG, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return ((Data32 ^ GetSecondaryKey16(Key, nRound, Rand0)) * GetPrimaryKey16(Key, nRound))
            ^ (Data32 >> Limit(Rand1, 1, 15));
    }
    template <> __forceinline static ULONG RoundFunction<3>(ULONG Rand0, ULONG Rand1, ULONG, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return ((Data32 ^ GetSecondaryKey16(Key, nRound, Rand0)) * GetPrimaryKey16(Key, nRound))
            + RotateRight32(Data32, Limit(Rand1, 1, 15));
    }
    template <> __forceinline static ULONG RoundFunction<4>(ULONG Rand0, ULONG Rand1, ULONG, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return ((Data32 ^ GetSecondaryKey16(Key, nRound, Rand0)) * GetPrimaryKey16(Key, nRound))
            - RotateRight32(Data32, Limit(Rand1, 1, 15));
    }
    template <> __forceinline static ULONG RoundFunction<5>(ULONG Rand0, ULONG Rand1, ULONG, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return ((Data32 ^ GetSecondaryKey16(Key, nRound, Rand0)) * GetPrimaryKey16(Key, nRound))
            ^ RotateRight32(Data32, Limit(Rand1, 1, 15));
    }
    template <> __forceinline static ULONG RoundFunction<6>(ULONG Rand0, ULONG Rand1, ULONG Rand2, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateLeft32((Data32 ^ GetSecondaryKey16(Key, nRound, Rand0)), Limit(Rand1, 1, 7)) * GetPrimaryKey16(Key, nRound)) 
            + (Data32 >> Limit(Rand2, 1, 15));
    }
    template <> __forceinline static ULONG RoundFunction<7>(ULONG Rand0, ULONG Rand1, ULONG Rand2, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateLeft32((GetRandKey32(Key, nRound, Rand0) ^ Data32), Limit(Rand1, 1, 7)) * GetPrimaryKey16(Key, nRound)) 
            - (Data32 >> Limit(Rand2, 1, 15));
    }
    template <> __forceinline static ULONG RoundFunction<8>(ULONG Rand0, ULONG Rand1, ULONG Rand2, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateLeft32((Data32 - GetSecondaryKey16(Key, nRound, Rand0)), Limit(Rand1, 1, 7)) * GetPrimaryKey16(Key, nRound))
            ^ (Data32 >> Limit(Rand2, 1, 15));
    }
    template <> __forceinline static ULONG RoundFunction<9>(ULONG Rand0, ULONG Rand1, ULONG Rand2, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateLeft32((Data32 ^ GetSecondaryKey16(Key, nRound, Rand0)), Limit(Rand1, 1, 7)) * GetPrimaryKey16(Key, nRound)) 
            + RotateRight32(Data32, Limit(Rand2, 1, 31));
    }
    template <> __forceinline static ULONG RoundFunction<10>(ULONG Rand0, ULONG Rand1, ULONG Rand2, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateLeft32((Data32 ^ GetSecondaryKey16(Key, nRound, Rand0)), Limit(Rand1, 1, 7)) * GetPrimaryKey16(Key, nRound)) 
            - RotateRight32(Data32, Limit(Rand2, 1, 31));
    }
    template <> __forceinline static ULONG RoundFunction<11>(ULONG Rand0, ULONG Rand1, ULONG Rand2, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateLeft32((Data32 ^ GetSecondaryKey16(Key, nRound, Rand0)), Limit(Rand1, 1, 7)) * GetPrimaryKey16(Key, nRound)) 
            ^ RotateRight32(Data32, Limit(Rand2, 1, 31));
    }
    template <> __forceinline static ULONG RoundFunction<12>(ULONG Rand0, ULONG Rand1, ULONG Rand2, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateRight32(GetRandKey32(Key, nRound, Rand0) + Data32, Limit(Rand1, 1, 31)) * GetPrimaryKey16(Key, nRound)) 
            + RotateRight32(Data32, Limit(Rand2, 1, 31));
    }
    template <> __forceinline static ULONG RoundFunction<13>(ULONG Rand0, ULONG Rand1, ULONG Rand2, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateRight32(GetRandKey32(Key, nRound, Rand0) - Data32, Limit(Rand1, 1, 31)) * GetPrimaryKey16(Key, nRound)) 
            + RotateRight32(Data32, Limit(Rand2, 1, 31));
    }
    template <> __forceinline static ULONG RoundFunction<14>(ULONG Rand0, ULONG Rand1, ULONG Rand2, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateRight32(GetRandKey32(Key, nRound, Rand0) ^ Data32, Limit(Rand1, 1, 31)) * GetPrimaryKey16(Key, nRound)) 
            + RotateRight32(Data32, Limit(Rand2, 1, 31));
    }
    template <> __forceinline static ULONG RoundFunction<15>(ULONG Rand0, ULONG Rand1, ULONG Rand2, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateRight32(GetRandKey32(Key, nRound, Rand0) + Data32, Limit(Rand1, 1, 31)) * GetPrimaryKey16(Key, nRound)) 
            - RotateRight32(Data32, Limit(Rand2, 1, 31));
    }
    template <> __forceinline static ULONG RoundFunction<16>(ULONG Rand0, ULONG Rand1, ULONG Rand2, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateRight32(GetRandKey32(Key, nRound, Rand0) - Data32, Limit(Rand1, 1, 31)) * GetPrimaryKey16(Key, nRound)) 
            - RotateRight32(Data32, Limit(Rand2, 1, 31));
    }
    template <> __forceinline static ULONG RoundFunction<17>(ULONG Rand0, ULONG Rand1, ULONG Rand2, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateRight32(GetRandKey32(Key, nRound, Rand0) ^ Data32, Limit(Rand1, 1, 31)) * GetPrimaryKey16(Key, nRound)) 
            - RotateRight32(Data32, Limit(Rand2, 1, 31));
    }
    template <> __forceinline static ULONG RoundFunction<18>(ULONG Rand0, ULONG Rand1, ULONG Rand2, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateRight32(Data32 - GetRandKey32(Key, nRound, Rand0), Limit(Rand1, 1, 31)) * GetPrimaryKey16(Key, nRound)) 
            ^ RotateRight32(Data32, Limit(Rand2, 1, 31));
    }
    template <> __forceinline static ULONG RoundFunction<19>(ULONG Rand0, ULONG Rand1, ULONG Rand2, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateRight32(GetRandKey32(Key, nRound, Rand0) - Data32, Limit(Rand1, 1, 31)) * GetPrimaryKey16(Key, nRound)) 
            ^ RotateRight32(Data32, Limit(Rand2, 1, 31));
    }
    template <> __forceinline static ULONG RoundFunction<20>(ULONG Rand0, ULONG Rand1, ULONG Rand2, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateRight32(GetRandKey32(Key, nRound, Rand0) ^ Data32, Limit(Rand1, 1, 31)) * GetPrimaryKey16(Key, nRound)) 
            ^ RotateRight32(Data32, Limit(Rand2, 1, 31));
    }
    template <> __forceinline static ULONG RoundFunction<21>(ULONG Rand0, ULONG Rand1, ULONG Rand2, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateRight32(Data32 - GetRandKey32(Key, nRound, Rand0), Limit(Rand1, 1, 31)) * GetPrimaryKey16(Key, nRound)) 
            + RotateRight32(Data32, Limit(Rand2, 1, 31));
    }
    template <> __forceinline static ULONG RoundFunction<22>(ULONG Rand0, ULONG Rand1, ULONG Rand2, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateRight32(Data32 - GetRandKey32(Key, nRound, Rand0), Limit(Rand1, 1, 31)) * GetPrimaryKey16(Key, nRound)) 
            - RotateRight32(Data32, Limit(Rand2, 1, 31));
    }
    template <> __forceinline static ULONG RoundFunction<23>(ULONG Rand0, ULONG Rand1, ULONG Rand2, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateRight32(Data32 - GetRandKey32(Key, nRound, Rand0), Limit(Rand1, 1, 31)) * GetPrimaryKey16(Key, nRound)) 
            ^ RotateRight32(Data32, Limit(Rand2, 1, 31));
    }
    template <> __forceinline static ULONG RoundFunction<24>(ULONG Rand0, ULONG Rand1, ULONG, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateRight32(~Data32, Limit(Rand0, 1, 15)) + GetPrimaryKey16(Key, nRound))
            * GetSecondaryKey16(Key, nRound, Rand1);
    }
    template <> __forceinline static ULONG RoundFunction<25>(ULONG Rand0, ULONG Rand1, ULONG, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateRight32(Data32, Limit(Rand0, 1, 15)) - GetPrimaryKey16(Key, nRound))
            * GetSecondaryKey16(Key, nRound, Rand1);
    }
    template <> __forceinline static ULONG RoundFunction<26>(ULONG Rand0, ULONG Rand1, ULONG, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (RotateRight32(Data32, Limit(Rand0, 1, 15)) ^ GetPrimaryKey16(Key, nRound))
            * GetSecondaryKey16(Key, nRound, Rand1);
    }
    template <> __forceinline static ULONG RoundFunction<27>(ULONG Rand0, ULONG, ULONG, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return GetSecondaryKey32(Key, nRound, Rand0)
            - (GetPrimaryKey32(Key, nRound) ^ Data32);
    }
    template <> __forceinline static ULONG RoundFunction<28>(ULONG Rand0, ULONG, ULONG, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return GetPrimaryKey32(Key, nRound) ^ Data32 
            ^ GetSecondaryKey32(Key, nRound, Rand0);
    }
    template <> __forceinline static ULONG RoundFunction<29>(ULONG Rand0, ULONG, ULONG, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (Data32 - GetPrimaryKey16(Key, nRound)) 
            ^ GetRandKey32(Key, nRound, Rand0);
    }
    template <> __forceinline static ULONG RoundFunction<30>(ULONG Rand0, ULONG, ULONG, SIZE_T nRound, CKey Key, ULONG Data32)
    {
        return (Data32 - GetRandKey32(Key, nRound, Rand0)) 
            - GetPrimaryKey16(Key, nRound);
    }

    __forceinline static USHORT 
    GetPrimaryKey16(
        CKey    Key,
        SIZE_T  nRound
        )
    {
        return Key.u16[nRound % USHORTS_PER_KEY];
    }

    __forceinline static USHORT 
    GetSecondaryKey16(
        CKey    Key,
        SIZE_T  nRound,
        ULONG   Rand
        )
    {
        return Key.u16[(nRound + Limit(Rand, 1, USHORTS_PER_KEY-1)) % USHORTS_PER_KEY];
    }
    
    __forceinline static ULONG 
    GetPrimaryKey32(
        CKey    Key,
        SIZE_T  nRound
        )
    {
        return Key.u32[nRound % ULONGS_PER_KEY];
    }

    __forceinline static ULONG 
    GetSecondaryKey32(
        CKey    Key,
        SIZE_T  nRound, 
        ULONG   Rand
        )
    {
        UNREFERENCED_PARAMETER(Rand);
        return Key.u32[(nRound + 1) % 2];
    }
        
    __forceinline static ULONG 
    GetRandKey32(
        CKey    Key,
        SIZE_T  nRound, 
        ULONG   Rand
        )
    {
        UNREFERENCED_PARAMETER(Rand);
        return Key.u32[(nRound/2 + 1) % 2];
    }

    __forceinline static ULONG
    Limit(
        ULONG  nValue,
        ULONG  nMin,
        ULONG  nRange
        )
    {
        return nMin + (nValue % nRange);
    }

#if defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

public:
    WarbirdRuntime::FEISTEL64_ROUND_DATA  m_Rounds[NUMBER_FEISTEL64_ROUNDS];

#endif //defined(WARBIRD_CRYPTO_ENABLE_CREATE_RANDOM) || defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)
};

#if defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

inline std::shared_ptr<CCipher>
CipherCreateFromType(
    PCSTR   pszTypeName
    )
{
    std::shared_ptr<CCipher> pCipher;

    if ((pCipher = CCipherFeistel64::CreateFromType(pszTypeName)) != NULL ||
        (pCipher = CCipherNop::CreateFromType(pszTypeName)) != NULL ||
        (pCipher = CCipherXor::CreateFromType(pszTypeName)) != NULL)
    {
    }

    return pCipher;
}

#endif //defined(WARBIRD_CRYPTO_ENABLE_CREATE_FROM_TYPE)

}; // namespace WarbirdCrypto