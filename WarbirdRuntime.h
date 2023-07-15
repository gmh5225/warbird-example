/*++

Copyright (c) 2012 Microsoft Corporation

Module Name:

    WarbirdRuntime.h

Abstract:

    Definitions of Warbird runtime APIs

Author:

    olafm 11-Sept-2012
    markzag 5-Nov-2012

--*/

#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

#if !defined __success
#define __success(x)
#endif

#if !defined __checkReturn
#define __checkReturn
#endif

#if !defined(_HRESULT_DEFINED) && !defined(HRESULT)
typedef __success(return >= 0) long HRESULT;
#endif

#if !defined(_NTSTATUS_DEFINED) && !defined(NTSTATUS)
typedef __success(return >= 0) long NTSTATUS;
#endif

#if !defined(ULONG_PTR)
#if defined(_WIN64)
    typedef unsigned __int64 ULONG_PTR;
#else
    typedef _W64 unsigned long ULONG_PTR;
#endif
#endif

#if !defined(SIZE_T)
typedef ULONG_PTR SIZE_T;
#endif

#if !defined(UINT)
typedef unsigned UINT;
#endif

#if !defined(BYTE)
typedef unsigned char BYTE;
#endif

#if !defined(BOOL)
typedef int BOOL;
#endif

#if defined(LEGACY_WARBIRD) || defined(SLC_PROTECTED_RUNTIME)

#define WARBIRD_NUM_RVA_BITS 28

#endif

/*++

    Description:

        Initializes the runtime library. This function needs to be called 
        for export drivers only, and it must be called near the entry point 
        of the module (preferably in DllInitialize), before any other warbird 
        runtime functions are used.

    Arguments:

        None.

    Returns:

        S_OK if successful, an error code otherwise.

--*/
HRESULT __stdcall WarbirdRuntimeInit(void);

/*++

    Description:

        Cleans up the resources used by the runtime library. This function 
        needs to be called for export drivers only, and it must be called 
        just before unloading the module (preferably in DllUnload), because
        no other warbird runtime function can be used after calling this 
        function.

    Arguments:

        None.

    Returns:

        None.

--*/
void __stdcall WarbirdRuntimeCleanup(void);

#if defined(LEGACY_WARBIRD)

/*++

    Description:

        Creates a dummy reference to the runtime support functions. 
        This is needed because otherwise the linker may optimize them 
        out, or Vulcan may consider them as unreachable dead code.

    Arguments:

        None.

    Returns:

        None.

--*/
extern const void* const WarbirdRuntimeRef[];

#define WARBIRD_DECRYPT_AT_STARTUP_SEGMENT_ID   0
#define WARBIRD_COMMA                           "_COMMA_"
#define WARBIRD_DBLCLN                          "_DBLCLN_"
#define WARBIRD_DUMMY_NAMESPACE                 "WARBIRDMARKER_"
#define WARBIRD_GEN_REROUTE_STR                 "WARBIRDMARKER_PXE_REROUTE_GEN_"

#define WARBIRD_RUNTIME_REF                         \
{                                                   \
    const void* volatile p = WarbirdRuntimeRef; p;  \
}                                                   \


#define WARBIRD_VERIFY_SEGMENT_INLINE(ID)     WarbirdVerifySegment##ID##Inline()
#define WARBIRD_VERIFY_SEGMENT_NOINLINE(ID)   WarbirdVerifySegment##ID##NoInline()
#define WARBIRD_VERIFY_SEGMENT_VAR_INLINE(ID, Value)  WarbirdVerifySegment##ID##VarInlineTemplate<Value>()

#define __WARBIRD_DECRYPT_SEGMENT_INLINE(ID)    WarbirdDecryptSegment##ID##Inline()
#define WARBIRD_DECRYPT_SEGMENT_INLINE(ID)      __WARBIRD_DECRYPT_SEGMENT_INLINE(ID)
#define __WARBIRD_DECRYPT_SEGMENT_NOINLINE(ID)  WarbirdDecryptSegment##ID##NoInline()
#define WARBIRD_DECRYPT_SEGMENT_NOINLINE(ID)    __WARBIRD_DECRYPT_SEGMENT_NOINLINE(ID)
#define WARBIRD_DECRYPT_SEGMENT(ID)             WARBIRD_DECRYPT_SEGMENT_INLINE(ID)

#define __WARBIRD_ENCRYPT_SEGMENT_INLINE(ID)    WarbirdEncryptSegment##ID##Inline()
#define WARBIRD_ENCRYPT_SEGMENT_INLINE(ID)      __WARBIRD_ENCRYPT_SEGMENT_INLINE(ID)
#define __WARBIRD_ENCRYPT_SEGMENT_NOINLINE(ID)  WarbirdEncryptSegment##ID##NoInline()
#define WARBIRD_ENCRYPT_SEGMENT_NOINLINE(ID)    __WARBIRD_ENCRYPT_SEGMENT_NOINLINE(ID)
#define WARBIRD_ENCRYPT_SEGMENT(ID)             WARBIRD_ENCRYPT_SEGMENT_INLINE(ID)

#define WARBIRD_SEGMENT_PROTOTYPE(ID)                \
__checkReturn HRESULT __fastcall WarbirdDecryptSegment##ID##Inline();       \
__checkReturn HRESULT __fastcall WarbirdDecryptSegment##ID##NoInline();     \
HRESULT __fastcall WarbirdEncryptSegment##ID##Inline();       \
HRESULT __fastcall WarbirdEncryptSegment##ID##NoInline();     \
\
size_t __fastcall WarbirdVerifySegment##ID##VarInline( \
    __in    __int64*    pStoredChecksum \
    ); \
\
void __fastcall WarbirdVerifySegment##ID##Inline(); \
void __fastcall WarbirdVerifySegment##ID##NoInline(); \

#else

#define WARBIRD_RUNTIME_REF

#define __WARBIRD_VERIFY_SEGMENT_INLINE(ID)     WarbirdVerifySegment##ID##Inline()
#define WARBIRD_VERIFY_SEGMENT_INLINE(ID)       __WARBIRD_VERIFY_SEGMENT_INLINE(ID)
#define __WARBIRD_VERIFY_SEGMENT_NOINLINE(ID)   WarbirdVerifySegment##ID##NoInline()
#define WARBIRD_VERIFY_SEGMENT_NOINLINE(ID)     __WARBIRD_VERIFY_SEGMENT_NOINLINE(ID)

#define WARBIRD_VERIFY_SEGMENT                  WARBIRD_VERIFY_SEGMENT_INLINE


//
// Macros to replace the calls to the warbird encryption functions
//
// Each macro has two layers e.g. WARBIRD_DECRYPT_SEGMENT_INLINE an
// __WARBIRD_DECRYPT_SEGMENT_INLINE. This is to allow the ID to be a #define:
//     #define MY_CRYPTO_SEGMENT 10
//     WARBIRD_DECRYPT_SEGMENT_INLINE(MY_CRYPTO_SEGMENT)
//
// This will generate a call to function:
//     WarbirdDecryptSegment10Inline.
//
// Without the second layer the macro would generate a call to a non-existing
// function because the define is not substituted before building the function
// name:
//     WarbirdDecryptSegmentMY_CRYPTO_SEGMENTInline
//
#define __WARBIRD_DECRYPT_SEGMENT_INLINE(ID)    WarbirdDecryptSegment##ID##Inline()
#define WARBIRD_DECRYPT_SEGMENT_INLINE(ID)      __WARBIRD_DECRYPT_SEGMENT_INLINE(ID)
#define __WARBIRD_DECRYPT_SEGMENT_NOINLINE(ID)  WarbirdDecryptSegment##ID##NoInline()
#define WARBIRD_DECRYPT_SEGMENT_NOINLINE(ID)    __WARBIRD_DECRYPT_SEGMENT_NOINLINE(ID)
#define WARBIRD_DECRYPT_SEGMENT(ID)             WARBIRD_DECRYPT_SEGMENT_INLINE(ID)

#define __WARBIRD_ENCRYPT_SEGMENT_INLINE(ID)    WarbirdEncryptSegment##ID##Inline()
#define WARBIRD_ENCRYPT_SEGMENT_INLINE(ID)      __WARBIRD_ENCRYPT_SEGMENT_INLINE(ID)
#define __WARBIRD_ENCRYPT_SEGMENT_NOINLINE(ID)  WarbirdEncryptSegment##ID##NoInline()
#define WARBIRD_ENCRYPT_SEGMENT_NOINLINE(ID)    __WARBIRD_ENCRYPT_SEGMENT_NOINLINE(ID)
#define WARBIRD_ENCRYPT_SEGMENT(ID)             WARBIRD_ENCRYPT_SEGMENT_INLINE(ID)

//
// Encryption function prototypes
//
#define WARBIRD_SEGMENT_PROTOTYPE(ID)                \
HRESULT __fastcall WarbirdDecryptSegment##ID##Inline();       \
HRESULT __fastcall WarbirdDecryptSegment##ID##NoInline();     \
HRESULT __fastcall WarbirdEncryptSegment##ID##Inline();       \
HRESULT __fastcall WarbirdEncryptSegment##ID##NoInline();     \
void __fastcall WarbirdVerifySegment##ID##Inline();           \
void __fastcall WarbirdVerifySegment##ID##NoInline();         \

#endif

/*
#pragma warbird(begin_foreach $(SID) $(EncryptedSegmentIDs))
WARBIRD_SEGMENT_PROTOTYPE( $(SID) );
#pragma warbird(end_foreach)
*/

//
// Creates a 255 encryption/verification function prototypes using the 
// encryption/verification prototypes.
// macros.
//
WARBIRD_SEGMENT_PROTOTYPE(0);
WARBIRD_SEGMENT_PROTOTYPE(1);
WARBIRD_SEGMENT_PROTOTYPE(2);
WARBIRD_SEGMENT_PROTOTYPE(3);
WARBIRD_SEGMENT_PROTOTYPE(4);
WARBIRD_SEGMENT_PROTOTYPE(5);
WARBIRD_SEGMENT_PROTOTYPE(6);
WARBIRD_SEGMENT_PROTOTYPE(7);
WARBIRD_SEGMENT_PROTOTYPE(8);
WARBIRD_SEGMENT_PROTOTYPE(9);
WARBIRD_SEGMENT_PROTOTYPE(10);
WARBIRD_SEGMENT_PROTOTYPE(11);
WARBIRD_SEGMENT_PROTOTYPE(12);
WARBIRD_SEGMENT_PROTOTYPE(13);
WARBIRD_SEGMENT_PROTOTYPE(14);
WARBIRD_SEGMENT_PROTOTYPE(15);
WARBIRD_SEGMENT_PROTOTYPE(16);
WARBIRD_SEGMENT_PROTOTYPE(17);
WARBIRD_SEGMENT_PROTOTYPE(18);
WARBIRD_SEGMENT_PROTOTYPE(19);
WARBIRD_SEGMENT_PROTOTYPE(20);
WARBIRD_SEGMENT_PROTOTYPE(21);
WARBIRD_SEGMENT_PROTOTYPE(22);
WARBIRD_SEGMENT_PROTOTYPE(23);
WARBIRD_SEGMENT_PROTOTYPE(24);
WARBIRD_SEGMENT_PROTOTYPE(25);
WARBIRD_SEGMENT_PROTOTYPE(26);
WARBIRD_SEGMENT_PROTOTYPE(27);
WARBIRD_SEGMENT_PROTOTYPE(28);
WARBIRD_SEGMENT_PROTOTYPE(29);
WARBIRD_SEGMENT_PROTOTYPE(30);
WARBIRD_SEGMENT_PROTOTYPE(31);
WARBIRD_SEGMENT_PROTOTYPE(32);
WARBIRD_SEGMENT_PROTOTYPE(33);
WARBIRD_SEGMENT_PROTOTYPE(34);
WARBIRD_SEGMENT_PROTOTYPE(35);
WARBIRD_SEGMENT_PROTOTYPE(36);
WARBIRD_SEGMENT_PROTOTYPE(37);
WARBIRD_SEGMENT_PROTOTYPE(38);
WARBIRD_SEGMENT_PROTOTYPE(39);
WARBIRD_SEGMENT_PROTOTYPE(40);
WARBIRD_SEGMENT_PROTOTYPE(41);
WARBIRD_SEGMENT_PROTOTYPE(42);
WARBIRD_SEGMENT_PROTOTYPE(43);
WARBIRD_SEGMENT_PROTOTYPE(44);
WARBIRD_SEGMENT_PROTOTYPE(45);
WARBIRD_SEGMENT_PROTOTYPE(46);
WARBIRD_SEGMENT_PROTOTYPE(47);
WARBIRD_SEGMENT_PROTOTYPE(48);
WARBIRD_SEGMENT_PROTOTYPE(49);
WARBIRD_SEGMENT_PROTOTYPE(50);
WARBIRD_SEGMENT_PROTOTYPE(51);
WARBIRD_SEGMENT_PROTOTYPE(52);
WARBIRD_SEGMENT_PROTOTYPE(53);
WARBIRD_SEGMENT_PROTOTYPE(54);
WARBIRD_SEGMENT_PROTOTYPE(55);
WARBIRD_SEGMENT_PROTOTYPE(56);
WARBIRD_SEGMENT_PROTOTYPE(57);
WARBIRD_SEGMENT_PROTOTYPE(58);
WARBIRD_SEGMENT_PROTOTYPE(59);
WARBIRD_SEGMENT_PROTOTYPE(60);
WARBIRD_SEGMENT_PROTOTYPE(61);
WARBIRD_SEGMENT_PROTOTYPE(62);
WARBIRD_SEGMENT_PROTOTYPE(63);
WARBIRD_SEGMENT_PROTOTYPE(64);
WARBIRD_SEGMENT_PROTOTYPE(65);
WARBIRD_SEGMENT_PROTOTYPE(66);
WARBIRD_SEGMENT_PROTOTYPE(67);
WARBIRD_SEGMENT_PROTOTYPE(68);
WARBIRD_SEGMENT_PROTOTYPE(69);
WARBIRD_SEGMENT_PROTOTYPE(70);
WARBIRD_SEGMENT_PROTOTYPE(71);
WARBIRD_SEGMENT_PROTOTYPE(72);
WARBIRD_SEGMENT_PROTOTYPE(73);
WARBIRD_SEGMENT_PROTOTYPE(74);
WARBIRD_SEGMENT_PROTOTYPE(75);
WARBIRD_SEGMENT_PROTOTYPE(76);
WARBIRD_SEGMENT_PROTOTYPE(77);
WARBIRD_SEGMENT_PROTOTYPE(78);
WARBIRD_SEGMENT_PROTOTYPE(79);
WARBIRD_SEGMENT_PROTOTYPE(80);
WARBIRD_SEGMENT_PROTOTYPE(81);
WARBIRD_SEGMENT_PROTOTYPE(82);
WARBIRD_SEGMENT_PROTOTYPE(83);
WARBIRD_SEGMENT_PROTOTYPE(84);
WARBIRD_SEGMENT_PROTOTYPE(85);
WARBIRD_SEGMENT_PROTOTYPE(86);
WARBIRD_SEGMENT_PROTOTYPE(87);
WARBIRD_SEGMENT_PROTOTYPE(88);
WARBIRD_SEGMENT_PROTOTYPE(89);
WARBIRD_SEGMENT_PROTOTYPE(90);
WARBIRD_SEGMENT_PROTOTYPE(91);
WARBIRD_SEGMENT_PROTOTYPE(92);
WARBIRD_SEGMENT_PROTOTYPE(93);
WARBIRD_SEGMENT_PROTOTYPE(94);
WARBIRD_SEGMENT_PROTOTYPE(95);
WARBIRD_SEGMENT_PROTOTYPE(96);
WARBIRD_SEGMENT_PROTOTYPE(97);
WARBIRD_SEGMENT_PROTOTYPE(98);
WARBIRD_SEGMENT_PROTOTYPE(99);
WARBIRD_SEGMENT_PROTOTYPE(100);
WARBIRD_SEGMENT_PROTOTYPE(101);
WARBIRD_SEGMENT_PROTOTYPE(102);
WARBIRD_SEGMENT_PROTOTYPE(103);
WARBIRD_SEGMENT_PROTOTYPE(104);
WARBIRD_SEGMENT_PROTOTYPE(105);
WARBIRD_SEGMENT_PROTOTYPE(106);
WARBIRD_SEGMENT_PROTOTYPE(107);
WARBIRD_SEGMENT_PROTOTYPE(108);
WARBIRD_SEGMENT_PROTOTYPE(109);
WARBIRD_SEGMENT_PROTOTYPE(111);
WARBIRD_SEGMENT_PROTOTYPE(112);
WARBIRD_SEGMENT_PROTOTYPE(113);
WARBIRD_SEGMENT_PROTOTYPE(114);
WARBIRD_SEGMENT_PROTOTYPE(115);
WARBIRD_SEGMENT_PROTOTYPE(116);
WARBIRD_SEGMENT_PROTOTYPE(117);
WARBIRD_SEGMENT_PROTOTYPE(118);
WARBIRD_SEGMENT_PROTOTYPE(119);
WARBIRD_SEGMENT_PROTOTYPE(120);
WARBIRD_SEGMENT_PROTOTYPE(121);
WARBIRD_SEGMENT_PROTOTYPE(122);
WARBIRD_SEGMENT_PROTOTYPE(123);
WARBIRD_SEGMENT_PROTOTYPE(124);
WARBIRD_SEGMENT_PROTOTYPE(125);
WARBIRD_SEGMENT_PROTOTYPE(126);
WARBIRD_SEGMENT_PROTOTYPE(127);
WARBIRD_SEGMENT_PROTOTYPE(128);
WARBIRD_SEGMENT_PROTOTYPE(129);
WARBIRD_SEGMENT_PROTOTYPE(130);
WARBIRD_SEGMENT_PROTOTYPE(131);
WARBIRD_SEGMENT_PROTOTYPE(132);
WARBIRD_SEGMENT_PROTOTYPE(133);
WARBIRD_SEGMENT_PROTOTYPE(134);
WARBIRD_SEGMENT_PROTOTYPE(135);
WARBIRD_SEGMENT_PROTOTYPE(136);
WARBIRD_SEGMENT_PROTOTYPE(137);
WARBIRD_SEGMENT_PROTOTYPE(138);
WARBIRD_SEGMENT_PROTOTYPE(139);
WARBIRD_SEGMENT_PROTOTYPE(140);
WARBIRD_SEGMENT_PROTOTYPE(141);
WARBIRD_SEGMENT_PROTOTYPE(142);
WARBIRD_SEGMENT_PROTOTYPE(143);
WARBIRD_SEGMENT_PROTOTYPE(144);
WARBIRD_SEGMENT_PROTOTYPE(145);
WARBIRD_SEGMENT_PROTOTYPE(146);
WARBIRD_SEGMENT_PROTOTYPE(147);
WARBIRD_SEGMENT_PROTOTYPE(148);
WARBIRD_SEGMENT_PROTOTYPE(149);
WARBIRD_SEGMENT_PROTOTYPE(150);
WARBIRD_SEGMENT_PROTOTYPE(151);
WARBIRD_SEGMENT_PROTOTYPE(152);
WARBIRD_SEGMENT_PROTOTYPE(153);
WARBIRD_SEGMENT_PROTOTYPE(154);
WARBIRD_SEGMENT_PROTOTYPE(155);
WARBIRD_SEGMENT_PROTOTYPE(156);
WARBIRD_SEGMENT_PROTOTYPE(157);
WARBIRD_SEGMENT_PROTOTYPE(158);
WARBIRD_SEGMENT_PROTOTYPE(159);
WARBIRD_SEGMENT_PROTOTYPE(160);
WARBIRD_SEGMENT_PROTOTYPE(161);
WARBIRD_SEGMENT_PROTOTYPE(162);
WARBIRD_SEGMENT_PROTOTYPE(163);
WARBIRD_SEGMENT_PROTOTYPE(164);
WARBIRD_SEGMENT_PROTOTYPE(165);
WARBIRD_SEGMENT_PROTOTYPE(166);
WARBIRD_SEGMENT_PROTOTYPE(167);
WARBIRD_SEGMENT_PROTOTYPE(168);
WARBIRD_SEGMENT_PROTOTYPE(169);
WARBIRD_SEGMENT_PROTOTYPE(170);
WARBIRD_SEGMENT_PROTOTYPE(171);
WARBIRD_SEGMENT_PROTOTYPE(172);
WARBIRD_SEGMENT_PROTOTYPE(173);
WARBIRD_SEGMENT_PROTOTYPE(174);
WARBIRD_SEGMENT_PROTOTYPE(175);
WARBIRD_SEGMENT_PROTOTYPE(176);
WARBIRD_SEGMENT_PROTOTYPE(177);
WARBIRD_SEGMENT_PROTOTYPE(178);
WARBIRD_SEGMENT_PROTOTYPE(179);
WARBIRD_SEGMENT_PROTOTYPE(180);
WARBIRD_SEGMENT_PROTOTYPE(181);
WARBIRD_SEGMENT_PROTOTYPE(182);
WARBIRD_SEGMENT_PROTOTYPE(183);
WARBIRD_SEGMENT_PROTOTYPE(184);
WARBIRD_SEGMENT_PROTOTYPE(185);
WARBIRD_SEGMENT_PROTOTYPE(186);
WARBIRD_SEGMENT_PROTOTYPE(187);
WARBIRD_SEGMENT_PROTOTYPE(188);
WARBIRD_SEGMENT_PROTOTYPE(189);
WARBIRD_SEGMENT_PROTOTYPE(190);
WARBIRD_SEGMENT_PROTOTYPE(191);
WARBIRD_SEGMENT_PROTOTYPE(192);
WARBIRD_SEGMENT_PROTOTYPE(193);
WARBIRD_SEGMENT_PROTOTYPE(194);
WARBIRD_SEGMENT_PROTOTYPE(195);
WARBIRD_SEGMENT_PROTOTYPE(196);
WARBIRD_SEGMENT_PROTOTYPE(197);
WARBIRD_SEGMENT_PROTOTYPE(198);
WARBIRD_SEGMENT_PROTOTYPE(199);
WARBIRD_SEGMENT_PROTOTYPE(200);
WARBIRD_SEGMENT_PROTOTYPE(201);
WARBIRD_SEGMENT_PROTOTYPE(202);
WARBIRD_SEGMENT_PROTOTYPE(203);
WARBIRD_SEGMENT_PROTOTYPE(204);
WARBIRD_SEGMENT_PROTOTYPE(205);
WARBIRD_SEGMENT_PROTOTYPE(206);
WARBIRD_SEGMENT_PROTOTYPE(207);
WARBIRD_SEGMENT_PROTOTYPE(208);
WARBIRD_SEGMENT_PROTOTYPE(209);
WARBIRD_SEGMENT_PROTOTYPE(211);
WARBIRD_SEGMENT_PROTOTYPE(212);
WARBIRD_SEGMENT_PROTOTYPE(213);
WARBIRD_SEGMENT_PROTOTYPE(214);
WARBIRD_SEGMENT_PROTOTYPE(215);
WARBIRD_SEGMENT_PROTOTYPE(216);
WARBIRD_SEGMENT_PROTOTYPE(217);
WARBIRD_SEGMENT_PROTOTYPE(218);
WARBIRD_SEGMENT_PROTOTYPE(219);
WARBIRD_SEGMENT_PROTOTYPE(220);
WARBIRD_SEGMENT_PROTOTYPE(221);
WARBIRD_SEGMENT_PROTOTYPE(222);
WARBIRD_SEGMENT_PROTOTYPE(223);
WARBIRD_SEGMENT_PROTOTYPE(224);
WARBIRD_SEGMENT_PROTOTYPE(225);
WARBIRD_SEGMENT_PROTOTYPE(226);
WARBIRD_SEGMENT_PROTOTYPE(227);
WARBIRD_SEGMENT_PROTOTYPE(228);
WARBIRD_SEGMENT_PROTOTYPE(229);
WARBIRD_SEGMENT_PROTOTYPE(230);
WARBIRD_SEGMENT_PROTOTYPE(231);
WARBIRD_SEGMENT_PROTOTYPE(232);
WARBIRD_SEGMENT_PROTOTYPE(233);
WARBIRD_SEGMENT_PROTOTYPE(234);
WARBIRD_SEGMENT_PROTOTYPE(235);
WARBIRD_SEGMENT_PROTOTYPE(236);
WARBIRD_SEGMENT_PROTOTYPE(237);
WARBIRD_SEGMENT_PROTOTYPE(238);
WARBIRD_SEGMENT_PROTOTYPE(239);
WARBIRD_SEGMENT_PROTOTYPE(240);
WARBIRD_SEGMENT_PROTOTYPE(241);
WARBIRD_SEGMENT_PROTOTYPE(242);
WARBIRD_SEGMENT_PROTOTYPE(243);
WARBIRD_SEGMENT_PROTOTYPE(244);
WARBIRD_SEGMENT_PROTOTYPE(245);
WARBIRD_SEGMENT_PROTOTYPE(246);
WARBIRD_SEGMENT_PROTOTYPE(247);
WARBIRD_SEGMENT_PROTOTYPE(248);
WARBIRD_SEGMENT_PROTOTYPE(249);
WARBIRD_SEGMENT_PROTOTYPE(250);
WARBIRD_SEGMENT_PROTOTYPE(251);
WARBIRD_SEGMENT_PROTOTYPE(252);
WARBIRD_SEGMENT_PROTOTYPE(253);
WARBIRD_SEGMENT_PROTOTYPE(254);
WARBIRD_SEGMENT_PROTOTYPE(255);
WARBIRD_SEGMENT_PROTOTYPE(256);
WARBIRD_SEGMENT_PROTOTYPE(257);
WARBIRD_SEGMENT_PROTOTYPE(258);
WARBIRD_SEGMENT_PROTOTYPE(259);
WARBIRD_SEGMENT_PROTOTYPE(260);
WARBIRD_SEGMENT_PROTOTYPE(261);
WARBIRD_SEGMENT_PROTOTYPE(262);
WARBIRD_SEGMENT_PROTOTYPE(263);
WARBIRD_SEGMENT_PROTOTYPE(264);
WARBIRD_SEGMENT_PROTOTYPE(265);
WARBIRD_SEGMENT_PROTOTYPE(266);
WARBIRD_SEGMENT_PROTOTYPE(267);
WARBIRD_SEGMENT_PROTOTYPE(268);
WARBIRD_SEGMENT_PROTOTYPE(269);
WARBIRD_SEGMENT_PROTOTYPE(270);
WARBIRD_SEGMENT_PROTOTYPE(271);
WARBIRD_SEGMENT_PROTOTYPE(272);
WARBIRD_SEGMENT_PROTOTYPE(273);
WARBIRD_SEGMENT_PROTOTYPE(274);
WARBIRD_SEGMENT_PROTOTYPE(275);
WARBIRD_SEGMENT_PROTOTYPE(276);
WARBIRD_SEGMENT_PROTOTYPE(277);
WARBIRD_SEGMENT_PROTOTYPE(178);
WARBIRD_SEGMENT_PROTOTYPE(279);
WARBIRD_SEGMENT_PROTOTYPE(280);
WARBIRD_SEGMENT_PROTOTYPE(281);
WARBIRD_SEGMENT_PROTOTYPE(282);
WARBIRD_SEGMENT_PROTOTYPE(283);
WARBIRD_SEGMENT_PROTOTYPE(284);
WARBIRD_SEGMENT_PROTOTYPE(285);
WARBIRD_SEGMENT_PROTOTYPE(286);
WARBIRD_SEGMENT_PROTOTYPE(287);
WARBIRD_SEGMENT_PROTOTYPE(288);
WARBIRD_SEGMENT_PROTOTYPE(289);
WARBIRD_SEGMENT_PROTOTYPE(290);
WARBIRD_SEGMENT_PROTOTYPE(291);
WARBIRD_SEGMENT_PROTOTYPE(292);
WARBIRD_SEGMENT_PROTOTYPE(293);
WARBIRD_SEGMENT_PROTOTYPE(294);
WARBIRD_SEGMENT_PROTOTYPE(295);
WARBIRD_SEGMENT_PROTOTYPE(296);
WARBIRD_SEGMENT_PROTOTYPE(297);
WARBIRD_SEGMENT_PROTOTYPE(298);
WARBIRD_SEGMENT_PROTOTYPE(299);
WARBIRD_SEGMENT_PROTOTYPE(300);

#ifdef WARBIRD_TEST

class CTest
{
public:
    CTest();

    void ReportVerifyFailure();

    void IncrementVerifyCount();

    ULONG GetVerifyCount();

    void ResetVerifyCount();

private:
    ULONG   m_nVerifyCount;
};

#endif

#if defined(__cplusplus)
}
#endif