#if defined(_M_E2)

#include "kse2.h"

        TEXTAREA

;
; private: static void __cdecl WarbirdRuntime::CTermination::TrashStack(int (__cdecl*)(void))
;
; Clears the stack and registers, and jumps to termination function
;

; WORKAROUND: Can't use LEAF_ENTRY here because of the quoted name
        TEXTAREA

        ALIGN 4

        .globl "?TrashStack@CTermination@WarbirdRuntime@@CAXP6A_JXZ@Z"
"?TrashStack@CTermination@WarbirdRuntime@@CAXP6A_JXZ@Z":

        read    t0, pr                  ; t0 = TEB
        ld      t1, TeStackLimit(t0)    ; t1 = TEB->StackLimit
        ld      t2, TeStackBase(t0)     ; t2 = TEB->StackBase
        read    t3, r3                  ; get parameter which is return address
        write   r11, t1                 ; r11 = destination pointer
        write   sp, t2                  ; sp = TEB->StackBase
        write   lr, t3                  ; lr = return address
        tge     t4, t1, t2              ; t3 = (dest >= TEB->StackBase)
        bro.t<t4> ClearRegs             ; skip if invalid
        bro.f<t4> ClearStack            ; else continue

ClearStack:
        movu    t0, 0                   ; t0 = 0
        read    t1, r11                 ; t1 = dest pointer
        addi    t2, t1, 16              ; t2 = dest pointer + 16
        read    t3, sp                  ; t3 = sp
        write   r11, t2                 ; r11 = updated dest pointer
        sd      t0, 0(t1)               ; write 0 to dest
        sd      t0, 8(t1)               ; write 0 to dest+8
        tge     t4, t2, t3              ; t4 = (dest >= sp)
        bro.t<t4> ClearRegs             ; skip if invalid
        bro.f<t4> ClearStack            ; else loop

ClearRegs:
        movu    t0, 0                   ; get a zero
        write   r3, t0                  ; clear all registers
        write   r4, t0                  ;
        write   r5, t0                  ;
        write   r6, t0                  ;
        write   r7, t0                  ;
        write   r8, t0                  ;
        write   r9, t0                  ;
        write   r10, t0                 ;
        write   r11, t0                 ;
        write   r12, t0                 ;
        write   r13, t0                 ;
        write   r14, t0                 ;
        write   r15, t0                 ;
        write   r16, t0                 ;
        write   r17, t0                 ;
        write   r18, t0                 ;
        write   r19, t0                 ;
        write   r20, t0                 ;
        write   r21, t0                 ;
        write   r22, t0                 ;
        write   r23, t0                 ;
        write   r24, t0                 ;
        write   r25, t0                 ;
        write   r26, t0                 ;
        write   r27, t0                 ;
        write   r28, t0                 ;
        write   r29, t0                 ;
        write   r30, t0                 ;
        write   r31, t0                 ;
        write   r32, t0                 ;
        write   r33, t0                 ;
        write   r34, t0                 ;
        write   r35, t0                 ;
        write   r36, t0                 ;
        write   r37, t0                 ;
        write   r38, t0                 ;
        write   r39, t0                 ;
        write   r40, t0                 ;
        write   r41, t0                 ;
        write   r42, t0                 ;
        write   r43, t0                 ;
        write   r44, t0                 ;
        write   r45, t0                 ;
        write   r46, t0                 ;
        write   r47, t0                 ;
        write   r48, t0                 ;
        write   r49, t0                 ;
        write   r50, t0                 ;
        write   r51, t0                 ;
        write   r52, t0                 ;
        write   r53, t0                 ;
        write   r54, t0                 ;
        write   r55, t0                 ;
        write   r56, t0                 ;
        write   r57, t0                 ;
        write   r58, t0                 ;
        write   r59, t0                 ;
        write   r60, t0                 ;
        write   r61, t0                 ;
        write   r62, t0                 ;
        write   r63, t0                 ;

        read    t1, lr                  ; get return address
        ret     t1                      ; return

#endif

#if defined(_M_ARM) || defined(_M_ARM64) || defined(_M_E2)
    END
#else
END
#endif // defined(_M_ARM) || defined(_M_ARM64) || defined(_M_E2)