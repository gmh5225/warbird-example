#if defined(_M_ARM)

#include "ksarm.h"

        TEXTAREA

;
; private: static void __cdecl WarbirdRuntime::CTermination::TrashStack(int (__cdecl*)(void))
;
; Clears the stack and registers, and jumps to termination function
;

        NESTED_ENTRY ?TrashStack@CTermination@WarbirdRuntime@@CAXP6AHXZ@Z

        sub     r1, r1, r1              ; set a scratch register to zero

        TEB_READ r2
        ldr     r3, [r2, #TeStackLimit] ; set a destination register to point to top of the stack
        ldr     sp, [r2, #TeStackBase]  ; move stack pointer to the bottom of the stack
        mov     r4, sp                  ; save sp to a temp tegister (otherwise assembler errors out on "cmp r3, sp")
        mov     lr, r0                  ; set lr to the termination function address (which will look like a
                                        ; fake return address after we jump to the termination function)
ClearStack
        cmp     r3, r4                  ; is the destination past the bottom of stack?
        bge     ClearRegs               ; yes - exit loop
        str     r1, [r3], #4            ; no - set destination to zero and increment destination pointer
        b       ClearStack              ; loop
ClearRegs
        mov     r0, r1                  ; set all integer registers to zero
        mov     r2, r1
        mov     r3, r1
        mov     r4, r1
        mov     r5, r1
        mov     r6, r1
        mov     r7, r1
        mov     r8, r1
        mov     r9, r1
        mov     r10, r1
        mov     r11, r1
        mov     r12, r1

        bx      lr                      ; jump to termination function
        
        NESTED_END ?TrashStack@CTermination@WarbirdRuntime@@CAXP6AHXZ@Z

#endif
#if defined(_M_ARM64)

#include "ksarm64.h"

        TEXTAREA

;
; private: static void __cdecl WarbirdRuntime::CTermination::TrashStack(int (__cdecl*)(void))
;
; Clears the stack and registers, and jumps to termination function
;

        NESTED_ENTRY ?TrashStack@CTermination@WarbirdRuntime@@CAXP6A_JXZ@Z

        ldr     x3, [x18, #TeStackLimit] ; set a destination register to point to top of the stack
        ldr     x4, [x18, #TeStackBase]  ; move stack pointer to the bottom of the stack
        mov     sp, x4                  ; save sp to a temp tegister (otherwise assembler errors out on "cmp r3, sp")
        mov     lr, x0                  ; set lr to the termination function address (which will look like a
                                        ; fake return address after we jump to the termination function)
ClearStack
        cmp     x3, x4                  ; is the destination past the bottom of stack?
        bge     ClearRegs               ; yes - exit loop
        str     xzr, [x3], #8            ; no - set destination to zero and increment destination pointer
        b       ClearStack              ; loop
ClearRegs
        mov     x0, #0                  ; set all integer registers to zero
        mov     x1, #0
        mov     x2, #0
        mov     x3, #0
        mov     x4, #0
        mov     x5, #0
        mov     x6, #0
        mov     x7, #0
        mov     x8, #0
        mov     x9, #0
        mov     x10, #0
        mov     x11, #0
        mov     x12, #0
        mov     x13, #0
        mov     x14, #0
        mov     x15, #0
        mov     x16, #0
        mov     x17, #0
        mov     x19, #0
        mov     x20, #0
        mov     x21, #0
        mov     x22, #0
        mov     x23, #0
        mov     x24, #0
        mov     x25, #0
        mov     x26, #0
        mov     x27, #0
        mov     x28, #0
        mov     x29, #0

        ret                      ; jump to termination function

        NESTED_END ?TrashStack@CTermination@WarbirdRuntime@@CAXP6A_JXZ@Z

#endif