#if defined(_M_IX86)

include ks386.inc

_TEXT$00 segment para 'CODE'

;
; private: static void __fastcall WarbirdRuntime::CTermination::TrashStack(int (__stdcall*)(void))
;
; Clears the stack and registers, and jumps to termination function
;

        ?TrashStack@CTermination@WarbirdRuntime@@CIXP6GHXZ@Z proc public

        sub     eax, eax                ; set a scratch register to zero

        mov     edx, fs:[TeStackLimit]  ; set a destination register to point to top of the stack
        mov     esp, fs:[TeStackBase]   ; move stack pointer to the bottom of the stack
        push    ecx                     ; push the termination function address (which will look like a
                                        ; fake return address after we jump to the termination function)
ClearStack:
        cmp     edx, esp                ; is the destination past the bottom of stack?
        jae     ClearRegs               ; yes - exit loop
        mov     dword ptr [edx], eax    ; no - set destination to zero
        add     edx, 4                  ; increment destination pointer
        jmp     ClearStack              ; loop

ClearRegs:
        mov     ebx, eax                ; set all integer registers to zero
        mov     ecx, eax
        mov     edx, eax
        mov     esi, eax
        mov     edi, eax
        mov     ebp, eax

        jmp     dword ptr [esp]         ; jump to termination function
        
        ?TrashStack@CTermination@WarbirdRuntime@@CIXP6GHXZ@Z endp

_TEXT$00 ends

#endif
#if defined(_M_AMD64)

include ksamd64.inc

_TEXT segment para 'CODE'

;
;
; private: static void __cdecl WarbirdRuntime::CTermination::TrashStack(__int64 (__cdecl*)(void))
;
; Clears the stack and registers, and jumps to termination function
;

        ?TrashStack@CTermination@WarbirdRuntime@@CAXP6A_JXZ@Z proc public frame

        .endprolog

        sub     eax, eax                ; set a scratch register to zero

        mov     rdx, gs:[TeStackLimit]  ; set a destination register to point to top of the stack
        mov     rsp, gs:[TeStackBase]   ; move stack pointer to the bottom of the stack
        push    rcx                     ; push the termination function address (which will look like a
                                        ; fake return address after we jump to the termination function)
ClearStack:
        cmp     rdx, rsp                ; is the destination past the bottom of stack?
        jae     ClearRegs               ; yes - exit loop
        mov     qword ptr [rdx], rax    ; no - set destination to zero
        add     rdx, 8                  ; increment destination pointer
        jmp     ClearStack              ; loop

ClearRegs:
        mov     rbx, rax                ; set all integer registers to zero
        mov     rcx, rax
        mov     rdx, rax
        mov     rsi, rax
        mov     rdi, rax
        mov     rbp, rax
        mov     r8, rax
        mov     r9, rax
        mov     r10, rax
        mov     r11, rax
        mov     r12, rax
        mov     r13, rax
        mov     r14, rax
        mov     r15, rax
        
        jmp     qword ptr [rsp]         ; jump to termination function
        
        ?TrashStack@CTermination@WarbirdRuntime@@CAXP6A_JXZ@Z endp

_TEXT ends

#endif