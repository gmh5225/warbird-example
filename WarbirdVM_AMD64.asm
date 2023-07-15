#ifdef _M_AMD64

#if $(WARBIRD_ENABLE_VM_EXECUTION)

title "VMExecAmd64Runtimes"

SR struct
        P1              dq ?
        P2              dq ?
        P3              dq ?
        P4              dq ?

        SavedAx         dq ?
        SavedCx         dq ?
        SavedDx         dq ?
        SavedBx         dq ?
        SavedSp         dq ?
        SavedBp         dq ?
        SavedSi         dq ?
        SavedDi         dq ?

        SavedR8         dq ?
        SavedR9         dq ?
        SavedR10        dq ?
        SavedR11        dq ?
        SavedR12        dq ?
        SavedR13        dq ?
        SavedR14        dq ?
        SavedR15        dq ?
SR ends

_TEXT segment para 'CODE'

    VMReEntry proc public frame

    ; "void __cdecl Warbird::VMExecMainLoop(void *,void *)" (?VMExecMainLoop@Warbird@@YAXPEAX0@Z)
        extrn ?VMExecMainLoop@Warbird@@YAXPEAX0@Z: Proc

        ; space
        sub rsp, 1000
        .ENDPROLOG

        ; pusha
        mov qword ptr SR.SavedAx[rsp], rax
        mov qword ptr SR.SavedCx[rsp], rcx
        mov qword ptr SR.SavedDx[rsp], rdx
        mov qword ptr SR.SavedBx[rsp], rbx

        ; must be after ax save
        lea rax, [rsp + 1000]
        mov qword ptr SR.SavedSP[rsp], rax

        mov qword ptr SR.SavedBp[rsp], rbp
        mov qword ptr SR.SavedSi[rsp], rsi
        mov qword ptr SR.SavedDi[rsp], rdi
        mov qword ptr SR.SavedR8[rsp], r8
        mov qword ptr SR.SavedR9[rsp], r9
        mov qword ptr SR.SavedR10[rsp], r10
        mov qword ptr SR.SavedR11[rsp], r11
        ; removed restore for r12 liveness usage
        ;mov qword ptr SR.SavedR12[rsp], r12
        mov qword ptr SR.SavedR13[rsp], r13
        mov qword ptr SR.SavedR14[rsp], r14
        mov qword ptr SR.SavedR15[rsp], r15

        ; r12 was live over the call and points to the offset
        mov     rcx, r12
        ; pass the pointer to the registers as the argument to the function
        lea     rdx, [rsp]

        ; call the runtime support function
        call ?VMExecMainLoop@Warbird@@YAXPEAX0@Z

        mov rax, qword ptr SR.SavedAx[rsp]
        mov rcx, qword ptr SR.SavedCx[rsp]
        mov rdx, qword ptr SR.SavedDx[rsp]
        mov rbx, qword ptr SR.SavedBx[rsp]
        mov rbp, qword ptr SR.SavedBp[rsp]
        mov rsi, qword ptr SR.SavedSi[rsp]
        mov rdi, qword ptr SR.SavedDi[rsp]
        mov r8, qword ptr SR.SavedR8[rsp]
        mov r9, qword ptr SR.SavedR9[rsp]
        mov r10, qword ptr SR.SavedR10[rsp]
        mov r11, qword ptr SR.SavedR11[rsp]
        mov r12, qword ptr SR.SavedR12[rsp]
        mov r13, qword ptr SR.SavedR13[rsp]
        mov r14, qword ptr SR.SavedR14[rsp]
        mov r15, qword ptr SR.SavedR15[rsp]
        ; and finally the sp
        mov rsp, qword ptr SR.SavedSP[rsp]

        ret
    VMReEntry endp

    VMExit proc public frame
        ; given rcx to regs
        ; given reentry param is live in SavedR12

        ; rsp now points at "proper" stack loc.
        .ENDPROLOG

        mov rdx, qword ptr SR.SavedDx[rcx]
        mov rbx, qword ptr SR.SavedBx[rcx]
        mov rsi, qword ptr SR.SavedSi[rcx]
        mov rdi, qword ptr SR.SavedDi[rcx]
        mov r8, qword ptr SR.SavedR8[rcx]
        mov r9, qword ptr SR.SavedR9[rcx]
        mov r10, qword ptr SR.SavedR10[rcx]
        mov r11, qword ptr SR.SavedR11[rcx]
        mov r12, qword ptr SR.SavedR12[rcx]
        mov r13, qword ptr SR.SavedR13[rcx]
        mov r14, qword ptr SR.SavedR14[rcx]
        mov r15, qword ptr SR.SavedR15[rcx]
        mov rax, qword ptr SR.SavedAx[rcx]
        mov rbp, qword ptr SR.SavedBp[rcx]
        ; drop the stack to the top of the regs
        mov rsp, rcx
        ; load rcx
        mov rcx, qword ptr SR.SavedCx[rcx]
        ; finally drop the stack to the top of the "real" stack
        mov rsp, qword ptr SR.SavedSP[rsp]
        ret
    VMExit endp

_TEXT ends

#endif

#endif