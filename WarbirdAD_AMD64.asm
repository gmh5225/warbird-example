#ifdef _AMD64_

    title "Warbird Anti-Debugging assembly functions for AMD64"

;-----------------------------------------------------------------------------
;
; Copyright (C) Microsoft Corporation.  All Rights Reserved.
; 
; File: WarbirdAD_AMD64.asm
;
; Description:
;
; Anti-Debug macro implementations for AMD64
;
;-----------------------------------------------------------------------------

#ifndef WARBIRD_KERNEL_MODE

;
; Anti-Debugging Functions
;
_TEXT SEGMENT

; Generate an AV to setup the Debug Registers
?Warbird_AD_AV4DebugRegisters@@YAXXZ PROC public
	mov dword ptr [00007978h],4c71950bh
	ret
?Warbird_AD_AV4DebugRegisters@@YAXXZ ENDP


; Generate a breakpoint
?Warbird_AD_FireBreakpoint@@YAXXZ PROC public
    int 3
?Warbird_AD_FireBreakpoint@@YAXXZ ENDP


; Divide by zero
?Warbird_AD_DivideByZero1@@YAXXZ PROC public
    xor rax, rax
    div rax	
    ret
?Warbird_AD_DivideByZero1@@YAXXZ ENDP


?Warbird_AD_DivideByZero2@@YAXXZ PROC public
    xor rax, rax
    div rax	
    ret
?Warbird_AD_DivideByZero2@@YAXXZ ENDP



;
; Read the PEB structure, just like IsDebuggerPresent()
;

; BOOL IsDebuggerPresent()
?Warbird_AD_UMD_TIBNT_1@@YAHXZ PROC public
    mov rax, gs:[30h]
    mov rax, [rax + 60h]
    movzx eax, byte ptr[rax + 2]
    ret
?Warbird_AD_UMD_TIBNT_1@@YAHXZ ENDP


; void IsDebuggerPresent(DWORD *IsPresent)
?Warbird_AD_UMD_TIBNT_2@@YAXPEAK@Z PROC public
    mov rdx, gs:[30h]
    mov rdx, [rdx + 60h]
    movzx rax, byte ptr[rdx + 2]
    mov [rcx], eax
    ret
?Warbird_AD_UMD_TIBNT_2@@YAXPEAK@Z ENDP

_TEXT ENDS


;
; Guard Debugger Functions
;
_TEXT SEGMENT

; Add 1 to the first arg and then invoke the GD to undo it. Second arg must be zero
WarbirdAD_GD_Add1_Sub1 PROC public
    inc rcx		; add 1 to the first arg
    mov rax, rcx	; move the first arg into rax, ready to divide
    mov rcx, rdx	; the second arg is zero, so move it into rcx to generate the AV
    mov rdx, 1		; rdx==1 informs the GD to subtract 1
    div rcx		; generate the AV
    ret
WarbirdAD_GD_Add1_Sub1 ENDP


; Invokes the GD to add 1 to the first arg and then return it. Second arg must be zero
WarbirdAD_GD_Add1 PROC public
    mov rax, rcx	; move the first arg into rax, ready to divide
    mov rcx, rdx	; the second arg is zero, so move it into rcx to generate the AV
    div rcx		; generate the AV
    ret
WarbirdAD_GD_Add1 ENDP


; Invokes the GD to subtract 1 to the first arg and then return it. Second arg must be zero
WarbirdAD_GD_Sub1 PROC public
    mov rax, rcx	; move the first arg into rax, ready to divide
    mov rcx, rdx	; the second arg is zero, so move it into rcx to generate the AV
    mov rdx, 1		; rdx==1 informs the GD to subtract 1
    div rcx		; generate the AV
    ret
WarbirdAD_GD_Sub1 ENDP


; Masks the first arg and then invokes the GD to undo the mask. Second arg must be zero
WarbirdAD_GD_XorA_XorA PROC public
    mov rax, rcx    	; move the first arg into rax, ready to xor and then divide
    xor rax, 03c9e4fd1h	; xor the first arg
    mov rcx, rdx	; the second arg is zero, so move it into rcx to generate the AV
    mov rdx, 2		; rdx==2 informs the GD to xor A
    div rcx		; generate the AV
    ret
WarbirdAD_GD_XorA_XorA ENDP


_TEXT ENDS

;
; Guard Shadow Stack support
;
_TEXT SEGMENT

;
; Workaround function that allows updating of control stack addresses.
; Temporary solution -- real solution needs to avoid modifying return
; addresses.
;
; There is no __writefsqword intrinsic on AMD64.
;
; rcx - Control stack offset (data stack RSP)
;
; rdx - Value to write
;
WarbirdWriteToControlStack PROC public
    mov fs:[rcx], rdx
    ret
WarbirdWriteToControlStack ENDP

;
; Workaround function to read the control stack contents.
; Temporary solution -- real solution needs to avoid modifying return
; addresses
;
; There is no __readfsqword intrinsic on AMD64.
;
; rcx - Control stack offset (data stack RSP)
;
WarbirdReadFromControlStack PROC public
    mov rax, fs:[rcx]
    ret
WarbirdReadFromControlStack ENDP

_TEXT ENDS

#endif

#endif
