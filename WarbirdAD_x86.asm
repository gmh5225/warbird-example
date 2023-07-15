#ifdef _X86_
 
    title "Warbird Anti-Debugging assembly functions for x86"

    .386
    
;-----------------------------------------------------------------------------
;
; Copyright (C) Microsoft Corporation.  All Rights Reserved.
; 
; File: WarbirdAD_x86.asm
;
; Description:
;
; Anti-Debug macro implementations for x86
;
;-----------------------------------------------------------------------------

#ifndef WARBIRD_KERNEL_MODE

;
; Guard Debugger Functions
;
_TEXT SEGMENT

; Add 1 to the first arg and then invoke the GD to undo it. Second arg must be zero
@WarbirdAD_GD_Add1_Sub1@8 PROC public
    inc ecx		; add 1 to the first arg
    mov eax, ecx	; move the first arg into eax, ready to divide
    mov ecx, edx	; the second arg is zero, so move it into ecx to generate the AV
    mov edx, 1		; edx==1 informs the GD to subtract 1
    div ecx		; generate the AV
    ret
@WarbirdAD_GD_Add1_Sub1@8 ENDP


; Invokes the GD to add 1 to the first arg and then return it. Second arg must be zero
@WarbirdAD_GD_Add1@8 PROC public
    mov eax, ecx	; move the first arg into eax, ready to divide
    mov ecx, edx	; the second arg is zero, so move it into ecx to generate the AV
    div ecx		; generate the AV
    ret
@WarbirdAD_GD_Add1@8 ENDP


; Invokes the GD to subtract 1 to the first arg and then return it. Second arg must be zero
@WarbirdAD_GD_Sub1@8 PROC public
    mov eax, ecx	; move the first arg into eax, ready to divide
    mov ecx, edx	; the second arg is zero, so move it into ecx to generate the AV
    mov edx, 1		; edx==1 informs the GD to subtract 1
    div ecx		; generate the AV
    ret
@WarbirdAD_GD_Sub1@8 ENDP


; Masks the first arg and then invokes the GD to undo the mask. Second arg must be zero
@WarbirdAD_GD_XorA_XorA@8 PROC public
    mov eax, ecx    	; move the first arg into eax, ready to xor and then divide
    xor eax, 03c9e4fd1h	; xor the first arg
    mov ecx, edx	; the second arg is zero, so move it into ecx to generate the AV
    mov edx, 2		; edx==2 informs the GD to xor A
    div ecx		; generate the AV
    ret
@WarbirdAD_GD_XorA_XorA@8 ENDP


_TEXT ENDS

#endif

#endif