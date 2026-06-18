; IntentKernel — ISR and IRQ stub generators
;
; All exception/IRQ entry points are generated via NASM macros to keep the
; code DRY.  Each stub:
;   1. Pushes a dummy error code (0) if the CPU does not push one.
;   2. Pushes the interrupt vector number.
;   3. Jumps to the common C-callable trampoline.
;
; Exceptions that push an error code automatically:
;   8 (Double Fault), 10 (Invalid TSS), 11 (Seg-Not-Present),
;   12 (Stack Fault), 13 (GPF), 14 (Page Fault), 17 (Alignment Check)

section .text

; -------------------------------------------------------------------------
; Macros
; -------------------------------------------------------------------------

%macro ISR_NOERRCODE 1
global isr%1
isr%1:
    cli
    push dword 0        ; dummy error code
    push dword %1       ; interrupt number
    jmp  isr_common_stub
%endmacro

%macro ISR_ERRCODE 1
global isr%1
isr%1:
    cli
    push dword %1       ; interrupt number (CPU already pushed error code)
    jmp  isr_common_stub
%endmacro

%macro IRQ 2
global irq%1
irq%1:
    cli
    push dword 0        ; dummy error code
    push dword %2       ; vector number (IRQ base + irq index)
    jmp  irq_common_stub
%endmacro

; -------------------------------------------------------------------------
; Exception stubs (vectors 0–31)
; -------------------------------------------------------------------------

ISR_NOERRCODE  0    ; Divide-by-zero
ISR_NOERRCODE  1    ; Debug
ISR_NOERRCODE  2    ; NMI
ISR_NOERRCODE  3    ; Breakpoint
ISR_NOERRCODE  4    ; Overflow
ISR_NOERRCODE  5    ; Bound range exceeded
ISR_NOERRCODE  6    ; Invalid opcode
ISR_NOERRCODE  7    ; Device not available
ISR_ERRCODE    8    ; Double fault        (error code)
ISR_NOERRCODE  9    ; Coprocessor segment overrun
ISR_ERRCODE   10    ; Invalid TSS         (error code)
ISR_ERRCODE   11    ; Segment not present (error code)
ISR_ERRCODE   12    ; Stack fault         (error code)
ISR_ERRCODE   13    ; General protection  (error code)
ISR_ERRCODE   14    ; Page fault          (error code)
ISR_NOERRCODE 15    ; Reserved
ISR_NOERRCODE 16    ; x87 FPU error
ISR_ERRCODE   17    ; Alignment check     (error code)
ISR_NOERRCODE 18    ; Machine check
ISR_NOERRCODE 19    ; SIMD FP exception
ISR_NOERRCODE 20    ; Virtualisation exception
ISR_NOERRCODE 21    ; Reserved
ISR_NOERRCODE 22    ; Reserved
ISR_NOERRCODE 23    ; Reserved
ISR_NOERRCODE 24    ; Reserved
ISR_NOERRCODE 25    ; Reserved
ISR_NOERRCODE 26    ; Reserved
ISR_NOERRCODE 27    ; Reserved
ISR_NOERRCODE 28    ; Reserved
ISR_NOERRCODE 29    ; Reserved
ISR_NOERRCODE 30    ; Security exception
ISR_NOERRCODE 31    ; Reserved

; -------------------------------------------------------------------------
; IRQ stubs (vectors 32–47 after PIC remapping)
; -------------------------------------------------------------------------

IRQ  0, 32    ; PIT timer
IRQ  1, 33    ; PS/2 keyboard
IRQ  2, 34    ; Cascade (internal)
IRQ  3, 35    ; COM2
IRQ  4, 36    ; COM1
IRQ  5, 37    ; LPT2
IRQ  6, 38    ; Floppy
IRQ  7, 39    ; LPT1 / spurious master
IRQ  8, 40    ; CMOS RTC
IRQ  9, 41    ; Free
IRQ 10, 42    ; Free
IRQ 11, 43    ; Free
IRQ 12, 44    ; PS/2 mouse
IRQ 13, 45    ; FPU
IRQ 14, 46    ; ATA primary
IRQ 15, 47    ; ATA secondary / spurious slave

; -------------------------------------------------------------------------
; Common exception trampoline
; -------------------------------------------------------------------------

extern isr_handler

isr_common_stub:
    pusha                    ; push eax,ecx,edx,ebx,esp,ebp,esi,edi

    mov  ax, ds              ; save data segment
    push eax

    mov  ax, 0x10            ; load kernel data segment
    mov  ds, ax
    mov  es, ax
    mov  fs, ax
    mov  gs, ax

    push esp                 ; arg0: pointer to registers_t
    call isr_handler
    add  esp, 4

    pop  eax                 ; restore data segment
    mov  ds, ax
    mov  es, ax
    mov  fs, ax
    mov  gs, ax

    popa                     ; restore general-purpose registers
    add  esp, 8              ; discard int_no and err_code
    iret

; -------------------------------------------------------------------------
; Common IRQ trampoline
; -------------------------------------------------------------------------

extern irq_handler

irq_common_stub:
    pusha

    mov  ax, ds
    push eax

    mov  ax, 0x10
    mov  ds, ax
    mov  es, ax
    mov  fs, ax
    mov  gs, ax

    push esp
    call irq_handler
    add  esp, 4

    pop  eax
    mov  ds, ax
    mov  es, ax
    mov  fs, ax
    mov  gs, ax

    popa
    add  esp, 8
    iret
