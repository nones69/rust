; IntentKernel — GDT flush helper
; Loads the new GDT and reloads all segment registers.
;
; C prototype: void gdt_flush(uint32_t gdt_ptr_addr);

section .text
global gdt_flush

gdt_flush:
    mov  eax, [esp + 4]     ; first argument: pointer to gdt_ptr_t
    lgdt [eax]              ; load GDT register

    ; Reload data-segment registers with the new kernel data selector (0x10)
    mov  ax, 0x10
    mov  ds, ax
    mov  es, ax
    mov  fs, ax
    mov  gs, ax
    mov  ss, ax

    ; Far jump to flush the code-segment register (0x08 = kernel code)
    jmp  0x08:.flush
.flush:
    ret
