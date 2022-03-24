.section .text

.global _start
_start:
    // push %rdi
    // push %rsi
    // push %rdx
    // push %rcx
    // call _init
    // pop %rcx
    // pop %rdx
    // pop %rsi
    // pop %rdi

    mov $main, %rdi
    call __mlibc_entry

.size _start, . - _start
