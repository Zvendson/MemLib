format binary
use64

ScanProc: ; (Pattern, Buffer)
    push    rbp                      ; start of building a stack frame
    mov     rbp, rsp                 ; storing the stack frame in rbp
    sub     rsp, 0x0010              ; Adding space for local variables (16 bytes)
    push    rbx rsi rdi              ; store the registers on the stack

    xor     rax, rax
    xor     rbx, rbx
    mov     eax, DWORD [rcx]         ; rax = Pattern.Length
    test    rax, rax
    je      .exit

    dec     rax                       ; i = i - 1

    mov     ebx, DWORD [rcx + 0x0204] ; rbx = Pattern.Offset
    mov     qword [rbp - 0x0008], rbx

    lea     rsi, [rcx + 0x0004]       ; rsi = AddressOf(Pattern.Binary)
    lea     rdi, [rcx + 0x0104]       ; rdi = AddressOf(Pattern.Mask)

    mov     rbx, QWORD [rdx]          ; rbx (Cursor)  = Buffer.Base
    mov     rcx, QWORD [rdx + 0x0004] ; rcx (ScanEnd) = Buffer.End

    mov     QWORD [rbp - 0x0010], rbx ; store base in local var

    sub     rcx, rax                  ; rcx = ScanEnd - i
    movzx   rdx, BYTE [rsi + rax]     ; use r8d as 32-bit index


.loop:
    cmp     rbx, rcx                  ; if rbx (Cursor) >= rcx (ScanEnd)
    jae     .returnZero               ;     GoTo .returnZero

    cmp     BYTE [rbx + rax], dl
    jne     .next

    push    rax                       ; push i -> n

.patternLoop:
    dec     rax                       ; n = n - 1
    cmp     BYTE [rdi + rax], 'x'     ; if (Mask[n] != 'x')
    jne     .checkLoopDone            ;     GoTo .checkLoopDone

    mov     dh, BYTE [rsi + rax]      ; dh = Binary[n]
    cmp     BYTE [rbx + rax], dh      ; if (ReadByte[ScanStart + n] != Binary[n])
    jne     .continue                 ;     GoTo .continue

.checkLoopDone:
    test    rax, rax                  ; if (n != 0)
    jne     .patternLoop              ;     GoTo .patternLoop

.continue:
    pop     rax                       ; recycle n
    jne     .next                     ; GoTo .next

    ; match found
    mov     rax, rbx                  ; rax = Cursor
    mov     rbx, [rbp - 0x0010]       ; rbx = Buffer.Base
    sub     rax, rbx                  ; rax = RVA
    jmp     .exit

.next:
    inc     rbx                       ; Cursor = Cursor + 1
    jmp     .loop                     ; GoTo .loop

.returnZero:
    xor     rax, rax                  ; return 0

.exit:
    test    rax, rax                  ; checks if returnValue == 0
    jz      .skipOffset               ; if it is zero, goto .skipOffset
    add     rax, qword [rbp - 0x0008] ; add or subtract the offset of the pattern

.skipOffset:
    pop     rdi rsi rbx               ; restore the registers to the values before the function got called
    mov     rsp, rbp                  ; Remove local variables
    pop     rbp                       ; leaves the stack frame
    ret                               ; returns to the calling address.
